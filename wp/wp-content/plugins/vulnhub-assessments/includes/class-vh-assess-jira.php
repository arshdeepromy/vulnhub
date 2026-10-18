<?php
/**
 * Supplier assessment register: what Jira can tell it.
 *
 * Read-only and optional. Everything here comes from data the Jira plugin
 * already keeps -- the assessment-request inbox it refreshes every fifteen
 * minutes, with each open request's recent conversation -- so this makes no
 * Jira call of its own. With the Jira plugin off, keys still print, just not
 * as links, and the "not yet in the register" tab says why it is empty.
 *
 * Decision hints are exactly that. A comment that reads "Approved with
 * conditions" is shown beside the row and offered as a starting point in the
 * form; it never changes a row by itself.
 *
 * @package VulnHub\Assessments
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VH_Assess_Jira {

	/** @var array<string,array<string,mixed>>|null */
	private static ?array $inbox = null;

	private static ?string $site = null;

	public static function available(): bool {
		return class_exists( 'VulnHub_Jira_Inbox' );
	}

	/**
	 * The Jira site's address, from the connector's own client, so the link
	 * matches whatever site the connector is pointed at today.
	 */
	public static function site(): string {
		if ( null !== self::$site ) {
			return self::$site;
		}

		self::$site = '';

		if ( function_exists( 'vulnhub' ) && isset( vulnhub()->connectors ) ) {
			$c = vulnhub()->connectors->get( 'jira' );

			if ( $c && method_exists( $c, 'client' ) && ( ! method_exists( $c, 'is_mock' ) || ! $c->is_mock() ) ) {
				try {
					self::$site = (string) $c->client()->site_url();
				} catch ( \Throwable $e ) {
					self::$site = '';
				}
			}
		}

		return self::$site;
	}

	public static function browse_url( string $key ): string {
		$site = self::site();

		return '' !== $site ? $site . '/browse/' . rawurlencode( $key ) : '';
	}

	/**
	 * The issue's page inside the portal, when the inbox holds it (the
	 * portal only opens issues it has already read).
	 */
	public static function portal_url( string $key ): string {
		$row = self::inbox()[ $key ] ?? null;

		if ( ! $row || ! class_exists( 'VulnHub_Dash_Portal' ) ) {
			return '';
		}

		return VulnHub_Dash_Portal::portal_url(
			'tickets',
			array(
				'tview' => (string) $row['set_key'],
				'jkey'  => $key,
			)
		);
	}

	/**
	 * Every issue the inbox holds, keyed by issue key. Where an issue sits in
	 * more than one set, the assessments set wins.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	public static function inbox(): array {
		if ( null !== self::$inbox ) {
			return self::$inbox;
		}

		self::$inbox = array();

		if ( ! self::available() ) {
			return self::$inbox;
		}

		global $wpdb;

		$t = VulnHub_Jira_Inbox::table();

		// The table may not exist yet on a fresh install.
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $t ) ) !== $t ) {
			return self::$inbox;
		}

		$rows = (array) $wpdb->get_results(
			"SELECT set_key, issue_key, summary, status, status_category, reporter, assignee, created_at, resolved_at, updated_at, tag, conversation
			FROM {$t} ORDER BY ( set_key = 'assessments' ) ASC, id ASC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);

		foreach ( $rows as $r ) {
			self::$inbox[ strtoupper( (string) $r['issue_key'] ) ] = $r;
		}

		return self::$inbox;
	}

	/**
	 * Assessment requests the inbox holds that no row links to and nobody
	 * has set aside. Newest first.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function unregistered(): array {
		$linked    = VH_Assess_Repo::linked_keys() + self::exception_keys();
		$dismissed = VH_Assess_Repo::dismissed();
		$out       = array();

		foreach ( self::inbox() as $key => $r ) {
			if ( 'assessments' !== (string) $r['set_key'] || isset( $linked[ $key ] ) || isset( $dismissed[ $key ] ) ) {
				continue;
			}
			$r['key']  = $key;
			$r['hint'] = self::hint( (string) ( $r['conversation'] ?? '' ), (string) ( $r['reporter'] ?? '' ) );
			$out[]     = $r;
		}

		usort( $out, static fn( array $a, array $b ): int => strcmp( (string) $b['created_at'], (string) $a['created_at'] ) );

		return $out;
	}

	/**
	 * Jira keys already recorded in the portal's Exception register, so a
	 * request recorded there is not listed as missing here.
	 *
	 * @return array<string,int> key => exception id
	 */
	public static function exception_keys(): array {
		if ( ! class_exists( '\\VulnHub\\Core\\Exceptions' ) ) {
			return array();
		}

		global $wpdb;

		$out = array();
		foreach ( (array) $wpdb->get_results( 'SELECT id, jira_key FROM ' . vh_table( 'exceptions' ) . " WHERE jira_key <> ''", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			foreach ( VH_Assess_Repo::split_keys( (string) $r['jira_key'] ) as $k ) {
				$out[ $k ] = (int) $r['id'];
			}
		}

		return $out;
	}

	/**
	 * Assessment requests set aside as not register items, with why.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function set_aside(): array {
		$out = array();

		foreach ( VH_Assess_Repo::dismissed() as $key => $d ) {
			$r      = self::inbox()[ $key ] ?? array();
			$out[]  = array(
				'key'     => $key,
				'summary' => (string) ( $r['summary'] ?? '' ),
				'status'  => (string) ( $r['status'] ?? '' ),
				'created' => (string) ( $r['created_at'] ?? '' ),
				'reason'  => (string) ( $d['reason'] ?? '' ),
				'at'      => (string) ( $d['at'] ?? '' ),
			);
		}

		usort( $out, static fn( array $a, array $b ): int => strcmp( $b['created'], $a['created'] ) );

		return $out;
	}

	/**
	 * The newest decision-like comment among a row's linked issues.
	 *
	 * @param array<int,string> $keys Jira keys.
	 * @return array{key:string,by:string,at:string,text:string,outcome:string}|null
	 */
	public static function hint_for_keys( array $keys, string $requester = '', string $reviewer = '' ): ?array {
		$best = null;

		foreach ( $keys as $k ) {
			$r = self::inbox()[ $k ] ?? null;
			if ( ! $r ) {
				continue;
			}
			$h = self::hint( (string) ( $r['conversation'] ?? '' ), '' !== $requester ? $requester : (string) ( $r['reporter'] ?? '' ), $reviewer );
			if ( $h && ( ! $best || $h['at'] > $best['at'] ) ) {
				$best = array( 'key' => $k ) + $h;
			}
		}

		return $best;
	}

	/**
	 * Read a stored conversation for the most recent comment that reads as a
	 * decision. Questions about a decision ("should I record it as
	 * approved?") are the commonest false match, so anything asking is
	 * skipped. So is anything the requester wrote: nobody approves their own
	 * request, and "it was approved previously" from them is a claim, not a
	 * decision. Nor the reviewer's: a reviewer recommends, the approver
	 * decides.
	 *
	 * @return array{by:string,at:string,text:string,outcome:string}|null
	 */
	public static function hint( string $json, string $requester = '', string $reviewer = '' ): ?array {
		if ( '' === $json ) {
			return null;
		}

		$conv = json_decode( $json, true );

		foreach ( (array) ( $conv['said'] ?? array() ) as $s ) {
			$text = trim( (string) ( $s['text'] ?? '' ) );

			if ( '' === $text || ! preg_match( self::decision_pattern(), $text ) ) {
				continue;
			}
			foreach ( array( $requester, $reviewer ) as $not ) {
				if ( '' !== $not && 0 === strcasecmp( trim( $not ), trim( (string) ( $s['by'] ?? '' ) ) ) ) {
					continue 2;
				}
			}
			if ( preg_match( '/\?|\bshould i\b|\bcan you\b|\bcould you\b|\blooks like\b|\bcan (?:we |i )?record\b|\bplease (?:add|provide|comment)\b|\brequires? (?:an? )?approval\b|\bfor (?:your )?approval\b|\bawaiting\b|\bpending\b/i', $text ) ) {
				continue;
			}

			return array(
				'by'      => (string) ( $s['by'] ?? '' ),
				'at'      => (string) ( $s['at'] ?? '' ),
				'text'    => $text,
				'outcome' => self::guess( $text ),
			);
		}

		return null;
	}

	public static function decision_pattern(): string {
		return (string) apply_filters(
			'vulnhub_assess_decision_pattern',
			'/\b(approved?|approval (?:is )?granted|happy to approve|rejected|not approved|declined?)\b/i'
		);
	}

	public static function guess( string $text ): string {
		if ( preg_match( '/\breject/i', $text ) ) {
			return 'rejected';
		}
		if ( preg_match( '/\bnot approved\b|\bdeclin/i', $text ) ) {
			return 'not_approved';
		}
		if ( preg_match( '/\bcondition|\bguardrail|\bprovided that\b|\bsubject to\b|\btrial use only\b/i', $text ) ) {
			return 'conditional';
		}

		return 'approved';
	}
}

