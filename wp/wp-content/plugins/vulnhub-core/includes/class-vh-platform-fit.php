<?php
/**
 * Platform fit: a scanner finding that names a platform the asset is not.
 *
 * Since January 2026 Microsoft gives Windows Server 2025 its own monthly KB
 * and its own build numbers, separate from Windows 11 24H2/25H2 -- but both
 * still report build 10.0.26100. Tenable's "Windows Server 2025 Security
 * Update" plugins compare ntoskrnl.exe against the *Server* build number
 * (26100.33158 for July 2026) and so fire on every Windows 11 workstation a
 * month or more behind, which is also missing the Windows 11 update that
 * actually applies. The result was the same machines counted two or three
 * times, and tickets telling a workstation team to install a server package.
 *
 * This decides, when a finding is written, that a plugin aimed only at
 * Windows Server does not apply to a Windows client, and the finding lands
 * `suppressed` -- the state every count, widget, report, export and ticket
 * draft already excludes (vh_live_finding_states()). Nothing is deleted:
 * `prev_state` keeps the way back, and the decision is re-made on every write
 * and on every Tenable sync (sweep()), so an asset that turns out to be a
 * server gets its findings back.
 *
 * Deliberately narrow:
 *  - only plugins whose title names Windows Server (or Azure Stack HCI) and
 *    no client Windows -- "Windows 10 version 1809 / Windows Server 2019" and
 *    "Windows 11 Version 24H2 / Windows Server 2025" titles apply to both and
 *    are left alone;
 *  - only assets whose operating system is positively a Windows client
 *    (Os::parse() family `windows`). An asset with no OS string is never
 *    suppressed on a guess.
 *
 * The reverse (a client-only plugin on a server) is not suppressed: no case of
 * it has been seen, and hiding a real server finding would cost more than a
 * duplicate. Filter `vulnhub_platform_mismatch` to widen or narrow the rule.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Platform_Fit {

	/** Server-only vuln ids, loaded once per request. */
	private static ?array $server_vulns = null;

	/** Highest vuln id that load saw; anything newer is looked up singly. */
	private static int $vuln_ceiling = 0;

	/** @var array<int,bool> Per-request cache for vulns past the ceiling. */
	private static array $late_vulns = array();

	/** @var array<int,string> asset id => Os family. */
	private static array $asset_family = array();

	/**
	 * Does this plugin title target Windows Server only?
	 */
	public static function server_only_title( string $title ): bool {
		$server = (bool) preg_match( '/\bWindows Server\b|\bAzure Stack HCI\b/i', $title );
		$client = (bool) preg_match( '/\bWindows (?:10|11|7|8(?:\.1)?|RT|Vista|XP)\b/i', $title );

		return $server && ! $client;
	}

	/**
	 * Would a finding of this plugin on this asset be a platform mismatch?
	 */
	public static function mismatch( int $vuln_id, int $asset_id ): bool {
		if ( $vuln_id <= 0 || $asset_id <= 0 ) {
			return false;
		}

		$server_only = self::is_server_vuln( $vuln_id );
		$family      = $server_only ? self::asset_family( $asset_id ) : '';
		$mismatch    = $server_only && 'windows' === $family;

		/**
		 * Filters whether a finding is a platform mismatch and lands suppressed.
		 *
		 * @param bool $mismatch Default decision.
		 * @param int  $vuln_id  Vuln row id.
		 * @param int  $asset_id Asset row id.
		 * @param string $family Os::parse() family of the asset ('' when not looked up).
		 */
		return (bool) apply_filters( 'vulnhub_platform_mismatch', $mismatch, $vuln_id, $asset_id, $family );
	}

	/**
	 * Why a suppressed finding is suppressed, for a person, or ''.
	 */
	public static function reason( int $vuln_id, int $asset_id ): string {
		return self::mismatch( $vuln_id, $asset_id )
			? __( 'Windows Server update reported on a Windows client. Tenable compares the client against the server build number; the client update for the same month is what applies.', 'vulnhub' )
			: '';
	}

	/**
	 * Forget the cached lookups -- after an asset's OS changes in a long run.
	 */
	public static function reset(): void {
		self::$server_vulns = null;
		self::$vuln_ceiling = 0;
		self::$late_vulns   = array();
		self::$asset_family = array();
	}

	private static function is_server_vuln( int $vuln_id ): bool {
		global $wpdb;

		if ( null === self::$server_vulns ) {
			$table = vh_table( 'vulns' );
			$rows  = (array) $wpdb->get_results(
				"SELECT id, title FROM {$table} WHERE LOCATE('Windows Server', title) > 0 OR LOCATE('Azure Stack HCI', title) > 0", // phpcs:ignore WordPress.DB.PreparedSQL
				ARRAY_A
			);

			self::$server_vulns = array();
			foreach ( $rows as $r ) {
				if ( self::server_only_title( (string) $r['title'] ) ) {
					self::$server_vulns[ (int) $r['id'] ] = true;
				}
			}
			self::$vuln_ceiling = (int) $wpdb->get_var( "SELECT MAX(id) FROM {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL
		}

		if ( $vuln_id <= self::$vuln_ceiling ) {
			return isset( self::$server_vulns[ $vuln_id ] );
		}

		// A plugin first seen during this run.
		if ( ! isset( self::$late_vulns[ $vuln_id ] ) ) {
			$title = (string) $wpdb->get_var( $wpdb->prepare( 'SELECT title FROM ' . vh_table( 'vulns' ) . ' WHERE id = %d', $vuln_id ) ); // phpcs:ignore WordPress.DB.PreparedSQL

			self::$late_vulns[ $vuln_id ] = self::server_only_title( $title );
		}

		return self::$late_vulns[ $vuln_id ];
	}

	private static function asset_family( int $asset_id ): string {
		global $wpdb;

		if ( ! isset( self::$asset_family[ $asset_id ] ) ) {
			$os = (string) $wpdb->get_var( $wpdb->prepare( 'SELECT operating_system FROM ' . vh_table( 'assets' ) . ' WHERE id = %d', $asset_id ) ); // phpcs:ignore WordPress.DB.PreparedSQL

			self::$asset_family[ $asset_id ] = (string) Os::parse( $os )['family'];
		}

		return self::$asset_family[ $asset_id ];
	}

	/**
	 * Bring every existing finding of a server-only plugin into line.
	 *
	 * Suppresses the mismatches that are not suppressed yet, and gives back
	 * the ones that no longer are (the asset turned out to be a server, or the
	 * rule changed). Runs after every Tenable sync, because a delta sync only
	 * re-sends findings that changed and an asset's OS can change without its
	 * findings doing so. Archived rows are left alone.
	 *
	 * @return array{checked:int,suppressed:int,restored:int,by_vuln:array<string,int>}
	 */
	public static function sweep( bool $write = true ): array {
		global $wpdb;

		self::reset();
		self::is_server_vuln( 0 );

		$out = array( 'checked' => 0, 'suppressed' => 0, 'restored' => 0, 'by_vuln' => array(), 'detached' => 0, 'tickets' => array() );
		$parked = array();
		$ids = array_keys( (array) self::$server_vulns );

		if ( ! $ids ) {
			return $out;
		}

		$f      = vh_table( 'findings' );
		$v      = vh_table( 'vulns' );
		$titles = array();

		foreach ( array_chunk( $ids, 500 ) as $chunk ) {
			$in   = implode( ',', array_map( 'intval', $chunk ) );
			$rows = (array) $wpdb->get_results(
				"SELECT f.id, f.vuln_id, f.asset_id, f.state, f.prev_state, f.severity, v.title
				 FROM {$f} f JOIN {$v} v ON v.id = f.vuln_id
				 WHERE f.vuln_id IN ({$in}) AND f.archived_at IS NULL AND f.state <> 'archived'", // phpcs:ignore WordPress.DB.PreparedSQL
				ARRAY_A
			);

			foreach ( $rows as $r ) {
				++$out['checked'];
				$is_mismatch = self::mismatch( (int) $r['vuln_id'], (int) $r['asset_id'] );
				$state       = (string) $r['state'];

				if ( $is_mismatch ) {
					$parked[] = (int) $r['id'];
				}

				if ( $is_mismatch && 'suppressed' !== $state ) {
					++$out['suppressed'];
					$key                    = (string) $r['title'];
					$out['by_vuln'][ $key ] = ( $out['by_vuln'][ $key ] ?? 0 ) + 1;

					if ( $write ) {
						$wpdb->update(
							$f,
							array( 'state' => 'suppressed', 'prev_state' => $state, 'updated_at' => vh_now() ),
							array( 'id' => (int) $r['id'] )
						);
					}
				} elseif ( ! $is_mismatch && 'suppressed' === $state && ! vh_severity_suppressed( (string) $r['severity'] ) ) {
					// Only rows this rule parked: a server-only plugin, not an
					// informational one, now judged to fit.
					++$out['restored'];

					if ( $write ) {
						$back = (string) $r['prev_state'];
						$wpdb->update(
							$f,
							array( 'state' => in_array( $back, array( 'open', 'reopened', 'fixed' ), true ) ? $back : 'open', 'prev_state' => '', 'updated_at' => vh_now() ),
							array( 'id' => (int) $r['id'] )
						);
					}
				}
			}
		}

		arsort( $out['by_vuln'] );

		$detach              = self::detach_from_tickets( $parked, $write );
		$out['detached']     = $detach['links'];
		$out['tickets']      = $detach['tickets'];

		return $out;
	}

	/**
	 * Take parked findings off the tickets they were raised on.
	 *
	 * A ticket is a list of work. A finding that does not apply to the asset
	 * is not work, and leaving the link in place would have every reader of
	 * ticket_findings -- the progress bar, the findings table, verification,
	 * the ticket report, the automations -- decide separately what to do with
	 * it, and the progress bar would have counted it as done (it is "not
	 * outstanding"). So the link goes, and the ticket's finding_count is
	 * recounted: the ticket is then about the findings that apply.
	 *
	 * Recorded in the audit log per ticket, with the finding ids, because the
	 * links are not recreated if a finding is ever restored.
	 *
	 * @param int[] $finding_ids Findings this rule parks.
	 * @return array{links:int,tickets:array<string,int>}
	 */
	private static function detach_from_tickets( array $finding_ids, bool $write ): array {
		global $wpdb;

		$out = array( 'links' => 0, 'tickets' => array() );

		if ( ! $finding_ids ) {
			return $out;
		}

		$tf = vh_table( 'ticket_findings' );
		$tk = vh_table( 'tickets' );

		foreach ( array_chunk( $finding_ids, 1000 ) as $chunk ) {
			$in   = implode( ',', array_map( 'intval', $chunk ) );
			$rows = (array) $wpdb->get_results( "SELECT tf.id, tf.ticket_id, tf.finding_id, t.external_key FROM {$tf} tf JOIN {$tk} t ON t.id = tf.ticket_id WHERE tf.finding_id IN ({$in})", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL

			$by_ticket = array();
			foreach ( $rows as $r ) {
				$by_ticket[ (int) $r['ticket_id'] ]['key']        = (string) $r['external_key'];
				$by_ticket[ (int) $r['ticket_id'] ]['links'][]    = (int) $r['id'];
				$by_ticket[ (int) $r['ticket_id'] ]['findings'][] = (int) $r['finding_id'];
			}

			foreach ( $by_ticket as $ticket_id => $t ) {
				$n                         = count( $t['links'] );
				$out['links']             += $n;
				$out['tickets'][ $t['key'] ] = ( $out['tickets'][ $t['key'] ] ?? 0 ) + $n;

				if ( ! $write ) {
					continue;
				}

				$wpdb->query( "DELETE FROM {$tf} WHERE id IN (" . implode( ',', $t['links'] ) . ')' ); // phpcs:ignore WordPress.DB.PreparedSQL
				$wpdb->update(
					$tk,
					array(
						'finding_count' => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$tf} WHERE ticket_id = %d", $ticket_id ) ), // phpcs:ignore WordPress.DB.PreparedSQL
						'updated_at'    => vh_now(),
					),
					array( 'id' => $ticket_id )
				);

				vulnhub()->logger->audit(
					'ticket.platform_fit',
					sprintf(
						/* translators: 1: number of findings, 2: ticket key. */
						__( '%1$d Windows Server findings on Windows clients taken off %2$s: they do not apply to those machines.', 'vulnhub' ),
						$n,
						$t['key']
					),
					'ticket',
					$ticket_id,
					array( 'finding_ids' => $t['findings'] )
				);
			}
		}

		return $out;
	}

	/**
	 * Hooked to `vulnhub_sync_complete` ahead of the lifecycle recount, so the
	 * asset roll-ups that recount writes already leave these out.
	 */
	public static function after_sync( string $connector = '' ): void {
		if ( 'tenable' !== $connector ) {
			return;
		}

		$stats = self::sweep( true );

		if ( $stats['suppressed'] || $stats['restored'] || $stats['detached'] ) {
			if ( class_exists( 'VulnHub_Dash_Widgets' ) ) {
				\VulnHub_Dash_Widgets::bust();
			}
			vulnhub()->logger->audit(
				'findings.platform_fit',
				sprintf(
					/* translators: 1: findings suppressed, 2: findings restored, 3: ticket links removed. */
					__( 'Platform fit: %1$d Windows Server findings on Windows clients suppressed, %2$d restored, %3$d taken off tickets.', 'vulnhub' ),
					$stats['suppressed'],
					$stats['restored'],
					$stats['detached']
				),
				'finding',
				0,
				array( 'by_vuln' => array_slice( $stats['by_vuln'], 0, 20, true ) )
			);
		}
	}
}

