<?php
/**
 * Jira inbox: what is waiting on the connected Jira account itself.
 *
 * Three sets, read from Jira into one local table and drawn as tabs on the
 * portal's Tickets page, beside the remediation tickets this portal raises:
 *
 *  - `mine`        Issues the account reported directly in Jira. Tickets this
 *                  portal raises carry the same account as reporter, because
 *                  it raises them as that account, so those are left out at
 *                  read time against `vulnhub_tickets.external_key`. They
 *                  already have their own tab, with verification.
 *  - `approvals`   Service-desk requests whose approval is waiting on the
 *                  account. Read from the service desk API, never from JQL:
 *                  `approver = currentUser()` and `approval = myPending()`
 *                  both came back empty on a real site that had five
 *                  requests waiting, because the approver list is hidden
 *                  from the approver. GET /servicedeskapi/request with
 *                  `requestOwnership=APPROVER` returned all five.
 *  - `assessments` Requests of the request types named in the connector's
 *                  "Assessment request types" setting, whoever raised them.
 *                  Third-party questionnaires sit inside the same request
 *                  type on most desks, so they are a tag on the row rather
 *                  than a set of their own.
 *
 * Each issue also opens in the portal (`&jkey=KEY` on its tab): fields,
 * description, attachments, the conversation with a reply box, and Change
 * status -- the same components a ticket raised here uses, reached through
 * `/vulnhub/v1/tickets/jira/{KEY}/…`. Jira decides what the account may do:
 * the moves offered are the ones its workflow offers this account, and a
 * reply it refuses comes back as Jira's own refusal.
 *
 * Reading is most of what this does. The writes: answering an approval, only
 * when a person clicks, and only after a fresh read confirms Jira still has
 * that approval pending and still lets this account answer it. The answer is
 * given as the connected account -- the same identity the portal raises
 * tickets as -- so the button is held to `vulnhub_manage` by default.
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use VulnHub\Core\Caps;

final class VulnHub_Jira_Inbox {

	public const DB_VERSION     = '2';
	public const VERSION_OPTION = 'vulnhub_jira_inbox_db';
	public const STATE_OPTION   = 'vulnhub_jira_inbox_state';

	/** Cron hook: re-read every set. */
	public const HOOK = 'vulnhub_jira_inbox_refresh';

	/** admin-post actions. */
	public const ACTION_REFRESH = 'vulnhub_jira_inbox_now';
	public const ACTION_DECIDE  = 'vulnhub_jira_approval_decide';

	public const SETS = array( 'mine', 'approvals', 'assessments' );

	/** A read that would go past this is stopped and flagged, not trimmed silently. */
	private const MAX_ROWS = 2000;

	/** Closed issues of your own are kept this long after their last update. */
	private const MINE_DAYS = 90;

	private const PER_PAGE = 25;

	private const LOCK = 'vulnhub_jira_inbox_lock';

	/** An issue key in a REST route. */
	private const KEY_RE = '[A-Za-z][A-Za-z0-9_]*-\d+';

	/** Live issue reads are kept this long; a comment or a move clears them. */
	private const ISSUE_TTL = 2 * MINUTE_IN_SECONDS;

	/** Columns refreshed from a live read of one issue. */
	private const DISPLAY_COLS = array( 'project_key', 'summary', 'issue_type', 'request_type', 'status', 'status_category', 'priority', 'reporter', 'assignee', 'assignee_id', 'created_at', 'updated_at', 'resolved_at', 'due_on' );

	/** Comment threads read per refresh, newest activity first. */
	private const CONVERSATIONS_PER_RUN = 40;

	/* =================================================================
	 * Wiring
	 * ============================================================== */

	public static function hooks(): void {
		self::maybe_install();

		add_action( self::HOOK, array( __CLASS__, 'cron' ) );
		add_action( 'init', array( __CLASS__, 'ensure_schedule' ), 30 );
		add_action( 'admin_post_' . self::ACTION_REFRESH, array( __CLASS__, 'handle_refresh' ) );
		add_action( 'admin_post_' . self::ACTION_DECIDE, array( __CLASS__, 'handle_decide' ) );
		add_filter( 'vulnhub_ticket_views', array( __CLASS__, 'views' ) );
		add_action( 'rest_api_init', array( __CLASS__, 'routes' ) );
		add_filter( 'vulnhub_notifications', array( __CLASS__, 'notify' ), 20 );
		add_filter( 'vulnhub_ticket_signal_conversations', array( __CLASS__, 'signal_conversations' ) );
	}

	public static function table(): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_jira_inbox';
	}

	public static function maybe_install(): void {
		if ( self::DB_VERSION === (string) get_option( self::VERSION_OPTION, '' ) ) {
			return;
		}

		self::install();
	}

	public static function install(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$c = $wpdb->get_charset_collate();

		dbDelta(
			'CREATE TABLE ' . self::table() . " (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				set_key varchar(20) NOT NULL DEFAULT '',
				issue_key varchar(40) NOT NULL DEFAULT '',
				project_key varchar(32) NOT NULL DEFAULT '',
				summary varchar(500) NOT NULL DEFAULT '',
				issue_type varchar(120) NOT NULL DEFAULT '',
				request_type varchar(190) NOT NULL DEFAULT '',
				status varchar(120) NOT NULL DEFAULT '',
				status_category varchar(20) NOT NULL DEFAULT '',
				priority varchar(60) NOT NULL DEFAULT '',
				reporter varchar(190) NOT NULL DEFAULT '',
				assignee varchar(190) NOT NULL DEFAULT '',
				assignee_id varchar(128) NOT NULL DEFAULT '',
				created_at datetime NULL DEFAULT NULL,
				updated_at datetime NULL DEFAULT NULL,
				resolved_at datetime NULL DEFAULT NULL,
				due_on date NULL DEFAULT NULL,
				approval_id varchar(40) NOT NULL DEFAULT '',
				approval_name varchar(190) NOT NULL DEFAULT '',
				can_answer tinyint(1) NOT NULL DEFAULT 0,
				tag varchar(40) NOT NULL DEFAULT '',
				conversation longtext NULL,
				conv_at varchar(32) NOT NULL DEFAULT '',
				synced_at datetime NULL DEFAULT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY set_issue (set_key,issue_key),
				KEY set_cat (set_key,status_category)
			) {$c};"
		);

		update_option( self::VERSION_OPTION, self::DB_VERSION, false );
	}

	/**
	 * Keep the 15-minute read scheduled while the inbox is on, and off the
	 * cron list while it is not.
	 */
	public static function ensure_schedule(): void {
		$next = wp_next_scheduled( self::HOOK );

		if ( self::enabled() ) {
			if ( ! $next ) {
				wp_schedule_event( time() + wp_rand( 60, 300 ), 'vh_15min', self::HOOK );
			}
			return;
		}

		while ( $next ) {
			wp_unschedule_event( $next, self::HOOK );
			$next = wp_next_scheduled( self::HOOK );
		}
	}

	public static function cron(): void {
		if ( self::enabled() ) {
			self::refresh();
		}
	}

	/* =================================================================
	 * Who may do what
	 * ============================================================== */

	private static function connector(): ?VulnHub_Jira_Connector {
		return function_exists( 'vulnhub_jira_connector' ) ? vulnhub_jira_connector() : null;
	}

	/** The connector is set up for a real site and the inbox is switched on. */
	public static function enabled(): bool {
		$c = self::connector();

		return $c
			&& $c->is_enabled()
			&& ! $c->is_mock()
			&& (int) $c->get( 'inbox_enabled', 1 ) === 1
			&& $c->client()->has_credentials();
	}

	/** The tabs are drawn whenever the inbox is switched on, even before the first read. */
	private static function shown(): bool {
		$c = self::connector();

		return $c && (int) $c->get( 'inbox_enabled', 1 ) === 1 && current_user_can( Caps::VIEW );
	}

	/** Answering an approval acts as the connected account. */
	public static function decide_cap(): string {
		return (string) apply_filters( 'vulnhub_jira_approval_cap', Caps::MANAGE );
	}

	public static function can_refresh(): bool {
		return current_user_can( Caps::RUN_SYNC );
	}

	/* =================================================================
	 * Reading from Jira
	 * ============================================================== */

	/**
	 * Re-read the given sets. Each set is replaced only by a complete read;
	 * a failed page leaves the previous rows in place and records the error.
	 *
	 * @param string[] $sets Which sets.
	 * @return array<string,array{ok:bool,count:int,error:string}>
	 */
	public static function refresh( array $sets = self::SETS ): array {
		$out = array();

		if ( ! self::enabled() ) {
			return $out;
		}
		if ( get_transient( self::LOCK ) ) {
			foreach ( $sets as $set ) {
				$out[ $set ] = array( 'ok' => false, 'count' => 0, 'error' => __( 'A read from Jira is already running.', 'vulnhub' ) );
			}
			return $out;
		}

		set_transient( self::LOCK, 1, 5 * MINUTE_IN_SECONDS );

		try {
			$cl    = self::connector()->client();
			$state = self::state();

			$me = $cl->myself();
			if ( $me->ok() ) {
				$state['account']    = (string) ( $me->data()['displayName'] ?? '' );
				$state['account_id'] = (string) ( $me->data()['accountId'] ?? '' );
			}

			$rt_field = self::request_type_field( $cl, $state );

			foreach ( array_intersect( self::SETS, $sets ) as $set ) {
				$read = match ( $set ) {
					'mine'        => self::read_mine( $cl, $rt_field ),
					'approvals'   => self::read_approvals( $cl, $rt_field ),
					'assessments' => self::read_assessments( $cl, $rt_field ),
				};

				if ( $read['ok'] ) {
					self::replace_set( $set, $read['rows'] );
				}

				$state['sets'][ $set ] = array(
					'at'      => vh_now(),
					'ok'      => (bool) $read['ok'],
					'count'   => count( $read['rows'] ),
					'error'   => (string) $read['error'],
					'capped'  => ! empty( $read['capped'] ),
					'skipped' => ! empty( $read['skipped'] ),
				);
				if ( $read['ok'] ) {
					$state['sets'][ $set ]['ok_at'] = vh_now();
				} else {
					$state['sets'][ $set ]['ok_at'] = (string) ( self::state()['sets'][ $set ]['ok_at'] ?? '' );
				}

				$out[ $set ] = array(
					'ok'    => (bool) $read['ok'],
					'count' => count( $read['rows'] ),
					'error' => (string) $read['error'],
				);
			}

			// Whose turn it is lives in the comments: read the threads that
			// moved since they were last read, a bounded number a run.
			$state['conversations'] = array( 'at' => vh_now(), 'read' => self::read_conversations( self::CONVERSATIONS_PER_RUN ) );

			update_option( self::STATE_OPTION, $state, false );
		} finally {
			delete_transient( self::LOCK );
		}

		return $out;
	}

	/** @return array<string,mixed> */
	public static function state(): array {
		$s = get_option( self::STATE_OPTION, array() );

		return is_array( $s ) ? $s + array( 'sets' => array() ) : array( 'sets' => array() );
	}

	/**
	 * The request-type field's id differs per site, so it is looked up by
	 * its schema rather than written down.
	 *
	 * @param array<string,mixed> $state Inbox state, updated in place.
	 */
	private static function request_type_field( VulnHub_Jira_Client $cl, array &$state ): string {
		if ( ! empty( $state['rt_field'] ) && ! empty( $state['rt_field_at'] ) && strtotime( (string) $state['rt_field_at'] . ' UTC' ) > time() - DAY_IN_SECONDS ) {
			return (string) $state['rt_field'];
		}

		$r = $cl->fields();
		if ( ! $r->ok() ) {
			return (string) ( $state['rt_field'] ?? '' );
		}

		foreach ( $r->data() as $f ) {
			if ( is_array( $f ) && 'com.atlassian.servicedesk:vp-origin' === ( $f['schema']['custom'] ?? '' ) ) {
				$state['rt_field']    = (string) $f['id'];
				$state['rt_field_at'] = vh_now();
				return (string) $f['id'];
			}
		}

		return '';
	}

	/** @return string[] */
	private static function search_fields( string $rt_field ): array {
		$f = array( 'summary', 'status', 'issuetype', 'project', 'created', 'updated', 'resolutiondate', 'duedate', 'priority', 'reporter', 'assignee' );

		if ( '' !== $rt_field ) {
			$f[] = $rt_field;
		}

		return $f;
	}

	/**
	 * Every page of a JQL search. One failed page fails the whole read: a
	 * partial list would quietly drop rows from the table.
	 *
	 * @return array{ok:bool,issues:array<int,array<string,mixed>>,error:string,capped:bool}
	 */
	private static function search_all( VulnHub_Jira_Client $cl, string $jql, array $fields ): array {
		$issues = array();
		$token  = '';

		do {
			$r = $cl->search_jql( $jql, $fields, 100, $token );

			if ( ! $r->ok() ) {
				return array( 'ok' => false, 'issues' => array(), 'error' => vh_trim( $r->error_message(), 240 ), 'capped' => false );
			}

			$d      = $r->data();
			$page   = is_array( $d['issues'] ?? null ) ? $d['issues'] : array();
			$issues = array_merge( $issues, $page );
			$token  = (string) ( $d['nextPageToken'] ?? '' );

			if ( count( $issues ) >= self::MAX_ROWS ) {
				return array( 'ok' => true, 'issues' => array_slice( $issues, 0, self::MAX_ROWS ), 'error' => '', 'capped' => '' !== $token || count( $issues ) > self::MAX_ROWS );
			}
		} while ( '' !== $token && $page );

		return array( 'ok' => true, 'issues' => $issues, 'error' => '', 'capped' => false );
	}

	/** @return array{ok:bool,rows:array<int,array<string,mixed>>,error:string,capped?:bool,skipped?:bool} */
	private static function read_mine( VulnHub_Jira_Client $cl, string $rt_field ): array {
		$jql = sprintf( 'reporter = currentUser() AND (statusCategory != Done OR updated >= -%dd) ORDER BY updated DESC', self::MINE_DAYS );
		$s   = self::search_all( $cl, $jql, self::search_fields( $rt_field ) );

		if ( ! $s['ok'] ) {
			return array( 'ok' => false, 'rows' => array(), 'error' => $s['error'] );
		}

		return array(
			'ok'     => true,
			'rows'   => array_map( static fn( array $i ): array => self::row( $i, $rt_field ), $s['issues'] ),
			'error'  => '',
			'capped' => $s['capped'],
		);
	}

	/** @return array{ok:bool,rows:array<int,array<string,mixed>>,error:string,capped?:bool} */
	private static function read_approvals( VulnHub_Jira_Client $cl, string $rt_field ): array {
		$requests = array();
		$start    = 0;

		do {
			$r = $cl->approver_requests( $start, 50 );

			if ( ! $r->ok() ) {
				return array( 'ok' => false, 'rows' => array(), 'error' => vh_trim( $r->error_message(), 240 ) );
			}

			$d    = $r->data();
			$page = is_array( $d['values'] ?? null ) ? $d['values'] : array();

			foreach ( $page as $v ) {
				if ( ! empty( $v['issueKey'] ) ) {
					$requests[ (string) $v['issueKey'] ] = $v;
				}
			}

			$start += count( $page );
		} while ( empty( $d['isLastPage'] ) && $page && count( $requests ) < self::MAX_ROWS );

		if ( ! $requests ) {
			return array( 'ok' => true, 'rows' => array(), 'error' => '' );
		}

		// The issue fields (project, priority, assignee) come from one search
		// per 50 keys rather than one call per request.
		$issues = array();
		foreach ( array_chunk( array_keys( $requests ), 50 ) as $keys ) {
			$s = self::search_all( $cl, 'key in (' . implode( ',', $keys ) . ')', self::search_fields( $rt_field ) );

			if ( ! $s['ok'] ) {
				return array( 'ok' => false, 'rows' => array(), 'error' => $s['error'] );
			}
			foreach ( $s['issues'] as $i ) {
				$issues[ (string) $i['key'] ] = $i;
			}
		}

		$rows = array();
		foreach ( $requests as $key => $req ) {
			$a = $cl->request_approvals( $key );

			if ( ! $a->ok() ) {
				return array( 'ok' => false, 'rows' => array(), 'error' => vh_trim( $a->error_message(), 240 ) );
			}

			$pending = null;
			foreach ( (array) ( $a->data()['values'] ?? array() ) as $ap ) {
				if ( 'pending' !== ( $ap['finalDecision'] ?? '' ) ) {
					continue;
				}
				// Prefer the one this account can answer, if a request has two.
				if ( null === $pending || ! empty( $ap['canAnswerApproval'] ) ) {
					$pending = $ap;
				}
			}

			$row = isset( $issues[ $key ] )
				? self::row( $issues[ $key ], $rt_field )
				: self::row_from_request( $req );

			$row['approval_id']   = (string) ( $pending['id'] ?? '' );
			$row['approval_name'] = (string) ( $pending['name'] ?? '' );
			$row['can_answer']    = ! empty( $pending['canAnswerApproval'] ) ? 1 : 0;

			if ( '' === $row['request_type'] ) {
				$row['request_type'] = (string) ( $req['requestType']['name'] ?? '' );
			}

			$rows[] = $row;
		}

		return array( 'ok' => true, 'rows' => $rows, 'error' => '' );
	}

	/** @return array{ok:bool,rows:array<int,array<string,mixed>>,error:string,capped?:bool,skipped?:bool} */
	private static function read_assessments( VulnHub_Jira_Client $cl, string $rt_field ): array {
		$types = self::assessment_types();

		if ( ! $types ) {
			return array( 'ok' => true, 'rows' => array(), 'error' => '', 'skipped' => true );
		}

		$quoted = array_map( static fn( string $t ): string => '"' . addcslashes( $t, '"\\' ) . '"', $types );
		$s      = self::search_all( $cl, '"Request Type" in (' . implode( ', ', $quoted ) . ') ORDER BY created DESC', self::search_fields( $rt_field ) );

		if ( ! $s['ok'] ) {
			return array( 'ok' => false, 'rows' => array(), 'error' => $s['error'] );
		}

		$pattern = self::third_party_pattern();
		$rows    = array();

		foreach ( $s['issues'] as $i ) {
			$row        = self::row( $i, $rt_field );
			$row['tag'] = '' !== $pattern && preg_match( $pattern, (string) $row['summary'] ) ? 'third_party' : '';
			$rows[]     = $row;
		}

		return array( 'ok' => true, 'rows' => $rows, 'error' => '', 'capped' => $s['capped'] );
	}

	/**
	 * Request type names from the connector setting, one per line.
	 *
	 * @return string[]
	 */
	public static function assessment_types(): array {
		$c   = self::connector();
		$raw = $c ? (string) $c->get( 'inbox_assessment_types', '' ) : '';

		$lines = preg_split( '/[\r\n]+/', $raw ) ?: array();

		return array_values( array_unique( array_filter( array_map( static fn( string $l ): string => trim( $l ), $lines ), static fn( string $l ): bool => '' !== $l ) ) );
	}

	/**
	 * Which assessment requests read as a third-party (supplier)
	 * assessment. Matched against the summary; filterable because desks
	 * name them differently.
	 */
	public static function third_party_pattern(): string {
		return (string) apply_filters( 'vulnhub_jira_third_party_pattern', '/\bTPISA\b|third[\s-]*party|information\s+security\s+assessment|questionnaire|\bRFP\b/i' );
	}

	/**
	 * One table row from a search result.
	 *
	 * @param array<string,mixed> $i Issue.
	 * @return array<string,mixed>
	 */
	private static function row( array $i, string $rt_field ): array {
		$f = (array) ( $i['fields'] ?? array() );

		return array(
			'issue_key'       => (string) ( $i['key'] ?? '' ),
			'project_key'     => (string) ( $f['project']['key'] ?? strtok( (string) ( $i['key'] ?? '' ), '-' ) ),
			'summary'         => (string) ( $f['summary'] ?? '' ),
			'issue_type'      => (string) ( $f['issuetype']['name'] ?? '' ),
			'request_type'    => '' !== $rt_field ? (string) ( $f[ $rt_field ]['requestType']['name'] ?? '' ) : '',
			'status'          => (string) ( $f['status']['name'] ?? '' ),
			'status_category' => (string) ( $f['status']['statusCategory']['key'] ?? '' ),
			'priority'        => (string) ( $f['priority']['name'] ?? '' ),
			'reporter'        => (string) ( $f['reporter']['displayName'] ?? '' ),
			'assignee'        => (string) ( $f['assignee']['displayName'] ?? '' ),
			'assignee_id'     => (string) ( $f['assignee']['accountId'] ?? '' ),
			'created_at'      => self::utc( $f['created'] ?? null ),
			'updated_at'      => self::utc( $f['updated'] ?? null ),
			'resolved_at'     => self::utc( $f['resolutiondate'] ?? null ),
			'due_on'          => ! empty( $f['duedate'] ) ? substr( (string) $f['duedate'], 0, 10 ) : null,
			'approval_id'     => '',
			'approval_name'   => '',
			'can_answer'      => 0,
			'tag'             => '',
		);
	}

	/**
	 * Fallback when the issue search could not see a request (the service
	 * desk API and the issue API apply different permissions).
	 *
	 * @param array<string,mixed> $r Request.
	 * @return array<string,mixed>
	 */
	private static function row_from_request( array $r ): array {
		$summary = '';
		foreach ( (array) ( $r['requestFieldValues'] ?? array() ) as $fv ) {
			if ( 'summary' === ( $fv['fieldId'] ?? '' ) ) {
				$summary = (string) ( $fv['value'] ?? '' );
			}
		}

		$cat = strtolower( (string) ( $r['currentStatus']['statusCategory'] ?? '' ) );

		return array(
			'issue_key'       => (string) $r['issueKey'],
			'project_key'     => (string) strtok( (string) $r['issueKey'], '-' ),
			'summary'         => $summary,
			'issue_type'      => '',
			'request_type'    => (string) ( $r['requestType']['name'] ?? '' ),
			'status'          => (string) ( $r['currentStatus']['status'] ?? '' ),
			'status_category' => in_array( $cat, array( 'new', 'indeterminate', 'done' ), true ) ? $cat : 'indeterminate',
			'priority'        => '',
			'reporter'        => (string) ( $r['reporter']['displayName'] ?? '' ),
			'assignee'        => '',
			'assignee_id'     => '',
			'created_at'      => self::utc( $r['createdDate']['iso8601'] ?? null ),
			'updated_at'      => null,
			'resolved_at'     => null,
			'due_on'          => null,
			'approval_id'     => '',
			'approval_name'   => '',
			'can_answer'      => 0,
			'tag'             => '',
		);
	}

	private static function utc( mixed $iso ): ?string {
		if ( ! is_string( $iso ) || '' === $iso ) {
			return null;
		}

		$ts = strtotime( $iso );

		return false === $ts ? null : gmdate( 'Y-m-d H:i:s', $ts );
	}

	/**
	 * Swap one set's rows in a single transaction.
	 *
	 * @param array<int,array<string,mixed>> $rows Rows.
	 */
	private static function replace_set( string $set, array $rows ): void {
		global $wpdb;

		$t   = self::table();
		$now = vh_now();

		// The comment summary belongs to the issue, not to this read of the
		// set: carry it across the swap rather than reading every thread again.
		$keep = array();
		foreach ( (array) $wpdb->get_results( "SELECT issue_key, conversation, conv_at FROM {$t} WHERE conversation IS NOT NULL", ARRAY_A ) as $k ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$keep[ (string) $k['issue_key'] ] = $k;
		}

		$wpdb->query( 'START TRANSACTION' );

		$wpdb->delete( $t, array( 'set_key' => $set ) );

		$seen = array();
		foreach ( $rows as $row ) {
			$key = (string) $row['issue_key'];

			if ( '' === $key || isset( $seen[ $key ] ) ) {
				continue;
			}
			$seen[ $key ] = true;

			$row['summary']       = mb_substr( (string) $row['summary'], 0, 500 );
			$row['issue_type']    = mb_substr( (string) $row['issue_type'], 0, 120 );
			$row['request_type']  = mb_substr( (string) $row['request_type'], 0, 190 );
			$row['status']        = mb_substr( (string) $row['status'], 0, 120 );
			$row['reporter']      = mb_substr( (string) $row['reporter'], 0, 190 );
			$row['assignee']      = mb_substr( (string) $row['assignee'], 0, 190 );
			$row['approval_name'] = mb_substr( (string) $row['approval_name'], 0, 190 );
			$row['set_key']       = $set;
			$row['synced_at']     = $now;

			if ( isset( $keep[ $key ] ) ) {
				$row['conversation'] = $keep[ $key ]['conversation'];
				$row['conv_at']      = $keep[ $key ]['conv_at'];
			}

			$wpdb->insert( $t, $row );
		}

		$wpdb->query( 'COMMIT' );
	}

	/* =================================================================
	 * Querying the local copy
	 * ============================================================== */

	/**
	 * The WHERE for a set, shared by query() and counts() so a tab's number
	 * and the rows on that tab come from one filter.
	 *
	 * @param array<string,string> $a state, search, project, tag.
	 * @return array{0:string,1:array<int,mixed>}
	 */
	private static function where( string $set, array $a ): array {
		global $wpdb;

		$w = array( 'i.set_key = %s' );
		$p = array( $set );

		if ( 'mine' === $set ) {
			// Raised by this portal: those live on the Remediation tab.
			$w[] = "i.issue_key NOT IN ( SELECT t.external_key FROM {$wpdb->prefix}vulnhub_tickets t WHERE t.external_key <> '' )";
		}

		$state = (string) ( $a['state'] ?? '' );
		if ( 'open' === $state ) {
			$w[] = "i.status_category <> 'done'";
		} elseif ( 'closed' === $state ) {
			$w[] = "i.status_category = 'done'";
		}

		$search = trim( (string) ( $a['search'] ?? '' ) );
		if ( '' !== $search ) {
			$w[] = '( LOCATE( %s, i.issue_key ) > 0 OR LOCATE( %s, i.summary ) > 0 OR LOCATE( %s, i.reporter ) > 0 OR LOCATE( %s, i.assignee ) > 0 )';
			array_push( $p, $search, $search, $search, $search );
		}

		if ( '' !== (string) ( $a['project'] ?? '' ) ) {
			$w[] = 'i.project_key = %s';
			$p[] = (string) $a['project'];
		}

		if ( isset( $a['keys'] ) && is_array( $a['keys'] ) ) {
			if ( ! $a['keys'] ) {
				$w[] = '1 = 0';
			} else {
				$w[] = 'i.issue_key IN ( ' . implode( ', ', array_fill( 0, count( $a['keys'] ), '%s' ) ) . ' )';
				$p   = array_merge( $p, array_values( $a['keys'] ) );
			}
		}

		$tag = (string) ( $a['tag'] ?? '' );
		if ( 'third_party' === $tag ) {
			$w[] = "i.tag = 'third_party'";
		} elseif ( 'other' === $tag ) {
			$w[] = "i.tag <> 'third_party'";
		}

		return array( implode( ' AND ', $w ), $p );
	}

	/**
	 * @param array<string,string|int> $a Filters plus limit/offset.
	 * @return array{rows:array<int,array<string,mixed>>,total:int}
	 */
	public static function query( string $set, array $a = array() ): array {
		global $wpdb;

		list( $where, $p ) = self::where( $set, $a );

		$t     = self::table();
		$order = 'approvals' === $set ? 'i.created_at ASC' : 'COALESCE( i.updated_at, i.created_at ) DESC';
		$limit = max( 1, (int) ( $a['limit'] ?? self::PER_PAGE ) );
		$off   = max( 0, (int) ( $a['offset'] ?? 0 ) );

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$total = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$t} i WHERE {$where}", $p ) );
		$rows  = (array) $wpdb->get_results( $wpdb->prepare( "SELECT i.* FROM {$t} i WHERE {$where} ORDER BY {$order}, i.id ASC LIMIT %d OFFSET %d", array_merge( $p, array( $limit, $off ) ) ), ARRAY_A );
		// phpcs:enable

		return array( 'rows' => $rows, 'total' => $total );
	}

	/**
	 * Open, closed and all under the filters in force, with the state axis
	 * stripped -- the counts on the Open / Closed / All tabs.
	 *
	 * @param array<string,string> $a Filters.
	 * @return array{open:int,closed:int,all:int}
	 */
	public static function state_counts( string $set, array $a = array() ): array {
		$a['state'] = '';
		$all        = self::query( $set, $a + array( 'limit' => 1 ) )['total'];
		$a['state'] = 'closed';
		$closed     = self::query( $set, $a + array( 'limit' => 1 ) )['total'];

		return array( 'open' => $all - $closed, 'closed' => $closed, 'all' => $all );
	}

	/**
	 * How many issues this portal raised that also match "raised by me" --
	 * so the tab can say where they went.
	 */
	private static function mine_on_remediation(): int {
		global $wpdb;

		$t = self::table();

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$t} i WHERE i.set_key = 'mine' AND i.issue_key IN ( SELECT t.external_key FROM {$wpdb->prefix}vulnhub_tickets t WHERE t.external_key <> '' )" );
	}

	/** @return string[] */
	private static function projects( string $set ): array {
		global $wpdb;

		$t = self::table();

		return array_map( 'strval', (array) $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT project_key FROM {$t} WHERE set_key = %s AND project_key <> '' ORDER BY project_key", $set ) ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	/* =================================================================
	 * The tabs on the Tickets page
	 * ============================================================== */

	/**
	 * Filter `vulnhub_ticket_views`: the three extra tabs.
	 *
	 * @param array<string,array<string,mixed>> $views Views so far.
	 * @return array<string,array<string,mixed>>
	 */
	public static function views( array $views ): array {
		if ( ! self::shown() ) {
			return $views;
		}

		$account = (string) ( self::state()['account'] ?? '' );

		$views['mine'] = array(
			'label'  => __( 'My Jira tickets', 'vulnhub' ),
			'count'  => self::state_counts( 'mine' )['open'],
			'title'  => __( 'My Jira tickets', 'vulnhub' ),
			'sub'    => '' !== $account
				/* translators: %s: Jira account name. */
				? sprintf( __( 'Issues %s raised directly in Jira. Tickets raised from this portal are on the Remediation tab.', 'vulnhub' ), $account )
				: __( 'Issues the connected Jira account raised directly in Jira. Tickets raised from this portal are on the Remediation tab.', 'vulnhub' ),
			'render' => array( __CLASS__, 'render_mine' ),
			'flag'   => count( self::keys_with( 'mine', 'mention' ) ),
			'replies' => count( self::keys_with( 'mine', 'answered' ) ),
		);

		$views['approvals'] = array(
			'label'  => __( 'Approvals', 'vulnhub' ),
			'count'  => self::state_counts( 'approvals' )['all'],
			'tone'   => 'warn',
			'title'  => __( 'Waiting for your approval', 'vulnhub' ),
			'sub'    => '' !== $account
				/* translators: %s: Jira account name. */
				? sprintf( __( 'Service requests whose approval step is waiting on %s.', 'vulnhub' ), $account )
				: __( 'Service requests whose approval step is waiting on the connected Jira account.', 'vulnhub' ),
			'render' => array( __CLASS__, 'render_approvals' ),
			'flag'   => count( self::keys_with( 'approvals', 'mention' ) ),
			'replies' => count( self::keys_with( 'approvals', 'answered' ) ),
		);

		$views['assessments'] = array(
			'label'  => __( 'Assessments', 'vulnhub' ),
			'count'  => self::state_counts( 'assessments' )['open'],
			'title'  => __( 'Security assessment requests', 'vulnhub' ),
			'sub'    => __( 'Cyber security and third-party information security assessment requests raised to the service desk, whoever raised them.', 'vulnhub' ),
			'render' => array( __CLASS__, 'render_assessments' ),
			'flag'   => count( self::keys_with( 'assessments', 'mention' ) ),
			'replies' => count( self::keys_with( 'assessments', 'answered' ) ),
		);

		return $views;
	}

	/** One GET value from the current request. */
	private static function q( string $key ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return isset( $_GET[ $key ] ) && ! is_array( $_GET[ $key ] ) ? sanitize_text_field( wp_unslash( (string) $_GET[ $key ] ) ) : '';
	}

	/**
	 * When the set was last read, whether that read worked, the refresh
	 * button, and any message a redirect brought back.
	 */
	private static function status_bar( string $set, string $base ): void {
		$st  = (array) ( self::state()['sets'][ $set ] ?? array() );
		$c   = self::connector();
		$msg = self::q( 'vh_msg' );
		$err = self::q( 'vh_err' );

		if ( '' !== $msg ) {
			echo '<p class="vh-flash vh-flash--good" role="status">' . esc_html( $msg ) . '</p>';
		}
		if ( '' !== $err ) {
			echo '<div class="vh-notice vh-notice--warn" role="alert">' . esc_html( $err ) . '</div>';
		}

		if ( $c && $c->is_mock() ) {
			echo '<div class="vh-notice vh-notice--info">' . esc_html__( 'Jira is in demo mode, so there is nothing to read here. Connect a real site under Integrations → Jira.', 'vulnhub' ) . '</div>';
			return;
		}
		if ( ! self::enabled() ) {
			echo '<div class="vh-notice vh-notice--info">' . esc_html__( 'Jira is not connected or is switched off under Integrations → Jira, so this list is not being refreshed.', 'vulnhub' ) . '</div>';
		}

		if ( ! empty( $st ) && empty( $st['ok'] ) ) {
			echo '<div class="vh-notice vh-notice--warn">';
			echo esc_html(
				sprintf(
					/* translators: 1: when, 2: error. */
					__( 'The last read from Jira (%1$s) failed, so this list is from the read before it: %2$s', 'vulnhub' ),
					vh_ago( (string) $st['at'] ),
					(string) $st['error']
				)
			);
			echo '</div>';
		}
		if ( ! empty( $st['capped'] ) ) {
			echo '<div class="vh-notice vh-notice--info">';
			/* translators: %s: row limit. */
			echo esc_html( sprintf( __( 'Jira returned more than %s issues; only the first are held here. Open Jira for the rest.', 'vulnhub' ), number_format_i18n( self::MAX_ROWS ) ) );
			echo '</div>';
		}

		echo '<div class="vh-check-bar">';
		echo '<span class="vh-meta">';
		echo esc_html(
			! empty( $st['ok_at'] )
				/* translators: %s: time ago. */
				? sprintf( __( 'Read from Jira %s. Refreshed every 15 minutes.', 'vulnhub' ), vh_ago( (string) $st['ok_at'] ) )
				: __( 'Not read from Jira yet.', 'vulnhub' )
		);
		echo '</span>';

		if ( self::can_refresh() && self::enabled() ) {
			?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
				<?php wp_nonce_field( self::ACTION_REFRESH ); ?>
				<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION_REFRESH ); ?>">
				<input type="hidden" name="set" value="<?php echo esc_attr( $set ); ?>">
				<input type="hidden" name="back" value="<?php echo esc_attr( $base ); ?>">
				<button class="vh-btn vh-btn--sm vh-btn--ghost"><?php esc_html_e( 'Refresh now', 'vulnhub' ); ?></button>
			</form>
			<?php
		}
		echo '</div>';
	}

	/**
	 * Open / Closed / All, with counts under the filters still in force.
	 *
	 * @param array{open:int,closed:int,all:int} $counts Counts.
	 */
	private static function state_tabs( string $current, array $counts ): void {
		echo '<nav class="vh-tabs vh-tabs--count" aria-label="' . esc_attr__( 'Which issues', 'vulnhub' ) . '">';
		foreach ( array(
			'open'   => __( 'Open', 'vulnhub' ),
			'closed' => __( 'Closed', 'vulnhub' ),
			'all'    => __( 'All', 'vulnhub' ),
		) as $tab => $label ) {
			$url = add_query_arg( 'jstate', $tab, remove_query_arg( array( 'jp', 'vh_msg', 'vh_err' ) ) );
			printf(
				'<a class="vh-tabs__tab %1$s" href="%2$s"%3$s>%4$s <span class="vh-tabs__n">%5$s</span></a>',
				$tab === $current ? 'is-active' : '',
				esc_url( $url ),
				$tab === $current ? ' aria-current="page"' : '',
				esc_html( $label ),
				esc_html( number_format_i18n( (int) $counts[ $tab ] ) )
			);
		}
		echo '</nav>';
	}

	/**
	 * Search, project and (for assessments) third-party filter.
	 *
	 * @param string[] $projects Projects present in the set.
	 */
	private static function filter_form( string $set, array $projects, bool $with_tag ): void {
		?>
		<form class="vh-filters" method="get">
			<?php
			foreach ( array( 'tview', 'jstate', 'jfor', 'page_id' ) as $keep ) {
				if ( '' !== self::q( $keep ) ) {
					printf( '<input type="hidden" name="%s" value="%s">', esc_attr( $keep ), esc_attr( self::q( $keep ) ) );
				}
			}
			?>
			<label><?php esc_html_e( 'Search', 'vulnhub' ); ?>
				<input type="search" name="jq" value="<?php echo esc_attr( self::q( 'jq' ) ); ?>" placeholder="<?php esc_attr_e( 'key, summary or person…', 'vulnhub' ); ?>">
			</label>
			<?php if ( count( $projects ) > 1 ) : ?>
				<label><?php esc_html_e( 'Project', 'vulnhub' ); ?>
					<select name="jproj">
						<option value=""><?php esc_html_e( 'All', 'vulnhub' ); ?></option>
						<?php foreach ( $projects as $p ) : ?>
							<option value="<?php echo esc_attr( $p ); ?>" <?php selected( self::q( 'jproj' ), $p ); ?>><?php echo esc_html( $p ); ?></option>
						<?php endforeach; ?>
					</select>
				</label>
			<?php endif; ?>
			<?php if ( $with_tag ) : ?>
				<label><?php esc_html_e( 'Kind', 'vulnhub' ); ?>
					<select name="jtag">
						<option value=""><?php esc_html_e( 'All assessments', 'vulnhub' ); ?></option>
						<option value="third_party" <?php selected( self::q( 'jtag' ), 'third_party' ); ?>><?php esc_html_e( 'Third-party (supplier) assessments', 'vulnhub' ); ?></option>
						<option value="other" <?php selected( self::q( 'jtag' ), 'other' ); ?>><?php esc_html_e( 'Other security assessments', 'vulnhub' ); ?></option>
					</select>
				</label>
			<?php endif; ?>
			<button class="vh-btn"><?php esc_html_e( 'Apply', 'vulnhub' ); ?></button>
			<a class="vh-btn vh-btn--ghost" href="<?php echo esc_url( add_query_arg( 'tview', $set, remove_query_arg( array( 'jq', 'jproj', 'jtag', 'jstate', 'jfor', 'jp', 'vh_msg', 'vh_err' ) ) ) ); ?>"><?php esc_html_e( 'Reset', 'vulnhub' ); ?></a>
		</form>
		<?php
	}

	/** The issue's page in the portal, from the list it is on. */
	private static function issue_url( string $key ): string {
		return add_query_arg( 'jkey', rawurlencode( $key ), remove_query_arg( array( 'vh_msg', 'vh_err', 'jkey' ) ) );
	}

	private static function jira_url( string $key ): string {
		$c = self::connector();

		return $c ? $c->client()->browse_url( $key ) : '';
	}

	/**
	 * The key opens the issue here; the arrow beside it opens it in Jira.
	 */
	private static function key_cell( array $r ): string {
		$key = (string) $r['issue_key'];

		return sprintf(
			'<a class="vh-mono" href="%1$s"><strong>%2$s</strong></a> <a class="vh-meta" href="%3$s" target="_blank" rel="noopener noreferrer" title="%4$s" aria-label="%4$s">&nearr;</a>',
			esc_url( self::issue_url( $key ) ),
			esc_html( $key ),
			esc_url( self::jira_url( $key ) ),
			/* translators: %s: issue key. */
			esc_attr( sprintf( __( 'Open %s in Jira', 'vulnhub' ), $key ) )
		);
	}

	/** The summary, linked to the issue's page here. */
	private static function summary_cell( array $r, int $len = 90 ): string {
		return sprintf(
			'<a href="%1$s">%2$s</a>',
			esc_url( self::issue_url( (string) $r['issue_key'] ) ),
			esc_html( vh_trim( (string) $r['summary'], $len ) )
		);
	}

	private static function status_chip( array $r ): string {
		$tone = match ( (string) $r['status_category'] ) {
			'done'          => 'good',
			'indeterminate' => 'warn',
			default         => 'muted',
		};

		return sprintf( '<span class="vh-chip vh-chip--%1$s">%2$s</span>', esc_attr( $tone ), esc_html( (string) $r['status'] ) );
	}

	private static function type_label( array $r ): string {
		return '' !== (string) $r['request_type'] ? (string) $r['request_type'] : (string) $r['issue_type'];
	}

	/**
	 * Previous / next, keeping every other parameter.
	 */
	private static function pager( int $page, int $pages ): void {
		if ( $pages < 2 ) {
			return;
		}

		$base = remove_query_arg( array( 'jp', 'vh_msg', 'vh_err' ) );

		echo '<nav class="vh-pager" aria-label="' . esc_attr__( 'Pagination', 'vulnhub' ) . '">';
		if ( $page > 1 ) {
			echo '<a class="vh-btn vh-btn--ghost" href="' . esc_url( add_query_arg( 'jp', $page - 1, $base ) ) . '">&larr; ' . esc_html__( 'Previous', 'vulnhub' ) . '</a>';
		}
		/* translators: 1: page, 2: pages. */
		echo '<span class="vh-pager__count">' . esc_html( sprintf( __( 'Page %1$d of %2$d', 'vulnhub' ), $page, $pages ) ) . '</span>';
		if ( $page < $pages ) {
			echo '<a class="vh-btn vh-btn--ghost" href="' . esc_url( add_query_arg( 'jp', $page + 1, $base ) ) . '">' . esc_html__( 'Next', 'vulnhub' ) . ' &rarr;</a>';
		}
		echo '</nav>';
	}

	/**
	 * Shared body of the two Open/Closed/All lists.
	 *
	 * @return array{rows:array<int,array<string,mixed>>,total:int,page:int,pages:int,counts:array{open:int,closed:int,all:int},state:string}
	 */
	private static function list_state( string $set, bool $with_tag ): array {
		$state = in_array( self::q( 'jstate' ), array( 'open', 'closed', 'all' ), true ) ? self::q( 'jstate' ) : 'open';
		$args  = array(
			'search'  => self::q( 'jq' ),
			'project' => self::q( 'jproj' ),
			'tag'     => $with_tag ? self::q( 'jtag' ) : '',
		);

		// For you: the issues carrying that signal for whoever is looking.
		if ( in_array( self::q( 'jfor' ), array( 'mention', 'answered', 'assigned' ), true ) ) {
			$args['keys'] = self::keys_with( $set, self::q( 'jfor' ) );
		}

		$counts = self::state_counts( $set, $args );
		$page   = max( 1, (int) self::q( 'jp' ) );
		$q      = self::query( $set, $args + array( 'state' => 'all' === $state ? '' : $state, 'limit' => self::PER_PAGE, 'offset' => ( $page - 1 ) * self::PER_PAGE ) );

		return array(
			'rows'   => $q['rows'],
			'total'  => $q['total'],
			'page'   => $page,
			'pages'  => max( 1, (int) ceil( $q['total'] / self::PER_PAGE ) ),
			'counts' => $counts,
			'state'  => $state,
		);
	}

	/** Empty-tab wording that says where the rows went. */
	private static function empty_note( string $state, array $counts, string $nothing ): void {
		echo '<p class="vh-chart-empty">';
		if ( in_array( self::q( 'jfor' ), array( 'mention', 'answered', 'assigned' ), true ) && 0 === $counts['all'] ) {
			echo esc_html(
				array(
					'mention'  => __( 'Nothing here mentions you without an answer from you since.', 'vulnhub' ),
					'answered' => __( 'Nobody has commented here since your last comment.', 'vulnhub' ),
					'assigned' => __( 'Nothing open here is assigned to you.', 'vulnhub' ),
				)[ self::q( 'jfor' ) ]
			);
		} elseif ( 'open' === $state && $counts['closed'] > 0 ) {
			/* translators: %s: number. */
			echo esc_html( sprintf( _n( 'Nothing open matches. %s closed issue matches — it is on the Closed tab.', 'Nothing open matches. %s closed issues match — they are on the Closed tab.', $counts['closed'], 'vulnhub' ), number_format_i18n( $counts['closed'] ) ) );
		} elseif ( 'closed' === $state && $counts['open'] > 0 ) {
			/* translators: %s: number. */
			echo esc_html( sprintf( _n( 'Nothing closed matches. %s open issue matches — it is on the Open tab.', 'Nothing closed matches. %s open issues match — they are on the Open tab.', $counts['open'], 'vulnhub' ), number_format_i18n( $counts['open'] ) ) );
		} else {
			echo esc_html( $nothing );
		}
		echo '</p>';
	}

	/** Tab: issues the account raised directly in Jira. */
	public static function render_mine( string $base ): void {
		if ( self::render_issue( 'mine', $base ) ) {
			return;
		}

		self::status_bar( 'mine', $base );

		$l     = self::list_state( 'mine', false );
		$moved = self::mine_on_remediation();
		$flags = self::flags_for_rows( $l['rows'] );

		self::foryou( 'mine' );
		self::state_tabs( $l['state'], $l['counts'] );
		self::filter_form( 'mine', self::projects( 'mine' ), false );

		if ( $moved > 0 ) {
			echo '<p class="vh-meta">';
			/* translators: %s: number of tickets. */
			echo esc_html( sprintf( _n( '%s ticket raised from this portal is not repeated here; it is on the Remediation tab.', '%s tickets raised from this portal are not repeated here; they are on the Remediation tab.', $moved, 'vulnhub' ), number_format_i18n( $moved ) ) );
			echo '</p>';
		}

		if ( ! $l['rows'] ) {
			/* translators: %d: days. */
			self::empty_note( $l['state'], $l['counts'], sprintf( __( 'Nothing to show. Open issues are held, and closed ones for %d days after their last update.', 'vulnhub' ), self::MINE_DAYS ) );
			return;
		}
		?>
		<div class="vh-tablewrap">
			<table class="vh-table">
				<thead><tr>
					<th><?php esc_html_e( 'Key', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Summary', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Type', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Assigned to', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Raised', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Updated', 'vulnhub' ); ?></th>
				</tr></thead>
				<tbody>
				<?php foreach ( $l['rows'] as $r ) : ?>
					<?php $sig = $flags[ (string) $r['issue_key'] ] ?? array(); ?>
					<tr class="<?php echo esc_attr( self::row_class( $sig ) ); ?>">
						<td><?php echo self::key_cell( $r ) . self::bell( $sig ); // phpcs:ignore WordPress.Security.EscapeOutput ?></td>
						<td title="<?php echo esc_attr( (string) $r['summary'] ); ?>"><?php echo self::sig_tags( $sig ) . self::summary_cell( $r ); // phpcs:ignore WordPress.Security.EscapeOutput ?></td>
						<td class="vh-sub"><?php echo esc_html( self::type_label( $r ) ); ?></td>
						<td><?php echo self::status_chip( $r ); // phpcs:ignore WordPress.Security.EscapeOutput ?></td>
						<td><?php echo esc_html( '' !== (string) $r['assignee'] ? (string) $r['assignee'] : __( 'Unassigned', 'vulnhub' ) ); ?></td>
						<td class="vh-nowrap"><?php echo esc_html( vh_date( (string) $r['created_at'], 'j M Y' ) ); ?></td>
						<td class="vh-nowrap" title="<?php echo esc_attr( vh_date( (string) $r['updated_at'] ) ); ?>"><?php echo esc_html( vh_ago( (string) $r['updated_at'] ) ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
		self::pager( $l['page'], $l['pages'] );
	}

	/** Tab: requests waiting for the account's approval. */
	public static function render_approvals( string $base ): void {
		if ( self::render_issue( 'approvals', $base ) ) {
			return;
		}

		self::status_bar( 'approvals', $base );

		$q       = self::query( 'approvals', array( 'limit' => 200 ) );
		$flags   = self::flags_for_rows( $q['rows'] );
		$can     = current_user_can( self::decide_cap() ) && self::enabled();
		$account = (string) ( self::state()['account'] ?? __( 'the connected Jira account', 'vulnhub' ) );

		if ( ! $q['rows'] ) {
			echo '<p class="vh-chart-empty">' . esc_html__( 'Nothing is waiting for your approval.', 'vulnhub' ) . '</p>';
			return;
		}

		if ( ! $can ) {
			echo '<p class="vh-meta">' . esc_html__( 'Approving here answers in Jira as the connected account, so it needs the manage permission on this portal. Use the Jira link to answer instead.', 'vulnhub' ) . '</p>';
		}
		?>
		<div class="vh-tablewrap">
			<table class="vh-table">
				<thead><tr>
					<th><?php esc_html_e( 'Key', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Summary', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Request type', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Raised by', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Waiting since', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
					<th><span class="screen-reader-text"><?php esc_html_e( 'Decision', 'vulnhub' ); ?></span></th>
				</tr></thead>
				<tbody>
				<?php foreach ( $q['rows'] as $r ) : ?>
					<?php $sig = $flags[ (string) $r['issue_key'] ] ?? array(); ?>
					<tr class="<?php echo esc_attr( self::row_class( $sig ) ); ?>">
						<td><?php echo self::key_cell( $r ) . self::bell( $sig ); // phpcs:ignore WordPress.Security.EscapeOutput ?></td>
						<td title="<?php echo esc_attr( (string) $r['summary'] ); ?>"><?php echo self::sig_tags( $sig ) . self::summary_cell( $r ); // phpcs:ignore WordPress.Security.EscapeOutput ?></td>
						<td class="vh-sub"><?php echo esc_html( self::type_label( $r ) ); ?></td>
						<td><?php echo esc_html( (string) $r['reporter'] ); ?></td>
						<td class="vh-nowrap" title="<?php echo esc_attr( vh_date( (string) $r['created_at'] ) ); ?>"><?php echo esc_html( vh_ago( (string) $r['created_at'] ) ); ?></td>
						<td><?php echo self::status_chip( $r ); // phpcs:ignore WordPress.Security.EscapeOutput ?></td>
						<td class="vh-col-act vh-nowrap">
							<?php if ( $can && (int) $r['can_answer'] === 1 && '' !== (string) $r['approval_id'] ) : ?>
								<?php echo self::approval_forms( $r, $base, $account ); // phpcs:ignore WordPress.Security.EscapeOutput ?>
							<?php elseif ( (int) $r['can_answer'] !== 1 ) : ?>
								<span class="vh-meta"><?php esc_html_e( 'Jira does not let this account answer it', 'vulnhub' ); ?></span>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	/** Tab: security assessment requests. */
	public static function render_assessments( string $base ): void {
		if ( self::render_issue( 'assessments', $base ) ) {
			return;
		}

		self::status_bar( 'assessments', $base );

		if ( ! self::assessment_types() ) {
			echo '<div class="vh-notice vh-notice--info">';
			esc_html_e( 'No assessment request types are set. Add the service-desk request type names to "Assessment request types" under Integrations → Jira, one per line, and the next read fills this tab.', 'vulnhub' );
			if ( current_user_can( Caps::MANAGE ) && function_exists( 'vh_admin_url' ) ) {
				echo ' <a href="' . esc_url( vh_admin_url( 'vulnhub-integrations', array( 'connector' => 'jira' ) ) ) . '">' . esc_html__( 'Open the Jira settings', 'vulnhub' ) . '</a>';
			}
			echo '</div>';
			return;
		}

		$l     = self::list_state( 'assessments', true );
		$flags = self::flags_for_rows( $l['rows'] );

		self::foryou( 'assessments' );
		self::state_tabs( $l['state'], $l['counts'] );
		self::filter_form( 'assessments', self::projects( 'assessments' ), true );

		echo '<p class="vh-meta">';
		/* translators: %s: request type names. */
		echo esc_html( sprintf( __( 'Request types read: %s.', 'vulnhub' ), implode( ', ', self::assessment_types() ) ) );
		echo '</p>';

		if ( ! $l['rows'] ) {
			self::empty_note( $l['state'], $l['counts'], __( 'No assessment requests match.', 'vulnhub' ) );
			return;
		}
		?>
		<div class="vh-tablewrap">
			<table class="vh-table">
				<thead><tr>
					<th><?php esc_html_e( 'Key', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Summary', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Raised by', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Assigned to', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Raised', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Updated', 'vulnhub' ); ?></th>
				</tr></thead>
				<tbody>
				<?php foreach ( $l['rows'] as $r ) : ?>
					<?php $sig = $flags[ (string) $r['issue_key'] ] ?? array(); ?>
					<tr class="<?php echo esc_attr( self::row_class( $sig ) ); ?>">
						<td><?php echo self::key_cell( $r ) . self::bell( $sig ); // phpcs:ignore WordPress.Security.EscapeOutput ?></td>
						<td title="<?php echo esc_attr( (string) $r['summary'] ); ?>">
							<?php if ( 'third_party' === (string) $r['tag'] ) : ?>
								<span class="vh-chip vh-chip--xs vh-chip--warn"><?php esc_html_e( 'Third-party', 'vulnhub' ); ?></span>
							<?php endif; ?>
							<?php echo self::sig_tags( $sig ) . self::summary_cell( $r ); // phpcs:ignore WordPress.Security.EscapeOutput ?>
						</td>
						<td><?php echo esc_html( (string) $r['reporter'] ); ?></td>
						<td><?php echo esc_html( '' !== (string) $r['assignee'] ? (string) $r['assignee'] : __( 'Unassigned', 'vulnhub' ) ); ?></td>
						<td><?php echo self::status_chip( $r ); // phpcs:ignore WordPress.Security.EscapeOutput ?></td>
						<td class="vh-nowrap" title="<?php echo esc_attr( vh_date( (string) $r['created_at'] ) ); ?>"><?php echo esc_html( vh_date( (string) $r['created_at'], 'j M Y' ) ); ?></td>
						<td class="vh-nowrap" title="<?php echo esc_attr( vh_date( (string) $r['updated_at'] ) ); ?>"><?php echo esc_html( vh_ago( (string) $r['updated_at'] ) ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
		self::pager( $l['page'], $l['pages'] );
	}

	/**
	 * Approve and Decline, as two small forms.
	 *
	 * @param array<string,mixed> $r    Approvals row.
	 * @param string              $back Where to land afterwards.
	 */
	private static function approval_forms( array $r, string $back, string $account ): string {
		$out = '';

		foreach ( array( 'approve', 'decline' ) as $decision ) {
			$ask = 'approve' === $decision
				/* translators: 1: issue key, 2: account. */
				? __( 'Approve %1$s in Jira as %2$s? Jira moves the request on straight away.', 'vulnhub' )
				/* translators: 1: issue key, 2: account. */
				: __( 'Decline %1$s in Jira as %2$s? Jira will tell the requester it was declined.', 'vulnhub' );

			$out .= '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline">'
				. wp_nonce_field( self::ACTION_DECIDE, '_wpnonce', true, false )
				. '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_DECIDE ) . '">'
				. '<input type="hidden" name="key" value="' . esc_attr( (string) $r['issue_key'] ) . '">'
				. '<input type="hidden" name="approval" value="' . esc_attr( (string) $r['approval_id'] ) . '">'
				. '<input type="hidden" name="decision" value="' . esc_attr( $decision ) . '">'
				. '<input type="hidden" name="back" value="' . esc_attr( $back ) . '">'
				. '<button class="vh-btn vh-btn--sm ' . ( 'approve' === $decision ? 'vh-btn--primary' : 'vh-btn--danger' ) . '"'
				. ' data-vh-confirm="' . esc_attr( sprintf( $ask, (string) $r['issue_key'], $account ) ) . '">'
				. esc_html( 'approve' === $decision ? __( 'Approve', 'vulnhub' ) : __( 'Decline', 'vulnhub' ) )
				. '</button></form> ';
		}

		return $out;
	}

	/* =================================================================
	 * Waiting on you: the same signals as a ticket raised here
	 *
	 * Mentioned you, Your reply and Yours are worked out by
	 * VulnHub_Dash_Ticket_Signals::flags() from the same comment summary
	 * (VulnHub_Jira_Connector::conversation()), for whoever is looking, so an
	 * issue here is flagged by exactly the rules a remediation ticket is.
	 * ============================================================== */

	/**
	 * Read and store the comment summary of open issues whose `updated`
	 * moved since their thread was last read. Bounded, newest activity first.
	 *
	 * @return int Threads read.
	 */
	public static function read_conversations( int $max ): int {
		global $wpdb;

		$c = self::connector();
		if ( ! $c || ! self::enabled() ) {
			return 0;
		}

		$t     = self::table();
		$due   = (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT issue_key, MAX( COALESCE( updated_at, created_at ) ) AS u, MAX( conv_at ) AS c FROM {$t}
				WHERE status_category <> 'done' GROUP BY issue_key HAVING c = '' OR c < u ORDER BY u DESC LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				max( 1, $max )
			),
			ARRAY_A
		);
		$read  = 0;
		$until = time() + 60;

		foreach ( $due as $d ) {
			if ( time() > $until ) {
				break;
			}

			$res = $c->comments( (string) $d['issue_key'], 50 );

			if ( ! empty( $res['ok'] ) ) {
				self::store_conversation( (string) $d['issue_key'], (array) $res['comments'], (string) $d['u'] );
				++$read;
			}
		}

		return $read;
	}

	/**
	 * Keep one issue's comment summary on every row it has.
	 *
	 * @param array<int,array<string,mixed>> $comments Normalised, newest first.
	 * @param string                         $at       The issue's `updated` it was read at;
	 *                                                 '' takes the row's own.
	 */
	public static function store_conversation( string $key, array $comments, string $at = '' ): void {
		global $wpdb;

		$t = self::table();

		if ( '' === $at ) {
			$at = (string) $wpdb->get_var( $wpdb->prepare( "SELECT MAX( COALESCE( updated_at, created_at ) ) FROM {$t} WHERE issue_key = %s", $key ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		}

		$wpdb->update(
			$t,
			array(
				'conversation' => wp_json_encode( VulnHub_Jira_Connector::conversation( $comments ) ),
				'conv_at'      => $at,
			),
			array( 'issue_key' => $key )
		);

		self::$open_flags = array();
	}

	/**
	 * A ticket-shaped row for the signals: a negative id, which no ticket
	 * raised here has, so the template check keeps the two apart.
	 *
	 * @param array<string,mixed> $r Inbox row.
	 * @return array<string,mixed>
	 */
	private static function as_ticket( array $r ): array {
		$conv = json_decode( (string) ( $r['conversation'] ?? '' ), true );

		return array(
			'id'              => self::signal_id( (string) $r['issue_key'] ),
			'external_key'    => (string) $r['issue_key'],
			'status_category' => (string) $r['status_category'],
			'assignee_id'     => (string) ( $r['assignee_id'] ?? '' ),
			'payload_json'    => wp_json_encode( array( 'conversation' => is_array( $conv ) ? $conv : array() ) ),
		);
	}

	private static function signal_id( string $key ): int {
		return -1 - ( crc32( 'jira-inbox|' . strtoupper( $key ) ) & 0x3fffffff );
	}

	/**
	 * Signals for rows, issue key => flags. Empty when the dashboard's
	 * signals are not loaded.
	 *
	 * @param array<int,array<string,mixed>> $rows Inbox rows.
	 * @return array<string,array<string,mixed>>
	 */
	public static function flags_for_rows( array $rows ): array {
		if ( ! class_exists( 'VulnHub_Dash_Ticket_Signals' ) ) {
			return array();
		}

		$me  = VulnHub_Dash_Ticket_Signals::me();
		$out = array();

		foreach ( $rows as $r ) {
			$out[ (string) $r['issue_key'] ] = VulnHub_Dash_Ticket_Signals::flags( self::as_ticket( $r ), $me );
		}

		return $out;
	}

	/** @var array<string,array<string,array<string,mixed>>> set => key => flags, once a request. */
	private static array $open_flags = array();

	/**
	 * Every open issue's signals in one set, under the set's own WHERE (so
	 * My Jira tickets still leaves out what was raised here).
	 *
	 * @return array<string,array<string,mixed>>
	 */
	public static function open_flags( string $set ): array {
		if ( ! isset( self::$open_flags[ $set ] ) ) {
			self::$open_flags[ $set ] = self::flags_for_rows( self::query( $set, array( 'state' => 'open', 'limit' => 2000 ) )['rows'] );
		}

		return self::$open_flags[ $set ];
	}

	/** Keys in a set carrying a signal. @return string[] */
	private static function keys_with( string $set, string $for ): array {
		return array_keys( array_filter( self::open_flags( $set ), static fn( array $f ): bool => ! empty( $f[ $for ] ) ) );
	}

	/**
	 * Filter `vulnhub_ticket_signal_conversations`: these threads join the
	 * check for desk templates ("Hi <name>, thanks for raising this"), which
	 * are the same macros on these issues as on tickets raised here.
	 *
	 * @param array<int,array<string,mixed>> $rows Extra rows so far.
	 * @return array<int,array<string,mixed>>
	 */
	public static function signal_conversations( array $rows ): array {
		global $wpdb;

		$t = self::table();

		foreach ( (array) $wpdb->get_results( "SELECT issue_key, MAX( conversation ) AS conversation FROM {$t} WHERE conversation IS NOT NULL GROUP BY issue_key", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$t2     = self::as_ticket( $r + array( 'status_category' => '', 'assignee_id' => '' ) );
			$rows[] = array( 'id' => $t2['id'], 'payload_json' => $t2['payload_json'] );
		}

		return $rows;
	}

	private static function row_class( array $f ): string {
		return $f && class_exists( 'VulnHub_Dash_Ticket_Signals' ) ? VulnHub_Dash_Ticket_Signals::row_class( $f ) : '';
	}

	private static function bell( array $f ): string {
		return $f && class_exists( 'VulnHub_Dash_Ticket_Signals' ) ? ' ' . VulnHub_Dash_Ticket_Signals::bell( $f ) : '';
	}

	private static function sig_tags( array $f ): string {
		return $f && class_exists( 'VulnHub_Dash_Ticket_Signals' ) ? VulnHub_Dash_Ticket_Signals::tags( $f ) : '';
	}

	/**
	 * "For you" on a tab: one chip per signal, each a filter (`jfor`).
	 */
	private static function foryou( string $set ): void {
		if ( ! class_exists( 'VulnHub_Dash_Ticket_Signals' ) || '' === VulnHub_Dash_Ticket_Signals::me() ) {
			return;
		}

		$active = self::q( 'jfor' );
		$counts = array(
			'mention'  => count( self::keys_with( $set, 'mention' ) ),
			'answered' => count( self::keys_with( $set, 'answered' ) ),
			'assigned' => count( self::keys_with( $set, 'assigned' ) ),
		);

		echo '<section class="vh-foryou' . ( array_sum( $counts ) > 0 ? ' has-yours' : '' ) . '" aria-label="' . esc_attr__( 'Issues waiting on you', 'vulnhub' ) . '">';
		echo '<span class="vh-foryou__h">' . esc_html__( 'For you', 'vulnhub' ) . '</span>';

		foreach ( $counts as $k => $n ) {
			$on  = $active === $k;
			$url = $on ? remove_query_arg( array( 'jfor', 'jp', 'vh_msg', 'vh_err' ) ) : add_query_arg( 'jfor', $k, remove_query_arg( array( 'jp', 'vh_msg', 'vh_err' ) ) );

			printf(
				'<a class="vh-foryou__chip vh-foryou__chip--%1$s%2$s%3$s" href="%4$s"%5$s><span>%6$s</span><b>%7$s</b></a>',
				esc_attr( $k ),
				$on ? ' is-active' : '',
				0 === $n ? ' is-zero' : '',
				esc_url( $url ),
				$on ? ' aria-current="true"' : '',
				esc_html( array( 'mention' => __( 'Mentioned you, not answered', 'vulnhub' ), 'answered' => __( 'Replied since you commented', 'vulnhub' ), 'assigned' => __( 'Assigned to you', 'vulnhub' ) )[ $k ] ),
				esc_html( number_format_i18n( $n ) )
			);
		}

		echo '</section>';
	}

	/**
	 * The topbar bell: mentions on these issues (critical, as on tickets
	 * raised here) and issues assigned to you.
	 *
	 * @param array<int,array<string,mixed>> $items Notices so far.
	 * @return array<int,array<string,mixed>>
	 */
	public static function notify( array $items ): array {
		if ( ! self::shown() || ! class_exists( 'VulnHub_Dash_Portal' ) || ! class_exists( 'VulnHub_Dash_Ticket_Signals' ) || '' === VulnHub_Dash_Ticket_Signals::me() ) {
			return $items;
		}

		foreach ( array( 'mention', 'answered', 'assigned' ) as $for ) {
			$hits = array();

			foreach ( self::SETS as $set ) {
				foreach ( self::open_flags( $set ) as $key => $f ) {
					if ( ! empty( $f[ $for ] ) && ! isset( $hits[ $key ] ) ) {
						$hits[ $key ] = $f + array( 'set' => $set );
					}
				}
			}

			if ( ! $hits ) {
				continue;
			}

			uasort( $hits, static fn( array $a, array $b ): int => strcmp( (string) ( $b[ $for . '_at' ] ?? '' ), (string) ( $a[ $for . '_at' ] ?? '' ) ) );
			$first = reset( $hits );
			$keys  = implode( ', ', array_slice( array_keys( $hits ), 0, 4 ) );
			$url   = VulnHub_Dash_Portal::portal_url( 'tickets', array( 'tview' => (string) $first['set'], 'jfor' => $for ) );

			if ( 'answered' === $for ) {
				$items[] = array(
					'id'       => 'jira-inbox-answered',
					'severity' => 'warn',
					'count'    => count( $hits ),
					'title'    => __( 'New replies on your Jira issues', 'vulnhub' ),
					/* translators: 1: person, 2: time ago, 3: issue keys. */
					'body'     => sprintf( __( '%1$s replied %2$s, after your comment. Also: %3$s.', 'vulnhub' ), (string) $first['answered_by'], vh_ago( (string) $first['answered_at'] ), $keys ),
					'url'      => $url,
				);
				continue;
			}

			$items[] = 'mention' === $for
				? array(
					'id'       => 'jira-inbox-mention',
					'severity' => 'crit',
					'count'    => count( $hits ),
					'title'    => __( 'You were mentioned on a Jira issue', 'vulnhub' ),
					/* translators: 1: person, 2: time ago, 3: issue keys. */
					'body'     => sprintf( __( '%1$s mentioned you %2$s. Not answered yet: %3$s.', 'vulnhub' ), (string) $first['mention_by'], vh_ago( (string) $first['mention_at'] ), $keys ),
					'url'      => $url,
				)
				: array(
					'id'       => 'jira-inbox-assigned',
					'severity' => 'info',
					'count'    => count( $hits ),
					'title'    => __( 'Jira issues assigned to you', 'vulnhub' ),
					/* translators: %s: issue keys. */
					'body'     => sprintf( __( 'Open on your Jira lists, with you as the assignee: %s.', 'vulnhub' ), $keys ),
					'url'      => $url,
				);
		}

		return $items;
	}

	/* =================================================================
	 * One issue, in the portal
	 * ============================================================== */

	/**
	 * The stored row for a key, preferring the given set. The issue routes
	 * act only on keys these lists hold -- they are not a way to reach any
	 * issue on the site.
	 *
	 * @return array<string,mixed>|null
	 */
	public static function held( string $key, string $prefer = '' ): ?array {
		global $wpdb;

		$t   = self::table();
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$t} WHERE issue_key = %s ORDER BY ( set_key = %s ) DESC, id ASC LIMIT 1", strtoupper( $key ), $prefer ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		return $row ?: null;
	}

	/**
	 * The issue as Jira has it now: every field the page shows, the
	 * description and the attachment list. Kept for two minutes; a comment
	 * or a move clears it. A good read also refreshes the stored rows, so the
	 * lists catch up with what the page just showed.
	 *
	 * @return array{ok:bool,fields:array<string,mixed>,error:string}
	 */
	public static function issue_live( string $key, bool $fresh = false ): array {
		$key   = strtoupper( $key );
		$cache = 'vh_jira_inbox_issue_' . md5( $key );

		if ( ! $fresh ) {
			$hit = get_transient( $cache );

			if ( is_array( $hit ) && ! empty( $hit['ok'] ) ) {
				return $hit;
			}
		}

		$c = self::connector();

		if ( ! $c || ! self::enabled() ) {
			return array( 'ok' => false, 'fields' => array(), 'error' => __( 'Jira is not connected.', 'vulnhub' ) );
		}

		$rt = (string) ( self::state()['rt_field'] ?? '' );
		$r  = $c->client()->get_issue( $key, array_merge( self::search_fields( $rt ), array( 'description', 'attachment', 'resolution', 'labels' ) ) );

		if ( ! $r->ok() ) {
			return array(
				'ok'     => false,
				'fields' => array(),
				/* translators: 1: issue key, 2: HTTP status, 3: error. */
				'error'  => sprintf( __( 'Could not read %1$s from Jira (HTTP %2$d): %3$s', 'vulnhub' ), $key, $r->status, vh_trim( $r->error_message(), 160 ) ),
			);
		}

		$out = array( 'ok' => true, 'fields' => (array) ( $r->data()['fields'] ?? array() ), 'error' => '' );

		set_transient( $cache, $out, self::ISSUE_TTL );
		self::update_rows( $key, self::row( array( 'key' => $key, 'fields' => $out['fields'] ), $rt ) );

		return $out;
	}

	private static function forget_live( string $key ): void {
		delete_transient( 'vh_jira_inbox_issue_' . md5( strtoupper( $key ) ) );
	}

	/**
	 * Bring every stored row of one issue up to a fresh read. Approval and
	 * tag columns are left alone: they come from their own reads.
	 *
	 * @param array<string,mixed> $row From row().
	 */
	private static function update_rows( string $key, array $row ): void {
		global $wpdb;

		$set = array_intersect_key( $row, array_flip( self::DISPLAY_COLS ) );

		foreach ( array( 'summary' => 500, 'issue_type' => 120, 'request_type' => 190, 'status' => 120, 'reporter' => 190, 'assignee' => 190 ) as $col => $len ) {
			$set[ $col ] = mb_substr( (string) ( $set[ $col ] ?? '' ), 0, $len );
		}

		// A request-type read can come back blank when the field is hidden from
		// this account on one call and not the other; keep what the list had.
		if ( '' === $set['request_type'] ) {
			unset( $set['request_type'] );
		}

		$set['synced_at'] = vh_now();

		$wpdb->update( self::table(), $set, array( 'issue_key' => $key ) );
	}

	/**
	 * Attachment rows ready for the page: the same shape a ticket raised here
	 * gets from Attachments::describe(), with the file routes pointed at
	 * this issue.
	 *
	 * @param array<string,mixed> $result {ok, message, attachments}.
	 * @return array<string,mixed>
	 */
	public static function described( string $key, array $result ): array {
		$own   = (string) apply_filters( 'vulnhub_ticket_own_account', '' );
		$nonce = wp_create_nonce( 'wp_rest' );

		$result['attachments'] = array_map(
			static function ( $a ) use ( $key, $own, $nonce ): array {
				$d   = \VulnHub\Core\Attachments::describe( 0, (array) $a, $own, '' );
				$url = rest_url( 'vulnhub/v1/tickets/jira/' . rawurlencode( $key ) . '/attachments/' . rawurlencode( (string) ( $a['id'] ?? '' ) ) . '/file' );

				$d['view_url'] = add_query_arg( array( '_wpnonce' => $nonce ), $url );
				$d['download'] = add_query_arg( array( '_wpnonce' => $nonce, 'download' => 1 ), $url );

				return $d;
			},
			(array) ( $result['attachments'] ?? array() )
		);
		$result['fetch_cap'] = size_format( \VulnHub\Core\Attachments::fetch_cap() );

		return $result;
	}

	/** @return array{ok:bool,message:string,attachments:array<int,array<string,mixed>>} */
	private static function attachments_for( string $key, bool $fresh = false ): array {
		$live = self::issue_live( $key, $fresh );

		if ( ! $live['ok'] ) {
			return array( 'ok' => false, 'message' => $live['error'], 'attachments' => array() );
		}

		return array(
			'ok'          => true,
			'message'     => '',
			'attachments' => VulnHub_Jira_Connector::normalise_attachments( (array) ( $live['fields']['attachment'] ?? array() ) ),
		);
	}

	/**
	 * The issue's page, when `jkey` names one. Returns false when it does
	 * not, so the tab draws its list instead.
	 */
	private static function render_issue( string $set, string $base ): bool {
		$key = strtoupper( self::q( 'jkey' ) );

		if ( '' === $key ) {
			return false;
		}

		$list = remove_query_arg( array( 'jkey', 'vh_msg', 'vh_err' ) );
		$msg  = self::q( 'vh_msg' );
		$err  = self::q( 'vh_err' );

		echo '<p><a class="vh-back" href="' . esc_url( $list ) . '">&larr; ' . esc_html__( 'Back to the list', 'vulnhub' ) . '</a></p>';

		if ( '' !== $msg ) {
			echo '<p class="vh-flash vh-flash--good" role="status">' . esc_html( $msg ) . '</p>';
		}
		if ( '' !== $err ) {
			echo '<div class="vh-notice vh-notice--warn" role="alert">' . esc_html( $err ) . '</div>';
		}

		$row = preg_match( '/^[A-Z][A-Z0-9_]*-\d+$/', $key ) ? self::held( $key, $set ) : null;

		if ( ! $row ) {
			echo '<p class="vh-chart-empty">' . esc_html__( 'That issue is not on these lists any more. It may have closed more than 90 days ago, or been answered. Open it in Jira.', 'vulnhub' ) . '</p>';
			return true;
		}

		$live = self::issue_live( $key );
		$rt   = (string) ( self::state()['rt_field'] ?? '' );
		$f    = $live['fields'];

		if ( $live['ok'] ) {
			$fresh = self::row( array( 'key' => $key, 'fields' => $f ), $rt );
			if ( '' === $fresh['request_type'] ) {
				unset( $fresh['request_type'] );
			}
			$row = array_merge( $row, array_intersect_key( $fresh, array_flip( self::DISPLAY_COLS ) ) );
		}

		$apv     = self::held( $key, 'approvals' );
		$apv     = $apv && 'approvals' === (string) $apv['set_key'] ? $apv : null;
		$account = (string) ( self::state()['account'] ?? __( 'the connected Jira account', 'vulnhub' ) );
		$dash    = class_exists( 'VulnHub_Dash_Tickets' );
		$move    = $dash && VulnHub_Dash_Tickets::can_transition() && self::enabled();
		$ref     = 'jira/' . $key;
		?>
		<div class="vh-jissue__head">
			<?php $sig = self::flags_for_rows( array( $row ) )[ $key ] ?? array(); ?>
			<h2><span class="vh-mono"><?php echo esc_html( $key ); ?></span><?php echo self::bell( $sig ); // phpcs:ignore WordPress.Security.EscapeOutput ?> <?php echo esc_html( (string) $row['summary'] ); ?><?php echo $sig ? '<br>' . self::sig_tags( $sig ) : ''; // phpcs:ignore WordPress.Security.EscapeOutput ?></h2>
			<div class="vh-jissue__actions">
				<?php if ( $apv && (int) $apv['can_answer'] === 1 && '' !== (string) $apv['approval_id'] && current_user_can( self::decide_cap() ) && self::enabled() ) : ?>
					<?php
					// After a decision the request leaves Approvals, so land on that list.
					echo self::approval_forms( $apv, add_query_arg( 'tview', 'approvals', remove_query_arg( array( 'jkey', 'vh_msg', 'vh_err', 'tview', 'jstate', 'jq', 'jproj', 'jtag', 'jp' ), $base ) ), $account ); // phpcs:ignore WordPress.Security.EscapeOutput
					?>
				<?php endif; ?>
				<a class="vh-btn vh-btn--ghost vh-btn--sm" href="<?php echo esc_url( self::jira_url( $key ) ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Open in Jira', 'vulnhub' ); ?> &nearr;</a>
			</div>
		</div>

		<?php if ( ! $live['ok'] ) : ?>
			<div class="vh-notice vh-notice--warn">
				<?php
				/* translators: %s: error. */
				echo esc_html( sprintf( __( 'Showing the copy from the last read: %s', 'vulnhub' ), $live['error'] ) );
				?>
			</div>
		<?php endif; ?>

		<div class="vh-grid vh-grid--2">
			<section class="vh-panel">
				<header class="vh-panel__head"><h2><?php esc_html_e( 'Issue', 'vulnhub' ); ?></h2></header>
				<dl class="vh-dl">
					<dt><?php esc_html_e( 'Status', 'vulnhub' ); ?></dt>
					<dd class="vh-dd--act">
						<?php echo self::status_chip( $row ); // phpcs:ignore WordPress.Security.EscapeOutput ?>
						<?php if ( $move ) : ?>
							<button type="button" class="vh-btn vh-btn--ghost vh-btn--sm" data-vh-move="<?php echo esc_attr( $ref ); ?>" data-vh-move-key="<?php echo esc_attr( $key ); ?>"><?php esc_html_e( 'Change status', 'vulnhub' ); ?></button>
						<?php endif; ?>
					</dd>
					<?php if ( $apv ) : ?>
						<dt><?php esc_html_e( 'Approval', 'vulnhub' ); ?></dt>
						<dd><?php echo esc_html( (int) $apv['can_answer'] === 1 ? __( 'Waiting for your decision', 'vulnhub' ) : __( 'Waiting, but Jira does not let this account answer it', 'vulnhub' ) ); ?></dd>
					<?php endif; ?>
					<?php
					$facts = array(
						__( 'Request type', 'vulnhub' ) => (string) $row['request_type'],
						__( 'Issue type', 'vulnhub' )   => (string) $row['issue_type'],
						__( 'Project', 'vulnhub' )      => (string) $row['project_key'],
						__( 'Priority', 'vulnhub' )     => (string) $row['priority'],
						__( 'Raised by', 'vulnhub' )    => (string) $row['reporter'],
						__( 'Assigned to', 'vulnhub' )  => '' !== (string) $row['assignee'] ? (string) $row['assignee'] : __( 'Unassigned', 'vulnhub' ),
						__( 'Raised', 'vulnhub' )       => vh_date( (string) $row['created_at'] ),
						__( 'Updated', 'vulnhub' )      => vh_ago( (string) $row['updated_at'] ),
						__( 'Due', 'vulnhub' )          => ! empty( $row['due_on'] ) ? vh_date_only( (string) $row['due_on'] ) : '',
						__( 'Resolution', 'vulnhub' )   => trim( (string) ( $f['resolution']['name'] ?? '' ) . ( ! empty( $row['resolved_at'] ) ? ' · ' . vh_date( (string) $row['resolved_at'], 'j M Y' ) : '' ), ' ·' ),
						__( 'Labels', 'vulnhub' )       => implode( ', ', array_map( 'strval', (array) ( $f['labels'] ?? array() ) ) ),
					);
					foreach ( $facts as $label => $value ) :
						if ( '' === $value || '—' === $value ) {
							continue;
						}
						?>
						<dt><?php echo esc_html( $label ); ?></dt>
						<dd><?php echo esc_html( $value ); ?></dd>
					<?php endforeach; ?>
				</dl>

				<?php if ( $live['ok'] ) : ?>
					<?php echo self::attachments_block( $key ); // phpcs:ignore WordPress.Security.EscapeOutput ?>
				<?php endif; ?>

				<?php if ( $dash ) : ?>
					<div class="vh-panel__sub">
						<h3><?php esc_html_e( 'Comments', 'vulnhub' ); ?></h3>
						<?php echo VulnHub_Dash_Tickets::comments_body( $ref, true ); // phpcs:ignore WordPress.Security.EscapeOutput ?>
						<p class="vh-meta"><?php esc_html_e( 'Jira decides what this account may do here: a reply or internal note it does not allow comes back as its own refusal.', 'vulnhub' ); ?></p>
					</div>
				<?php endif; ?>
			</section>

			<section class="vh-panel">
				<header class="vh-panel__head"><h2><?php esc_html_e( 'Description', 'vulnhub' ); ?></h2></header>
				<?php
				$desc = is_array( $f['description'] ?? null ) ? trim( VulnHub_Jira_Adf::to_html( (array) $f['description'] ) ) : '';

				if ( '' !== $desc ) {
					echo '<div class="vh-jissue__desc">' . wp_kses_post( $desc ) . '</div>'; // Built from escaped text; kses as a second fence.
				} else {
					echo '<p class="vh-meta">' . esc_html( $live['ok'] ? __( 'No description.', 'vulnhub' ) : __( 'The description is read from Jira when it can be reached.', 'vulnhub' ) ) . '</p>';
				}
				?>
			</section>
		</div>
		<?php
		if ( $dash ) {
			echo VulnHub_Dash_Tickets::transition_dialog(); // phpcs:ignore WordPress.Security.EscapeOutput
			echo VulnHub_Dash_Tickets::attachment_dialog(); // phpcs:ignore WordPress.Security.EscapeOutput
		}

		return true;
	}

	/**
	 * The Attachments block, in the markup and JSON the ticket page's
	 * script already draws, pointed at this issue.
	 */
	private static function attachments_block( string $key ): string {
		$seed = self::described( $key, self::attachments_for( $key ) );
		$n    = count( $seed['attachments'] );

		return '<div class="vh-panel__sub vh-atts" id="vh-attachments" data-vh-atts-for="' . esc_attr( 'jira/' . $key ) . '">'
			. '<div class="vh-atts__head">'
			. '<h3>' . esc_html__( 'Attachments', 'vulnhub' ) . ' <span class="vh-atts__count" data-vh-atts-count>' . esc_html( number_format_i18n( $n ) ) . '</span></h3>'
			. '<div class="vh-atts__tools">'
			. '<button type="button" class="vh-btn vh-btn--ghost vh-btn--sm" data-vh-atts-refresh>' . esc_html__( 'Refresh from Jira', 'vulnhub' ) . '</button>'
			. '</div></div>'
			. '<ul class="vh-atts__list" data-vh-atts-list></ul>'
			. '<p class="vh-meta vh-atts__status" data-vh-atts-status role="status"></p>'
			. '<script type="application/json" data-vh-atts-seed>' . wp_json_encode( $seed, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT ) . '</script>'
			. '</div>';
	}

	/* =================================================================
	 * REST: /vulnhub/v1/tickets/jira/{KEY}/…
	 *
	 * The same routes, and the same answers, a ticket raised here has under
	 * /tickets/{id}/…, so the page's comment, status and attachment scripts
	 * work on both. Every route acts only on a key these lists hold.
	 * ============================================================== */

	public static function routes(): void {
		$ns   = 'vulnhub/v1';
		$base = '/tickets/jira/(?P<key>' . self::KEY_RE . ')';
		$view = static fn() => self::permit( Caps::VIEW );
		$act  = static fn() => self::permit( Caps::RAISE_TICKET );

		register_rest_route(
			$ns,
			$base . '/comments',
			array(
				array( 'methods' => 'GET', 'callback' => array( __CLASS__, 'rest_comments' ), 'permission_callback' => $view ),
				array( 'methods' => 'POST', 'callback' => array( __CLASS__, 'rest_post_comment' ), 'permission_callback' => $act ),
			)
		);
		register_rest_route(
			$ns,
			$base . '/transitions',
			array(
				array( 'methods' => 'GET', 'callback' => array( __CLASS__, 'rest_transitions' ), 'permission_callback' => $act ),
				array( 'methods' => 'POST', 'callback' => array( __CLASS__, 'rest_apply_transition' ), 'permission_callback' => $act ),
			)
		);
		// Who "@" may suggest, on these issues and on tickets raised here.
		register_rest_route( $ns, $base . '/mentionable', array( 'methods' => 'GET', 'callback' => array( __CLASS__, 'rest_mentionable' ), 'permission_callback' => $act ) );
		register_rest_route( $ns, '/tickets/(?P<id>\d+)/mentionable', array( 'methods' => 'GET', 'callback' => array( __CLASS__, 'rest_ticket_mentionable' ), 'permission_callback' => $act ) );
		register_rest_route( $ns, $base . '/attachments', array( 'methods' => 'GET', 'callback' => array( __CLASS__, 'rest_attachments' ), 'permission_callback' => $view ) );
		register_rest_route( $ns, $base . '/attachments/(?P<att>[A-Za-z0-9_-]+)/preview', array( 'methods' => 'GET', 'callback' => array( __CLASS__, 'rest_attachment_preview' ), 'permission_callback' => $view ) );
		register_rest_route( $ns, $base . '/attachments/(?P<att>[A-Za-z0-9_-]+)/file', array( 'methods' => 'GET', 'callback' => array( __CLASS__, 'rest_attachment_file' ), 'permission_callback' => $view ) );
	}

	private static function permit( string $cap ): bool|\WP_Error {
		return Caps::can( $cap )
			? true
			: new \WP_Error( 'vulnhub_forbidden', __( 'You do not have permission to do that.', 'vulnhub' ), array( 'status' => is_user_logged_in() ? 403 : 401 ) );
	}

	/**
	 * The key, its stored row and the connector -- or why not.
	 *
	 * @return array{0:string,1:array<string,mixed>,2:VulnHub_Jira_Connector}|\WP_Error
	 */
	private static function target( \WP_REST_Request $r ): array|\WP_Error {
		$key = strtoupper( (string) $r['key'] );
		$row = self::held( $key );

		if ( ! $row ) {
			return new \WP_Error( 'vulnhub_not_found', __( 'That issue is not on your Jira lists here. Open it in Jira.', 'vulnhub' ), array( 'status' => 404 ) );
		}

		$c = self::connector();

		if ( ! $c || ! self::enabled() ) {
			return new \WP_Error( 'vulnhub_no_itsm', __( 'Jira is not connected.', 'vulnhub' ), array( 'status' => 409 ) );
		}

		return array( $key, $row, $c );
	}

	/** A read-only copy of this portal never writes to the real site. */
	private static function blocked(): ?\WP_Error {
		$why = (string) apply_filters( 'vulnhub_connector_sync_blocked', '', 'jira', array( 'inbox' => 'write' ) );

		return '' === $why ? null : new \WP_Error( 'vulnhub_blocked', $why, array( 'status' => 409 ) );
	}

	public static function rest_comments( \WP_REST_Request $r ): \WP_REST_Response|\WP_Error {
		$t = self::target( $r );
		if ( $t instanceof \WP_Error ) {
			return $t;
		}

		$res = $t[2]->comments( $t[0] );

		if ( ! empty( $res['ok'] ) ) {
			self::store_conversation( $t[0], (array) $res['comments'] );
		}

		return new \WP_REST_Response( $res );
	}

	public static function rest_post_comment( \WP_REST_Request $r ): \WP_REST_Response|\WP_Error {
		$t = self::target( $r );
		if ( $t instanceof \WP_Error ) {
			return $t;
		}
		$stop = self::blocked();
		if ( $stop ) {
			return $stop;
		}

		[ $key, , $c ] = $t;

		$body = trim( (string) $r->get_param( 'body' ) );
		if ( '' === $body ) {
			return new \WP_Error( 'vulnhub_bad_request', __( 'Write something first.', 'vulnhub' ), array( 'status' => 400 ) );
		}

		// Absent means internal, as on a ticket raised here: a default that
		// reaches the customer is the wrong way round for a field nobody set.
		$public = in_array( $r->get_param( 'public' ), array( true, 1, '1', 'true', 'yes', 'on' ), true );

		$mentions = \VulnHub\Core\Rest::mentions_param( $r->get_param( 'mentions' ) );

		$cl = $c->client();
		$cl->allow_issue( $key );

		try {
			$res = $c->post_comment( $key, $body, $public, $mentions );
		} finally {
			$cl->forget_issues();
		}

		if ( empty( $res['ok'] ) ) {
			return new \WP_Error( 'vulnhub_comment_failed', (string) ( $res['message'] ?? __( 'The comment was not posted.', 'vulnhub' ) ), array( 'status' => 502 ) );
		}

		self::forget_live( $key );

		// Your reply is what clears "Mentioned you": read the thread now,
		// not at the next refresh.
		$fresh = $c->comments( $key, 50, true );
		if ( ! empty( $fresh['ok'] ) ) {
			self::store_conversation( $key, (array) $fresh['comments'] );
		}

		vulnhub()->logger->audit(
			'jira.inbox_comment',
			sprintf( 'Commented on %s (%s)', $key, $public ? 'reply to customer' : 'internal note' ),
			'jira_issue',
			$key,
			array(
				'public'   => $public,
				'mentions' => count( (array) ( $res['mentioned'] ?? array() ) ),
			)
		);

		return new \WP_REST_Response( $res );
	}

	/** People who can view one of these issues, for "@" in the reply box. */
	public static function rest_mentionable( \WP_REST_Request $r ): \WP_REST_Response|\WP_Error {
		$t = self::target( $r );
		if ( $t instanceof \WP_Error ) {
			return $t;
		}

		return new \WP_REST_Response( $t[2]->mentionable( $t[0], (string) $r->get_param( 'q' ) ) );
	}

	/** The same, for a ticket raised here: its Jira issue decides who can see it. */
	public static function rest_ticket_mentionable( \WP_REST_Request $r ): \WP_REST_Response|\WP_Error {
		$ticket = \VulnHub\Core\Tickets::get( (int) $r['id'] );
		$c      = self::connector();

		if ( ! $ticket || 'jira' !== (string) ( $ticket['provider'] ?? '' ) || '' === (string) ( $ticket['external_key'] ?? '' ) ) {
			return new \WP_Error( 'vulnhub_not_found', __( 'That ticket has no Jira issue to tag people on.', 'vulnhub' ), array( 'status' => 404 ) );
		}
		if ( ! $c || ! $c->is_enabled() || $c->is_mock() ) {
			return new \WP_Error( 'vulnhub_no_itsm', __( 'Jira is not connected.', 'vulnhub' ), array( 'status' => 409 ) );
		}

		return new \WP_REST_Response( $c->mentionable( (string) $ticket['external_key'], (string) $r->get_param( 'q' ) ) );
	}

	public static function rest_transitions( \WP_REST_Request $r ): \WP_REST_Response|\WP_Error {
		$t = self::target( $r );
		if ( $t instanceof \WP_Error ) {
			return $t;
		}

		[ $key, $row, $c ] = $t;

		$res           = $c->transitions_for( $key );
		$res['status'] = (string) $row['status'];
		$res['url']    = self::jira_url( $key );

		return new \WP_REST_Response( $res );
	}

	public static function rest_apply_transition( \WP_REST_Request $r ): \WP_REST_Response|\WP_Error {
		$t = self::target( $r );
		if ( $t instanceof \WP_Error ) {
			return $t;
		}
		$stop = self::blocked();
		if ( $stop ) {
			return $stop;
		}

		[ $key, $row, $c ] = $t;

		$transition = trim( (string) $r->get_param( 'transition' ) );
		if ( '' === $transition ) {
			return new \WP_Error( 'vulnhub_bad_request', __( 'Choose a status to move the issue to.', 'vulnhub' ), array( 'status' => 400 ) );
		}

		$values = array();
		foreach ( (array) $r->get_param( 'fields' ) as $field => $value ) {
			if ( is_scalar( $value ) ) {
				$values[ (string) $field ] = (string) $value;
			}
		}

		$cl = $c->client();
		$cl->allow_issue( $key );

		try {
			$res = $c->apply_transition( $key, $transition, $values, trim( (string) $r->get_param( 'note' ) ) );
		} finally {
			$cl->forget_issues();
		}

		if ( empty( $res['ok'] ) ) {
			return new \WP_Error( 'vulnhub_transition_failed', (string) ( $res['message'] ?? __( 'The issue was not moved.', 'vulnhub' ) ), array( 'status' => 502 ) );
		}

		// Read it straight back, so the page and the lists show what Jira
		// recorded rather than what was asked for.
		$c->forget_comments( $key );
		self::issue_live( $key, true );

		vulnhub()->logger->audit(
			'jira.inbox_transition',
			sprintf( 'Moved %1$s from %2$s to %3$s', $key, (string) $row['status'], (string) ( $res['status'] ?? '' ) ),
			'jira_issue',
			$key,
			array(
				'transition' => $transition,
				'from'       => (string) $row['status'],
				'to'         => (string) ( $res['status'] ?? '' ),
				'fields'     => array_keys( $values ),
			)
		);

		return new \WP_REST_Response( $res );
	}

	public static function rest_attachments( \WP_REST_Request $r ): \WP_REST_Response|\WP_Error {
		$t = self::target( $r );
		if ( $t instanceof \WP_Error ) {
			return $t;
		}

		$fresh = in_array( $r->get_param( 'fresh' ), array( true, 1, '1', 'true', 'yes' ), true );

		return new \WP_REST_Response( self::described( $t[0], self::attachments_for( $t[0], $fresh ) ) );
	}

	/**
	 * The issue and one of its files -- only a file Jira lists on that issue.
	 *
	 * @return array{0:array<string,mixed>,1:array<string,mixed>}|\WP_Error
	 */
	private static function attachment_target( \WP_REST_Request $r ): array|\WP_Error {
		$t = self::target( $r );
		if ( $t instanceof \WP_Error ) {
			return $t;
		}

		$key  = $t[0];
		$want = (string) $r['att'];

		foreach ( array( false, true ) as $fresh ) {
			foreach ( self::attachments_for( $key, $fresh )['attachments'] as $a ) {
				if ( (string) $a['id'] === $want ) {
					// The shape Attachments::local() and the Jira byte fetch
					// expect of a ticket. Id 0 keeps the cached copy apart from
					// every ticket raised here; attachment ids are unique site-wide.
					return array( array( 'id' => 0, 'provider' => 'jira', 'external_key' => $key ), $a );
				}
			}
		}

		return new \WP_Error( 'vulnhub_not_found', __( 'That file is not on this issue. Refresh the list of attachments.', 'vulnhub' ), array( 'status' => 404 ) );
	}

	public static function rest_attachment_preview( \WP_REST_Request $r ): \WP_REST_Response|\WP_Error {
		$t = self::attachment_target( $r );
		if ( $t instanceof \WP_Error ) {
			return $t;
		}

		[ $ticket, $att ] = $t;
		$name             = (string) ( $att['filename'] ?? '' );

		if ( 'none' === \VulnHub\Core\Attachments::kind( $name, (string) ( $att['mime'] ?? '' ) ) ) {
			return new \WP_REST_Response( \VulnHub\Core\Attachments::preview( '', $name ) );
		}

		$local = \VulnHub\Core\Attachments::local( $ticket, $att );

		if ( ! $local['ok'] ) {
			return new \WP_REST_Response( array( 'ok' => false, 'kind' => 'none', 'name' => $name, 'message' => $local['message'] ) );
		}

		return new \WP_REST_Response( \VulnHub\Core\Attachments::preview( $local['path'], $name, (string) ( $att['mime'] ?? '' ) ) );
	}

	public static function rest_attachment_file( \WP_REST_Request $r ): \WP_REST_Response|\WP_Error {
		$t = self::attachment_target( $r );
		if ( $t instanceof \WP_Error ) {
			return $t;
		}

		[ $ticket, $att ] = $t;
		$local            = \VulnHub\Core\Attachments::local( $ticket, $att );

		if ( ! $local['ok'] ) {
			return new \WP_Error( 'vulnhub_attachment', $local['message'], array( 'status' => 502 ) );
		}

		\VulnHub\Core\Attachments::stream( $local['path'], (string) ( $att['filename'] ?? 'attachment' ), in_array( $r->get_param( 'download' ), array( 1, '1', 'true' ), true ) );

		return new \WP_REST_Response( null, 204 );
	}

	/* =================================================================
	 * Actions
	 * ============================================================== */

	private static function posted( string $key ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- checked by the caller.
		return isset( $_POST[ $key ] ) && ! is_array( $_POST[ $key ] ) ? sanitize_text_field( wp_unslash( (string) $_POST[ $key ] ) ) : '';
	}

	/** Where to send the person back to: the tab they came from. */
	private static function back( string $fallback_view ): string {
		$back = wp_validate_redirect( self::posted( 'back' ), '' );

		if ( '' === $back ) {
			$pages = (array) get_option( 'vulnhub_dash_pages', array() );
			$base  = ! empty( $pages['tickets'] ) ? (string) get_permalink( (int) $pages['tickets'] ) : home_url( '/' );
			$back  = add_query_arg( 'tview', $fallback_view, $base );
		}

		return remove_query_arg( array( 'vh_msg', 'vh_err' ), $back );
	}

	public static function handle_refresh(): void {
		if ( ! is_user_logged_in() || ! self::can_refresh() ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( self::ACTION_REFRESH );

		$set  = in_array( self::posted( 'set' ), self::SETS, true ) ? self::posted( 'set' ) : 'mine';
		$back = self::back( $set );
		$res  = self::refresh( array( $set ) )[ $set ] ?? array( 'ok' => false, 'count' => 0, 'error' => __( 'Jira is not connected.', 'vulnhub' ) );

		wp_safe_redirect(
			add_query_arg(
				$res['ok'] ? 'vh_msg' : 'vh_err',
				rawurlencode(
					$res['ok']
						/* translators: %s: number of issues. */
						? sprintf( _n( 'Read %s issue from Jira.', 'Read %s issues from Jira.', $res['count'], 'vulnhub' ), number_format_i18n( $res['count'] ) )
						/* translators: %s: error. */
						: sprintf( __( 'Could not read from Jira: %s', 'vulnhub' ), $res['error'] )
				),
				$back
			)
		);
		exit;
	}

	public static function handle_decide(): void {
		if ( ! is_user_logged_in() || ! current_user_can( self::decide_cap() ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( self::ACTION_DECIDE );

		$res = self::decide( strtoupper( self::posted( 'key' ) ), self::posted( 'approval' ), self::posted( 'decision' ) );

		wp_safe_redirect( add_query_arg( $res['ok'] ? 'vh_msg' : 'vh_err', rawurlencode( $res['message'] ), self::back( 'approvals' ) ) );
		exit;
	}

	/**
	 * Answer one approval in Jira as the connected account.
	 *
	 * Checked against Jira itself immediately before answering: a page that
	 * has been open for an hour, or a second click, must not send a decision
	 * Jira already has, or one this account may no longer give.
	 *
	 * @return array{ok:bool,message:string}
	 */
	public static function decide( string $key, string $approval_id, string $decision ): array {
		if ( ! preg_match( '/^[A-Z][A-Z0-9_]*-\d+$/', $key ) || ! preg_match( '/^\d+$/', $approval_id ) || ! in_array( $decision, array( 'approve', 'decline' ), true ) ) {
			return array( 'ok' => false, 'message' => __( 'That approval could not be read from the form.', 'vulnhub' ) );
		}

		if ( ! self::enabled() ) {
			return array( 'ok' => false, 'message' => __( 'Jira is not connected, so nothing was sent.', 'vulnhub' ) );
		}

		// A read-only copy of this portal must never act on the real site.
		$blocked = (string) apply_filters( 'vulnhub_connector_sync_blocked', '', 'jira', array( 'inbox' => 'approval' ) );
		if ( '' !== $blocked ) {
			return array( 'ok' => false, 'message' => $blocked );
		}

		$lock = 'vh_jira_apv_' . md5( $key . '|' . $approval_id );
		if ( get_transient( $lock ) ) {
			return array( 'ok' => false, 'message' => __( 'That approval is already being answered.', 'vulnhub' ) );
		}
		set_transient( $lock, 1, MINUTE_IN_SECONDS );

		try {
			$cl  = self::connector()->client();
			$now = $cl->request_approval( $key, $approval_id );

			if ( ! $now->ok() ) {
				/* translators: %s: error. */
				return array( 'ok' => false, 'message' => sprintf( __( 'Could not read the approval from Jira, so nothing was sent: %s', 'vulnhub' ), vh_trim( $now->error_message(), 200 ) ) );
			}

			$cur = $now->data();

			if ( 'pending' !== ( $cur['finalDecision'] ?? '' ) ) {
				self::forget_approval( $key );
				/* translators: 1: issue key, 2: decision. */
				return array( 'ok' => false, 'message' => sprintf( __( '%1$s is no longer waiting: Jira has it as %2$s. Nothing was sent.', 'vulnhub' ), $key, (string) ( $cur['finalDecision'] ?? '?' ) ) );
			}
			if ( empty( $cur['canAnswerApproval'] ) ) {
				/* translators: %s: issue key. */
				return array( 'ok' => false, 'message' => sprintf( __( 'Jira no longer lets this account answer %s. Nothing was sent.', 'vulnhub' ), $key ) );
			}

			$r = $cl->answer_approval( $key, $approval_id, $decision );

			vulnhub()->logger->audit(
				$r->ok() ? 'jira.approval_answered' : 'jira.approval_failed',
				sprintf(
					/* translators: 1: issue key, 2: approve or decline. */
					$r->ok() ? __( '%1$s: %2$s sent to Jira', 'vulnhub' ) : __( '%1$s: %2$s refused by Jira', 'vulnhub' ),
					$key,
					$decision
				),
				'jira_issue',
				$key,
				array(
					'approval' => $approval_id,
					'decision' => $decision,
					'as'       => (string) ( self::state()['account'] ?? '' ),
					'status'   => $r->status,
					'error'    => $r->ok() ? '' : vh_trim( $r->error_message(), 200 ),
				),
				$r->ok() ? 'info' : 'warning'
			);

			if ( ! $r->ok() ) {
				/* translators: %s: error. */
				return array( 'ok' => false, 'message' => sprintf( __( 'Jira refused the answer: %s', 'vulnhub' ), vh_trim( $r->error_message(), 200 ) ) );
			}

			self::forget_approval( $key );

			return array(
				'ok'      => true,
				'message' => 'approve' === $decision
					/* translators: %s: issue key. */
					? sprintf( __( '%s approved in Jira.', 'vulnhub' ), $key )
					/* translators: %s: issue key. */
					: sprintf( __( '%s declined in Jira.', 'vulnhub' ), $key ),
			);
		} finally {
			delete_transient( $lock );
		}
	}

	/** Drop one row from the approvals set once Jira no longer has it waiting. */
	private static function forget_approval( string $key ): void {
		global $wpdb;

		$wpdb->delete( self::table(), array( 'set_key' => 'approvals', 'issue_key' => $key ) );
	}
}

