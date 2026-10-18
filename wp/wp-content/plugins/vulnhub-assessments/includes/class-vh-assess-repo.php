<?php
/**
 * Supplier assessment and security exception register: data.
 *
 * One table, one row per decision. A row is either a supplier (third-party
 * information security) assessment or a security exception, because both
 * arrive through the same service-desk request type and both end the same
 * way: somebody reviewed it, somebody decided, and the decision may carry
 * conditions and a date to look at it again.
 *
 * Rows are entered by people (or imported from a register handed over by a
 * previous team), never created by a sync. Jira is read to suggest what is
 * missing and what an approver has written, but a row only changes when a
 * person saves it -- an approval read out of a comment is a claim about
 * somebody else's intent, and the register is the record of that intent.
 *
 * Anything identifying (supplier names, people, ticket keys) lives in the
 * database and the operator's import file, never in this code.
 *
 * @package VulnHub\Assessments
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VH_Assess_Repo {

	public const DB_VERSION     = '1';
	public const VERSION_OPTION = 'vulnhub_assess_db';
	public const META_OPTION    = 'vulnhub_assess_meta';
	public const DISMISS_OPTION = 'vulnhub_assess_dismissed';

	public const KINDS = array( 'supplier', 'exception' );

	public const SOURCES = array( 'inherited', 'internal' );

	/** Hard cap on a list read: this is a register, not a findings table. */
	private const MAX_ROWS = 2000;

	public static function init(): void {
		add_action( 'init', array( __CLASS__, 'maybe_install' ), 5 );
	}

	public static function table(): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_assessments';
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
				kind varchar(20) NOT NULL DEFAULT 'supplier',
				subject varchar(255) NOT NULL DEFAULT '',
				source varchar(20) NOT NULL DEFAULT 'internal',
				origin varchar(190) NOT NULL DEFAULT '',
				raised_on date NULL DEFAULT NULL,
				period_text varchar(80) NOT NULL DEFAULT '',
				requested_by varchar(190) NOT NULL DEFAULT '',
				outcome varchar(30) NOT NULL DEFAULT 'in_review',
				reviewer varchar(190) NOT NULL DEFAULT '',
				reviewed_on date NULL DEFAULT NULL,
				review_summary text NULL,
				approver varchar(190) NOT NULL DEFAULT '',
				decided_on date NULL DEFAULT NULL,
				conditions text NULL,
				review_due date NULL DEFAULT NULL,
				ended_on date NULL DEFAULT NULL,
				jira_keys varchar(255) NOT NULL DEFAULT '',
				notes text NULL,
				created_at datetime NULL DEFAULT NULL,
				updated_at datetime NULL DEFAULT NULL,
				updated_by bigint(20) unsigned NOT NULL DEFAULT 0,
				PRIMARY KEY  (id),
				KEY kind_outcome (kind,outcome),
				KEY source (source)
			) {$c};"
		);

		update_option( self::VERSION_OPTION, self::DB_VERSION, false );
	}

	/* =================================================================
	 * Vocabulary
	 * ============================================================== */

	/**
	 * Every outcome a row can carry, and the group it counts in. Groups are
	 * what the tiles add up, so a new outcome only has to name its group.
	 *
	 * @return array<string,array{label:string,group:string,tone:string}>
	 */
	public static function outcomes(): array {
		return (array) apply_filters(
			'vulnhub_assess_outcomes',
			array(
				'approved'          => array( 'label' => __( 'Approved', 'vulnhub' ), 'group' => 'approved', 'tone' => 'good' ),
				'conditional'       => array( 'label' => __( 'Approved with conditions', 'vulnhub' ), 'group' => 'approved', 'tone' => 'cond' ),
				'rejected'          => array( 'label' => __( 'Rejected', 'vulnhub' ), 'group' => 'declined', 'tone' => 'bad' ),
				'not_approved'      => array( 'label' => __( 'Not approved', 'vulnhub' ), 'group' => 'declined', 'tone' => 'bad' ),
				'awaiting_approval' => array( 'label' => __( 'Reviewed, awaiting decision', 'vulnhub' ), 'group' => 'open', 'tone' => 'warn' ),
				'in_review'         => array( 'label' => __( 'Awaiting review', 'vulnhub' ), 'group' => 'open', 'tone' => 'warn' ),
				'awaiting_supplier' => array( 'label' => __( 'Waiting on the questionnaire', 'vulnhub' ), 'group' => 'open', 'tone' => 'muted' ),
				'not_recorded'      => array( 'label' => __( 'Closed, no decision recorded', 'vulnhub' ), 'group' => 'closed', 'tone' => 'muted' ),
				'withdrawn'         => array( 'label' => __( 'Withdrawn', 'vulnhub' ), 'group' => 'closed', 'tone' => 'muted' ),
				'not_required'      => array( 'label' => __( 'Not required', 'vulnhub' ), 'group' => 'closed', 'tone' => 'muted' ),
			)
		);
	}

	/** @return array<string,string> */
	public static function groups(): array {
		return array(
			'approved' => __( 'Approved', 'vulnhub' ),
			'declined' => __( 'Rejected or not approved', 'vulnhub' ),
			'open'     => __( 'Waiting on a decision', 'vulnhub' ),
			'closed'   => __( 'Closed without approval', 'vulnhub' ),
		);
	}

	public static function outcome_label( string $o ): string {
		return (string) ( self::outcomes()[ $o ]['label'] ?? $o );
	}

	public static function group_of( string $o ): string {
		return (string) ( self::outcomes()[ $o ]['group'] ?? 'open' );
	}

	/* =================================================================
	 * Reads
	 * ============================================================== */

	/**
	 * Rows matching the filters, newest decision first.
	 *
	 * @param array{kind?:string,source?:string,outcome?:string,group?:string,q?:string,due?:string} $f Filters.
	 * @return array<int,array<string,mixed>>
	 */
	public static function rows( array $f = array() ): array {
		global $wpdb;

		$t     = self::table();
		$where = array( '1=1' );
		$args  = array();

		if ( ! empty( $f['kind'] ) && in_array( $f['kind'], self::KINDS, true ) ) {
			$where[] = 'kind = %s';
			$args[]  = $f['kind'];
		}
		if ( ! empty( $f['source'] ) && in_array( $f['source'], self::SOURCES, true ) ) {
			$where[] = 'source = %s';
			$args[]  = $f['source'];
		}
		if ( ! empty( $f['outcome'] ) && isset( self::outcomes()[ $f['outcome'] ] ) ) {
			$where[] = 'outcome = %s';
			$args[]  = $f['outcome'];
		}
		if ( ! empty( $f['group'] ) && isset( self::groups()[ $f['group'] ] ) ) {
			$in = array_keys( array_filter( self::outcomes(), static fn( array $o ): bool => $o['group'] === $f['group'] ) );
			if ( $in ) {
				$where[] = 'outcome IN (' . implode( ',', array_fill( 0, count( $in ), '%s' ) ) . ')';
				$args    = array_merge( $args, $in );
			}
		}
		if ( ! empty( $f['due'] ) ) {
			// Anything with a look-again date that is still in force.
			$where[] = 'review_due IS NOT NULL AND ended_on IS NULL';
		}
		if ( isset( $f['q'] ) && '' !== trim( (string) $f['q'] ) ) {
			// LOCATE, not LIKE: no literal % to escape through prepare().
			$where[] = '( LOCATE( %s, CONCAT_WS( " ", subject, origin, requested_by, reviewer, approver, jira_keys, conditions, notes, review_summary, period_text ) ) > 0 )';
			$args[]  = trim( (string) $f['q'] );
		}

		$sql = "SELECT * FROM {$t} WHERE " . implode( ' AND ', $where )
			. ' ORDER BY COALESCE( decided_on, reviewed_on, raised_on ) DESC, id DESC LIMIT ' . self::MAX_ROWS;

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$rows = (array) $wpdb->get_results( $args ? $wpdb->prepare( $sql, $args ) : $sql, ARRAY_A );

		return array_map( array( __CLASS__, 'shape' ), $rows );
	}

	/** @return array<string,mixed>|null */
	public static function get( int $id ): ?array {
		global $wpdb;

		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . self::table() . ' WHERE id = %d', $id ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

		return $row ? self::shape( $row ) : null;
	}

	/**
	 * Counts per kind, source and outcome group, for the tiles.
	 *
	 * @return array<string,int>
	 */
	public static function counts( string $kind ): array {
		$out = array(
			'all'       => 0,
			'inherited' => 0,
			'internal'  => 0,
			'due'       => 0,
			'overdue'   => 0,
		);
		foreach ( array_keys( self::groups() ) as $g ) {
			$out[ $g ]               = 0;
			$out[ 'internal_' . $g ] = 0;
			$out[ 'inherited_' . $g ] = 0;
		}

		$today = gmdate( 'Y-m-d' );
		$soon  = gmdate( 'Y-m-d', time() + 60 * DAY_IN_SECONDS );

		foreach ( self::rows( array( 'kind' => $kind ) ) as $r ) {
			$g = self::group_of( (string) $r['outcome'] );
			++$out['all'];
			++$out[ $r['source'] ];
			++$out[ $g ];
			++$out[ $r['source'] . '_' . $g ];

			if ( $r['review_due'] && ! $r['ended_on'] ) {
				if ( $r['review_due'] < $today ) {
					++$out['overdue'];
				} elseif ( $r['review_due'] <= $soon ) {
					++$out['due'];
				}
			}
		}

		return $out;
	}

	/**
	 * Every Jira key any row links to, upper-cased.
	 *
	 * @return array<string,int> key => row id
	 */
	public static function linked_keys(): array {
		global $wpdb;

		$out = array();

		foreach ( (array) $wpdb->get_results( 'SELECT id, jira_keys FROM ' . self::table() . " WHERE jira_keys <> ''", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			foreach ( self::split_keys( (string) $r['jira_keys'] ) as $k ) {
				$out[ $k ] = (int) $r['id'];
			}
		}

		return $out;
	}

	/**
	 * Distinct people who have decided or reviewed, for the form's
	 * suggestions.
	 *
	 * @return array{approvers:array<int,string>,reviewers:array<int,string>}
	 */
	public static function people(): array {
		global $wpdb;

		$t = self::table();

		return array(
			'approvers' => array_values( array_filter( (array) $wpdb->get_col( "SELECT DISTINCT approver FROM {$t} WHERE approver <> '' ORDER BY approver" ) ) ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			'reviewers' => array_values( array_filter( (array) $wpdb->get_col( "SELECT DISTINCT reviewer FROM {$t} WHERE reviewer <> '' ORDER BY reviewer" ) ) ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		);
	}

	/* =================================================================
	 * Writes
	 * ============================================================== */

	/**
	 * Insert (no id) or update (id) one row. Returns the id, or 0.
	 *
	 * @param array<string,mixed> $data Unsanitised input.
	 */
	public static function save( array $data, int $id = 0 ): int {
		global $wpdb;

		$row = self::clean( $data );

		if ( '' === $row['subject'] ) {
			return 0;
		}

		$row['updated_at'] = vh_now();
		$row['updated_by'] = get_current_user_id();

		if ( $id > 0 ) {
			$ok = false !== $wpdb->update( self::table(), $row, array( 'id' => $id ) );
			return $ok ? $id : 0;
		}

		$row['created_at'] = $row['updated_at'];
		$ok                = false !== $wpdb->insert( self::table(), $row );

		return $ok ? (int) $wpdb->insert_id : 0;
	}

	public static function delete( int $id ): bool {
		global $wpdb;

		return (bool) $wpdb->delete( self::table(), array( 'id' => $id ), array( '%d' ) );
	}

	/**
	 * Replace the whole register (import with --replace).
	 */
	public static function truncate(): void {
		global $wpdb;

		$wpdb->query( 'TRUNCATE TABLE ' . self::table() ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
	}

	/* =================================================================
	 * Tickets kept out of the register on purpose
	 * ============================================================== */

	/** @return array<string,array{reason:string,by:int,at:string}> */
	public static function dismissed(): array {
		return (array) get_option( self::DISMISS_OPTION, array() );
	}

	public static function dismiss( string $key, string $reason ): void {
		$key = self::norm_key( $key );
		if ( '' === $key ) {
			return;
		}

		$all         = self::dismissed();
		$all[ $key ] = array(
			'reason' => mb_substr( sanitize_text_field( $reason ), 0, 190 ),
			'by'     => get_current_user_id(),
			'at'     => vh_now(),
		);
		update_option( self::DISMISS_OPTION, $all, false );
	}

	public static function undismiss( string $key ): void {
		$all = self::dismissed();
		unset( $all[ self::norm_key( $key ) ] );
		update_option( self::DISMISS_OPTION, $all, false );
	}

	/* =================================================================
	 * Register-level facts (inherited register summary, as-at date)
	 * ============================================================== */

	/**
	 * @return array{inherited_label:string,inherited_as_at:string,inherited_summary:array<string,int>,notes:array<int,string>}
	 */
	public static function meta(): array {
		$m = (array) get_option( self::META_OPTION, array() );

		return array(
			'inherited_label'   => (string) ( $m['inherited_label'] ?? '' ),
			'inherited_as_at'   => (string) ( $m['inherited_as_at'] ?? '' ),
			'inherited_summary' => array_map( 'intval', (array) ( $m['inherited_summary'] ?? array() ) ),
			'notes'             => array_values( array_map( 'strval', (array) ( $m['notes'] ?? array() ) ) ),
		);
	}

	/** @param array<string,mixed> $m */
	public static function set_meta( array $m ): void {
		$clean = array(
			'inherited_label'   => mb_substr( sanitize_text_field( (string) ( $m['inherited_label'] ?? '' ) ), 0, 190 ),
			'inherited_as_at'   => self::date( $m['inherited_as_at'] ?? '' ) ?? '',
			'inherited_summary' => array_map( 'absint', array_intersect_key( (array) ( $m['inherited_summary'] ?? array() ), self::outcomes() ) ),
			'notes'             => array_slice( array_map( static fn( $n ): string => mb_substr( sanitize_text_field( (string) $n ), 0, 400 ), (array) ( $m['notes'] ?? array() ) ), 0, 10 ),
		);
		update_option( self::META_OPTION, $clean, false );
	}

	/* =================================================================
	 * Helpers
	 * ============================================================== */

	/** @return array<int,string> */
	public static function split_keys( string $raw ): array {
		$out = array();

		foreach ( preg_split( '/[\s,;]+/', $raw ) ?: array() as $k ) {
			$k = self::norm_key( (string) $k );
			if ( '' !== $k ) {
				$out[ $k ] = $k;
			}
		}

		return array_values( $out );
	}

	public static function norm_key( string $k ): string {
		$k = strtoupper( trim( $k ) );

		return preg_match( '/^[A-Z][A-Z0-9_]{0,30}-\d{1,9}$/', $k ) ? $k : '';
	}

	public static function date( $v ): ?string {
		$v = trim( (string) $v );
		if ( '' === $v ) {
			return null;
		}
		$ts = strtotime( $v . ' 00:00:00 UTC' );

		return $ts ? gmdate( 'Y-m-d', $ts ) : null;
	}

	/**
	 * @param array<string,mixed> $d Unsanitised.
	 * @return array<string,mixed>
	 */
	private static function clean( array $d ): array {
		$txt  = static fn( string $k, int $max = 190 ): string => mb_substr( sanitize_text_field( (string) ( $d[ $k ] ?? '' ) ), 0, $max );
		$long = static fn( string $k ): string => mb_substr( sanitize_textarea_field( (string) ( $d[ $k ] ?? '' ) ), 0, 4000 );

		$kind    = (string) ( $d['kind'] ?? 'supplier' );
		$source  = (string) ( $d['source'] ?? 'internal' );
		$outcome = (string) ( $d['outcome'] ?? 'in_review' );

		return array(
			'kind'           => in_array( $kind, self::KINDS, true ) ? $kind : 'supplier',
			'subject'        => $txt( 'subject', 255 ),
			'source'         => in_array( $source, self::SOURCES, true ) ? $source : 'internal',
			'origin'         => $txt( 'origin' ),
			'raised_on'      => self::date( $d['raised_on'] ?? '' ),
			'period_text'    => $txt( 'period_text', 80 ),
			'requested_by'   => $txt( 'requested_by' ),
			'outcome'        => isset( self::outcomes()[ $outcome ] ) ? $outcome : 'in_review',
			'reviewer'       => $txt( 'reviewer' ),
			'reviewed_on'    => self::date( $d['reviewed_on'] ?? '' ),
			'review_summary' => $long( 'review_summary' ),
			'approver'       => $txt( 'approver' ),
			'decided_on'     => self::date( $d['decided_on'] ?? '' ),
			'conditions'     => $long( 'conditions' ),
			'review_due'     => self::date( $d['review_due'] ?? '' ),
			'ended_on'       => self::date( $d['ended_on'] ?? '' ),
			'jira_keys'      => mb_substr( implode( ', ', self::split_keys( is_array( $d['jira_keys'] ?? null ) ? implode( ',', (array) $d['jira_keys'] ) : (string) ( $d['jira_keys'] ?? '' ) ) ), 0, 255 ),
			'notes'          => $long( 'notes' ),
		);
	}

	/**
	 * @param array<string,mixed> $r Raw row.
	 * @return array<string,mixed>
	 */
	private static function shape( array $r ): array {
		$r['id']        = (int) $r['id'];
		$r['keys']      = self::split_keys( (string) $r['jira_keys'] );
		$r['group']     = self::group_of( (string) $r['outcome'] );
		$r['sort_date'] = (string) ( $r['decided_on'] ?: ( $r['reviewed_on'] ?: (string) $r['raised_on'] ) );

		return $r;
	}
}

