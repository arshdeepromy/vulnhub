<?php
/**
 * Tenable Agent coverage — a dimension of its own, kept apart from scan coverage.
 *
 * `Coverage` answers "does Tenable know this asset at all", which a network
 * scan satisfies. This class answers a different question: "is there a Tenable
 * Agent on it". They are not the same, and an estate that reports only the
 * first cannot tell an agent rollout from a scanner sweep.
 *
 * **Why not `assets.has_agent`.** That column means "has *an* agent": the
 * Defender and Intune importers both set it to true unconditionally, for their
 * own agents. 87 assets in this estate carry it while having no Tenable record
 * whatsoever. It is a useful flag and a useless answer to this question, so
 * agent state gets its own column that only Tenable evidence ever writes.
 *
 * **The evidence.** Tenable's asset record carries `sources[]`, and an agent
 * check-in appears there as `NESSUS_AGENT` (a network scan appears as
 * `NESSUS_SCAN`). That is authoritative and already synced into `raw_json` --
 * unlike `agent_uuid`, which comes back null on assets that demonstrably do
 * have an agent.
 *
 * **What to do about the ones without.** An agent cannot be installed on a
 * hypervisor appliance or an operating system older than the agent supports,
 * so "no agent" splits into work somebody can actually do and work nobody can.
 * The split comes from a curated, dated file -- see `support_table()`.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Agent_Coverage {

	/** Tenable reports an agent checking in. */
	public const AGENT = 'agent';

	/** No agent, and the operating system can run one. Real work. */
	public const REQUIRED = 'agent_required';

	/** No agent, and none exists for this platform, or the OS is too old. */
	public const NOT_POSSIBLE = 'agent_out_of_scope';

	/** No agent, and the operating system is not one the table recognises. */
	public const OS_UNKNOWN = 'agent_os_unknown';

	/** Outside the scanning scope entirely — retired, or not a machine. */
	public const OUT_OF_SCOPE = 'out_of_scope';

	/** How long before the curated table should be looked at again. */
	private const STALE_MONTHS = 6;

	/**
	 * Every state, worst first, with how to describe it.
	 *
	 * `gap` marks the states somebody is expected to close. "Agent out of
	 * scope" is deliberately not a gap: chasing a hypervisor for an agent that
	 * does not exist is the exact waste this dimension was added to stop.
	 *
	 * @return array<string,array{label:string,tone:string,gap:bool,help:string}>
	 */
	public static function states(): array {
		return array(
			self::REQUIRED     => array(
				'label' => __( 'Agent required', 'vulnhub' ),
				'tone'  => 'bad',
				'gap'   => true,
				'help'  => __( 'No Tenable Agent, and this operating system can run one.', 'vulnhub' ),
			),
			self::OS_UNKNOWN   => array(
				'label' => __( 'Agent — OS unknown', 'vulnhub' ),
				'tone'  => 'warn',
				'gap'   => true,
				'help'  => __( 'No Tenable Agent, and the operating system is not one the support table recognises. Somebody has to look.', 'vulnhub' ),
			),
			self::AGENT        => array(
				'label' => __( 'Agent installed', 'vulnhub' ),
				'tone'  => 'good',
				'gap'   => false,
				'help'  => __( 'Tenable reports an agent checking in from this asset.', 'vulnhub' ),
			),
			self::NOT_POSSIBLE => array(
				'label' => __( 'Agent out of scope', 'vulnhub' ),
				'tone'  => 'muted',
				'gap'   => false,
				'help'  => __( 'No Tenable Agent exists for this platform, or the operating system is below the agent’s minimum. Scan it another way.', 'vulnhub' ),
			),
			self::OUT_OF_SCOPE => array(
				'label' => __( 'Out of scope', 'vulnhub' ),
				'tone'  => 'muted',
				'gap'   => false,
				'help'  => __( 'Not in service, or not a machine an agent would go on.', 'vulnhub' ),
			),
		);
	}

	public static function label( string $state ): string {
		return (string) ( self::states()[ $state ]['label'] ?? $state );
	}

	public static function tone( string $state ): string {
		return (string) ( self::states()[ $state ]['tone'] ?? 'muted' );
	}

	/** States somebody is expected to close. */
	public static function gap_states(): array {
		return array_keys( array_filter( self::states(), static fn( array $s ): bool => $s['gap'] ) );
	}

	/* =================================================================
	 * The curated support table
	 * ============================================================== */

	/**
	 * Which operating systems can run a Tenable Agent.
	 *
	 * Read from the newest `data/agent-support-*.csv`. There is no Tenable API
	 * for this and their documentation is an HTML page with no contract, so it
	 * is curated by hand and carries the date it was checked: a docs redesign
	 * must never be able to silently reclassify an estate overnight.
	 *
	 * Rows are matched in file order, first match wins, so the specific rows
	 * ("red hat enterprise linux 6") sit above the general one.
	 *
	 * @return array{checked:string,rows:array<int,array<string,string>>}
	 */
	public static function support_table(): array {
		static $cache = null;

		if ( null !== $cache ) {
			return $cache;
		}

		$dir   = trailingslashit( VULNHUB_DIR ) . 'data/';
		$files = (array) glob( $dir . 'agent-support-*.csv' );

		rsort( $files );
		$file = $files[0] ?? '';

		$out = array( 'checked' => '', 'rows' => array() );

		if ( '' === $file || ! is_readable( $file ) ) {
			$cache = $out;
			return $cache;
		}

		if ( preg_match( '/agent-support-(\d{4}-\d{2}-\d{2})\.csv$/', $file, $m ) ) {
			$out['checked'] = $m[1];
		}

		$handle = fopen( $file, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( false === $handle ) {
			$cache = $out;
			return $cache;
		}

		$header = null;

		while ( false !== ( $row = fgetcsv( $handle, 0, ',', '"', '\\' ) ) ) {
			if ( ! is_array( $row ) || ! isset( $row[0] ) ) {
				continue;
			}
			// Comments carry the provenance; they are not data.
			if ( '' === trim( (string) $row[0] ) || str_starts_with( trim( (string) $row[0] ), '#' ) ) {
				continue;
			}
			if ( null === $header ) {
				$header = array_map( 'trim', $row );
				continue;
			}

			/*
			 * Tolerate a bad row, never fatal on one. This file is edited by
			 * hand, and an unquoted comma in a note is the obvious mistake --
			 * it makes the row wider than the header, which array_combine()
			 * turns into a fatal error on every page of the site. A curated
			 * table is worth having; taking the estate down when somebody
			 * mistypes it is not.
			 */
			$cells = array_map( 'trim', $row );

			if ( count( $cells ) > count( $header ) ) {
				// Everything past the last column belongs to the last column.
				$tail   = array_splice( $cells, count( $header ) - 1 );
				$cells[] = implode( ', ', $tail );
			}

			$out['rows'][] = array_combine( $header, array_pad( $cells, count( $header ), '' ) );
		}

		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		$cache = $out;

		return $cache;
	}

	/** True when the curated table is old enough to want re-checking. */
	public static function table_is_stale(): bool {
		$checked = self::support_table()['checked'];

		if ( '' === $checked ) {
			return true;
		}

		return strtotime( $checked ) < strtotime( '-' . self::STALE_MONTHS . ' months' );
	}

	/**
	 * Judge one operating system string against the table.
	 *
	 * @return array{state:string,family:string,note:string}
	 */
	public static function judge_os( string $operating_system ): array {
		$os = strtolower( trim( $operating_system ) );

		if ( '' === $os ) {
			return array( 'state' => self::OS_UNKNOWN, 'family' => '', 'note' => __( 'No operating system recorded.', 'vulnhub' ) );
		}

		foreach ( self::support_table()['rows'] as $row ) {
			$match = strtolower( (string) ( $row['match'] ?? '' ) );

			if ( '' === $match || ! str_contains( $os, $match ) ) {
				continue;
			}

			$family = (string) ( $row['family'] ?? '' );
			$note   = (string) ( $row['note'] ?? '' );

			if ( 'yes' !== strtolower( (string) ( $row['supported'] ?? '' ) ) ) {
				return array( 'state' => self::NOT_POSSIBLE, 'family' => $family, 'note' => $note );
			}

			/*
			 * The table already names the versions that are too old, row by
			 * row. This is the safety net for the ones nobody has written down
			 * yet: where a minimum is numeric and the OS string carries a
			 * number, compare them rather than assume the general row's "yes".
			 */
			$min = (string) ( $row['min_version'] ?? '' );

			if ( '' !== $min && is_numeric( $min ) && preg_match( '/(\d+(?:\.\d+)?)/', substr( $os, strpos( $os, $match ) + strlen( $match ) ), $v ) ) {
				if ( (float) $v[1] > 0 && (float) $v[1] < (float) $min ) {
					return array(
						'state'  => self::NOT_POSSIBLE,
						'family' => $family,
						'note'   => sprintf(
							/* translators: 1: family, 2: minimum version. */
							__( 'Below the agent’s minimum of %1$s %2$s.', 'vulnhub' ),
							$family,
							$min
						),
					);
				}
			}

			return array( 'state' => self::REQUIRED, 'family' => $family, 'note' => $note );
		}

		return array(
			'state'  => self::OS_UNKNOWN,
			'family' => '',
			'note'   => __( 'Not in the agent support table. Add a row for it, or check it by hand.', 'vulnhub' ),
		);
	}

	/* =================================================================
	 * Recalculation
	 * ============================================================== */

	/**
	 * Recompute `agent_coverage_state` for the whole estate.
	 *
	 * Two passes, for a reason. The agent test is a JSON search over
	 * `raw_json` that no index can help, so it runs once as a set update; the
	 * supportability test needs the curated table in PHP, so it runs per
	 * distinct operating system string -- of which there are a few hundred,
	 * not a few thousand -- and is applied by string, not by row.
	 */
	public static function recalculate(): void {
		global $wpdb;

		$a        = vh_table( 'assets' );
		$in_scope = vh_scannable_sql();
		$types    = vh_scannable_types_sql();

		/*
		 * Pass one: everything is either out of scope, or has an agent, or is
		 * parked as OS-unknown for pass two to judge.
		 *
		 * The evidence is Tenable's, tied to this asset's own Tenable identity:
		 * the agent list (`agent_status` on/off, `agent_last_connect`, written
		 * per Tenable uuid by the hourly agent reading), or a NESSUS_AGENT
		 * source inside a Tenable block whose id is this asset's uuid. A bare
		 * text search of raw_json was not enough: a record with no Tenable
		 * identity carried a copy of another machine's block and read "Agent
		 * installed" beside "Not in Tenable", while machines whose Tenable
		 * block had been overwritten read "Agent required" with a live agent.
		 * LOCATE, never LIKE '%…%': a literal % is a wpdb::prepare() placeholder.
		 */
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$a} a SET a.agent_coverage_state = CASE
					WHEN a.lifecycle_status NOT IN ({$in_scope}) THEN %s
					WHEN a.asset_type NOT IN ({$types}) THEN %s
					WHEN COALESCE(a.tenable_uuid, '') <> '' AND (
						a.agent_status IN ('on', 'off')
						OR a.agent_last_connect IS NOT NULL
						OR ( LOCATE('NESSUS_AGENT', COALESCE(a.raw_json, '')) > 0 AND JSON_VALUE(a.raw_json, '\$.tenable.id') = a.tenable_uuid )
					) THEN %s
					ELSE %s
				END", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				self::OUT_OF_SCOPE,
				self::OUT_OF_SCOPE,
				self::AGENT,
				self::OS_UNKNOWN
			)
		);

		// Pass two: only the ones still parked, and only one update per
		// distinct operating system string.
		$systems = (array) $wpdb->get_col(
			$wpdb->prepare(
				"SELECT DISTINCT operating_system FROM {$a} WHERE agent_coverage_state = %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				self::OS_UNKNOWN
			)
		);

		foreach ( $systems as $os ) {
			$verdict = self::judge_os( (string) $os );

			if ( self::OS_UNKNOWN === $verdict['state'] ) {
				continue;
			}

			$wpdb->query(
				$wpdb->prepare(
					"UPDATE {$a} SET agent_coverage_state = %s WHERE agent_coverage_state = %s AND operating_system = %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$verdict['state'],
					self::OS_UNKNOWN,
					(string) $os
				)
			);
		}

		/** Fires once agent coverage has been recomputed for the whole estate. */
		do_action( 'vulnhub_agent_coverage_recalculated' );
	}

	/**
	 * Counts per state, across the scannable estate.
	 *
	 * @return array<string,int> Every key of states(), plus `total` and `gap`.
	 */
	public static function summary(): array {
		global $wpdb;

		$out = array_fill_keys( array_keys( self::states() ), 0 );

		$rows = (array) $wpdb->get_results(
			'SELECT agent_coverage_state AS state, COUNT(*) AS n FROM ' . vh_table( 'assets' ) . ' GROUP BY agent_coverage_state',
			ARRAY_A
		);

		foreach ( $rows as $row ) {
			$state = (string) $row['state'];

			if ( isset( $out[ $state ] ) ) {
				$out[ $state ] = (int) $row['n'];
			}
		}

		$gaps = self::gap_states();

		$out['gap']   = array_sum( array_intersect_key( $out, array_flip( $gaps ) ) );
		$out['total'] = $out['gap'] + $out[ self::AGENT ];

		return $out;
	}
}
