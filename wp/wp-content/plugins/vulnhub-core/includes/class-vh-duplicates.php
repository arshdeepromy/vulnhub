<?php
/**
 * One machine recorded twice — found, never merged automatically.
 *
 * A rebuilt or re-enrolled machine gets fresh identifiers from every system
 * that manages it: a new Intune enrolment, a new Defender onboarding, a new
 * Tenable agent, a new Entra device. Nothing ties the new objects to the old
 * ones except the serial burned into the chassis, and `match_asset()`
 * deliberately refuses to merge on a serial when the identifiers disagree.
 *
 * That refusal is right, and this estate is the proof: nine pairs of servers
 * share a VMware UUID because they are DR replicas of each other, carry
 * different CMDB CI numbers, sit at different sites and are both in service.
 * Folding those together on serial would destroy real inventory.
 *
 * So the same evidence has two opposite meanings, and only a human can tell
 * them apart. This class finds the pairs and says so; it never merges, and
 * nothing downstream treats a flagged row as less real.
 *
 * The one thing it can rule out on its own: two rows that each carry a
 * *different* CMDB CI number are two configuration items by the system of
 * record's own reckoning, whatever their serial says.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Duplicates {

	/**
	 * Re-examine the estate and flag the rows that look like one machine twice.
	 *
	 * The survivor of a group -- the row the others point at -- is the one a
	 * person should keep: most recently seen, preferring a row the CMDB knows,
	 * because that is the record the rest of the business is holding on to.
	 *
	 * @return array{groups:int,flagged:int,cleared:int}
	 */
	public static function scan(): array {
		global $wpdb;

		$a   = vh_table( 'assets' );
		$out = array( 'groups' => 0, 'flagged' => 0, 'cleared' => 0 );

		$serials = (array) $wpdb->get_col(
			"SELECT serial_number FROM {$a}
			 WHERE serial_number <> ''
			 GROUP BY serial_number HAVING COUNT(*) > 1" // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		);

		$keep = array();

		foreach ( $serials as $serial ) {
			// Placeholders like "Not Applicable" are words, not serials.
			if ( '' === vh_clean_serial( (string) $serial ) ) {
				continue;
			}

			$rows = (array) $wpdb->get_results(
				$wpdb->prepare(
					/*
					 * The agent connection decides, not the scan date.
					 *
					 * A scanner can go on reporting a record long after the
					 * machine behind it stopped existing -- the export still
					 * lists it, so `last_seen` keeps advancing and makes a
					 * dead record look the liveliest thing on the estate. An
					 * agent check-in is different: it only happens when the
					 * machine is powered on and talking. So when one chassis
					 * serial carries two records, the one whose agent spoke
					 * most recently is the machine; the other is what it used
					 * to be before it was rebuilt.
					 */
					"SELECT id, hostname, cmdb_id, cmdb_key, cmdb_last_scan, tenable_uuid, intune_id, defender_id,
						agent_status, agent_last_connect, last_seen
					 FROM {$a} WHERE serial_number = %s
					 ORDER BY ( lifecycle_status = 'retired' ) ASC,
						( agent_status = 'on' ) DESC,
						COALESCE(agent_last_connect, '1970-01-01') DESC,
						COALESCE(last_seen, '1970-01-01') DESC,
						id DESC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					(string) $serial
				),
				ARRAY_A
			);

			if ( count( $rows ) < 2 ) {
				continue;
			}

			/*
			 * Distinct CI numbers settle it: the system of record says these
			 * are two configuration items, so they are, and a shared serial
			 * means the hardware identifier was cloned rather than the record
			 * duplicated.
			 */
			$cis = array_values( array_unique( array_filter( array_map( static fn( array $r ): string => (string) $r['cmdb_id'], $rows ) ) ) );

			if ( count( $cis ) > 1 ) {
				continue;
			}

			/*
			 * Two agents connected at the same time cannot be one machine.
			 * Whatever the serial says, something is running in two places at
			 * once -- a clone, a restored image, a VM and its replica -- and
			 * merging would delete a host that is up right now. Flagged for a
			 * person, never merged.
			 */
			$online = array_filter( $rows, static fn( array $r ): bool => 'on' === (string) ( $r['agent_status'] ?? '' ) );

			if ( count( $online ) > 1 ) {
				continue;
			}

			++$out['groups'];

			$survivor = (int) $rows[0]['id'];

			foreach ( array_slice( $rows, 1 ) as $row ) {
				$keep[ (int) $row['id'] ] = $survivor;
			}
		}

		// Write the flags, and clear any that no longer apply.
		$current = (array) $wpdb->get_results( "SELECT id, duplicate_of FROM {$a} WHERE duplicate_of IS NOT NULL", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		foreach ( $current as $row ) {
			$id = (int) $row['id'];

			if ( ! isset( $keep[ $id ] ) ) {
				$wpdb->update( $a, array( 'duplicate_of' => null ), array( 'id' => $id ) );
				++$out['cleared'];
			}
		}

		foreach ( $keep as $id => $survivor ) {
			$wpdb->update( $a, array( 'duplicate_of' => $survivor ), array( 'id' => $id ) );
		}

		$out['flagged'] = count( $keep );

		update_option( 'vulnhub_duplicates_scanned_at', vh_now(), false );

		return $out;
	}

	/**
	 * The flagged rows with their survivors, for the screen.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function pairs( int $limit = 100 ): array {
		global $wpdb;

		$a = vh_table( 'assets' );

		return (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT d.id, d.hostname, d.serial_number, d.last_seen, d.sources_json,
					k.id AS keep_id, k.hostname AS keep_hostname, k.cmdb_key AS keep_cmdb_key,
					k.last_seen AS keep_last_seen, k.sources_json AS keep_sources_json
				 FROM {$a} d INNER JOIN {$a} k ON k.id = d.duplicate_of
				 ORDER BY d.hostname ASC LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				max( 1, min( 500, $limit ) )
			),
			ARRAY_A
		);
	}

	/**
	 * Fold one row into another. The CMDB record is the survivor.
	 *
	 * The rule this implements: a fresh CMDB import is the system of record,
	 * so the surviving asset keeps the CMDB's name and CMDB fields, and
	 * everything the scanners and management tools knew about the other row is
	 * merged onto it.
	 *
	 * **Findings do not simply change hands.** `vh_fingerprint()` folds the
	 * asset id in, so re-pointing a row would leave a fingerprint describing a
	 * machine it no longer belongs to -- and on this estate 174 of 186
	 * findings existed on *both* rows, every one of them a unique-key
	 * collision waiting to happen. So a finding the survivor already has is
	 * merged by value: the more recent sighting wins, and the loser's row is
	 * archived in place rather than moved. Only a finding the survivor has
	 * never seen actually moves, and its fingerprint is recomputed.
	 *
	 * Nothing is deleted. The losing row is retired and keeps pointing at its
	 * survivor, and every superseded finding keeps its `prev_state`, so the
	 * whole merge stays legible afterwards.
	 *
	 * @return array<string,mixed> What happened, or what would.
	 */
	public static function merge( int $loser_id, int $survivor_id, bool $dry_run = true ): array {
		return self::fold( $loser_id, $survivor_id, $dry_run );
	}

	/** True when this pair has already been folded in and needs nothing. */
	public static function already_merged( int $loser_id, int $survivor_id ): bool {
		global $wpdb;

		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT lifecycle_status, duplicate_of FROM ' . vh_table( 'assets' ) . ' WHERE id = %d',
				$loser_id
			),
			ARRAY_A
		);

		return $row && 'retired' === (string) $row['lifecycle_status'] && (int) $row['duplicate_of'] === $survivor_id;
	}

	private static function fold( int $loser_id, int $survivor_id, bool $dry_run = true ): array {
		global $wpdb;

		$a = vh_table( 'assets' );
		$f = vh_table( 'findings' );

		$out = array(
			'ok'             => false,
			'loser'          => $loser_id,
			'survivor'       => $survivor_id,
			'ids_copied'     => array(),
			'sources_added'  => array(),
			'findings_moved' => 0,
			'findings_newer' => 0,
			'findings_kept'  => 0,
			'dry_run'        => $dry_run,
		);

		if ( $loser_id === $survivor_id || $loser_id <= 0 || $survivor_id <= 0 ) {
			$out['error'] = 'A row cannot be merged into itself.';
			return $out;
		}

		$loser    = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$a} WHERE id = %d", $loser_id ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$survivor = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$a} WHERE id = %d", $survivor_id ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		if ( ! $loser || ! $survivor ) {
			$out['error'] = 'One of the assets no longer exists.';
			return $out;
		}

		/*
		 * The same guard the detector uses, restated at the point of no
		 * return: two different CI numbers means the system of record calls
		 * these two machines, and no serial may overrule that.
		 */
		if ( '' !== (string) $loser['cmdb_id'] && '' !== (string) $survivor['cmdb_id'] && $loser['cmdb_id'] !== $survivor['cmdb_id'] ) {
			$out['error'] = 'These rows carry different CMDB CI numbers, so the CMDB says they are two machines.';
			return $out;
		}

		if ( 'on' === (string) $loser['agent_status'] && 'on' === (string) $survivor['agent_status'] ) {
			$out['error'] = 'Both agents are connected right now, so these are two running machines, not one rebuilt one.';
			return $out;
		}

		/*
		 * The CMDB identity always moves to the survivor, even when that means
		 * taking it off the other row. It is the one thing that must follow
		 * the live machine: leave it behind and the next CMDB import matches
		 * the retired row by `cmdb_id` and the CI never reaches the record
		 * anyone is looking at.
		 *
		 * The *telemetry* identifiers deliberately stay where they are. The
		 * losing row's Intune, Defender and Tenable objects are the stale ones
		 * and they still exist upstream -- so leaving them on the retired row
		 * means those feeds keep matching it and keep it out of scope, instead
		 * of failing to match anything and minting a fresh duplicate every
		 * night. That is what makes the merge stick without anyone having to
		 * tidy up the source systems first.
		 */
		$fill = array();

		if ( '' !== (string) $loser['cmdb_id'] && '' === (string) $survivor['cmdb_id'] ) {
			$fill['cmdb_id']          = $loser['cmdb_id'];
			$fill['cmdb_key']         = $loser['cmdb_key'];
			$fill['cmdb_last_scan']   = $loser['cmdb_last_scan'];
			$out['ids_copied'][]      = 'cmdb_id';
		}

		foreach ( array(
			'azure_ad_device_id', 'azure_vm_id',
			'aws_instance_id', 'gcp_instance_id', 'cloud_provider', 'cloud_account_id', 'cloud_region',
			'ipv4', 'ipv6', 'mac_address', 'serial_number', 'fqdn', 'netbios_name',
			'manufacturer', 'model', 'operating_system', 'os_version',
			'agent_status', 'agent_last_connect', 'agent_status_since', 'tenable_last_scan', 'defender_last_seen',
		) as $col ) {
			$mine  = trim( (string) ( $survivor[ $col ] ?? '' ) );
			$theirs = trim( (string) ( $loser[ $col ] ?? '' ) );

			if ( '' === $mine && '' !== $theirs ) {
				$fill[ $col ]        = $loser[ $col ];
				$out['ids_copied'][] = $col;
			}
		}

		// 2. Sources: the union, keeping whichever saw it later.
		$mine   = (array) json_decode( (string) ( $survivor['sources_json'] ?? '' ), true );
		$theirs = (array) json_decode( (string) ( $loser['sources_json'] ?? '' ), true );

		foreach ( $theirs as $source => $when ) {
			if ( ! isset( $mine[ $source ] ) || (string) $when > (string) $mine[ $source ] ) {
				$mine[ $source ]        = $when;
				$out['sources_added'][] = (string) $source;
			}
		}

		$fill['sources_json'] = (string) wp_json_encode( $mine );

		// 3. Findings.
		self::move_findings( $loser_id, $survivor_id, $dry_run, $out );

		if ( $dry_run ) {
			$out['ok'] = true;
			return $out;
		}

		// 4. The online history belongs to the machine, not the record.
		$wpdb->update( vh_table( 'agent_status' ), array( 'asset_id' => $survivor_id ), array( 'asset_id' => $loser_id ) );

		$fill['updated_at'] = vh_now();
		$wpdb->update( $a, $fill, array( 'id' => $survivor_id ) );

		// 5. Retire the losing record, still pointing at where it went.
		$retire = array(
			'lifecycle_status' => 'retired',
			'duplicate_of'     => $survivor_id,
			'updated_at'       => vh_now(),
		);

		// Whatever moved to the survivor must not stay here as well.
		if ( isset( $fill['cmdb_id'] ) ) {
			$retire['cmdb_id']  = '';
			$retire['cmdb_key'] = '';
		}

		$wpdb->update( $a, $retire, array( 'id' => $loser_id ) );

		self::recount( $survivor_id );
		self::recount( $loser_id );

		vulnhub()->logger->audit(
			'asset.merge',
			sprintf( 'Merged %s into %s', (string) $loser['hostname'], (string) $survivor['hostname'] ),
			'asset',
			$survivor_id,
			array( 'loser' => $loser_id, 'findings_moved' => $out['findings_moved'], 'findings_superseded' => $out['findings_newer'] )
		);

		if ( class_exists( 'VulnHub_Dash_Widgets' ) ) {
			\VulnHub_Dash_Widgets::bust();
		}

		$out['ok'] = true;

		return $out;
	}

	/**
	 * Move one row's findings onto another: a finding the survivor lacks is
	 * re-keyed onto it; one both hold keeps whichever was seen later, and the
	 * loser's copy is archived, never deleted.
	 *
	 * Public for callers that fold records without copying identifiers onto
	 * the survivor -- a pooled fleet record must not take on one session's
	 * instance id (see Fleets).
	 *
	 * @param array<string,mixed> $out Counters: findings_moved, findings_newer, findings_kept.
	 */
	public static function move_findings( int $loser_id, int $survivor_id, bool $dry_run, array &$out ): void {
		global $wpdb;

		$f = vh_table( 'findings' );

		foreach ( array( 'findings_moved', 'findings_newer', 'findings_kept' ) as $k ) {
			$out[ $k ] = (int) ( $out[ $k ] ?? 0 );
		}

		$theirs_rows = (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$f} WHERE asset_id = %d", $loser_id ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		foreach ( $theirs_rows as $row ) {
			$twin = $wpdb->get_row(
				$wpdb->prepare(
					"SELECT id, last_found, state FROM {$f} WHERE asset_id = %d AND vuln_id = %d AND port = %d AND protocol = %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$survivor_id,
					(int) $row['vuln_id'],
					(int) $row['port'],
					(string) $row['protocol']
				),
				ARRAY_A
			);

			if ( ! $twin ) {
				++$out['findings_moved'];

				if ( ! $dry_run ) {
					$wpdb->update(
						$f,
						array(
							'asset_id'    => $survivor_id,
							'fingerprint' => vh_fingerprint( (string) $survivor_id, (string) (int) $row['vuln_id'], (string) (int) $row['port'], (string) $row['protocol'] ),
							'updated_at'  => vh_now(),
						),
						array( 'id' => (int) $row['id'] )
					);
				}

				continue;
			}

			$newer = (string) ( $row['last_found'] ?? '' ) > (string) ( $twin['last_found'] ?? '' );

			$newer ? $out['findings_newer']++ : $out['findings_kept']++;

			if ( $dry_run ) {
				continue;
			}

			if ( $newer ) {
				// The loser saw it more recently: its answer wins, in place.
				$wpdb->update(
					$f,
					array(
						'state'      => (string) $row['state'],
						'severity'   => (string) $row['severity'],
						'last_found' => $row['last_found'],
						'last_fixed' => $row['last_fixed'],
						'output'     => $row['output'],
						'prev_state' => (string) $twin['state'],
						'updated_at' => vh_now(),
					),
					array( 'id' => (int) $twin['id'] )
				);
			}

			// Superseded either way — archived, never deleted.
			$wpdb->update(
				$f,
				array( 'archived_at' => vh_now(), 'updated_at' => vh_now() ),
				array( 'id' => (int) $row['id'] )
			);
		}
	}

	/** Recompute one asset's open-finding rollups after a merge. */
	public static function recount( int $asset_id ): void {
		global $wpdb;

		$f = vh_table( 'findings' );

		$wpdb->query(
			$wpdb->prepare(
				'UPDATE ' . vh_table( 'assets' ) . " a SET
					a.open_critical = (SELECT COUNT(*) FROM {$f} WHERE asset_id = a.id AND archived_at IS NULL AND state IN ('open','reopened') AND severity = 'critical'),
					a.open_high     = (SELECT COUNT(*) FROM {$f} WHERE asset_id = a.id AND archived_at IS NULL AND state IN ('open','reopened') AND severity = 'high'),
					a.open_medium   = (SELECT COUNT(*) FROM {$f} WHERE asset_id = a.id AND archived_at IS NULL AND state IN ('open','reopened') AND severity = 'medium'),
					a.open_low      = (SELECT COUNT(*) FROM {$f} WHERE asset_id = a.id AND archived_at IS NULL AND state IN ('open','reopened') AND severity = 'low')
				 WHERE a.id = %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$asset_id
			)
		);
	}

	/**
	 * Find duplicates and fold in the ones that are safe to fold, unattended.
	 *
	 * Three conditions have to hold before anything is merged automatically,
	 * and each exists because of a case on this estate that would otherwise
	 * have been destroyed:
	 *
	 *  - **The CMDB vouches for it.** At least one row in the group carries a
	 *    CI number, and no two rows carry different ones. A shared serial with
	 *    no CI behind it could be anything -- a cloned image, a reused
	 *    chassis, a vendor that ships one serial across a batch -- so it is
	 *    flagged and left alone.
	 *  - **Not both agents connected.** Two agents checking in at the same
	 *    time is two running machines, whatever the chassis says.
	 *  - **The survivor is decided by the agent, not the scan.** A scanner
	 *    keeps listing a record long after the machine behind it is gone, so
	 *    `last_seen` makes a dead record look lively; an agent only checks in
	 *    when something is powered on.
	 *
	 * Anything that fails those stays flagged, visible, and untouched.
	 *
	 * @return array{groups:int,flagged:int,cleared:int,merged:int,held:int}
	 */
	public static function run(): array {
		$out = self::scan();

		$out['merged'] = 0;
		$out['held']   = 0;

		foreach ( self::pairs( 200 ) as $pair ) {
			// Already folded in on an earlier pass: nothing to do, and doing
			// it again would re-audit and re-bust the caches every night.
			if ( self::already_merged( (int) $pair['id'], (int) $pair['keep_id'] ) ) {
				continue;
			}

			$result = self::merge( (int) $pair['id'], (int) $pair['keep_id'], true );

			// A group the CMDB has not vouched for is never merged unattended.
			if ( ! empty( $result['error'] ) || '' === trim( (string) ( $pair['keep_cmdb_key'] ?? '' ) ) ) {
				++$out['held'];
				continue;
			}

			$done = self::merge( (int) $pair['id'], (int) $pair['keep_id'], false );

			empty( $done['error'] ) ? $out['merged']++ : $out['held']++;
		}

		return $out;
	}

	/** How many rows are currently flagged. */
	public static function count(): int {
		global $wpdb;

		return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . vh_table( 'assets' ) . ' WHERE duplicate_of IS NOT NULL' );
	}
}
