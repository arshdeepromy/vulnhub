<?php
/**
 * Agent online history — the part Tenable does not keep.
 *
 * `GET /scanners/{id}/agents` says whether an agent is connected *now*, and
 * when it last checked in. That is all: there is no uptime series anywhere in
 * the API, so "which hours was this machine up" cannot be asked of Tenable at
 * all. It can only be accumulated, by sampling that endpoint and writing down
 * what changed.
 *
 * **Transitions, not samples.** A row per poll over ~900 agents would be
 * ~22,000 rows a day and would answer the same questions no better: the state
 * between two identical readings is not in doubt. A row is written only when
 * an agent flips on<->off, which on a real estate is a few hundred rows a
 * week and makes "offline since" a single indexed lookup.
 *
 * **What this is not.** It says the *agent* was connected, which is a good
 * proxy for the machine being up and not the same claim -- a stopped agent
 * service on a running server reads as offline, correctly for scanning
 * purposes and misleadingly for anything else. Resolution is the poll
 * interval, and history starts the day it is switched on: there is nothing to
 * backfill from, because Tenable never had it.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Agent_Status {

	public const ON  = 'on';
	public const OFF = 'off';

	/** Agents per API page. */
	private const PAGE = 500;

	/**
	 * Record one reading of the estate's agents.
	 *
	 * @param array<int,array<string,mixed>> $agents Records from the Tenable agents endpoint.
	 * @return array{seen:int,matched:int,changed:int,first:int}
	 */
	public static function record( array $agents ): array {
		global $wpdb;

		$out = array( 'seen' => 0, 'matched' => 0, 'changed' => 0, 'first' => 0 );

		if ( ! $agents ) {
			return $out;
		}

		$assets = vh_table( 'assets' );
		$hist   = vh_table( 'agent_status' );
		$now    = vh_now();

		/*
		 * Resolve Tenable's asset uuid to ours in one query rather than one
		 * per agent: 900 agents is 900 round trips otherwise, and this runs
		 * on a schedule.
		 */
		$uuids = array();

		foreach ( $agents as $agent ) {
			$uuid = strtolower( trim( (string) ( $agent['asset_uuid'] ?? '' ) ) );

			if ( '' !== $uuid ) {
				$uuids[ $uuid ] = true;
			}
		}

		$out['seen'] = count( $agents );

		if ( ! $uuids ) {
			return $out;
		}

		$keys  = array_keys( $uuids );
		$holes = implode( ', ', array_fill( 0, count( $keys ), '%s' ) );

		$rows = (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, LOWER(tenable_uuid) AS uuid, agent_status, agent_status_since
				 FROM {$assets} WHERE LOWER(tenable_uuid) IN ({$holes})", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				...$keys
			),
			ARRAY_A
		);

		$known = array();

		foreach ( $rows as $row ) {
			$known[ (string) $row['uuid'] ] = $row;
		}

		foreach ( $agents as $agent ) {
			$uuid = strtolower( trim( (string) ( $agent['asset_uuid'] ?? '' ) ) );
			$row  = $known[ $uuid ] ?? null;

			if ( ! $row ) {
				continue;
			}

			++$out['matched'];

			$asset_id = (int) $row['id'];
			$was      = (string) ( $row['agent_status'] ?? '' );
			$is       = self::ON === strtolower( (string) ( $agent['status'] ?? '' ) ) ? self::ON : self::OFF;

			// Tenable sends unix seconds; storage is UTC, always.
			$connect = (int) ( $agent['last_connect'] ?? 0 );
			$connect = $connect > 0 ? gmdate( 'Y-m-d H:i:s', $connect ) : null;

			$update = array(
				'agent_status'       => $is,
				'agent_last_connect' => $connect,
				'updated_at'         => $now,
			);

			if ( $was === $is ) {
				// Same as last time: update the check-in, leave the clock alone.
				$wpdb->update( $assets, $update, array( 'id' => $asset_id ) );
				continue;
			}

			/*
			 * A change. The first reading of an asset is a change from ''
			 * and is recorded too -- without it the timeline would have no
			 * opening state and "offline since" would have nothing to date
			 * from -- but it is counted apart so a first run does not read as
			 * 900 machines having just gone down.
			 */
			'' === $was ? $out['first']++ : $out['changed']++;

			$update['agent_status_since'] = $now;

			$wpdb->update( $assets, $update, array( 'id' => $asset_id ) );

			$wpdb->insert(
				$hist,
				array(
					'asset_id'     => $asset_id,
					'status'       => $is,
					'changed_at'   => $now,
					'last_connect' => $connect,
				)
			);
		}

		return $out;
	}

	/**
	 * Read every agent from Tenable and record the reading.
	 *
	 * @return array{seen:int,matched:int,changed:int,first:int,total:int}
	 */
	public static function poll( \VulnHub_Tenable_Connector $connector ): array {
		$totals = array( 'seen' => 0, 'matched' => 0, 'changed' => 0, 'first' => 0, 'total' => 0 );

		if ( ! $connector->is_enabled() ) {
			return $totals;
		}

		$offset = 0;

		do {
			$page = $connector->client()->agents( $offset, self::PAGE );
			$rows = (array) $page['agents'];

			if ( ! $rows ) {
				break;
			}

			$totals['total'] = (int) $page['total'];

			foreach ( self::record( $rows ) as $key => $n ) {
				$totals[ $key ] += (int) $n;
			}

			$offset += count( $rows );
			/*
			 * Stop on the total Tenable reported, and also when a page comes
			 * back short: a paging loop that trusts only the total will spin
			 * for ever if the total is wrong, and one that imports a partial
			 * set silently looks exactly like an estate that lost machines.
			 */
		} while ( count( $rows ) >= self::PAGE && $offset < $totals['total'] );

		update_option( 'vulnhub_agent_status_polled_at', vh_now(), false );

		/** Fires after every agent-status reading. */
		do_action( 'vulnhub_agent_status_polled', $totals );

		return $totals;
	}

	/** When the last reading was taken, or ''. */
	public static function last_polled(): string {
		return (string) get_option( 'vulnhub_agent_status_polled_at', '' );
	}

	/**
	 * The recorded up/down history for one asset, newest first.
	 *
	 * @return array<int,array{status:string,changed_at:string,last_connect:?string}>
	 */
	public static function history( int $asset_id, int $limit = 50 ): array {
		global $wpdb;

		return (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT status, changed_at, last_connect FROM ' . vh_table( 'agent_status' ) . '
				 WHERE asset_id = %d ORDER BY changed_at DESC LIMIT %d',
				$asset_id,
				max( 1, min( 500, $limit ) )
			),
			ARRAY_A
		);
	}
}
