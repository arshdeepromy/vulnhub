<?php
/**
 * Poll a feed, store what came back, and work out who it touches.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Alerts_Runner {

	/**
	 * Poll one feed.
	 *
	 * @param int  $feed_id Feed row id.
	 * @param bool $dry_run Parse and match, but write nothing. Used by the
	 *                      "test" button when somebody adds a feed.
	 * @return array<string,mixed> Result summary for the UI and the log.
	 */
	public static function run_feed( int $feed_id, bool $dry_run = false ): array {
		global $wpdb;

		$feeds = $wpdb->prefix . 'vulnhub_alert_feeds';
		$feed  = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$feeds} WHERE id = %d", $feed_id ), ARRAY_A );

		if ( ! $feed ) {
			return self::fail( __( 'No such feed.', 'vulnhub' ) );
		}

		$class = VulnHub_Alerts_Registry::adapter_class( (string) $feed['adapter'] );

		if ( '' === $class || ! class_exists( $class ) ) {
			$result = self::fail(
				sprintf(
					/* translators: %s: adapter name */
					__( 'No adapter called "%s" is installed.', 'vulnhub' ),
					(string) $feed['adapter']
				)
			);

			if ( ! $dry_run ) {
				self::record( $feed_id, $result, array() );
			}

			return $result;
		}

		$started = microtime( true );

		try {
			/** @var VulnHub_Alerts_Adapter $adapter */
			$adapter = new $class( $feed );
			$rows    = $adapter->fetch();
			$notes   = $adapter->notes();
		} catch ( Throwable $e ) {
			$result = self::fail( $e->getMessage() );

			if ( ! $dry_run ) {
				self::record( $feed_id, $result, array() );
			}

			return $result;
		}

		$stats = array(
			'ok'       => true,
			'fetched'  => count( $rows ),
			'new'      => 0,
			'updated'  => 0,
			'matched'  => 0,
			'matches'  => 0,
			'notes'    => $notes,
			'error'    => '',
			'seconds'  => round( microtime( true ) - $started, 1 ),
			'samples'  => array(),
		);

		foreach ( $rows as $row ) {
			$matches = VulnHub_Alerts_Matcher::match( $row );

			if ( $matches ) {
				++$stats['matched'];
				$stats['matches'] += count( $matches );
			}

			if ( $dry_run ) {
				if ( count( $stats['samples'] ) < 8 ) {
					$stats['samples'][] = array(
						'title'      => (string) $row['title'],
						'severity'   => (string) $row['severity'],
						'cves'       => (array) $row['cves'],
						'products'   => array_column( (array) $row['products'], 'product' ),
						'matches'    => count( $matches ),
						'confidence' => $matches ? (string) $matches[0]['confidence'] : '',
					);
				}
				continue;
			}

			$written = self::store( (int) $feed['id'], (string) $feed['slug'], $row, $matches );

			if ( 'new' === $written ) {
				++$stats['new'];
			} elseif ( 'updated' === $written ) {
				++$stats['updated'];
			}
		}

		if ( ! $dry_run ) {
			self::record( $feed_id, $stats, $rows );
		}

		return $stats;
	}

	/** @return array<string,mixed> */
	private static function fail( string $message ): array {
		return array(
			'ok'      => false,
			'fetched' => 0,
			'new'     => 0,
			'updated' => 0,
			'matched' => 0,
			'matches' => 0,
			'notes'   => array(),
			'error'   => $message,
			'seconds' => 0,
			'samples' => array(),
		);
	}

	/**
	 * Insert or refresh one advisory and rewrite its matches.
	 *
	 * @return string 'new', 'updated' or 'unchanged'.
	 */
	private static function store( int $feed_id, string $source, array $row, array $matches ): string {
		global $wpdb;

		$alerts = $wpdb->prefix . 'vulnhub_alerts';
		$now    = current_time( 'mysql', true );

		// Identity is source plus the publisher's own id. Two feeds carrying
		// the same CVE stay two rows on purpose: they are two advisories, and
		// collapsing them would lose whichever one a person was reading.
		$fingerprint = hash( 'sha256', $source . '|' . (string) $row['external_id'] );

		$best  = $matches ? (string) $matches[0]['confidence'] : '';
		$asset = count( array_unique( array_column( $matches, 'asset_id' ) ) );

		$data = array(
			'feed_id'         => $feed_id,
			'source'          => $source,
			'external_id'     => vh_trim( (string) $row['external_id'], 190 ),
			'fingerprint'     => $fingerprint,
			'title'           => (string) $row['title'],
			'summary'         => (string) $row['summary'],
			'url'             => (string) $row['url'],
			'severity'        => (string) $row['severity'],
			'cvss'            => (float) $row['cvss'],
			'epss'            => (float) $row['epss'],
			'kev'             => (int) $row['kev'],
			'cve_json'        => wp_json_encode( array_values( (array) $row['cves'] ) ),
			'products_json'   => wp_json_encode( array_values( (array) $row['products'] ) ),
			'raw_json'        => wp_json_encode( $row['raw'] ),
			'published_at'    => $row['published_at'],
			'updated_at'      => $row['updated_at'],
			'last_seen'       => $now,
			'matched'         => $matches ? 1 : 0,
			'best_confidence' => $best,
			'match_count'     => count( $matches ),
			'asset_count'     => $asset,
		);

		$existing = $wpdb->get_row(
			$wpdb->prepare( "SELECT id, state FROM {$alerts} WHERE fingerprint = %s", $fingerprint ),
			ARRAY_A
		);

		if ( $existing ) {
			// Triage state is the operator's, not the feed's. A re-poll
			// refreshes the facts and leaves the decision alone.
			$wpdb->update( $alerts, $data, array( 'id' => (int) $existing['id'] ) );
			$alert_id = (int) $existing['id'];
			$verdict  = 'updated';
		} else {
			$data['first_seen'] = $now;
			$data['state']      = 'new';
			$wpdb->insert( $alerts, $data );
			$alert_id = (int) $wpdb->insert_id;
			$verdict  = 'new';
		}

		if ( $alert_id ) {
			self::write_matches( $alert_id, $matches );
		}

		return $verdict;
	}

	/**
	 * How many asset rows one advisory may store.
	 *
	 * An advisory affecting Windows 11 legitimately touches several hundred
	 * machines, and writing every one cost 388,000 rows across the first full
	 * poll for no benefit: nobody reads past the first screen, and the true
	 * figure is kept on the alert itself. What is stored is a sample, ordered
	 * so the most certain matches survive the cut.
	 */
	private const MAX_MATCH_ROWS = 100;

	private static function write_matches( int $alert_id, array $matches ): void {
		global $wpdb;

		$table = $wpdb->prefix . 'vulnhub_alert_matches';
		$now   = current_time( 'mysql', true );

		// Matches are derived, so they are rebuilt rather than merged: the
		// estate changes, and yesterday's match against a machine that has
		// since been rebuilt should disappear rather than linger.
		$wpdb->delete( $table, array( 'alert_id' => $alert_id ), array( '%d' ) );

		$seen    = array();
		$written = 0;

		foreach ( $matches as $m ) {
			$key = $m['asset_id'] . '|' . $m['product'];

			if ( isset( $seen[ $key ] ) ) {
				continue;
			}
			$seen[ $key ] = true;

			if ( $written >= self::MAX_MATCH_ROWS ) {
				break;
			}

			++$written;

			$wpdb->insert(
				$table,
				array(
					'alert_id'          => $alert_id,
					'asset_id'          => (int) $m['asset_id'],
					'confidence'        => (string) $m['confidence'],
					'matched_on'        => (string) $m['matched_on'],
					'vendor'            => vh_trim( (string) $m['vendor'], 190 ),
					'product'           => vh_trim( (string) $m['product'], 190 ),
					'installed_version' => vh_trim( (string) $m['installed_version'], 90 ),
					'affected_range'    => vh_trim( (string) $m['affected_range'], 190 ),
					'evidence'          => (string) $m['evidence'],
					'created_at'        => $now,
				)
			);
		}
	}

	private static function record( int $feed_id, array $stats, array $rows ): void {
		global $wpdb;

		$table = $wpdb->prefix . 'vulnhub_alert_feeds';
		$now   = current_time( 'mysql', true );

		$update = array(
			'last_run_at' => $now,
			'last_status' => $stats['ok'] ? 'ok' : 'error',
			'last_error'  => (string) $stats['error'],
			'last_count'  => (int) $stats['fetched'],
			'updated_at'  => $now,
		);

		if ( $stats['ok'] ) {
			$update['last_ok_at'] = $now;
			$wpdb->query(
				$wpdb->prepare(
					"UPDATE {$table} SET total_seen = total_seen + %d WHERE id = %d",
					(int) $stats['fetched'],
					$feed_id
				)
			);

			// Carry the conditional-request headers forward so the next poll
			// can be answered with a 304.
			if ( isset( $rows['__etag'] ) ) {
				$update['http_etag'] = (string) $rows['__etag'];
			}
		}

		$wpdb->update( $table, $update, array( 'id' => $feed_id ) );
	}

	/**
	 * Poll every feed that is enabled and due.
	 *
	 * @return array<string,mixed>
	 */
	public static function run_due(): array {
		global $wpdb;

		$table = $wpdb->prefix . 'vulnhub_alert_feeds';

		$due = $wpdb->get_results(
			"SELECT id, slug, interval_minutes, last_run_at
			   FROM {$table}
			  WHERE enabled = 1
			  ORDER BY last_run_at IS NULL DESC, last_run_at ASC",
			ARRAY_A
		);

		$ran = array();

		foreach ( (array) $due as $feed ) {
			$last = (string) ( $feed['last_run_at'] ?? '' );
			$mins = max( 15, (int) $feed['interval_minutes'] );

			if ( $last && strtotime( $last . ' UTC' ) > time() - ( $mins * MINUTE_IN_SECONDS ) ) {
				continue;
			}

			$ran[ (string) $feed['slug'] ] = self::run_feed( (int) $feed['id'] );
		}

		if ( $ran ) {
			do_action( 'vulnhub_alerts_polled', $ran );
		}

		return $ran;
	}
}
