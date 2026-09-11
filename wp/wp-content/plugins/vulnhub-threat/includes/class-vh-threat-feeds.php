<?php
/**
 * The three public feeds this plugin reads, and the job that reads them.
 *
 * NVD  — the CVSS vector, which is where "how would somebody reach this"
 *        actually lives: AV tells you whether it is over a network, PR
 *        whether they need an account first, UI whether a person has to open
 *        something. Also the reference tags, because NVD marks a reference
 *        "Exploit" when it points at working code.
 * KEV  — CISA's list of what is being exploited in the wild right now.
 * EPSS — FIRST's daily model of how likely each CVE is to be exploited in the
 *        next 30 days. It is re-scored every day, which is what lets the
 *        widget say "today" and mean it.
 *
 * All three are free and unauthenticated. None of them is asked about the
 * estate: the only thing that leaves this box is a request for a public file,
 * so no asset, hostname or finding is disclosed to run this.
 *
 * @package VulnHub\Threat
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Downloads and ingests the CVE feeds.
 */
final class VulnHub_Threat_Feeds {

	public const CRON_HOOK  = 'vulnhub_threat_refresh';
	public const OPT_STATUS = 'vulnhub_threat_status';
	public const OPT_META   = 'vulnhub_threat_feed_meta';

	private const KEV_URL  = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
	private const EPSS_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';
	private const NVD_YEAR = 'https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-%d.json.%s';
	private const NVD_API  = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

	/** How many CVE rows to write per statement. */
	private const BATCH = 400;

	public static function init(): void {
		add_action( self::CRON_HOOK, array( __CLASS__, 'run_scheduled' ) );

		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			self::schedule();
		}
	}

	public static function schedule(): void {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			// Just after 03:00 local, so a refresh has landed before anybody
			// looks at the board in the morning. EPSS republishes daily at
			// roughly 00:00 UTC.
			wp_schedule_event( time() + 300, 'daily', self::CRON_HOOK );
		}
	}

	public static function unschedule(): void {
		$ts = wp_next_scheduled( self::CRON_HOOK );

		while ( $ts ) {
			wp_unschedule_event( $ts, self::CRON_HOOK );
			$ts = wp_next_scheduled( self::CRON_HOOK );
		}
	}

	/** Fired by cron. Kept separate so the CLI command can pass `--force`. */
	public static function run_scheduled(): void {
		self::refresh_all( false );
	}

	/**
	 * What the admin screen and `wp vulnhub threat status` report.
	 *
	 * @return array<string,mixed>
	 */
	public static function status(): array {
		global $wpdb;

		$intel  = VulnHub_Threat_Install::table( 'cve_intel' );
		$paths  = VulnHub_Threat_Install::table( 'vuln_paths' );
		$stored = get_option( self::OPT_STATUS, array() );
		$stored = is_array( $stored ) ? $stored : array();

		return array_merge(
			array(
				'last_run'    => '',
				'last_error'  => '',
				'duration'    => 0,
				'nvd_source'  => '',
			),
			$stored,
			array(
				'cves_known'    => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$intel}" ), // phpcs:ignore
				'cves_vectored' => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$intel} WHERE attack_vector <> ''" ), // phpcs:ignore
				'cves_kev'      => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$intel} WHERE kev = 1" ), // phpcs:ignore
				'cves_poc'      => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$intel} WHERE has_poc = 1" ), // phpcs:ignore
				'vulns_placed'  => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$paths}" ), // phpcs:ignore
				'next_run'      => (int) wp_next_scheduled( self::CRON_HOOK ),
			)
		);
	}

	/**
	 * Fetch everything and re-place every vulnerability definition.
	 *
	 * @param bool $force Ignore the stored feed timestamps and re-download.
	 * @return string[] Log lines.
	 */
	public static function refresh_all( bool $force = false ): array {
		@set_time_limit( 0 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		wp_raise_memory_limit( 'admin' );

		$started = microtime( true );
		$log     = array();
		$error   = '';

		try {
			$wanted = VulnHub_Threat_Classify::wanted_cves();
			$log[]  = sprintf( '%d distinct CVE ids referenced by %d vulnerability definitions.', count( $wanted ), VulnHub_Threat_Classify::definition_count() );

			if ( $wanted ) {
				$source = self::fetch_nvd( $wanted, $force, $log );
				self::fetch_kev( $wanted, $log );
				self::fetch_epss( $wanted, $log );
				self::derive_cve_columns( $log );

				$placed = VulnHub_Threat_Classify::rebuild_all();
				$log[]  = sprintf( '%d vulnerability definitions placed on a route.', $placed );

				$exposed = VulnHub_Threat_Classify::rebuild_exposure();
				$log[]   = sprintf( '%d assets treated as reachable from the internet.', $exposed );
			} else {
				$source = '';
				$log[]  = 'No CVE ids found in any vulnerability title or description — nothing to enrich.';
			}
		} catch ( Throwable $e ) {
			$error = $e->getMessage();
			$log[] = 'FAILED: ' . $error;
			$source = '';
		}

		update_option(
			self::OPT_STATUS,
			array(
				'last_run'   => gmdate( 'Y-m-d H:i:s' ),
				'last_error' => $error,
				'duration'   => round( microtime( true ) - $started, 1 ),
				'nvd_source' => $source,
				'log'        => array_slice( $log, -40 ),
			),
			false
		);

		if ( class_exists( 'VulnHub_Dash_Widgets' ) ) {
			VulnHub_Dash_Widgets::bust();
		}

		return $log;
	}

	/* =================================================================
	 * NVD
	 * ============================================================== */

	/**
	 * Fill in the CVSS vector and reference tags for every wanted CVE.
	 *
	 * Preferred route is the year files: 26 downloads totalling about 100 MB
	 * compressed, against roughly 1.5 GB if the same 13,000 vectors are paged
	 * out of the NVD API. The API is kept as the fallback for the case where
	 * this is running somewhere without a decompressor, and for the handful of
	 * ids the year files do not contain.
	 *
	 * @param array<string,int> $wanted CVE id => 1.
	 * @param bool              $force  Re-download regardless of timestamps.
	 * @param string[]          $log    Log lines, by reference.
	 * @return string Which route was used.
	 */
	private static function fetch_nvd( array $wanted, bool $force, array &$log ): string {
		$years = array();

		foreach ( array_keys( $wanted ) as $cve ) {
			$years[ (int) substr( $cve, 4, 4 ) ] = true;
		}

		$years = array_keys( $years );
		sort( $years );

		if ( ! self::can_decompress() ) {
			$log[] = 'No xz decompressor available; falling back to the NVD API.';
			self::fetch_nvd_api( self::missing_vectors( $wanted ), $log );

			return 'api';
		}

		$meta  = get_option( self::OPT_META, array() );
		$meta  = is_array( $meta ) ? $meta : array();
		$total = 0;

		foreach ( $years as $year ) {
			$stamp = self::head_meta( $year );
			$key   = 'nvd-' . $year;

			if ( ! $force && '' !== $stamp && ( $meta[ $key ] ?? '' ) === $stamp && ! self::year_has_gaps( $wanted, $year ) ) {
				continue;
			}

			$file = self::download( sprintf( self::NVD_YEAR, $year, 'xz' ) );

			if ( '' === $file ) {
				$log[] = sprintf( 'CVE-%d: download failed, skipped.', $year );
				continue;
			}

			$n = self::ingest_year_file( $file, $wanted );
			wp_delete_file( $file );

			if ( 0 === $n ) {
				// The parser reads the feed's pretty-printed layout. Zero rows
				// from a file that downloaded fine means that layout changed,
				// which is a silent-wrong-answer bug rather than a missing
				// year -- so say so and let the API fill the year in.
				$log[] = sprintf( 'CVE-%d: parsed 0 records from a file that downloaded. Falling back to the API for this year.', $year );
				continue;
			}

			$meta[ $key ] = $stamp;
			$total       += $n;
			$log[]        = sprintf( 'CVE-%d: %d records ingested.', $year, $n );
		}

		update_option( self::OPT_META, $meta, false );

		$missing = self::missing_vectors( $wanted );

		if ( $missing ) {
			$log[] = sprintf( '%d CVE ids still without a vector; asking the NVD API.', count( $missing ) );
			self::fetch_nvd_api( $missing, $log );
		}

		$log[] = sprintf( '%d CVE records ingested from the year files.', $total );

		return 'year-files';
	}

	/** True when we can shell out to xz. */
	private static function can_decompress(): bool {
		if ( ! function_exists( 'popen' ) || ! function_exists( 'escapeshellarg' ) ) {
			return false;
		}

		$disabled = array_map( 'trim', explode( ',', (string) ini_get( 'disable_functions' ) ) );

		if ( in_array( 'popen', $disabled, true ) ) {
			return false;
		}

		$probe = @popen( 'command -v xz 2>/dev/null', 'r' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		if ( ! is_resource( $probe ) ) {
			return false;
		}

		$path = trim( (string) fread( $probe, 256 ) );
		pclose( $probe );

		return '' !== $path;
	}

	/** The feed's own last-modified stamp for a year, or '' if unreachable. */
	private static function head_meta( int $year ): string {
		$res = wp_remote_get(
			sprintf( self::NVD_YEAR, $year, 'meta' ),
			array(
				'timeout'     => 30,
				'redirection' => 5,
			)
		);

		if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
			return '';
		}

		return trim( (string) wp_remote_retrieve_body( $res ) );
	}

	/**
	 * Are any of this year's wanted ids missing from the table entirely?
	 *
	 * Deliberately "missing a row", not "missing a vector". Around 1,100 of
	 * the CVEs this estate references have no CVSS v3 vector and never will --
	 * they are v2-only or unscored. Testing for a vector would report those as
	 * a gap for ever, and every nightly run would re-download all 26 year
	 * files chasing something that does not exist.
	 */
	private static function year_has_gaps( array $wanted, int $year ): bool {
		global $wpdb;

		$intel  = VulnHub_Threat_Install::table( 'cve_intel' );
		$prefix = $wpdb->esc_like( 'CVE-' . $year . '-' ) . '%';

		$have = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$intel} WHERE cve_id LIKE %s", $prefix ) ); // phpcs:ignore

		$want = 0;

		foreach ( array_keys( $wanted ) as $cve ) {
			if ( (int) substr( $cve, 4, 4 ) === $year ) {
				++$want;
			}
		}

		return $have < $want;
	}

	/**
	 * Stream one year file, keeping only the CVEs the estate mentions.
	 *
	 * The feed is pretty-printed with two-space indents, so a CVE object opens
	 * on a line that is exactly four spaces and a brace and closes the same
	 * way. That makes a line reader enough, and a line reader is the only thing
	 * that fits: the 2026 file is 364 MB decompressed and json_decode of the
	 * whole thing needs several times that in memory.
	 *
	 * The id is on the object's first line, so an unwanted CVE is discarded
	 * without ever being decoded -- roughly 300,000 of them per full pass.
	 *
	 * @param array<string,int> $wanted CVE id => 1.
	 * @return int Rows written.
	 */
	private static function ingest_year_file( string $path, array $wanted ): int {
		$fh = @popen( 'xz -dc ' . escapeshellarg( $path ), 'r' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		if ( ! is_resource( $fh ) ) {
			return 0;
		}

		$rows    = array();
		$written = 0;
		$buf     = null;
		$keep    = false;

		while ( false !== ( $line = fgets( $fh ) ) ) {
			$trim = rtrim( $line, "\r\n" );

			if ( null === $buf ) {
				if ( '    {' === $trim ) {
					$buf  = "{\n";
					$keep = false;
				}
				continue;
			}

			if ( '    }' === $trim || '    },' === $trim ) {
				if ( $keep ) {
					$row = self::row_from_nvd( json_decode( $buf . '}', true ) );

					if ( $row ) {
						$rows[] = $row;
					}

					if ( count( $rows ) >= self::BATCH ) {
						$written += self::write_intel( $rows );
						$rows     = array();
					}
				}

				$buf  = null;
				$keep = false;
				continue;
			}

			if ( ! $keep ) {
				// The id line, if this is it. Anything else before the id is
				// cheap to hold; anything after it on an unwanted record is
				// dropped on the floor.
				if ( preg_match( '/^\s*"id":\s*"(CVE-\d{4}-\d{4,10})"/', $trim, $m ) ) {
					if ( ! isset( $wanted[ $m[1] ] ) ) {
						$buf = null;
						continue;
					}
					$keep = true;
				}
			}

			$buf .= $line;
		}

		pclose( $fh );

		if ( $rows ) {
			$written += self::write_intel( $rows );
		}

		return $written;
	}

	/**
	 * Page the NVD API for a specific list of ids.
	 *
	 * One request per CVE, which is why this is the fallback and not the
	 * default. NVD allows 5 requests per 30 seconds unauthenticated and 50 with
	 * a key, so a key turns hours into minutes; the key is optional and asked
	 * for on the admin screen.
	 *
	 * @param string[] $ids CVE ids.
	 * @param string[] $log Log lines, by reference.
	 */
	private static function fetch_nvd_api( array $ids, array &$log ): void {
		if ( ! $ids ) {
			return;
		}

		$key   = (string) get_option( 'vulnhub_threat_nvd_key', '' );
		$gap   = $key ? 700000 : 6500000; // Microseconds between calls.
		/*
		 * A hard ceiling on how much of a run the fallback may consume.
		 * Unauthenticated NVD allows one request per 6.5 seconds, so 200 ids
		 * is about 20 minutes -- long, but bounded, and the remainder is
		 * picked up by tomorrow's run rather than turning tonight's into an
		 * eight-hour job that never reaches the roll-up.
		 */
		$cap   = (int) get_option( 'vulnhub_threat_api_cap', 200 );
		$ids   = array_slice( $ids, 0, max( 0, $cap ) );
		$rows  = array();
		$done  = 0;
		$fails = 0;

		foreach ( $ids as $id ) {
			$args = array(
				'timeout'     => 40,
				'redirection' => 3,
			);

			if ( $key ) {
				$args['headers'] = array( 'apiKey' => $key );
			}

			$res = wp_remote_get( add_query_arg( 'cveId', rawurlencode( $id ), self::NVD_API ), $args );

			if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
				++$fails;

				if ( $fails > 20 ) {
					$log[] = 'NVD API: too many consecutive failures, giving up for this run.';
					break;
				}

				usleep( $gap );
				continue;
			}

			$fails = 0;
			$body  = json_decode( (string) wp_remote_retrieve_body( $res ), true );

			foreach ( (array) ( $body['vulnerabilities'] ?? array() ) as $entry ) {
				$row = self::row_from_nvd( (array) ( $entry['cve'] ?? array() ) );

				if ( $row ) {
					$rows[] = $row;
				}
			}

			if ( count( $rows ) >= 100 ) {
				$done += self::write_intel( $rows );
				$rows  = array();
			}

			usleep( $gap );
		}

		if ( $rows ) {
			$done += self::write_intel( $rows );
		}

		$log[] = sprintf( 'NVD API: %d records ingested.', $done );
	}

	/**
	 * Wanted ids the year files did not contain at all.
	 *
	 * Same distinction as `year_has_gaps()`: a CVE that NVD has published
	 * without a v3 vector is answered, not missing. Asking the API for it
	 * again every night would cost hours and return the same blank vector, so
	 * the only ids worth a request are the ones with no row.
	 *
	 * @return string[]
	 */
	private static function missing_vectors( array $wanted ): array {
		global $wpdb;

		$intel = VulnHub_Threat_Install::table( 'cve_intel' );
		$have  = (array) $wpdb->get_col( "SELECT cve_id FROM {$intel}" ); // phpcs:ignore

		return array_values( array_diff( array_keys( $wanted ), $have ) );
	}

	/**
	 * Turn one NVD CVE object into a row for `cve_intel`.
	 *
	 * @param array<string,mixed>|null $cve Decoded NVD record.
	 * @return array<string,mixed>|null
	 */
	private static function row_from_nvd( ?array $cve ): ?array {
		if ( ! $cve || empty( $cve['id'] ) ) {
			return null;
		}

		$metrics = (array) ( $cve['metrics'] ?? array() );
		$vector  = null;
		$version = '';

		foreach ( array( 'cvssMetricV31' => '3.1', 'cvssMetricV30' => '3.0', 'cvssMetricV40' => '4.0' ) as $key => $label ) {
			if ( ! empty( $metrics[ $key ][0]['cvssData'] ) ) {
				$vector  = (array) $metrics[ $key ][0]['cvssData'];
				$version = $label;
				break;
			}
		}

		/*
		 * CVSS v2 has no UI or PR field, so it cannot answer the question this
		 * plugin asks. It is stored for the score alone and the route is left
		 * unknown rather than guessed -- an honest gap is easier to work with
		 * than a confident wrong lane.
		 */
		if ( null === $vector && ! empty( $metrics['cvssMetricV2'][0]['cvssData'] ) ) {
			$vector  = (array) $metrics['cvssMetricV2'][0]['cvssData'];
			$version = '2.0';
		}

		$exploit_refs = 0;

		foreach ( (array) ( $cve['references'] ?? array() ) as $ref ) {
			if ( in_array( 'Exploit', (array) ( $ref['tags'] ?? array() ), true ) ) {
				++$exploit_refs;
			}
		}

		$text = '';

		foreach ( (array) ( $cve['descriptions'] ?? array() ) as $d ) {
			if ( 'en' === ( $d['lang'] ?? '' ) ) {
				$text = (string) ( $d['value'] ?? '' );
				break;
			}
		}

		$av = strtoupper( (string) ( $vector['attackVector'] ?? '' ) );
		$ui = strtoupper( (string) ( $vector['userInteraction'] ?? '' ) );

		return array(
			'cve_id'              => (string) $cve['id'],
			'attack_vector'       => '2.0' === $version ? '' : ( 'ADJACENT' === $av ? 'ADJACENT_NETWORK' : $av ),
			'attack_complexity'   => '2.0' === $version ? '' : strtoupper( (string) ( $vector['attackComplexity'] ?? '' ) ),
			'privileges_required' => '2.0' === $version ? '' : strtoupper( (string) ( $vector['privilegesRequired'] ?? '' ) ),
			'user_interaction'    => '2.0' === $version ? '' : $ui,
			'scope'               => strtoupper( (string) ( $vector['scope'] ?? '' ) ),
			'base_score'          => (float) ( $vector['baseScore'] ?? 0 ),
			'cvss_version'        => $version,
			'exploit_refs'        => $exploit_refs,
			'delivery'            => VulnHub_Threat_Classify::delivery_for( $text, $av, $ui ),
			'nvd_published'       => substr( (string) ( $cve['published'] ?? '' ), 0, 10 ) ?: null,
			'nvd_modified'        => str_replace( 'T', ' ', substr( (string) ( $cve['lastModified'] ?? '' ), 0, 19 ) ) ?: null,
		);
	}

	/**
	 * Write a batch of CVE rows, leaving KEV and EPSS columns alone.
	 *
	 * @param array<int,array<string,mixed>> $rows Rows.
	 */
	private static function write_intel( array $rows ): int {
		global $wpdb;

		if ( ! $rows ) {
			return 0;
		}

		$intel  = VulnHub_Threat_Install::table( 'cve_intel' );
		$now    = gmdate( 'Y-m-d H:i:s' );
		$values = array();
		$params = array();

		foreach ( $rows as $r ) {
			$values[] = '(%s,%s,%s,%s,%s,%s,%f,%s,%d,%s,%s,%s,%s)';
			array_push(
				$params,
				$r['cve_id'],
				$r['attack_vector'],
				$r['attack_complexity'],
				$r['privileges_required'],
				$r['user_interaction'],
				$r['scope'],
				(float) $r['base_score'],
				$r['cvss_version'],
				(int) $r['exploit_refs'],
				$r['delivery'],
				$r['nvd_published'],
				$r['nvd_modified'],
				$now
			);
		}

		/*
		 * INSERT ... ON DUPLICATE KEY UPDATE rather than REPLACE: REPLACE
		 * deletes the row first, which would throw away the KEV and EPSS
		 * columns this statement does not mention every time NVD is
		 * re-ingested.
		 */
		$sql = "INSERT INTO {$intel}
			(cve_id,attack_vector,attack_complexity,privileges_required,user_interaction,scope,base_score,cvss_version,exploit_refs,delivery,nvd_published,nvd_modified,fetched_at)
			VALUES " . implode( ',', $values ) . '
			ON DUPLICATE KEY UPDATE
				attack_vector=VALUES(attack_vector),
				attack_complexity=VALUES(attack_complexity),
				privileges_required=VALUES(privileges_required),
				user_interaction=VALUES(user_interaction),
				scope=VALUES(scope),
				base_score=VALUES(base_score),
				cvss_version=VALUES(cvss_version),
				exploit_refs=VALUES(exploit_refs),
				delivery=VALUES(delivery),
				nvd_published=VALUES(nvd_published),
				nvd_modified=VALUES(nvd_modified),
				fetched_at=VALUES(fetched_at)';

		$wpdb->query( $wpdb->prepare( $sql, ...$params ) ); // phpcs:ignore

		return count( $rows );
	}

	/* =================================================================
	 * KEV and EPSS
	 * ============================================================== */

	/**
	 * @param array<string,int> $wanted CVE id => 1.
	 * @param string[]          $log    Log lines, by reference.
	 */
	private static function fetch_kev( array $wanted, array &$log ): void {
		global $wpdb;

		$res = wp_remote_get( self::KEV_URL, array( 'timeout' => 60, 'redirection' => 5 ) );

		if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
			$log[] = 'CISA KEV: unreachable, keeping the previous flags.';
			return;
		}

		$body = json_decode( (string) wp_remote_retrieve_body( $res ), true );
		$list = (array) ( $body['vulnerabilities'] ?? array() );

		if ( ! $list ) {
			$log[] = 'CISA KEV: empty response, keeping the previous flags.';
			return;
		}

		$intel = VulnHub_Threat_Install::table( 'cve_intel' );

		// A CVE can be withdrawn from KEV. Clear first so the table reflects
		// today's catalogue rather than the union of every catalogue seen.
		$wpdb->query( "UPDATE {$intel} SET kev = 0, kev_ransomware = 0, kev_added = NULL WHERE kev = 1" ); // phpcs:ignore

		$hits = 0;

		foreach ( array_chunk( $list, 200 ) as $chunk ) {
			$cases = array();
			$rans  = array();
			$ids   = array();

			foreach ( $chunk as $v ) {
				$id = (string) ( $v['cveID'] ?? '' );

				if ( '' === $id || ! isset( $wanted[ $id ] ) ) {
					continue;
				}

				$ids[]   = $id;
				$cases[] = $wpdb->prepare( 'WHEN %s THEN %s', $id, substr( (string) ( $v['dateAdded'] ?? '' ), 0, 10 ) );
				$rans[]  = $wpdb->prepare( 'WHEN %s THEN %d', $id, 'Known' === ( $v['knownRansomwareCampaignUse'] ?? '' ) ? 1 : 0 );
			}

			if ( ! $ids ) {
				continue;
			}

			$in    = implode( ',', array_fill( 0, count( $ids ), '%s' ) );
			$hits += count( $ids );

			$wpdb->query( // phpcs:ignore
				$wpdb->prepare(
					"UPDATE {$intel} SET kev = 1,
						kev_added = CASE cve_id " . implode( ' ', $cases ) . " END,
						kev_ransomware = CASE cve_id " . implode( ' ', $rans ) . " END
					 WHERE cve_id IN ({$in})", // phpcs:ignore
					...$ids
				)
			);
		}

		$log[] = sprintf( 'CISA KEV: %d of %d catalogued CVEs are present in this estate.', $hits, count( $list ) );
	}

	/**
	 * @param array<string,int> $wanted CVE id => 1.
	 * @param string[]          $log    Log lines, by reference.
	 */
	private static function fetch_epss( array $wanted, array &$log ): void {
		global $wpdb;

		$file = self::download( self::EPSS_URL );

		if ( '' === $file ) {
			$log[] = 'FIRST EPSS: unreachable, keeping yesterday\'s scores.';
			return;
		}

		$fh = gzopen( $file, 'rb' );

		if ( ! $fh ) {
			wp_delete_file( $file );
			$log[] = 'FIRST EPSS: could not read the download.';
			return;
		}

		$intel = VulnHub_Threat_Install::table( 'cve_intel' );
		$rows  = array();
		$hits  = 0;

		while ( false !== ( $line = gzgets( $fh ) ) ) {
			$line = trim( $line );

			if ( '' === $line || '#' === $line[0] || str_starts_with( $line, 'cve,' ) ) {
				continue;
			}

			$cols = explode( ',', $line );

			if ( count( $cols ) < 3 || ! isset( $wanted[ $cols[0] ] ) ) {
				continue;
			}

			$rows[] = array( $cols[0], (float) $cols[1], (float) $cols[2] );
			++$hits;

			if ( count( $rows ) >= self::BATCH ) {
				self::write_epss( $intel, $rows );
				$rows = array();
			}
		}

		gzclose( $fh );
		wp_delete_file( $file );

		if ( $rows ) {
			self::write_epss( $intel, $rows );
		}

		$log[] = sprintf( 'FIRST EPSS: %d of %d CVE ids scored for today.', $hits, count( $wanted ) );
	}

	/** @param array<int,array{0:string,1:float,2:float}> $rows Rows. */
	private static function write_epss( string $intel, array $rows ): void {
		global $wpdb;

		$values = array();
		$params = array();

		foreach ( $rows as $r ) {
			$values[] = '(%s,%f,%f)';
			array_push( $params, $r[0], $r[1], $r[2] );
		}

		$wpdb->query( // phpcs:ignore
			$wpdb->prepare(
				"INSERT INTO {$intel} (cve_id,epss,epss_percentile) VALUES " . implode( ',', $values ) . // phpcs:ignore
				' ON DUPLICATE KEY UPDATE epss=VALUES(epss), epss_percentile=VALUES(epss_percentile)',
				...$params
			)
		);
	}

	/**
	 * Set `has_poc` and `route` from the columns the feeds just filled.
	 *
	 * Done in SQL over 13,000 rows rather than in PHP, so that changing the
	 * EPSS threshold on the settings screen is a single statement and not
	 * another full re-ingest.
	 *
	 * @param string[] $log Log lines, by reference.
	 */
	public static function derive_cve_columns( array &$log ): void {
		global $wpdb;

		$intel   = VulnHub_Threat_Install::table( 'cve_intel' );
		$sources = VulnHub_Threat_Classify::poc_sources();
		$min     = VulnHub_Threat_Classify::epss_threshold();
		$tests   = array();

		if ( in_array( 'kev', $sources, true ) ) {
			$tests[] = 'kev = 1';
		}
		if ( in_array( 'refs', $sources, true ) ) {
			$tests[] = 'exploit_refs > 0';
		}
		if ( in_array( 'epss', $sources, true ) ) {
			$tests[] = $wpdb->prepare( 'epss >= %f', $min );
		}

		$wpdb->query( "UPDATE {$intel} SET has_poc = " . ( $tests ? '( ' . implode( ' OR ', $tests ) . ' )' : '0' ) ); // phpcs:ignore

		/*
		 * The whole classification, in one CASE. Order matters: user
		 * interaction wins over everything, because a bug that needs somebody
		 * to open a file is delivered to the person no matter how the CVSS
		 * vector describes the network. After that, "network and no
		 * privileges" is the only combination an unauthenticated stranger can
		 * use, and everything left over needs a foothold first.
		 */
		$wpdb->query( // phpcs:ignore
			"UPDATE {$intel} SET route = CASE
				WHEN attack_vector = '' THEN 'unknown'
				WHEN user_interaction IN ('REQUIRED','PASSIVE','ACTIVE') THEN 'user'
				WHEN attack_vector = 'NETWORK' AND privileges_required = 'NONE' THEN 'edge'
				ELSE 'inside'
			END"
		);

		$counts = (array) $wpdb->get_results( "SELECT route, COUNT(*) n, SUM(has_poc) p FROM {$intel} GROUP BY route", ARRAY_A ); // phpcs:ignore

		foreach ( $counts as $row ) {
			$log[] = sprintf( 'route %-8s %6d CVEs, %d with an exploit.', (string) $row['route'], (int) $row['n'], (int) $row['p'] );
		}
	}

	/* =================================================================
	 * Plumbing
	 * ============================================================== */

	/** Download to a temp file and return its path, or '' on failure. */
	private static function download( string $url ): string {
		$dir = self::work_dir();

		if ( '' === $dir ) {
			return '';
		}

		$path = $dir . '/' . md5( $url ) . '-' . wp_generate_password( 8, false );

		$res = wp_remote_get(
			$url,
			array(
				'timeout'     => 300,
				'redirection' => 5,
				'stream'      => true,
				'filename'    => $path,
			)
		);

		if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) || ! file_exists( $path ) ) {
			if ( file_exists( $path ) ) {
				wp_delete_file( $path );
			}

			return '';
		}

		return $path;
	}

	/** A private scratch directory under uploads, created on first use. */
	private static function work_dir(): string {
		$up = wp_upload_dir();

		if ( ! empty( $up['error'] ) ) {
			return '';
		}

		$dir = trailingslashit( $up['basedir'] ) . 'vulnhub-threat';

		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return '';
		}

		// Nothing in here is ever meant to be served.
		if ( ! file_exists( $dir . '/index.php' ) ) {
			file_put_contents( $dir . '/index.php', "<?php\n// Silence is golden.\n" ); // phpcs:ignore
		}
		if ( ! file_exists( $dir . '/.htaccess' ) ) {
			file_put_contents( $dir . '/.htaccess', "Require all denied\n" ); // phpcs:ignore
		}

		return $dir;
	}
}
