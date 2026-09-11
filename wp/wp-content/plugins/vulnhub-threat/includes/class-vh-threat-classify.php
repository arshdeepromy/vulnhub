<?php
/**
 * Turning CVE facts into "how would somebody get to this".
 *
 * Three decisions live here, and each one is deliberately dull enough to
 * explain to an auditor:
 *
 * 1. Which CVEs is a scanner definition talking about. Tenable puts them in
 *    the title ("Linux Distros Unpatched Vulnerability : CVE-2016-10217") and
 *    in the description; on this estate the title carries one for 9,650 of
 *    11,746 definitions and the description carries at least one for 11,532.
 *    `cve_json` is empty on every row, so a regular expression over both text
 *    fields is not a shortcut -- it is the only source there is.
 *
 * 2. Which route each CVE opens. Straight from the CVSS v3 vector, no
 *    judgement added. See `VulnHub_Threat_Feeds::derive_cve_columns()`.
 *
 * 3. Which route a definition opens. The most reachable route any of its CVEs
 *    opens: a kernel advisory bundling thirty CVEs is as exposed as its worst
 *    one, because patching is per-package, not per-CVE.
 *
 * @package VulnHub\Threat
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Extraction, roll-up and asset exposure.
 */
final class VulnHub_Threat_Classify {

	/** Route ids, most reachable first. The order is the precedence. */
	public const ROUTES = array( 'edge', 'user', 'inside' );

	/** Definitions read per pass. Descriptions are longtext. */
	private const CHUNK = 500;

	/** Matches a CVE id anywhere in free text. */
	private const CVE_RX = '/CVE-\d{4}-\d{4,10}/i';

	/* =================================================================
	 * Settings
	 * ============================================================== */

	/** @return string[] Which signals count as "an exploit exists". */
	public static function poc_sources(): array {
		$stored = get_option( 'vulnhub_threat_poc_sources', array( 'kev', 'refs', 'epss' ) );
		$stored = is_array( $stored ) ? $stored : array( 'kev', 'refs', 'epss' );

		return array_values( array_intersect( $stored, array( 'kev', 'refs', 'epss' ) ) );
	}

	/** EPSS probability at or above which a CVE counts as exploitable today. */
	public static function epss_threshold(): float {
		return min( 1.0, max( 0.0, (float) get_option( 'vulnhub_threat_epss_min', 0.10 ) ) );
	}

	/** Which assets the rule treats as reachable from the internet. */
	public static function exposure_rule(): string {
		$rule = (string) get_option( 'vulnhub_threat_exposure_rule', 'servers_and_cloud' );

		return in_array( $rule, array( 'servers_and_cloud', 'cloud_only', 'tagged', 'all' ), true ) ? $rule : 'servers_and_cloud';
	}

	/* =================================================================
	 * CVE extraction
	 * ============================================================== */

	public static function definition_count(): int {
		global $wpdb;

		return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . vh_table( 'vulns' ) ); // phpcs:ignore
	}

	/**
	 * Every distinct CVE id the estate's vulnerability definitions mention.
	 *
	 * @return array<string,int> Upper-cased CVE id => 1, so lookups are O(1).
	 */
	public static function wanted_cves(): array {
		$wanted = array();

		foreach ( self::walk_definitions() as $batch ) {
			foreach ( $batch as $row ) {
				foreach ( $row['cves'] as $cve ) {
					$wanted[ $cve ] = 1;
				}
			}
		}

		return $wanted;
	}

	/**
	 * Read the vulns table in chunks, yielding ids and their CVEs.
	 *
	 * A generator rather than one big array: descriptions are longtext and
	 * 11,746 of them at once is a needless several hundred megabytes.
	 *
	 * @return Generator<int,array<int,array{id:int,cves:string[]}>>
	 */
	private static function walk_definitions(): Generator {
		global $wpdb;

		$v     = vh_table( 'vulns' );
		$after = 0;

		do {
			$rows = (array) $wpdb->get_results( // phpcs:ignore
				$wpdb->prepare(
					"SELECT id, title, description FROM {$v} WHERE id > %d ORDER BY id ASC LIMIT %d", // phpcs:ignore
					$after,
					self::CHUNK
				),
				ARRAY_A
			);

			if ( ! $rows ) {
				return;
			}

			$out = array();

			foreach ( $rows as $row ) {
				$after = (int) $row['id'];
				$out[] = array(
					'id'   => (int) $row['id'],
					'cves' => self::cves_in( (string) $row['title'] . ' ' . (string) $row['description'] ),
				);
			}

			yield $out;
		} while ( count( $rows ) === self::CHUNK );
	}

	/**
	 * Every CVE id in a blob of text, upper-cased and de-duplicated.
	 *
	 * @return string[]
	 */
	public static function cves_in( string $text ): array {
		if ( ! preg_match_all( self::CVE_RX, $text, $m ) ) {
			return array();
		}

		return array_values( array_unique( array_map( 'strtoupper', $m[0] ) ) );
	}

	/* =================================================================
	 * Delivery: how a user-interaction bug actually arrives
	 * ============================================================== */

	/**
	 * Which of the three doors a user-delivered CVE comes through.
	 *
	 * Keyword matching on the NVD description, which is coarse and admits it.
	 * It only ever refines a lane the CVSS vector already decided -- getting it
	 * wrong moves a finding between "email" and "website" inside the same
	 * number, never between lanes -- so a cheap heuristic is the right amount
	 * of machinery. Order matters: mail clients render web content and open
	 * attachments, so mail is tested first or everything lands under web.
	 */
	public static function delivery_for( string $text, string $av, string $ui ): string {
		if ( '' === $ui || 'NONE' === $ui ) {
			return '';
		}

		$t = strtolower( $text );

		$mail = array( 'outlook', 'thunderbird', 'e-mail', ' email', 'smtp', 'imap', 'mime', 's/mime', 'mail client', 'message preview', 'calendar invit' );
		$web  = array( 'browser', 'chrome', 'chromium', 'firefox', 'safari', 'webkit', 'javascript', 'v8 ', 'blink', 'gecko', 'web page', 'webpage', 'html', 'css', 'xss', 'cross-site', 'visit', 'url' );
		$file = array( 'crafted file', 'malicious file', 'document', 'word', 'excel', 'powerpoint', 'pdf', 'acrobat', 'archive', 'zip', 'rar', 'tar', 'font file', 'image file', 'codec', 'installer', 'macro', 'opens a file', 'open a file', 'crafted input file' );

		foreach ( array( 'mail' => $mail, 'file' => $file, 'web' => $web ) as $bucket => $needles ) {
			foreach ( $needles as $needle ) {
				if ( str_contains( $t, $needle ) ) {
					return $bucket;
				}
			}
		}

		// Nothing matched. A network-delivered click is a link; a local one is
		// something they were handed and opened.
		return 'NETWORK' === $av ? 'web' : 'file';
	}

	/* =================================================================
	 * Roll-up
	 * ============================================================== */

	/**
	 * Place every vulnerability definition on a route.
	 *
	 * @return int Definitions written.
	 */
	public static function rebuild_all(): int {
		global $wpdb;

		$paths = VulnHub_Threat_Install::table( 'vuln_paths' );
		$intel = self::intel_map();
		$now   = gmdate( 'Y-m-d H:i:s' );
		$order = array_flip( self::ROUTES );
		$done  = 0;

		// A definition that has been retired upstream must not keep a stale
		// lane, and there is no cheap way to know which those are, so the
		// table is rebuilt rather than merged.
		$wpdb->query( "TRUNCATE TABLE {$paths}" ); // phpcs:ignore

		foreach ( self::walk_definitions() as $batch ) {
			$values = array();
			$params = array();

			foreach ( $batch as $def ) {
				$route     = '';
				$poc_route = '';
				$delivery  = '';
				$evidence  = '';
				$top_cve   = '';
				$top_epss  = 0.0;
				$kev       = 0;
				$has_poc   = 0;
				$known     = 0;

				foreach ( $def['cves'] as $cve ) {
					$row = $intel[ $cve ] ?? null;

					if ( ! $row ) {
						continue;
					}

					if ( 'unknown' !== $row['route'] ) {
						++$known;

						if ( '' === $route || $order[ $row['route'] ] < $order[ $route ] ) {
							$route = $row['route'];
						}
					}

					if ( ! $row['has_poc'] ) {
						continue;
					}

					$has_poc = 1;
					$kev     = $kev || $row['kev'] ? 1 : 0;

					if ( 'unknown' !== $row['route'] && ( '' === $poc_route || $order[ $row['route'] ] < $order[ $poc_route ] ) ) {
						$poc_route = $row['route'];
						$delivery  = $row['delivery'];
					}

					/*
					 * The CVE named on the widget's drill-down is the most
					 * defensible one, not the highest scoring: on CISA's list
					 * beats a published exploit beats a model's probability.
					 */
					$rank = $row['kev'] ? 3 : ( $row['exploit_refs'] > 0 ? 2 : 1 );
					$best = '' === $top_cve ? 0 : ( 'kev' === $evidence ? 3 : ( 'exploit-ref' === $evidence ? 2 : 1 ) );

					if ( $rank > $best || ( $rank === $best && $row['epss'] > $top_epss ) ) {
						$top_cve  = $cve;
						$evidence = 3 === $rank ? 'kev' : ( 2 === $rank ? 'exploit-ref' : 'epss' );
					}

					$top_epss = max( $top_epss, $row['epss'] );
				}

				$values[] = '(%d,%d,%d,%s,%s,%s,%d,%d,%f,%s,%s,%s)';
				array_push(
					$params,
					$def['id'],
					count( $def['cves'] ),
					$known,
					'' === $route ? 'unknown' : $route,
					$poc_route,
					$delivery,
					$has_poc,
					$kev,
					$top_epss,
					$top_cve,
					$evidence,
					$now
				);
				++$done;
			}

			if ( $values ) {
				$wpdb->query( // phpcs:ignore
					$wpdb->prepare(
						"INSERT INTO {$paths} (vuln_id,cve_count,known_count,route,poc_route,delivery,has_poc,kev,top_epss,top_cve,evidence,updated_at) VALUES " // phpcs:ignore
						. implode( ',', $values ),
						...$params
					)
				);
			}
		}

		if ( get_option( 'vulnhub_threat_backfill_exploit', '1' ) ) {
			self::backfill_exploit_available();
		}

		if ( class_exists( 'VulnHub_Dash_Widgets' ) ) {
			VulnHub_Dash_Widgets::bust();
		}

		return $done;
	}

	/**
	 * Every CVE row this plugin knows, keyed by id.
	 *
	 * 13,000 rows of eight small columns. Held in memory for the length of one
	 * roll-up so that placing 11,746 definitions is one query rather than
	 * 11,746.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	private static function intel_map(): array {
		global $wpdb;

		$intel = VulnHub_Threat_Install::table( 'cve_intel' );
		$out   = array();

		foreach ( (array) $wpdb->get_results( "SELECT cve_id, route, delivery, has_poc, kev, epss, exploit_refs FROM {$intel}", ARRAY_A ) as $r ) { // phpcs:ignore
			$out[ (string) $r['cve_id'] ] = array(
				'route'        => (string) $r['route'],
				'delivery'     => (string) $r['delivery'],
				'has_poc'      => (int) $r['has_poc'],
				'kev'          => (int) $r['kev'],
				'epss'         => (float) $r['epss'],
				'exploit_refs' => (int) $r['exploit_refs'],
			);
		}

		return $out;
	}

	/**
	 * Write the exploit verdict back onto core's `exploit_available`.
	 *
	 * That column is 0 on all 11,746 rows here, because the Tenable export
	 * this estate was loaded from did not carry it -- which is why the
	 * dashboard's own impact funnel reads zero at every stage. Filling it in
	 * makes the funnel, and anything else reading that column, tell the truth.
	 *
	 * It is genuinely core's column, so a future Tenable sync that does carry
	 * the field will overwrite this, and that is the correct outcome: the
	 * vendor's answer should win over an inference. The next refresh will
	 * simply agree or defer.
	 */
	public static function backfill_exploit_available(): void {
		global $wpdb;

		$v     = vh_table( 'vulns' );
		$paths = VulnHub_Threat_Install::table( 'vuln_paths' );

		$wpdb->query( // phpcs:ignore
			"UPDATE {$v} v INNER JOIN {$paths} p ON p.vuln_id = v.id
			 SET v.exploit_available = p.has_poc
			 WHERE v.exploit_available <> p.has_poc"
		);
	}

	/* =================================================================
	 * Asset exposure
	 * ============================================================== */

	/**
	 * Decide which assets the internet can actually reach.
	 *
	 * This is the difference between a theoretical number and an actionable
	 * one. 7,395 open findings on this estate are network-exploitable with no
	 * credentials and no user action -- and they are on laptops, which nothing
	 * on the internet can open a socket to. Counting those in the edge lane
	 * would triple it and point remediation at the wrong work, so they are
	 * placed where they can actually be used: once somebody is already inside.
	 *
	 * Rows a person set by hand (`source = 'manual'`) survive a rule pass.
	 *
	 * @return int Assets marked internet-facing.
	 */
	public static function rebuild_exposure(): int {
		global $wpdb;

		$a    = vh_table( 'assets' );
		$expo = VulnHub_Threat_Install::table( 'asset_exposure' );
		$rule = self::exposure_rule();
		$now  = gmdate( 'Y-m-d H:i:s' );

		$rows = (array) $wpdb->get_results( "SELECT id, asset_type, cloud_provider, environment, tags_json FROM {$a}", ARRAY_A ); // phpcs:ignore

		$manual = array_map(
			'intval',
			(array) $wpdb->get_col( "SELECT asset_id FROM {$expo} WHERE source = 'manual'" ) // phpcs:ignore
		);
		$manual = array_flip( $manual );

		$values = array();
		$params = array();
		$facing = 0;

		foreach ( $rows as $row ) {
			$id = (int) $row['id'];

			if ( isset( $manual[ $id ] ) ) {
				continue;
			}

			[ $yes, $why ] = self::exposure_for( $row, $rule );

			$facing  += $yes ? 1 : 0;
			$values[] = '(%d,%d,%s,%s,%s)';
			array_push( $params, $id, $yes ? 1 : 0, 'rule', $why, $now );

			if ( count( $values ) >= 400 ) {
				self::write_exposure( $expo, $values, $params );
				$values = array();
				$params = array();
			}
		}

		if ( $values ) {
			self::write_exposure( $expo, $values, $params );
		}

		$facing += (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$expo} WHERE source = 'manual' AND internet_facing = 1" ); // phpcs:ignore

		if ( class_exists( 'VulnHub_Dash_Widgets' ) ) {
			VulnHub_Dash_Widgets::bust();
		}

		return $facing;
	}

	/**
	 * @param array<string,mixed> $row  Asset row.
	 * @param string              $rule Which rule is in force.
	 * @return array{0:bool,1:string} Verdict and the reason to show a person.
	 */
	private static function exposure_for( array $row, string $rule ): array {
		$type  = (string) $row['asset_type'];
		$cloud = (string) $row['cloud_provider'];
		$tags  = strtolower( (string) $row['tags_json'] );
		$hit   = '';

		foreach ( array( 'internet-facing', 'internet_facing', 'dmz', 'public-facing', 'edge', 'perimeter' ) as $needle ) {
			if ( str_contains( $tags, $needle ) ) {
				$hit = $needle;
				break;
			}
		}

		switch ( $rule ) {
			case 'all':
				return array( true, __( 'every asset, by setting', 'vulnhub' ) );

			case 'cloud_only':
				if ( '' !== $cloud ) {
					return array( true, sprintf( /* translators: %s: cloud provider. */ __( 'hosted on %s', 'vulnhub' ), $cloud ) );
				}
				if ( 'cloud' === $type ) {
					return array( true, __( 'cloud asset', 'vulnhub' ) );
				}
				break;

			case 'tagged':
				if ( '' !== $hit ) {
					return array( true, sprintf( /* translators: %s: matched tag. */ __( 'tagged %s', 'vulnhub' ), $hit ) );
				}
				break;

			case 'servers_and_cloud':
			default:
				if ( '' !== $hit ) {
					return array( true, sprintf( /* translators: %s: matched tag. */ __( 'tagged %s', 'vulnhub' ), $hit ) );
				}
				if ( '' !== $cloud ) {
					return array( true, sprintf( /* translators: %s: cloud provider. */ __( 'hosted on %s', 'vulnhub' ), $cloud ) );
				}
				if ( in_array( $type, array( 'server', 'cloud' ), true ) ) {
					return array( true, __( 'server or cloud instance', 'vulnhub' ) );
				}
				break;
		}

		return array(
			false,
			'' === $type
				? __( 'nothing says the internet can open a socket to it', 'vulnhub' )
				: sprintf( /* translators: %s: asset type. */ __( '%s — no inbound path from the internet', 'vulnhub' ), $type )
		);
	}

	/**
	 * @param string[] $values Placeholder groups.
	 * @param array<int,mixed> $params Bound values.
	 */
	private static function write_exposure( string $expo, array $values, array $params ): void {
		global $wpdb;

		$wpdb->query( // phpcs:ignore
			$wpdb->prepare(
				"INSERT INTO {$expo} (asset_id,internet_facing,source,reason,updated_at) VALUES " . implode( ',', $values ) . // phpcs:ignore
				' ON DUPLICATE KEY UPDATE internet_facing=VALUES(internet_facing), source=VALUES(source), reason=VALUES(reason), updated_at=VALUES(updated_at)',
				...$params
			)
		);
	}
}
