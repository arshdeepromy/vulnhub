<?php
/**
 * Has the application's vendor shipped the fix for a component it bundles?
 *
 * A finding whose route is "update the app that ships it" (Repo::fix_route())
 * leaves one question open: does updating that application actually fix it?
 * Tenable only knows the component's own fixed release ("libcurl 8.4.0"); it
 * does not know whether Power BI Desktop has shipped a build carrying it. The
 * estate does, from two signals:
 *
 *   1. A newer copy at the same place. Every open finding for a product lists
 *      the copies Tenable found, each with a path and an installed version.
 *      Normalised, the path identifies "this component inside this
 *      application" across machines (user folders and version-numbered
 *      folders are wildcarded). If any machine has that copy at or above the
 *      fixed version, a build that ships the fix exists.
 *   2. Resolved in place. The same vulnerability at the same path (read from
 *      the resolved finding's last scanner output) was fixed in the last year
 *      on a machine that is still in the reporting estate AND still has open
 *      findings in the same application -- so the application is still
 *      installed, and was updated rather than removed. Resolutions where the
 *      application is gone are reported, but do not count as proof.
 *
 * Each open component finding gets a verdict in `findings.app_fix`:
 *
 *   shipped   -- a fixed build has been seen: updating the application works
 *   not_seen  -- the newest copy seen at that place is still vulnerable, and
 *                nothing has been resolved: its vendor has not shipped it yet
 *   unknown   -- not enough evidence either way
 *
 * and a one-line reason in `findings.app_fix_note`. It is recomputed after
 * every Tenable sync (in the background) and with `wp vulnhub app-fix`.
 *
 * Only open copies are observed: a copy with no vulnerability at all never
 * appears in a finding, so signal 1 can miss a fixed build that signal 2
 * catches. A verdict of not_seen is therefore "not seen", not "does not exist".
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Vendor-fix evidence for bundled components.
 */
final class App_Fix {

	public const SHIPPED  = 'shipped';
	public const NOT_SEEN = 'not_seen';
	public const UNKNOWN  = 'unknown';

	public const HOOK = 'vulnhub_app_fix_recompute';

	private const PAGE = 1000;

	/** How far back a resolved finding counts as evidence. */
	private const RESOLVED_DAYS = 365;

	public function hooks(): void {
		add_action( self::HOOK, array( self::class, 'recompute' ), 10, 0 );
		add_action(
			'vulnhub_sync_complete',
			static function ( string $connector = '' ): void {
				// A few minutes after the sync, in its own cron run: this reads
				// every component finding's scanner output.
				if ( 'tenable' === $connector && ! wp_next_scheduled( self::HOOK ) ) {
					wp_schedule_single_event( time() + 120, self::HOOK );
				}
			},
			40,
			1
		);
	}

	/**
	 * Labels for the verdicts.
	 *
	 * @return array<string,string>
	 */
	public static function labels(): array {
		return array(
			self::SHIPPED  => __( 'fixed build seen', 'vulnhub' ),
			self::NOT_SEEN => __( 'no fixed build seen yet', 'vulnhub' ),
			self::UNKNOWN  => __( 'not enough evidence', 'vulnhub' ),
		);
	}

	/**
	 * Work out and store the verdict for every open component finding.
	 *
	 * @param bool $write False for a dry run.
	 * @return array{findings:int,changed:int,shipped:int,not_seen:int,unknown:int,cleared:int,paths:int,seconds:float,samples:array<int,array<string,string>>}
	 */
	public static function recompute( bool $write = true ): array {
		global $wpdb;

		$started = microtime( true );
		$f       = vh_table( 'findings' );
		$v       = vh_table( 'vulns' );
		$a       = vh_table( 'assets' );
		$comp    = Repo::component_sql( 'f', 'v' );

		/* ---- 1. What copies exist where, at which versions ---- */
		$seen = array(); // product|path => [ 'max' => version, 'assets' => [ id => version ] ]
		$last = 0;

		do {
			$rows = (array) $wpdb->get_results(
				$wpdb->prepare(
					"SELECT f.id, f.asset_id, f.output, v.product_slug
					 FROM {$f} f INNER JOIN {$v} v ON v.id = f.vuln_id
					 WHERE f.id > %d AND f.state IN ('open','reopened') AND f.output <> ''
					   AND v.product_kind IN ( 'library', 'application' )
					 ORDER BY f.id ASC LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL
					$last,
					self::PAGE
				),
				ARRAY_A
			);

			foreach ( $rows as $row ) {
				$last = (int) $row['id'];

				foreach ( self::copies( (string) $row['output'] ) as $copy ) {
					if ( '' === $copy['installed'] ) {
						continue;
					}

					$key = (string) $row['product_slug'] . '|' . $copy['key'];
					$aid = (int) $row['asset_id'];
					$old = $seen[ $key ]['assets'][ $aid ] ?? '';

					if ( '' === $old || version_compare( $copy['installed'], $old, '>' ) ) {
						$seen[ $key ]['assets'][ $aid ] = $copy['installed'];
						$seen[ $key ]['apps'][ $aid ]   = self::app_version( $copy['path'] );
					}
				}
			}
		} while ( count( $rows ) === self::PAGE );

		foreach ( $seen as $key => $obs ) {
			$max = '';
			foreach ( $obs['assets'] as $ver ) {
				if ( '' === $max || version_compare( $ver, $max, '>' ) ) {
					$max = $ver;
				}
			}
			$seen[ $key ]['max'] = $max;
		}

		/* ---- 2. Resolved at the same path, app still installed or not ---- */
		$resolved = array(); // vuln|product|path => [ 'kept' => machines, 'gone' => machines ]

		foreach ( (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT f.asset_id, f.vuln_id, f.output, v.product_slug,
					EXISTS ( SELECT 1 FROM {$f} o WHERE o.asset_id = f.asset_id AND o.bundle_app_slug = f.bundle_app_slug AND o.state IN ('open','reopened') ) AS app_kept
				 FROM {$f} f
				 INNER JOIN {$v} v ON v.id = f.vuln_id
				 INNER JOIN {$a} a ON a.id = f.asset_id
				 WHERE f.state = 'fixed' AND {$comp}
				   AND f.last_fixed >= %s
				   AND a.lifecycle_status IN (" . vh_reportable_sql() . ')', // phpcs:ignore WordPress.DB.PreparedSQL
				gmdate( 'Y-m-d H:i:s', time() - self::RESOLVED_DAYS * DAY_IN_SECONDS )
			),
			ARRAY_A
		) as $row ) {
			$first = self::copies( (string) $row['output'] )[0] ?? null;

			if ( ! $first ) {
				continue;
			}

			$key = (int) $row['vuln_id'] . '|' . (string) $row['product_slug'] . '|' . $first['key'];

			$resolved[ $key ][ $row['app_kept'] ? 'kept' : 'gone' ][ (int) $row['asset_id'] ] = true;
		}

		/* ---- 3. A verdict per open component finding ---- */
		$stats = array(
			'findings' => 0,
			'changed'  => 0,
			self::SHIPPED  => 0,
			self::NOT_SEEN => 0,
			self::UNKNOWN  => 0,
			'cleared'  => 0,
			'paths'    => count( $seen ),
			'seconds'  => 0.0,
			'samples'  => array(),
		);
		$last = 0;

		do {
			$rows = (array) $wpdb->get_results(
				$wpdb->prepare(
					"SELECT f.id, f.vuln_id, f.output, f.bundle_app, f.bundle_app_slug, f.app_fix, f.app_fix_note,
						v.title, v.product, v.product_slug
					 FROM {$f} f INNER JOIN {$v} v ON v.id = f.vuln_id
					 WHERE f.id > %d AND f.state IN ('open','reopened') AND {$comp}
					 ORDER BY f.id ASC LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL
					$last,
					self::PAGE
				),
				ARRAY_A
			);

			foreach ( $rows as $row ) {
				$last = (int) $row['id'];
				++$stats['findings'];

				[ $verdict, $note ] = self::judge( $row, $seen, $resolved );
				++$stats[ $verdict ];

				if ( count( $stats['samples'] ) < 400 ) {
					$stats['samples'][] = array( 'app' => (string) $row['bundle_app'], 'product' => (string) $row['product'], 'verdict' => $verdict, 'note' => $note );
				}

				if ( $verdict !== (string) $row['app_fix'] || $note !== (string) $row['app_fix_note'] ) {
					++$stats['changed'];

					if ( $write ) {
						$wpdb->update( $f, array( 'app_fix' => $verdict, 'app_fix_note' => $note ), array( 'id' => (int) $row['id'] ) );
					}
				}
			}
		} while ( count( $rows ) === self::PAGE );

		// Anything no longer an open component finding keeps no verdict.
		if ( $write ) {
			$stats['cleared'] = (int) $wpdb->query(
				"UPDATE {$f} f INNER JOIN {$v} v ON v.id = f.vuln_id
				 SET f.app_fix = '', f.app_fix_note = ''
				 WHERE f.app_fix <> '' AND NOT ( f.state IN ('open','reopened') AND {$comp} )" // phpcs:ignore WordPress.DB.PreparedSQL
			);

			if ( $stats['changed'] || $stats['cleared'] ) {
				do_action( 'vulnhub_app_fix_recomputed', $stats );

				if ( class_exists( '\\VulnHub_Dash_Widgets' ) ) {
					\VulnHub_Dash_Widgets::bust( 'findings' );
				}
			}

			update_option(
				'vulnhub_app_fix_last',
				array(
					'at'       => vh_now(),
					'findings' => $stats['findings'],
					'shipped'  => $stats[ self::SHIPPED ],
					'not_seen' => $stats[ self::NOT_SEEN ],
					'unknown'  => $stats[ self::UNKNOWN ],
				),
				false
			);
		}

		$stats['seconds'] = round( microtime( true ) - $started, 2 );

		return $stats;
	}

	/**
	 * The verdict for one finding.
	 *
	 * @param array<string,mixed>                $row      Finding row.
	 * @param array<string,array<string,mixed>> $seen     Copies by product|path.
	 * @param array<string,int>                  $resolved Machines resolved by vuln|app.
	 * @return array{0:string,1:string}
	 */
	private static function judge( array $row, array $seen, array $resolved ): array {
		$app     = (string) $row['bundle_app'];
		$product = '' !== (string) $row['product'] ? (string) $row['product'] : __( 'the component', 'vulnhub' );
		$copies  = self::copies( (string) $row['output'] );
		$first   = $copies[0] ?? null;
		$fixed   = $first && '' !== $first['fixed'] ? $first['fixed'] : \VH_Product::latest_fixed_version( array( (string) $row['title'] ) );
		$fixed   = self::version( $fixed );
		$obs     = $first ? ( $seen[ (string) $row['product_slug'] . '|' . $first['key'] ] ?? null ) : null;
		$rkey    = $first ? (int) $row['vuln_id'] . '|' . (string) $row['product_slug'] . '|' . $first['key'] : '';
		$done    = count( $resolved[ $rkey ]['kept'] ?? array() );
		$gone    = count( $resolved[ $rkey ]['gone'] ?? array() );

		$newer = $obs && '' !== $fixed && '' !== (string) $obs['max'] && version_compare( (string) $obs['max'], $fixed, '>=' );
		$span  = $obs && '' !== $fixed ? self::app_span( (array) $obs['assets'], (array) ( $obs['apps'] ?? array() ), $fixed ) : array( 'fixed_from' => '', 'newest_vulnerable' => '', 'newest' => '' );

		if ( $newer || $done > 0 ) {
			$bits = array();

			if ( $newer ) {
				$at_max = count( array_filter( $obs['assets'], static fn( string $ver ): bool => version_compare( $ver, $fixed, '>=' ) ) );
				/* translators: 1: component, 2: version, 3: machines, 4: application. */
				$bits[] = sprintf( _n( '%1$s %2$s or later is already in %4$s on %3$d machine', '%1$s %2$s or later is already in %4$s on %3$d machines', $at_max, 'vulnhub' ), $product, $fixed, $at_max, $app )
					/* translators: 1: application, 2: application version. */
					. ( '' !== $span['fixed_from'] ? sprintf( __( ' (from %1$s %2$s)', 'vulnhub' ), $app, $span['fixed_from'] ) : '' );
			}
			if ( $done > 0 ) {
				/* translators: 1: machines, 2: application. */
				$bits[] = sprintf( _n( 'this copy was resolved on %1$d machine that still has %2$s installed', 'this copy was resolved on %1$d machines that still have %2$s installed', $done, 'vulnhub' ), $done, $app );
			}

			/* translators: 1: evidence, 2: application. */
			$text = sprintf( __( '%1$s: updating %2$s fixes it.', 'vulnhub' ), implode( '; ', $bits ), $app );

			// Capitalise only our own opening word, never a product name (libcurl).
			return array( self::SHIPPED, vh_trim( str_starts_with( $text, 'this ' ) ? ucfirst( $text ) : $text, 390 ) );
		}

		/* translators: 1: machines, 2: application. */
		$gone_note = $gone > 0 ? ' ' . sprintf( _n( 'It went away on %1$d machine where %2$s no longer shows, which may be removal rather than an update.', 'It went away on %1$d machines where %2$s no longer shows, which may be removal rather than an update.', $gone, 'vulnhub' ), $gone, $app ) : '';

		if ( $obs && '' !== $fixed && '' !== (string) $obs['max'] ) {
			return array(
				self::NOT_SEEN,
				vh_trim(
					sprintf(
						/* translators: 1: component, 2: newest version, 3: machines, 4: application, 5: fixed version. */
						_n( 'The newest %1$s seen in %4$s is %2$s (on %3$d machine), below the fixed %5$s, and none has been resolved: its vendor does not appear to have shipped the fix yet.', 'The newest %1$s seen in %4$s is %2$s (across %3$d machines), below the fixed %5$s, and none has been resolved: its vendor does not appear to have shipped the fix yet.', count( $obs['assets'] ), 'vulnhub' ),
						$product,
						(string) $obs['max'],
						count( $obs['assets'] ),
						$app,
						$fixed
					)
					// When the install folder names the application's version, say
					// that even the newest version seen still ships the old copy.
					. ( '' !== $span['newest_vulnerable'] && $span['newest_vulnerable'] === $span['newest']
						/* translators: 1: application, 2: application version. */
						? ' ' . sprintf( __( 'That includes %1$s %2$s, the newest version seen.', 'vulnhub' ), $app, $span['newest'] )
						: '' )
					. $gone_note,
					390
				),
			);
		}

		return array(
			self::UNKNOWN,
			vh_trim(
				sprintf(
					/* translators: 1: application, 2: component. */
					__( 'Not enough evidence to tell whether %1$s ships a fixed %2$s: no version at this path to compare, and nothing resolved yet.', 'vulnhub' ),
					$app,
					$product
				) . $gone_note,
				390
			),
		);
	}

	/**
	 * The machines behind a verdict, for a person to check: where the same copy
	 * (same path key) is already at or above the fixed version, and where this
	 * vulnerability at that path was resolved while the application stayed
	 * installed. Reads the same evidence recompute() does, for one finding.
	 *
	 * @param array<string,mixed> $row Finding row: output, vuln_id, title, product_slug, bundle_app_slug.
	 * @return array{path:string,installed:string,fixed:string,max:string,observed:int,newer:array<int,array<string,string>>,newer_total:int,resolved:array<int,array<string,string>>,resolved_total:int}
	 */
	public static function references( array $row, int $limit = 3 ): array {
		global $wpdb;

		$copy  = self::copies( (string) ( $row['output'] ?? '' ) )[0] ?? null;
		$fixed = $copy && '' !== $copy['fixed'] ? $copy['fixed'] : self::version( \VH_Product::latest_fixed_version( array( (string) ( $row['vuln_title'] ?? $row['title'] ?? '' ) ) ) );
		$out   = array(
			'path'           => $copy ? $copy['path'] : '',
			'installed'      => $copy ? $copy['installed'] : '',
			'fixed'          => $fixed,
			'max'            => '',
			'observed'       => 0,
			'newer'          => array(),
			'newer_total'    => 0,
			'resolved'       => array(),
			'resolved_total' => 0,
		);

		if ( ! $copy ) {
			$out += array( 'fixed_from' => '', 'newest_vulnerable' => '', 'newest' => '' );
			return $out;
		}

		// The longest literal folder name in the key narrows the read to
		// outputs that can contain this copy; the key itself decides.
		$parts = array_filter( preg_split( '#[\\\\/]#', $copy['key'] ) ?: array(), static fn( string $p ): bool => '' !== $p && ! str_contains( $p, '*' ) && ! str_contains( $p, ':' ) );
		usort( $parts, static fn( string $x, string $y ): int => strlen( $y ) <=> strlen( $x ) );
		$needle = (string) ( $parts[0] ?? '' );

		if ( '' === $needle ) {
			return $out + array( 'fixed_from' => '', 'newest_vulnerable' => '', 'newest' => '' );
		}

		$f  = vh_table( 'findings' );
		$v  = vh_table( 'vulns' );
		$a  = vh_table( 'assets' );
		$lo = vh_table( 'locations' );

		$asset_cols = 'a.hostname, a.fqdn, a.ipv4, a.operating_system, a.asset_type, l.name AS location';

		/* ---- same copy, other machines ---- */
		$best = array();

		foreach ( (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT f.asset_id, f.output, f.last_found, {$asset_cols}
				 FROM {$f} f
				 INNER JOIN {$v} v ON v.id = f.vuln_id
				 INNER JOIN {$a} a ON a.id = f.asset_id
				 LEFT JOIN {$lo} l ON l.id = a.location_id
				 WHERE v.product_slug = %s AND f.state IN ('open','reopened') AND LOCATE( %s, f.output ) > 0", // phpcs:ignore WordPress.DB.PreparedSQL
				(string) ( $row['product_slug'] ?? '' ),
				$needle
			),
			ARRAY_A
		) as $r ) {
			foreach ( self::copies( (string) $r['output'] ) as $c ) {
				if ( $c['key'] !== $copy['key'] || '' === $c['installed'] ) {
					continue;
				}

				$aid = (int) $r['asset_id'];

				if ( ! isset( $best[ $aid ] ) || version_compare( $c['installed'], $best[ $aid ]['version'], '>' ) ) {
					$best[ $aid ] = self::asset_ref( $r ) + array( 'version' => $c['installed'], 'path' => $c['path'], 'app_version' => self::app_version( $c['path'] ), 'when' => substr( (string) $r['last_found'], 0, 10 ) );
				}
			}
		}

		$out['observed'] = count( $best );
		$out            += '' !== $fixed
			? self::app_span( array_map( static fn( array $b ): string => $b['version'], $best ), array_map( static fn( array $b ): string => $b['app_version'], $best ), $fixed )
			: array( 'fixed_from' => '', 'newest_vulnerable' => '', 'newest' => '' );

		foreach ( $best as $ref ) {
			if ( '' === $out['max'] || version_compare( $ref['version'], $out['max'], '>' ) ) {
				$out['max'] = $ref['version'];
			}
		}

		if ( '' !== $fixed ) {
			$newer = array_values( array_filter( $best, static fn( array $ref ): bool => version_compare( $ref['version'], $fixed, '>=' ) ) );
			usort( $newer, static fn( array $x, array $y ): int => strcmp( $y['when'], $x['when'] ) );
			$out['newer_total'] = count( $newer );
			$out['newer']       = array_slice( $newer, 0, $limit );
		}

		/* ---- resolved at this path, application still installed ---- */
		$resolved = array();

		foreach ( (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT f.asset_id, f.output, f.last_fixed, {$asset_cols}
				 FROM {$f} f
				 INNER JOIN {$a} a ON a.id = f.asset_id
				 LEFT JOIN {$lo} l ON l.id = a.location_id
				 WHERE f.vuln_id = %d AND f.bundle_app_slug = %s AND f.state = 'fixed' AND f.last_fixed >= %s
				   AND a.lifecycle_status IN (" . vh_reportable_sql() . ")
				   AND EXISTS ( SELECT 1 FROM {$f} o WHERE o.asset_id = f.asset_id AND o.bundle_app_slug = f.bundle_app_slug AND o.state IN ('open','reopened') )
				 ORDER BY f.last_fixed DESC", // phpcs:ignore WordPress.DB.PreparedSQL
				(int) ( $row['vuln_id'] ?? 0 ),
				(string) ( $row['bundle_app_slug'] ?? '' ),
				gmdate( 'Y-m-d H:i:s', time() - self::RESOLVED_DAYS * DAY_IN_SECONDS )
			),
			ARRAY_A
		) as $r ) {
			$c = self::copies( (string) $r['output'] )[0] ?? null;

			if ( $c && $c['key'] === $copy['key'] && ! isset( $resolved[ (int) $r['asset_id'] ] ) ) {
				$resolved[ (int) $r['asset_id'] ] = self::asset_ref( $r ) + array( 'version' => $c['installed'], 'path' => $c['path'], 'app_version' => self::app_version( $c['path'] ), 'when' => substr( (string) $r['last_fixed'], 0, 10 ) );
			}
		}

		$out['resolved_total'] = count( $resolved );
		$out['resolved']       = array_slice( array_values( $resolved ), 0, $limit );

		return $out;
	}

	/**
	 * @param array<string,mixed> $r Row with asset columns.
	 * @return array<string,string>
	 */
	private static function asset_ref( array $r ): array {
		return array(
			'hostname' => (string) $r['hostname'],
			'fqdn'     => (string) $r['fqdn'],
			'ipv4'     => (string) $r['ipv4'],
			'os'       => (string) $r['operating_system'],
			'type'     => vh_asset_type_label( (string) $r['asset_type'] ),
			'location' => (string) ( $r['location'] ?? '' ),
		);
	}

	/**
	 * The copies a scanner output lists: path key, installed and fixed version.
	 *
	 * Tenable writes one block per copy -- "Path : …", "Installed version : …",
	 * "Fixed version : …" -- in one finding.
	 *
	 * @return array<int,array{key:string,path:string,installed:string,fixed:string}>
	 */
	public static function copies( string $output ): array {
		$out    = array();
		$blocks = preg_split( '/^\s*Path\s*:/mi', $output );

		if ( ! is_array( $blocks ) || count( $blocks ) < 2 ) {
			return $out;
		}

		array_shift( $blocks );

		foreach ( $blocks as $block ) {
			$path = trim( (string) strtok( $block, "\r\n" ) );

			if ( '' === $path ) {
				continue;
			}

			$installed = preg_match( '/Installed version\s*:\s*([^\r\n]+)/i', $block, $m ) ? self::version( $m[1] ) : '';

			// For some packaged apps the scanner reports the package's version
			// as the component's ("SQLite 1.26071.84.0" inside a Store app of
			// that version). That is not the component's version and cannot be
			// compared with its fixed release, so it is not used.
			if ( '' !== $installed && $installed === self::app_version( $path ) ) {
				$installed = '';
			}
			$fixed     = preg_match( '/Fixed version\s*:\s*([^\r\n]+)/i', $block, $m ) ? self::version( $m[1] ) : '';

			$out[] = array(
				'key'       => self::path_key( $path ),
				'path'      => $path,
				'installed' => $installed,
				'fixed'     => $fixed,
			);
		}

		return $out;
	}

	/**
	 * A path with the parts that differ between machines wildcarded: the
	 * user's profile folder and any folder that is a version number.
	 */
	public static function path_key( string $path ): string {
		$p = strtolower( str_replace( '/', '\\', (string) preg_replace( '#\\\\{2,}#', '\\', trim( $path ) ) ) );
		$p = (string) preg_replace( '#\\\\users\\\\[^\\\\]+\\\\#', '\\users\\*\\', $p );
		$p = (string) preg_replace( '#^/home/[^/]+/#', '/home/*/', $p );
		$p = (string) preg_replace( '#(?<=\\\\|/)v?\d+(?:\.\d+)+(?=\\\\|/)#', '*', $p );
		// A Microsoft Store (MSIX) folder carries its version and publisher:
		// Microsoft.MicrosoftPowerBIDesktop_2.157.1354.0_x64__8wekyb3d8bbwe.
		$p = (string) preg_replace( '#(?<=\\\\)([a-z0-9.]+)_\d+(?:\.\d+)+_[a-z0-9]+__[a-z0-9]+(?=\\\\)#', '$1_*', $p );

		return $p;
	}

	/**
	 * The application's own version, when its install folder carries one:
	 * a Microsoft Store package (`…\WindowsApps\MSTeams_26213.1006.5014.9784_x64__…`)
	 * or a version-numbered folder (`…\Edge\Application\152.0.4191.66\…`).
	 * Most classic installs (`Program Files\App\bin\…`) carry none: ''.
	 */
	public static function app_version( string $path ): string {
		$p = str_replace( '/', '\\', (string) preg_replace( '#\\\\{2,}#', '\\', $path ) );

		if ( preg_match( '#\\\\WindowsApps\\\\[^\\\\_]+_(\d+(?:\.\d+)+)_#i', $p, $m ) ) {
			return $m[1];
		}
		if ( preg_match( '#\\\\(\d+(?:\.\d+){2,})\\\\#', $p, $m ) ) {
			return $m[1];
		}

		return '';
	}

	/**
	 * Across machines with one copy: the lowest application version whose copy
	 * is fixed, the highest whose copy is still vulnerable, and the highest
	 * seen at all. Machines whose path names no version are left out.
	 *
	 * @param array<int,string> $copy_versions Component version by asset.
	 * @param array<int,string> $app_versions  Application version by asset.
	 * @return array{fixed_from:string,newest_vulnerable:string,newest:string}
	 */
	private static function app_span( array $copy_versions, array $app_versions, string $fixed ): array {
		$out = array( 'fixed_from' => '', 'newest_vulnerable' => '', 'newest' => '' );

		foreach ( $app_versions as $aid => $app ) {
			if ( '' === (string) $app || ! isset( $copy_versions[ $aid ] ) ) {
				continue;
			}

			if ( '' === $out['newest'] || version_compare( $app, $out['newest'], '>' ) ) {
				$out['newest'] = $app;
			}

			if ( version_compare( (string) $copy_versions[ $aid ], $fixed, '>=' ) ) {
				if ( '' === $out['fixed_from'] || version_compare( $app, $out['fixed_from'], '<' ) ) {
					$out['fixed_from'] = $app;
				}
			} elseif ( '' === $out['newest_vulnerable'] || version_compare( $app, $out['newest_vulnerable'], '>' ) ) {
				$out['newest_vulnerable'] = $app;
			}
		}

		return $out;
	}

	/**
	 * The first dotted version number in a string, or ''.
	 */
	private static function version( string $text ): string {
		return preg_match( '/\d+(?:\.\d+)+/', $text, $m ) ? $m[0] : '';
	}
}
