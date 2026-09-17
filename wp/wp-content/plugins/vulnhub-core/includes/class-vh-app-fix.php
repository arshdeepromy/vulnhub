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

		if ( $newer || $done > 0 ) {
			$bits = array();

			if ( $newer ) {
				$at_max = count( array_filter( $obs['assets'], static fn( string $ver ): bool => version_compare( $ver, $fixed, '>=' ) ) );
				/* translators: 1: component, 2: version, 3: machines, 4: application. */
				$bits[] = sprintf( _n( '%1$s %2$s or later is already in %4$s on %3$d machine', '%1$s %2$s or later is already in %4$s on %3$d machines', $at_max, 'vulnhub' ), $product, $fixed, $at_max, $app );
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
					) . $gone_note,
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

		return $p;
	}

	/**
	 * The first dotted version number in a string, or ''.
	 */
	private static function version( string $text ): string {
		return preg_match( '/\d+(?:\.\d+)+/', $text, $m ) ? $m[0] : '';
	}
}
