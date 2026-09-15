<?php
/**
 * "What are we still running that nobody is patching any more?"
 *
 * A vulnerability with no patch is a decision. A platform past end of life is
 * a decision that has already been made and not noticed: there will be no
 * patch for the next thing either, and there is no ticket to raise, because
 * the fix is a project. Those two facts are why this is its own screen rather
 * than a filter on the vulnerability list.
 *
 * Three things are counted here, and they are deliberately kept apart because
 * they are three different conversations with three different people:
 *
 *   - Operating systems, matched from the inventory. Windows is keyed on the
 *     build number, because 21 machines in this estate are labelled
 *     "Windows 11 Enterprise" and are running build 19045, which is Windows
 *     10. The label is somebody's typing; the build is the machine's.
 *   - Installed software, matched from the CPE strings Tenable reports.
 *   - Hardware support, from the CMDB's own support_end_date. That is a
 *     warranty date, not a security one, so it is reported separately and
 *     never mixed into the platform counts.
 *
 * The dates come from data/eol.php, which is a checked-in table with a source
 * URL per row (see the long comment at the top of that file for why it is not
 * a live feed). Everything here reads that table through table(), which
 * layers the portal's own corrections on top, so a wrong date is a two-minute
 * fix on the Administration screen rather than a release.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * End-of-life tracking for platforms, software and hardware.
 */
final class Eol {

	/** Option holding the portal's corrections and additions. */
	public const OPTION = 'vulnhub_eol_overrides';

	/**
	 * How far ahead counts as "approaching".
	 *
	 * Six months, because that is roughly the shortest notice on which an
	 * organisation of this size can actually move an operating system: it
	 * has to clear a change window, and the budget for it usually sits in a
	 * quarter that has already been planned.
	 */
	public const SOON_DAYS = 180;

	/** @var array<int,array<string,mixed>>|null */
	private static ?array $bundled = null;

	/** @var array<string,array<string,mixed>>|null */
	private static ?array $table = null;

	/* =================================================================
	 * The table
	 * ============================================================== */

	/**
	 * The shipped table, exactly as it is in the repository.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function bundled(): array {
		if ( null === self::$bundled ) {
			$file = VULNHUB_DIR . 'data/eol.php';

			/** @var array<int,array<string,mixed>> $rows */
			$rows = is_readable( $file ) ? (array) require $file : array();

			self::$bundled = $rows;
		}

		return self::$bundled;
	}

	/**
	 * Corrections and additions made in the portal.
	 *
	 * Stored as key => changed fields, so that a future release which moves
	 * a bundled date still applies to every row nobody has touched.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	public static function overrides(): array {
		$raw = get_option( self::OPTION, array() );

		return is_array( $raw ) ? $raw : array();
	}

	/**
	 * The table the rest of the product reads: bundled, then corrected.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	public static function table(): array {
		if ( null !== self::$table ) {
			return self::$table;
		}

		$out = array();

		foreach ( self::bundled() as $row ) {
			$key = (string) ( $row['key'] ?? '' );

			if ( '' === $key ) {
				continue;
			}

			$out[ $key ]           = self::normalise( $row );
			$out[ $key ]['custom'] = false;
			$out[ $key ]['edited'] = false;
		}

		foreach ( self::overrides() as $key => $fields ) {
			$key = (string) $key;

			if ( '' === $key || ! is_array( $fields ) ) {
				continue;
			}

			if ( ! empty( $fields['deleted'] ) ) {
				unset( $out[ $key ] );
				continue;
			}

			$base = $out[ $key ] ?? array( 'key' => $key, 'custom' => true );
			$row  = self::normalise( array_merge( $base, $fields ) );

			$row['custom'] = ! isset( $out[ $key ] );
			$row['edited'] = true;

			$out[ $key ] = $row;
		}

		self::$table = $out;

		return $out;
	}

	/**
	 * Fill in the fields every consumer expects, whatever the row omitted.
	 *
	 * @param array<string,mixed> $row Raw row.
	 * @return array<string,mixed>
	 */
	private static function normalise( array $row ): array {
		return array_merge(
			array(
				'key'        => '',
				'kind'       => 'os',
				'family'     => '',
				'edition'    => '',
				'cpe'        => '',
				'product'    => '',
				'release'    => '',
				'build'      => '',
				'version'    => '',
				'eol'        => '',
				'mainstream' => '',
				'note'       => '',
				'source'     => '',
			),
			$row
		);
	}

	/**
	 * Store a correction or a new row.
	 *
	 * Only the fields that differ from the bundled row are kept, so that the
	 * next release's dates still reach every row the operator has not
	 * deliberately overridden.
	 *
	 * @param array<string,mixed> $fields Fields to set.
	 */
	public static function save_row( string $key, array $fields ): void {
		$key = sanitize_key( $key );

		if ( '' === $key ) {
			return;
		}

		$bundled = array();

		foreach ( self::bundled() as $row ) {
			if ( (string) ( $row['key'] ?? '' ) === $key ) {
				$bundled = self::normalise( $row );
				break;
			}
		}

		$allowed = array( 'kind', 'family', 'edition', 'cpe', 'product', 'release', 'build', 'version', 'eol', 'mainstream', 'note', 'source' );
		$store   = self::overrides();
		$diff    = array();

		foreach ( $allowed as $field ) {
			if ( ! array_key_exists( $field, $fields ) ) {
				continue;
			}

			$value = 'source' === $field
				? esc_url_raw( (string) $fields[ $field ] )
				: sanitize_text_field( (string) $fields[ $field ] );

			if ( in_array( $field, array( 'eol', 'mainstream' ), true ) ) {
				$value = self::clean_date( $value );
			}

			// A field that matches the shipped value is not an override, and
			// storing it would freeze that row against future corrections.
			if ( $bundled && isset( $bundled[ $field ] ) && (string) $bundled[ $field ] === $value ) {
				continue;
			}

			$diff[ $field ] = $value;
		}

		if ( $diff ) {
			$store[ $key ] = $diff;
		} else {
			unset( $store[ $key ] );
		}

		update_option( self::OPTION, $store, false );

		self::$table = null;
	}

	/**
	 * Hide a bundled row, or remove one that was added here.
	 */
	public static function delete_row( string $key ): void {
		$key   = sanitize_key( $key );
		$store = self::overrides();

		$bundled = false;

		foreach ( self::bundled() as $row ) {
			if ( (string) ( $row['key'] ?? '' ) === $key ) {
				$bundled = true;
				break;
			}
		}

		if ( $bundled ) {
			// Shipped rows cannot be deleted, only suppressed -- the file
			// will still have them after the next release.
			$store[ $key ] = array( 'deleted' => true );
		} else {
			unset( $store[ $key ] );
		}

		update_option( self::OPTION, $store, false );

		self::$table = null;
	}

	/** Put everything back to what the plugin shipped. */
	public static function reset(): void {
		delete_option( self::OPTION );

		self::$table = null;
	}

	private static function clean_date( string $raw ): string {
		$raw = trim( $raw );

		return preg_match( '/^\d{4}-\d{2}-\d{2}$/', $raw ) ? $raw : '';
	}

	/* =================================================================
	 * Status
	 * ============================================================== */

	/**
	 * @return array<string,array{label:string,tone:string}>
	 */
	public static function statuses(): array {
		return array(
			'past'      => array(
				/*
				 * "Out of support", not "past end of life". These are release
				 * branches: the vendor has stopped patching this one, which
				 * usually means upgrade rather than migrate. Rows carry
				 * `upgrade_to` so the display can say which.
				 */
				'label' => __( 'Out of support', 'vulnhub' ),
				'tone'  => 'critical',
			),
			'soon'      => array(
				'label' => __( 'Support ends within six months', 'vulnhub' ),
				'tone'  => 'high',
			),
			'supported' => array(
				'label' => __( 'Supported', 'vulnhub' ),
				'tone'  => 'good',
			),
			'unknown'   => array(
				'label' => __( 'No published date', 'vulnhub' ),
				'tone'  => 'muted',
			),
		);
	}

	/**
	 * Where a date sits relative to today.
	 *
	 * @return array{status:string,label:string,tone:string,days:int|null}
	 */
	public static function status( string $eol ): array {
		$statuses = self::statuses();

		if ( '' === $eol ) {
			return array_merge( array( 'status' => 'unknown', 'days' => null ), $statuses['unknown'] );
		}

		$then = strtotime( $eol . ' 00:00:00 UTC' );
		$now  = strtotime( gmdate( 'Y-m-d' ) . ' 00:00:00 UTC' );

		if ( ! $then || ! $now ) {
			return array_merge( array( 'status' => 'unknown', 'days' => null ), $statuses['unknown'] );
		}

		$days = (int) round( ( $then - $now ) / DAY_IN_SECONDS );

		if ( $days < 0 ) {
			$key = 'past';
		} elseif ( $days <= self::SOON_DAYS ) {
			$key = 'soon';
		} else {
			$key = 'supported';
		}

		return array_merge( array( 'status' => $key, 'days' => $days ), $statuses[ $key ] );
	}

	/* =================================================================
	 * Matching an operating system
	 * ============================================================== */

	/**
	 * The build number written inside the OS name itself.
	 *
	 * The CMDB records both, and on 21 machines here they disagree: the name
	 * says `Microsoft Windows 11 Enterprise 10.0.26100 0` while the version
	 * column says `19045 (22H2)`, which is Windows 10. All 21 carry the
	 * *identical* version string while their names carry builds of their own
	 * -- 26100, 26200, one apiece -- so the version column is one stale value
	 * copied across a fleet, and the name is the machine.
	 *
	 * Deliberately narrow: only `10.0.26100` and `Build 26100` shapes count.
	 * A looser read would take the 2012 out of "Windows Server 2012 R2" and
	 * the 11 out of "Windows 11".
	 *
	 * @param string $name The `operating_system` string.
	 */
	public static function windows_build_in_name( string $name ): string {
		if ( preg_match( '/\b\d+\.\d+\.(\d{4,5})(?:\.\d+)?\b/', $name, $m ) ) {
			return $m[1];
		}

		if ( preg_match( '/\bbuild\s*(\d{4,5})\b/i', $name, $m ) ) {
			return $m[1];
		}

		return '';
	}

	/**
	 * The client release named in an OS string -- "10" or "11" -- if any.
	 *
	 * `Windows Server 2012 R2` deliberately yields nothing: the number there
	 * is a year, not a release this can be compared against.
	 *
	 * @param string $name The `operating_system` string.
	 */
	public static function windows_client_major( string $name ): string {
		if ( preg_match( '/windows\s+server/i', $name ) ) {
			return '';
		}

		return preg_match( '/\bwindows\s+(10|11)\b/i', $name, $m ) ? $m[1] : '';
	}

	/**
	 * The Windows build number out of whatever the inventory recorded.
	 *
	 * Four shapes turn up in this estate and all four have to work:
	 *
	 *   26100 (24H2)      Intune, feature-update style
	 *   10.0.26100.9106   Tenable, full NT version
	 *   6.3.9600.21620    Windows 8.1 / Server 2012 R2, which is NT 6.3
	 *   26100             bare
	 */
	public static function windows_build( string $version ): string {
		$version = trim( $version );

		if ( '' === $version ) {
			return '';
		}

		// 10.0.26100.9106 and 6.3.9600.21620 -- the third field is the build.
		if ( preg_match( '/^\d+\.\d+\.(\d{4,5})(?:\.|$)/', $version, $m ) ) {
			return $m[1];
		}

		// 26100 (24H2), or just 26100.
		if ( preg_match( '/^(\d{4,5})\b/', $version, $m ) ) {
			return $m[1];
		}

		return '';
	}

	/**
	 * The table row for one asset's operating system, or null.
	 *
	 * @param array<string,mixed> $asset Asset row, needing operating_system,
	 *                                   os_version and asset_type.
	 * @return array<string,mixed>|null
	 */
	public static function match_os( array $asset ): ?array {
		$parsed = Os::parse( (string) ( $asset['operating_system'] ?? '' ) );
		$family = (string) $parsed['family'];

		if ( 'windows' === $family || 'windows_server' === $family ) {
			$name = (string) ( $asset['operating_system'] ?? '' );

			/*
			 * The name's own build first. It and the product label are one
			 * string from one source, so they corroborate each other; a
			 * separate version column can be, and here is, stale.
			 */
			$build     = self::windows_build_in_name( $name );
			$from_name = '' !== $build;

			if ( '' === $build ) {
				$build = self::windows_build( (string) ( $asset['os_version'] ?? '' ) );
			}

			if ( '' === $build ) {
				return null;
			}

			/*
			 * Builds 9600 and 26100 are a client release and a server
			 * release. The inventory string is the wrong tiebreaker -- half
			 * of these rows arrived truncated to "Microsoft" -- so ask what
			 * the machine is instead, which the classifier has already
			 * decided from far more than the OS name.
			 */
			$server = 'windows_server' === $family
				|| 'server' === (string) ( $asset['asset_type'] ?? '' );

			$want = $server ? 'server' : 'client';
			$fall = null;

			foreach ( self::table() as $row ) {
				if ( 'os' !== $row['kind'] || (string) $row['build'] !== $build ) {
					continue;
				}

				if ( (string) $row['edition'] === $want ) {
					$fall = $row;
					break;
				}

				$fall = $row;
			}

			/*
			 * A build taken from the version column that contradicts the
			 * release in the name settles nothing. Four machines here are
			 * named "Windows 11 Enterprise" with no build of their own and a
			 * version column reading 19045, which is Windows 10 -- and one
			 * of those two is wrong. Calling it past end of life on the
			 * weaker evidence is worse than saying the release is unknown,
			 * which is what the reader can actually act on.
			 */
			if ( $fall && ! $from_name && ! $server ) {
				$named = self::windows_client_major( $name );

				if ( '' !== $named && preg_match( '/^Windows\s+(10|11)$/', (string) $fall['product'], $m ) && $m[1] !== $named ) {
					return null;
				}
			}

			return $fall;
		}

		$version = (string) $parsed['version'];

		if ( '' === $version ) {
			return null;
		}

		$best = null;

		foreach ( self::table() as $row ) {
			if ( 'os' !== $row['kind'] || (string) $row['family'] !== $family ) {
				continue;
			}

			$pin = (string) $row['version'];

			if ( '' === $pin || ! self::version_matches( $version, $pin ) ) {
				continue;
			}

			// Longest pin wins, so that "9" cannot claim a 9.3 that has its
			// own row.
			if ( ! $best || strlen( $pin ) > strlen( (string) $best['version'] ) ) {
				$best = $row;
			}
		}

		return $best;
	}

	/**
	 * Prefix match on a version-number boundary.
	 *
	 * "3.0" matches 3.0.13 and 3.0, and does not match 3.01 or 30.
	 */
	public static function version_matches( string $version, string $pin ): bool {
		if ( $version === $pin ) {
			return true;
		}

		return str_starts_with( $version, $pin . '.' );
	}

	/* =================================================================
	 * The estate
	 * ============================================================== */

	/**
	 * Every in-service asset grouped by the platform release it is running.
	 *
	 * Assets whose release cannot be established are not dropped -- they are
	 * grouped under their own family with an unknown status, because "48 Red
	 * Hat machines whose release we do not know" is itself a finding, and
	 * silently omitting them would make the chart add up to less than the
	 * estate.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function estate(): array {
		global $wpdb;

		$rows = (array) $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			'SELECT id, operating_system, os_version, asset_type FROM ' . vh_table( 'assets' )
			. ' WHERE lifecycle_status IN (' . vh_reportable_sql() . ')', // phpcs:ignore
			ARRAY_A
		);

		$groups = array();

		foreach ( $rows as $asset ) {
			$row = self::match_os( $asset );

			if ( $row ) {
				$key   = (string) $row['key'];
				$label = (string) $row['product'];

				$release = (string) $row['release'];

				if ( 'os' === $row['kind'] && '' !== (string) $row['build'] ) {
					$release = trim( $release . ' ' . sprintf( '(build %s)', $row['build'] ) );
				}

				$eol   = (string) $row['eol'];
				$note  = (string) $row['note'];
				$early = (string) $row['mainstream'];
			} else {
				$parsed  = Os::parse( (string) $asset['operating_system'] );
				$key     = 'unknown:' . $parsed['family'];
				$label   = (string) $parsed['label'];
				$release = __( 'Release not recorded', 'vulnhub' );
				$eol     = '';
				$early   = '';
				$note    = __( 'The inventory does not say which release this is, so no lifecycle date can be applied.', 'vulnhub' );
			}

			if ( ! isset( $groups[ $key ] ) ) {
				$groups[ $key ] = array(
					'key'        => $key,
					'kind'       => 'os',
					'label'      => $label,
					'release'    => $release,
					'eol'        => $eol,
					/*
					 * Carried separately because it is a different promise.
					 * Windows Server 2022 gets security updates until 2031
					 * but leaves mainstream support in five weeks, and a
					 * chart that shows only the first number is telling a
					 * platform team the wrong thing about their next year.
					 */
					'mainstream' => $early,
					'note'       => $note,
					'assets'     => 0,
					'matched'    => (bool) $row,
				);
			}

			++$groups[ $key ]['assets'];
		}

		return self::finish( $groups );
	}

	/**
	 * Installed software past, or approaching, its end of life.
	 *
	 * Only software the table knows about is counted. An asset can hold
	 * several releases of the same product -- .NET is the usual culprit --
	 * and each is counted once per asset, so the number is "machines to
	 * visit", not "installations".
	 *
	 * @return array<int,array<string,mixed>>
	 */
	/**
	 * The newest still-supported release of each product, keyed by CPE.
	 *
	 * The lifecycle table tracks release branches, not products: OpenSSL has
	 * eight rows in it, six of them expired and two current. Without this,
	 * every expired branch reads as "the vendor has stopped shipping fixes",
	 * which for OpenSSL 3.0 is true of the branch and badly wrong about the
	 * product -- 3.5 LTS is supported until 2030 and the remediation is an
	 * upgrade, not a migration.
	 *
	 * A product with no supported release left is the genuinely retired case,
	 * and the two want different words and different urgency.
	 *
	 * @return array<string,array<string,mixed>> cpe => the newest supported row.
	 */
	public static function supported_releases(): array {
		$best = array();

		foreach ( self::table() as $row ) {
			$cpe = (string) ( $row['cpe'] ?? '' );

			if ( '' === $cpe ) {
				continue;
			}

			$eol = trim( (string) ( $row['eol'] ?? '' ) );

			// No date means "no announced end", which counts as supported.
			if ( '' !== $eol && strtotime( $eol ) <= time() ) {
				continue;
			}

			$ends = '' === $eol ? PHP_INT_MAX : (int) strtotime( $eol );

			if ( ! isset( $best[ $cpe ] ) || $ends > (int) $best[ $cpe ]['_ends'] ) {
				$row['_ends']  = $ends;
				$best[ $cpe ] = $row;
			}
		}

		return $best;
	}

	/**
	 * What to upgrade a lifecycle row to, if anything.
	 *
	 * @return array{release:string,eol:string,retired:bool}
	 */
	public static function upgrade_target( string $key ): array {
		$cpe = '';

		foreach ( self::table() as $row ) {
			if ( (string) ( $row['key'] ?? '' ) === $key ) {
				$cpe = (string) ( $row['cpe'] ?? '' );
				break;
			}
		}

		$supported = self::supported_releases();

		if ( '' === $cpe || ! isset( $supported[ $cpe ] ) ) {
			return array( 'release' => '', 'eol' => '', 'retired' => true );
		}

		$target = $supported[ $cpe ];

		// The row itself is the supported one: nothing to upgrade to.
		if ( (string) ( $target['key'] ?? '' ) === $key ) {
			return array( 'release' => '', 'eol' => '', 'retired' => false );
		}

		return array(
			'release' => (string) ( $target['release'] ?? '' ),
			'eol'     => (string) ( $target['eol'] ?? '' ),
			'retired' => false,
		);
	}

	public static function software(): array {
		global $wpdb;

		// Build the lookup once: cpe => list of rows, so the inner loop is a
		// hash hit rather than a scan of the whole table per CPE string.
		$by_cpe = array();

		foreach ( self::table() as $row ) {
			if ( 'software' !== $row['kind'] || '' === (string) $row['cpe'] ) {
				continue;
			}

			$by_cpe[ (string) $row['cpe'] ][] = $row;
		}

		if ( ! $by_cpe ) {
			return array();
		}

		$rows = (array) $wpdb->get_col( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			"SELECT software_json FROM " . vh_table( 'assets' )
			. ' WHERE lifecycle_status IN (' . vh_reportable_sql() . ')'
			. " AND software_json <> '' AND software_json <> '[]'", // phpcs:ignore
			0
		);

		$groups = array();

		foreach ( $rows as $json ) {
			$list = json_decode( (string) $json, true );

			if ( ! is_array( $list ) ) {
				continue;
			}

			$hit = array();

			foreach ( $list as $cpe ) {
				$parts = explode( ':', str_replace( '\\', '', (string) $cpe ) );

				// cpe : /a : vendor : product : version
				if ( count( $parts ) < 5 ) {
					continue;
				}

				$name = $parts[2] . ':' . $parts[3];

				if ( empty( $by_cpe[ $name ] ) ) {
					continue;
				}

				$version = $parts[4];
				$best    = null;

				foreach ( $by_cpe[ $name ] as $row ) {
					$pin = (string) $row['version'];

					if ( '' === $pin || ! self::version_matches( $version, $pin ) ) {
						continue;
					}

					if ( ! $best || strlen( $pin ) > strlen( (string) $best['version'] ) ) {
						$best = $row;
					}
				}

				if ( $best ) {
					$hit[ (string) $best['key'] ] = $best;
				}
			}

			foreach ( $hit as $key => $row ) {
				if ( ! isset( $groups[ $key ] ) ) {
					$groups[ $key ] = array(
						'key'        => $key,
						'kind'       => 'software',
						'label'      => (string) $row['product'],
						'release'    => (string) $row['release'],
						'eol'        => (string) $row['eol'],
						'mainstream' => (string) $row['mainstream'],
						'note'       => (string) $row['note'],
						'assets'     => 0,
						'matched'    => true,
					);
				}

				++$groups[ $key ]['assets'];
			}
		}

		return self::finish( $groups );
	}

	/**
	 * Hardware support expiry, straight from the CMDB's own column.
	 *
	 * Deliberately not merged into the platform counts: this is a warranty
	 * date. A machine out of warranty still gets security updates, and a
	 * machine on a current OS can still be a device nobody will repair.
	 *
	 * @return array<int,array{key:string,label:string,assets:int,status:string,tone:string}>
	 */
	public static function hardware(): array {
		global $wpdb;

		$today = gmdate( 'Y-m-d' );
		$soon  = gmdate( 'Y-m-d', strtotime( $today . ' +90 days' ) ?: time() );

		$row = $wpdb->get_row( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->prepare(
				'SELECT'
				. ' SUM(support_end_date IS NOT NULL AND support_end_date < %s) AS expired,'
				. ' SUM(support_end_date IS NOT NULL AND support_end_date >= %s AND support_end_date <= %s) AS soon,'
				. ' SUM(support_end_date IS NOT NULL AND support_end_date > %s) AS covered,'
				. ' SUM(support_end_date IS NULL) AS unknown'
				. ' FROM ' . vh_table( 'assets' ) // phpcs:ignore
				. ' WHERE lifecycle_status IN (' . vh_reportable_sql() . ')', // phpcs:ignore
				$today,
				$today,
				$soon,
				$soon
			),
			ARRAY_A
		);

		$row = is_array( $row ) ? $row : array();

		return array(
			array(
				'key'    => 'expired',
				'label'  => __( 'Out of hardware support', 'vulnhub' ),
				'assets' => (int) ( $row['expired'] ?? 0 ),
				'status' => 'past',
				'tone'   => 'critical',
			),
			array(
				'key'    => 'soon',
				'label'  => __( 'Expires within 90 days', 'vulnhub' ),
				'assets' => (int) ( $row['soon'] ?? 0 ),
				'status' => 'soon',
				'tone'   => 'high',
			),
			array(
				'key'    => 'covered',
				'label'  => __( 'Under support', 'vulnhub' ),
				'assets' => (int) ( $row['covered'] ?? 0 ),
				'status' => 'supported',
				'tone'   => 'good',
			),
			array(
				'key'    => 'unknown',
				'label'  => __( 'No support date recorded', 'vulnhub' ),
				'assets' => (int) ( $row['unknown'] ?? 0 ),
				'status' => 'unknown',
				'tone'   => 'muted',
			),
		);
	}

	/**
	 * Add the status to each group and sort by how urgent it is.
	 *
	 * @param array<string,array<string,mixed>> $groups Grouped rows.
	 * @return array<int,array<string,mixed>>
	 */
	private static function finish( array $groups ): array {
		$out = array();

		$supported = self::supported_releases();

		foreach ( $groups as $group ) {
			$state = self::status( (string) $group['eol'] );

			/*
			 * Where this row's product still has a supported release, say so.
			 * An expired branch of a living product is an upgrade; a product
			 * with nothing supported left is a migration. Reporting both as
			 * "past end of life" overstates the first and buries the second.
			 */
			$target  = self::upgrade_target( (string) ( $group['key'] ?? '' ) );
			$retired = (bool) $target['retired'];

			// Not array_merge: status() carries its own `label`, and the
			// group's label is the product name. Merging blindly renamed
			// every platform to "Past end of life".
			$out[] = array_merge(
				$group,
				array(
					'status'       => $state['status'],
					'status_label' => $state['label'],
					'tone'         => $state['tone'],
					'days'         => $state['days'],
					'upgrade_to'   => (string) $target['release'],
					'upgrade_eol'  => (string) $target['eol'],
					'retired'      => $retired,
				)
			);
		}

		$rank = array( 'past' => 0, 'soon' => 1, 'unknown' => 2, 'supported' => 3 );

		usort(
			$out,
			static function ( array $a, array $b ) use ( $rank ): int {
				$ra = $rank[ $a['status'] ] ?? 9;
				$rb = $rank[ $b['status'] ] ?? 9;

				if ( $ra !== $rb ) {
					return $ra <=> $rb;
				}

				// Within a bucket, the biggest population first: that is the
				// one somebody has to plan a project around.
				return (int) $b['assets'] <=> (int) $a['assets'];
			}
		);

		return $out;
	}

	/**
	 * The assets behind one estate() row, so a chart segment can be clicked.
	 *
	 * @return array<int,int>
	 */
	public static function asset_ids( string $key ): array {
		global $wpdb;

		$rows = (array) $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			'SELECT id, operating_system, os_version, asset_type FROM ' . vh_table( 'assets' )
			. ' WHERE lifecycle_status IN (' . vh_reportable_sql() . ')', // phpcs:ignore
			ARRAY_A
		);

		$out = array();

		foreach ( $rows as $asset ) {
			$row = self::match_os( $asset );

			if ( $row ) {
				$found = (string) $row['key'];
			} else {
				$found = 'unknown:' . Os::parse( (string) $asset['operating_system'] )['family'];
			}

			if ( $found === $key ) {
				$out[] = (int) $asset['id'];
			}
		}

		return $out;
	}

	/**
	 * Reportable assets whose OPERATING SYSTEM is past vendor support.
	 *
	 * This is the OS half of "end of life": the machine is running a Windows
	 * or Linux release the vendor has stopped shipping patches for, so a
	 * missing-OS-update finding on it can never actually be fixed. It is
	 * deliberately the OS only -- a machine that merely carries one retired
	 * library is not itself an end-of-life platform, and treating it as one
	 * swept every current finding on that box (a Server 2025 update with a
	 * patch waiting) into the EOL list. That was the whole bug.
	 *
	 * Memoised for the request; the findings list asks for it twice (count
	 * then rows) and the answer cannot change between them.
	 *
	 * @return array<int,int> Asset ids.
	 */
	public static function eol_os_asset_ids(): array {
		static $cache = null;

		if ( null !== $cache ) {
			return $cache;
		}

		global $wpdb;

		$rows = (array) $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			'SELECT id, operating_system, os_version, asset_type FROM ' . vh_table( 'assets' )
			. ' WHERE lifecycle_status IN (' . vh_reportable_sql() . ')', // phpcs:ignore
			ARRAY_A
		);

		$out = array();

		foreach ( $rows as $asset ) {
			$osrow = self::match_os( $asset );

			if ( $osrow && 'past' === self::status( (string) $osrow['eol'] )['status'] ) {
				$out[] = (int) $asset['id'];
			}
		}

		$cache = $out;

		return $out;
	}

	/**
	 * The vulnerability definitions that are themselves end-of-life findings.
	 *
	 * This is the SOFTWARE half of "end of life": Tenable ships explicit
	 * detections for discontinued software -- "Apache Log4j SEoL", "Mozilla
	 * Firefox SEoL", "Microsoft SQL Server Unsupported Version Detection" --
	 * whose whole point is that the product itself is retired, not merely a
	 * version that needs updating. Those are the findings a reader means by
	 * "the software is discontinued"; a routine "libcurl < 8.18.0" is not one
	 * and must not appear under the EOL filter just because it shares a host
	 * with a retired product.
	 *
	 * @return array<int,int> Vulnerability ids.
	 */
	public static function seol_vuln_ids(): array {
		static $cache = null;

		if ( null !== $cache ) {
			return $cache;
		}

		global $wpdb;

		$ids = (array) $wpdb->get_col(
			$wpdb->prepare(
				'SELECT id FROM ' . vh_table( 'vulns' ) . ' WHERE title REGEXP %s',
				'SEoL|End of Life|End-of-Life|Unsupported Version|End of Support|no longer supported'
			)
		);

		$cache = array_map( 'intval', $ids );

		return $cache;
	}

	/**
	 * Is one finding end of life, at the level of the finding rather than the
	 * host? True when the vulnerability is a discontinued-software detection,
	 * or when it is a missing-OS-update on a machine whose OS is past support.
	 * Everything else -- a patchable product, an OS-update on a live OS -- is
	 * in support, whatever else happens to be installed on the same machine.
	 *
	 * The two lookups are flipped to hash sets on first use and memoised, so
	 * calling this per row across a page of findings stays cheap.
	 *
	 * @param int    $asset_id        The finding's asset.
	 * @param int    $vuln_id         The finding's vulnerability.
	 * @param string $component_class The vulnerability's class (os_windows / os_linux / third_party).
	 */
	public static function finding_is_eol( int $asset_id, int $vuln_id, string $component_class ): bool {
		static $os_flip = null;
		static $sv_flip = null;

		if ( null === $os_flip ) {
			$os_flip = array_flip( self::eol_os_asset_ids() );
		}
		if ( null === $sv_flip ) {
			$sv_flip = array_flip( self::seol_vuln_ids() );
		}

		if ( isset( $sv_flip[ $vuln_id ] ) ) {
			return true;
		}

		return isset( $os_flip[ $asset_id ] )
			&& in_array( $component_class, array( 'os_windows', 'os_linux' ), true );
	}

	/**
	 * Headline counts for the widget: assets per status, platforms only.
	 *
	 * @return array<string,int>
	 */
	/**
	 * @param array<int,array<string,mixed>>|null $rows Estate rows already in
	 *        hand. Pass them whenever the caller is also drawing those rows:
	 *        estate() re-reads the asset table, and a connector sync writing
	 *        to it between the two reads leaves the summary tiles disagreeing
	 *        with the chart printed directly beneath them.
	 */
	public static function summary( ?array $rows = null ): array {
		$out = array( 'past' => 0, 'soon' => 0, 'supported' => 0, 'unknown' => 0 );

		foreach ( $rows ?? self::estate() as $row ) {
			$out[ $row['status'] ] += (int) $row['assets'];
		}

		return $out;
	}
}

