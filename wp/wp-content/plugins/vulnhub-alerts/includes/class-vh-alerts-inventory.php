<?php
/**
 * What we actually run, in a shape advisories can be tested against.
 *
 * Built from the CPE strings the scanner already collects, so it is the same
 * identifier both sides of the comparison. Roughly 58,000 CPE strings across
 * the estate collapse to a couple of hundred vendor/product pairs, which is
 * small enough to hold in memory and cheap enough to rebuild whenever the
 * inventory changes.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Alerts_Inventory {

	private const CACHE_KEY = 'vulnhub_alerts_inventory';
	private const TTL       = 6 * HOUR_IN_SECONDS;

	/** @var array<string,mixed>|null Per-request memo. */
	private static ?array $memo = null;

	/**
	 * The index.
	 *
	 *   products[vendor|product] => array of installed versions with asset ids
	 *   names[normalised product name] => vendor|product key
	 *   vendors[vendor] => asset-weighted count
	 *   os[family] => asset ids
	 *
	 * @return array<string,mixed>
	 */
	public static function index(): array {
		if ( null !== self::$memo ) {
			return self::$memo;
		}

		$cached = get_transient( self::CACHE_KEY );

		if ( is_array( $cached ) && isset( $cached['products'] ) ) {
			self::$memo = $cached;

			return $cached;
		}

		$index = self::build();

		set_transient( self::CACHE_KEY, $index, self::TTL );
		self::$memo = $index;

		return $index;
	}

	public static function flush(): void {
		delete_transient( self::CACHE_KEY );
		self::$memo = null;
	}

	/** @return array<string,mixed> */
	private static function build(): array {
		global $wpdb;

		$assets = $wpdb->prefix . 'vulnhub_assets';

		// In-scope only. An advisory affecting a decommissioned server is a
		// history lesson, not an alert.
		$rows = $wpdb->get_results(
			"SELECT id, software_json, operating_system, os_version
			   FROM {$assets}
			  WHERE lifecycle_status NOT IN ('retired','disposed','decommissioned')",
			ARRAY_A
		);

		$products = array();
		$names    = array();
		$vendors  = array();
		$os       = array();

		foreach ( (array) $rows as $row ) {
			$asset_id = (int) $row['id'];

			foreach ( self::cpes( (string) ( $row['software_json'] ?? '' ) ) as $cpe ) {
				$key = $cpe['vendor'] . '|' . $cpe['product'];

				if ( ! isset( $products[ $key ] ) ) {
					$products[ $key ] = array(
						'vendor'   => $cpe['vendor'],
						'product'  => $cpe['product'],
						'versions' => array(),
						'assets'   => array(),
					);
				}

				$products[ $key ]['assets'][ $asset_id ]                     = true;
				$products[ $key ]['versions'][ $cpe['version'] ][ $asset_id ] = true;

				$vendors[ $cpe['vendor'] ] = ( $vendors[ $cpe['vendor'] ] ?? 0 ) + 1;

				$names[ self::normalise( $cpe['product'] ) ] = $key;
			}

			$family = self::os_family( (string) ( $row['operating_system'] ?? '' ) );

			if ( '' !== $family ) {
				$os[ $family ][ $asset_id ] = true;
			}
		}

		arsort( $vendors );

		return array(
			'products' => $products,
			'names'    => $names,
			'vendors'  => $vendors,
			'os'       => $os,
			'built_at' => time(),
		);
	}

	/**
	 * Pull vendor, product and version out of the stored CPE list.
	 *
	 * Handles both CPE 2.2 (`cpe:/a:vendor:product:version`) and 2.3
	 * (`cpe:2.3:a:vendor:product:version:...`), because the importers store
	 * whatever the source gave them and both turn up in this column.
	 *
	 * @return array<int,array{vendor:string,product:string,version:string}>
	 */
	private static function cpes( string $json ): array {
		if ( '' === $json ) {
			return array();
		}

		$list = json_decode( $json, true );

		if ( ! is_array( $list ) ) {
			return array();
		}

		$out = array();

		foreach ( $list as $raw ) {
			$cpe = str_replace( '\\/', '/', (string) $raw );

			if ( preg_match( '~^cpe:2\.3:[aoh]:([^:]+):([^:]+):([^:]*)~i', $cpe, $m )
				|| preg_match( '~^cpe:/[aoh]:([^:]+):([^:]+):?([^:]*)~i', $cpe, $m ) ) {

				$vendor  = self::normalise( $m[1] );
				$product = self::normalise( $m[2] );

				if ( '' === $vendor || '' === $product ) {
					continue;
				}

				$out[] = array(
					'vendor'  => $vendor,
					'product' => $product,
					'version' => trim( (string) ( $m[3] ?? '' ) ),
				);
			}
		}

		return $out;
	}

	/**
	 * One spelling for a name that four systems spell four ways.
	 * "Microsoft Edge", "microsoft_edge" and "MICROSOFT EDGE" are one thing.
	 */
	public static function normalise( string $value ): string {
		$value = strtolower( trim( $value ) );
		$value = str_replace( array( '_', '-', '+' ), ' ', $value );
		$value = preg_replace( '/[^a-z0-9. ]+/', ' ', $value ) ?? '';
		$value = preg_replace( '/\s+/', ' ', $value ) ?? '';

		return trim( $value );
	}

	/** @return string[] */
	public static function top_vendors( int $limit = 25 ): array {
		$vendors = self::index()['vendors'] ?? array();

		return array_slice( array_keys( $vendors ), 0, max( 1, $limit ) );
	}

	/**
	 * Which products we run are named in this text?
	 *
	 * Used by the RSS and JSON adapters, where the only product signal is the
	 * advisory title. Short names are skipped: "ie" and "go" appear inside
	 * ordinary English words, and a false match here becomes a false alert.
	 *
	 * @return array<int,array{vendor:string,product:string,key:string}>
	 */
	public static function products_named_in( string $text ): array {
		$haystack = ' ' . self::normalise( $text ) . ' ';
		$index    = self::index();
		$out      = array();

		foreach ( $index['names'] as $name => $key ) {
			if ( strlen( $name ) < 5 ) {
				continue;
			}

			if ( ! str_contains( $haystack, ' ' . $name . ' ' )
				&& ! str_contains( $haystack, ' ' . $name . 's ' ) ) {
				continue;
			}

			$entry = $index['products'][ $key ] ?? null;

			if ( $entry ) {
				$out[] = array(
					'vendor'  => $entry['vendor'],
					'product' => $entry['product'],
					'key'     => $key,
				);
			}
		}

		return $out;
	}

	/**
	 * The OS family an advisory could plausibly be about.
	 * Deliberately coarse -- this is the weakest tier of matching and it
	 * should not pretend to more precision than it has.
	 */
	public static function os_family( string $os ): string {
		$o = strtolower( $os );

		if ( '' === trim( $o ) ) {
			return '';
		}

		foreach ( array(
			'windows server' => array( 'windows server' ),
			'windows'        => array( 'windows' ),
			'rhel'           => array( 'red hat', 'rhel' ),
			'ubuntu'         => array( 'ubuntu' ),
			'debian'         => array( 'debian' ),
			'suse'           => array( 'suse', 'sles' ),
			'linux'          => array( 'linux', 'centos', 'rocky', 'almalinux', 'oracle linux' ),
			'macos'          => array( 'macos', 'mac os', 'darwin' ),
			'esxi'           => array( 'esxi', 'vmware' ),
			'aix'            => array( 'aix', 'vios' ),
		) as $family => $needles ) {
			foreach ( $needles as $needle ) {
				if ( str_contains( $o, $needle ) ) {
					return $family;
				}
			}
		}

		return '';
	}

	/** Rebuild after an import changes what we run. */
	public static function init(): void {
		add_action( 'vulnhub_import_completed', array( __CLASS__, 'flush' ) );
		add_action( 'vulnhub_coverage_recalculated', array( __CLASS__, 'flush' ) );
	}
}
