<?php
/**
 * Names and edge coverage that AWS cannot tell us about.
 *
 * The Route 53 reader next door only sees the zones hosted in the AWS
 * accounts this login can read, which is the smaller half of the estate's
 * DNS. The authoritative zones live with the DNS provider, and the web
 * application firewall in front of the public estate is a CDN's, not AWS's
 * -- so neither the real names nor the real edge coverage is reachable from
 * an AWS API at all.
 *
 * This class imports both from operator-supplied exports and puts them in
 * the same store the AWS readers write to, so one question -- "what is this
 * called, and what stands in front of it" -- has one answer regardless of
 * which system happens to know it.
 *
 * Two imports:
 *
 *   1. **Zone files** in the usual master-file format, one per zone. Only
 *      A, AAAA and CNAME are kept: they are the records that name a
 *      resource. Every target goes through the same matcher the AWS reader
 *      uses, so a name resolving to an address or a load balancer we hold
 *      is tied to it.
 *   2. **An edge WAF hostname export**, listing each hostname the CDN
 *      serves, whether a security configuration covers it, and which
 *      policy. That is the only record of what is actually protected.
 *
 * Both are point-in-time drops, not live feeds, so every row carries the
 * file it came from and when it was imported, and the page must say so
 * rather than implying the picture is current.
 *
 * On data: these imports carry real hostnames and real addresses. They live
 * in the database and nowhere else -- never in a fixture, a doc, a test or
 * a commit message. See CLAUDE.md, Data hygiene.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Domain_Import {

	private const DB_VERSION = '4';
	private const OPT_DB     = 'vulnhub_domain_import_db';

	/** Record types that name a resource. The rest describe the zone. */
	private const KEEP = array( 'A', 'AAAA', 'CNAME' );

	public static function waf_table(): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_waf_coverage';
	}

	public static function property_table(): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_edge_properties';
	}

	public static function catalog_table(): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_service_catalog';
	}

	public static function install(): void {
		if ( self::DB_VERSION === (string) get_option( self::OPT_DB, '' ) ) {
			return;
		}

		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$t       = self::waf_table();

		dbDelta(
			"CREATE TABLE {$t} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				hostname varchar(255) NOT NULL DEFAULT '',
				covered tinyint(1) NOT NULL DEFAULT 0,
				status varchar(32) NOT NULL DEFAULT '',
				config varchar(190) NOT NULL DEFAULT '',
				policy varchar(255) NOT NULL DEFAULT '',
				has_match tinyint(1) NOT NULL DEFAULT 0,
				source varchar(64) NOT NULL DEFAULT '',
				imported_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				UNIQUE KEY host (hostname),
				KEY cov (covered)
			) {$charset};"
		);

		dbDelta(
			"CREATE TABLE " . self::property_table() . " (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				property varchar(190) NOT NULL DEFAULT '',
				origin varchar(255) NOT NULL DEFAULT '',
				origin_type varchar(48) NOT NULL DEFAULT '',
				siteshield varchar(190) NOT NULL DEFAULT '',
				prod_version varchar(24) NOT NULL DEFAULT '',
				hostnames int(10) unsigned NOT NULL DEFAULT 0,
				matched_kind varchar(24) NOT NULL DEFAULT '',
				matched_ref varchar(128) NOT NULL DEFAULT '',
				matched_name varchar(255) NOT NULL DEFAULT '',
				source varchar(64) NOT NULL DEFAULT '',
				imported_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				UNIQUE KEY prop (property),
				KEY og (origin)
			) {$charset};"
		);

		/*
		 * What a hostname *is*.
		 *
		 * Everything else in this plugin reads machines: a name resolves to a
		 * load balancer in an account, which carries a policy or does not.
		 * None of it can say that the name is a market-integration gateway, or
		 * that it is the pre-production one -- and that is the difference
		 * between "71 hostnames have no WAF policy" and a sentence somebody
		 * can act on. The environment in particular was being guessed from the
		 * spelling of the name; here it is stated by whoever owns the service.
		 *
		 * Operator-supplied, like the zone files: nothing discovers this.
		 */
		dbDelta(
			"CREATE TABLE " . self::catalog_table() . " (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				hostname varchar(255) NOT NULL DEFAULT '',
				system varchar(190) NOT NULL DEFAULT '',
				component varchar(190) NOT NULL DEFAULT '',
				environment varchar(32) NOT NULL DEFAULT '',
				purpose text NOT NULL,
				architecture text NOT NULL,
				source varchar(64) NOT NULL DEFAULT '',
				imported_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				UNIQUE KEY host (hostname),
				KEY env (environment),
				KEY sys (system)
			) {$charset};"
		);

		update_option( self::OPT_DB, self::DB_VERSION, false );
	}

	/* =================================================================
	 * The service catalogue
	 * ============================================================== */

	/**
	 * Import a hostname -> service table.
	 *
	 * Tab-separated, one row per hostname:
	 * hostname, system, component, environment, purpose, architecture.
	 * A header row is skipped; rows with no hostname are counted, not
	 * guessed at. Environments are normalised to a small set so the pages
	 * can colour them; anything unrecognised is kept verbatim rather than
	 * forced into one.
	 *
	 * The file lives outside the git checkout on purpose -- it is a list of
	 * real hostnames and real system names, and this repository is public.
	 *
	 * @return array{rows:int,skipped:int}
	 */
	public static function import_catalog_tsv( string $path ): array {
		$lines = @file( $path, FILE_IGNORE_NEW_LINES ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		if ( false === $lines ) {
			return array( 'rows' => 0, 'skipped' => 0 );
		}

		$rows    = array();
		$skipped = 0;

		foreach ( $lines as $line ) {
			$line = trim( $line );

			if ( '' === $line || '#' === $line[0] ) {
				continue;
			}

			$cols = array_map( 'trim', explode( "	", $line ) );
			$host = strtolower( rtrim( (string) ( $cols[0] ?? '' ), '.' ) );

			if ( '' === $host || 'hostname' === $host ) {
				++$skipped;
				continue;
			}

			$rows[ $host ] = array(
				'hostname'     => $host,
				'system'       => (string) ( $cols[1] ?? '' ),
				'component'    => (string) ( $cols[2] ?? '' ),
				'environment'  => self::environment_label( (string) ( $cols[3] ?? '' ) ),
				'purpose'      => (string) ( $cols[4] ?? '' ),
				'architecture' => (string) ( $cols[5] ?? '' ),
			);
		}

		return array( 'rows' => self::store_catalog( array_values( $rows ), 'confluence' ), 'skipped' => $skipped );
	}

	/**
	 * Normalise an environment word.
	 *
	 * Production is the one that has to be right -- it is what turns a
	 * missing policy from a note into a finding -- so the spellings people
	 * actually write are mapped, and anything else is kept as given rather
	 * than quietly relabelled.
	 */
	public static function environment_label( string $raw ): string {
		$key = strtolower( trim( $raw ) );

		$map = array(
			'prod'           => 'production',
			'production'     => 'production',
			'preprod'        => 'pre-production',
			'pre-production' => 'pre-production',
			'pprd'           => 'pre-production',
			'preprod2'       => 'pre-production 2',
			'uat'            => 'uat',
			'sit'            => 'sit',
			'dev'            => 'development',
			'development'    => 'development',
			'sandbox'        => 'development',
			'test'           => 'test',
		);

		return $map[ $key ] ?? trim( $raw );
	}

	/**
	 * Replace the catalogue for one source.
	 *
	 * @param array<int,array<string,string>> $rows Catalogue rows.
	 * @return int Rows written.
	 */
	public static function store_catalog( array $rows, string $source ): int {
		global $wpdb;

		self::install();

		$table = self::catalog_table();
		$now   = vh_now();

		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . $table . ' WHERE source = %s', $source ) ); // phpcs:ignore WordPress.DB

		$n = 0;

		foreach ( $rows as $row ) {
			if ( '' === (string) ( $row['hostname'] ?? '' ) ) {
				continue;
			}

			$ok = $wpdb->replace( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				$table,
				array(
					'hostname'     => (string) $row['hostname'],
					'system'       => (string) ( $row['system'] ?? '' ),
					'component'    => (string) ( $row['component'] ?? '' ),
					'environment'  => (string) ( $row['environment'] ?? '' ),
					'purpose'      => (string) ( $row['purpose'] ?? '' ),
					'architecture' => (string) ( $row['architecture'] ?? '' ),
					'source'       => $source,
					'imported_at'  => $now,
				)
			);

			if ( false !== $ok ) {
				++$n;
			}
		}

		return $n;
	}

	/**
	 * The catalogue, keyed by hostname.
	 *
	 * Read whole rather than per name: sixty rows is nothing beside a query
	 * for each hostname on a page that lists hundreds.
	 *
	 * @return array<string,array<string,string>>
	 */
	public static function catalog(): array {
		global $wpdb;

		static $cache = null;

		if ( null !== $cache ) {
			return $cache;
		}

		$rows  = (array) $wpdb->get_results( 'SELECT hostname, system, component, environment, purpose, architecture FROM ' . self::catalog_table(), ARRAY_A ); // phpcs:ignore WordPress.DB
		$cache = array();

		foreach ( $rows as $row ) {
			$cache[ strtolower( (string) $row['hostname'] ) ] = $row;
		}

		return $cache;
	}

	/** What the catalogue holds, for the sources note. */
	public static function catalog_summary(): array {
		global $wpdb;

		$table = self::catalog_table();

		return array(
			'rows'        => (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . $table ), // phpcs:ignore WordPress.DB
			'systems'     => (int) $wpdb->get_var( 'SELECT COUNT(DISTINCT system) FROM ' . $table ), // phpcs:ignore WordPress.DB
			'production'  => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE environment = 'production'" ), // phpcs:ignore WordPress.DB
			'imported_at' => (string) $wpdb->get_var( 'SELECT MAX(imported_at) FROM ' . $table ), // phpcs:ignore WordPress.DB
		);
	}

	/* =================================================================
	 * Edge properties, typed in by hand
	 * ============================================================== */

	/**
	 * Import a property / origin / hostname table.
	 *
	 * The CDN's console has no export on the property list and bulk search
	 * is API-only, so where nobody holds an API client this is transcribed
	 * by hand. The parser is deliberately forgiving about that: any of tab,
	 * comma or a run of two spaces separates columns, a header row is
	 * skipped, blank origins inherit from the last row of the same
	 * property, and order does not matter -- a person copying 45 screens
	 * should not have their hour wasted by a delimiter.
	 *
	 * Expected columns: property, origin, hostname, and optionally the
	 * production version. Each row is one hostname.
	 *
	 * @return array{properties:int,hostnames:int,matched:int,skipped:int}
	 */
	public static function import_properties( string $path ): array {
		$lines = @file( $path, FILE_IGNORE_NEW_LINES ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		if ( false === $lines ) {
			return array(
				'properties' => 0,
				'hostnames'  => 0,
				'matched'    => 0,
				'skipped'    => 0,
			);
		}

		$props   = array();
		$rows    = array();
		$skipped = 0;
		$last    = '';

		foreach ( $lines as $line ) {
			$line = trim( (string) $line );

			if ( '' === $line || 0 === strpos( $line, '#' ) ) {
				continue;
			}

			$cols = preg_split( '/\t|,|\s{2,}/', $line );
			$cols = false === $cols ? array() : array_values( array_filter( array_map( 'trim', $cols ), static fn( string $c ): bool => '' !== $c ) );

			if ( count( $cols ) < 2 ) {
				++$skipped;
				continue;
			}

			// A header row names itself.
			if ( 0 === strcasecmp( $cols[0], 'property' ) ) {
				continue;
			}

			$property = $cols[0];
			$origin   = strtolower( rtrim( $cols[1], '.' ) );
			$hostname = isset( $cols[2] ) ? strtolower( rtrim( $cols[2], '.' ) ) : '';
			$version  = isset( $cols[3] ) ? $cols[3] : '';
			$otype    = isset( $cols[4] ) ? $cols[4] : '';
			$shield   = isset( $cols[5] ) ? $cols[5] : '';

			// A row that repeats the property to add another hostname may
			// leave the origin out; carry the last one forward.
			if ( '' === $hostname && '' !== $origin && $property === $last ) {
				$hostname = $origin;
				$origin   = (string) ( $props[ $property ]['origin'] ?? '' );
			}

			$last = $property;

			if ( ! isset( $props[ $property ] ) ) {
				$props[ $property ] = array(
					'origin'  => $origin,
					'version' => $version,
					'otype'   => $otype,
					'shield'  => $shield,
					'hosts'   => 0,
				);
			}

			if ( '' === $props[ $property ]['origin'] && '' !== $origin ) {
				$props[ $property ]['origin'] = $origin;
			}

			if ( '' === $hostname ) {
				continue;
			}

			++$props[ $property ]['hosts'];

			/*
			 * The ROW's origin wins, not the property's. A property
			 * routinely sends each hostname to its own origin -- one per
			 * environment -- and collapsing them onto the property's first
			 * origin silently reassigns dev, sit and preprod names to the
			 * production server. The property-level origin is only the
			 * default, used where a row does not carry one.
			 */
			$og     = '' !== $origin ? $origin : (string) $props[ $property ]['origin'];
			$match  = '' !== $og ? VulnHub_AWS_Domains::classify( $og ) : array(
				'kind' => '',
				'ref'  => '',
				'name' => '',
			);
			$rows[] = array(
				'source'       => 'akamai',
				'zone'         => '',
				'name'         => $hostname,
				'record_type'  => 'PROPERTY',
				'target'       => $og,
				'private'      => 0,
				'matched_kind' => (string) $match['kind'],
				'matched_ref'  => (string) $match['ref'],
				'matched_name' => (string) $match['name'],
				'detail'       => array(
					'property'   => $property,
					'version'    => (string) $props[ $property ]['version'],
					'originType' => (string) $props[ $property ]['otype'],
					'siteshield' => (string) $props[ $property ]['shield'],
				),
			);
		}

		return self::store_properties( $props, $rows, basename( $path ), $skipped );
	}

	/**
	 * Store a property/origin set, however it was obtained.
	 *
	 * Split out from the file importer so the live connector writes through
	 * exactly the same path a hand-typed import does -- two ways in with two
	 * storage routines is how the two quietly start disagreeing.
	 *
	 * @param array<string,array<string,mixed>> $props Properties keyed by name.
	 * @param array<int,array<string,mixed>>    $rows  One row per hostname.
	 * @return array{properties:int,hostnames:int,matched:int,skipped:int}
	 */
	public static function store_properties( array $props, array $rows, string $source, int $skipped = 0 ): array {
		global $wpdb;

		$now = gmdate( 'Y-m-d H:i:s' );

		$wpdb->query( 'DELETE FROM ' . self::property_table() ); // phpcs:ignore WordPress.DB

		foreach ( $props as $name => $p ) {
			$match = '' !== (string) $p['origin'] ? VulnHub_AWS_Domains::classify( (string) $p['origin'] ) : array(
				'kind' => '',
				'ref'  => '',
				'name' => '',
			);

			$wpdb->query( // phpcs:ignore WordPress.DB
				$wpdb->prepare(
					'INSERT INTO ' . self::property_table() . ' (property,origin,origin_type,siteshield,prod_version,hostnames,matched_kind,matched_ref,matched_name,source,imported_at)
					 VALUES (%s,%s,%s,%s,%s,%d,%s,%s,%s,%s,%s)
					 ON DUPLICATE KEY UPDATE origin=VALUES(origin), origin_type=VALUES(origin_type), siteshield=VALUES(siteshield),
					   prod_version=VALUES(prod_version), hostnames=VALUES(hostnames),
					   matched_kind=VALUES(matched_kind), matched_ref=VALUES(matched_ref), matched_name=VALUES(matched_name), imported_at=VALUES(imported_at)',
					vh_trim( (string) $name, 185 ),
					vh_trim( (string) $p['origin'], 250 ),
					vh_trim( (string) $p['otype'], 44 ),
					vh_trim( (string) $p['shield'], 185 ),
					vh_trim( (string) $p['version'], 20 ),
					(int) $p['hosts'],
					(string) $match['kind'],
					vh_trim( (string) $match['ref'], 120 ),
					vh_trim( (string) $match['name'], 250 ),
					vh_trim( $source, 60 ),
					$now
				)
			);
		}

		$written = VulnHub_AWS_Domains::replace_source( 'akamai', $rows, '', count( $props ), $now );

		return array(
			'properties' => count( $props ),
			'hostnames'  => $written,
			'matched'    => count( array_filter( $rows, static fn( array $r ): bool => '' !== (string) $r['matched_kind'] ) ),
			'skipped'    => $skipped,
		);
	}

	/* =================================================================
	 * Zone files
	 * ============================================================== */

	/**
	 * Import every `*.zone` file in a directory, replacing what we hold.
	 *
	 * @return array{zones:int,records:int,matched:int}
	 */
	public static function import_zone_dir( string $dir ): array {
		$files = glob( rtrim( $dir, '/' ) . '/*.zone' );
		$files = false === $files ? array() : $files;
		$rows  = array();

		foreach ( $files as $path ) {
			$rows = array_merge( $rows, self::parse_zone( $path ) );
		}

		$now     = gmdate( 'Y-m-d H:i:s' );
		$written = VulnHub_AWS_Domains::replace_source( 'zonefile', $rows, '', count( $files ), $now );

		return array(
			'zones'   => count( $files ),
			'records' => $written,
			'matched' => count( array_filter( $rows, static fn( array $r ): bool => '' !== (string) $r['matched_kind'] ) ),
		);
	}

	/**
	 * One zone file into rows for the shared store.
	 *
	 * Master-file format: a record may omit the owner name, in which case it
	 * inherits the previous record's -- getting that wrong silently attaches
	 * records to the wrong host, so the last name is carried explicitly.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private static function parse_zone( string $path ): array {
		$zone  = strtolower( (string) preg_replace( '/\.zone$/', '', basename( $path ) ) );
		$lines = @file( $path, FILE_IGNORE_NEW_LINES ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		if ( false === $lines ) {
			return array();
		}

		$rows = array();
		$last = '';

		foreach ( $lines as $line ) {
			$line = trim( (string) $line );

			if ( '' === $line || 0 === strpos( $line, ';' ) ) {
				continue;
			}

			$parts = preg_split( '/\s+/', $line );
			$parts = false === $parts ? array() : $parts;
			$class = array_search( 'IN', $parts, true );

			if ( false === $class ) {
				continue;
			}

			$name = 0 === $class ? $last : strtolower( rtrim( (string) $parts[0], '.' ) );
			$last = $name;
			$type = strtoupper( (string) ( $parts[ $class + 1 ] ?? '' ) );

			if ( '' === $name || ! in_array( $type, self::KEEP, true ) ) {
				continue;
			}

			$value = strtolower( rtrim( trim( implode( ' ', array_slice( $parts, $class + 2 ) ) ), '.' ) );

			if ( '' === $value ) {
				continue;
			}

			$match  = VulnHub_AWS_Domains::classify( $value );
			$rows[] = array(
				'source'       => 'zonefile',
				'zone'         => $zone,
				'name'         => $name,
				'record_type'  => $type,
				'target'       => $value,
				'private'      => 0,
				'matched_kind' => (string) $match['kind'],
				'matched_ref'  => (string) $match['ref'],
				'matched_name' => (string) $match['name'],
				'detail'       => array( 'file' => basename( $path ) ),
			);
		}

		return $rows;
	}

	/* =================================================================
	 * Edge WAF hostname export
	 * ============================================================== */

	/**
	 * Import the CDN's hostname coverage export.
	 *
	 * Expected columns, by header name: Hostnames, Status, Web Security
	 * Configuration, Has Match Target Criteria, Policy Name. Matched by
	 * name rather than position, because an export with a column added in
	 * the middle should fail to find a column, not silently read the wrong
	 * one.
	 *
	 * @return array{rows:int,covered:int,uncovered:int}
	 */
	public static function import_waf_csv( string $path ): array {
		global $wpdb;

		$fh = @fopen( $path, 'r' ); // phpcs:ignore WordPress.WP.AlternativeFunctions,WordPress.PHP.NoSilencedErrors.Discouraged

		if ( false === $fh ) {
			return array(
				'rows'      => 0,
				'covered'   => 0,
				'uncovered' => 0,
			);
		}

		$head = fgetcsv( $fh );
		$head = is_array( $head ) ? array_map( static fn( $h ): string => strtolower( trim( (string) $h ) ), $head ) : array();
		$idx  = static fn( string $want ): int => (int) array_search( $want, $head, true );

		$host_at   = $idx( 'hostnames' );
		$status_at = $idx( 'status' );
		$config_at = $idx( 'web security configuration' );
		$match_at  = $idx( 'has match target criteria' );
		$policy_at = $idx( 'policy name' );

		if ( ! in_array( 'hostnames', $head, true ) ) {
			fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions

			return array(
				'rows'      => 0,
				'covered'   => 0,
				'uncovered' => 0,
			);
		}

		$now       = gmdate( 'Y-m-d H:i:s' );
		$source    = basename( $path );
		$rows      = 0;
		$covered   = 0;
		$uncovered = 0;

		$wpdb->query( 'DELETE FROM ' . self::waf_table() ); // phpcs:ignore WordPress.DB

		while ( false !== ( $line = fgetcsv( $fh ) ) ) {
			$host = strtolower( trim( (string) ( $line[ $host_at ] ?? '' ) ) );

			if ( '' === $host ) {
				continue;
			}

			$status = trim( (string) ( $line[ $status_at ] ?? '' ) );
			$is_cov = 0 === strcasecmp( $status, 'covered' );

			$wpdb->query( // phpcs:ignore WordPress.DB
				$wpdb->prepare(
					'INSERT INTO ' . self::waf_table() . ' (hostname,covered,status,config,policy,has_match,source,imported_at)
					 VALUES (%s,%d,%s,%s,%s,%d,%s,%s)
					 ON DUPLICATE KEY UPDATE covered=VALUES(covered), status=VALUES(status), config=VALUES(config),
					   policy=VALUES(policy), has_match=VALUES(has_match), source=VALUES(source), imported_at=VALUES(imported_at)',
					vh_trim( $host, 250 ),
					$is_cov ? 1 : 0,
					vh_trim( $status, 30 ),
					vh_trim( (string) ( $line[ $config_at ] ?? '' ), 185 ),
					vh_trim( (string) ( $line[ $policy_at ] ?? '' ), 250 ),
					0 === strcasecmp( trim( (string) ( $line[ $match_at ] ?? '' ) ), 'yes' ) ? 1 : 0,
					vh_trim( $source, 60 ),
					$now
				)
			);

			++$rows;
			$covered   += $is_cov ? 1 : 0;
			$uncovered += $is_cov ? 0 : 1;
		}

		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		return array(
			'rows'      => $rows,
			'covered'   => $covered,
			'uncovered' => $uncovered,
		);
	}

	/**
	 * Replace the edge WAF coverage table from live rows.
	 *
	 * @param array<int,array<string,mixed>> $rows hostname, covered, status, config, policy, has_match.
	 * @return array{rows:int,covered:int,uncovered:int}
	 */
	public static function store_waf( array $rows, string $source ): array {
		global $wpdb;

		$now       = gmdate( 'Y-m-d H:i:s' );
		$covered   = 0;
		$uncovered = 0;
		$written   = 0;

		$wpdb->query( 'DELETE FROM ' . self::waf_table() ); // phpcs:ignore WordPress.DB

		foreach ( $rows as $row ) {
			$host = strtolower( trim( (string) ( $row['hostname'] ?? '' ) ) );

			if ( '' === $host ) {
				continue;
			}

			$is_cov = ! empty( $row['covered'] );

			$wpdb->query( // phpcs:ignore WordPress.DB
				$wpdb->prepare(
					'INSERT INTO ' . self::waf_table() . ' (hostname,covered,status,config,policy,has_match,source,imported_at)
					 VALUES (%s,%d,%s,%s,%s,%d,%s,%s)
					 ON DUPLICATE KEY UPDATE covered=VALUES(covered), status=VALUES(status), config=VALUES(config),
					   policy=VALUES(policy), has_match=VALUES(has_match), source=VALUES(source), imported_at=VALUES(imported_at)',
					vh_trim( $host, 250 ),
					$is_cov ? 1 : 0,
					vh_trim( (string) ( $row['status'] ?? '' ), 30 ),
					vh_trim( (string) ( $row['config'] ?? '' ), 185 ),
					vh_trim( (string) ( $row['policy'] ?? '' ), 250 ),
					! empty( $row['has_match'] ) ? 1 : 0,
					vh_trim( $source, 60 ),
					$now
				)
			);

			++$written;
			$covered   += $is_cov ? 1 : 0;
			$uncovered += $is_cov ? 0 : 1;
		}

		return array(
			'rows'      => $written,
			'covered'   => $covered,
			'uncovered' => $uncovered,
		);
	}

	/* =================================================================
	 * What the two together can say
	 * ============================================================== */

	/**
	 * Names that look like they point at something that is no longer there.
	 *
	 * A CNAME to an AWS-shaped hostname that is not in our inventory is the
	 * classic dangling record: the resource was deleted and the name was
	 * left behind, which at best is dead and at worst is a subdomain
	 * somebody else can claim. This is deliberately a *candidate* list --
	 * proving a name is dead needs a resolution this system does not do,
	 * and the inventory only covers the accounts that sync -- so it is
	 * phrased as "worth checking", never as "dead".
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function dangling( int $limit = 200 ): array {
		global $wpdb;

		$t = VulnHub_AWS_Domains::table();

		return (array) $wpdb->get_results( // phpcs:ignore WordPress.DB
			$wpdb->prepare(
				"SELECT zone, name, record_type, target, matched_kind FROM {$t}
				 WHERE source = 'zonefile'
				   AND matched_ref = ''
				   AND (
				         target LIKE '%%.elb.%%amazonaws.com'
				      OR target LIKE '%%.execute-api.%%amazonaws.com'
				      OR target LIKE '%%.s3%%amazonaws.com'
				      OR target LIKE '%%.cloudfront.net'
				      OR target LIKE '%%.elasticbeanstalk.com'
				   )
				 ORDER BY zone, name LIMIT %d",
				$limit
			),
			ARRAY_A
		);
	}

	/**
	 * Names that reach the estate directly and are not behind the edge WAF.
	 *
	 * The test is deliberately narrow. A name qualifies only when it points
	 * at something of ours that serves traffic -- a load balancer, an API
	 * Gateway, an address we hold -- because those are the things a web
	 * application firewall is for; a name pointing at a SaaS product or a
	 * mail provider is somebody else's edge and none of our business. A
	 * name already CNAMEd to the CDN's edge is behind it whatever the
	 * export says, so those are excluded on the target rather than trusted
	 * to appear in the coverage list.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function unprotected( int $limit = 200 ): array {
		global $wpdb;

		$d = VulnHub_AWS_Domains::table();
		$w = self::waf_table();
		$n = VulnHub_AWS_Network::nodes_table();
		$r = VulnHub_AWS_Network::rules_table();

		/*
		 * Two tests decide this, and both had to be added after the first
		 * run produced a list nobody could have used.
		 *
		 * Internal or not. Most of these names point at an *internal* load
		 * balancer, reachable only from inside the network, and an edge
		 * firewall has nothing to do with those. That cut 40 to 12.
		 *
		 * Web or not. Of what was left, half were SFTP -- a network load
		 * balancer listening on tcp/22, and the host behind it. A *web*
		 * application firewall cannot protect SFTP, so naming those as
		 * "should be behind the WAF" is not a finding, it is a wrong
		 * answer. A balancer qualifies on its listeners, a machine on a
		 * security group opening 80 or 443 to the whole internet, and an
		 * API Gateway inherently.
		 *
		 * What is left is small and every row of it is arguable on its
		 * face, which is the only kind of list that gets acted on.
		 */
		return (array) $wpdb->get_results( // phpcs:ignore WordPress.DB
			$wpdb->prepare(
				"SELECT d.zone, d.name, d.record_type, d.target, d.matched_kind, d.matched_name,
				        COALESCE(w.status, '') AS waf_status
				   FROM {$d} d
				   LEFT JOIN {$w} w ON w.hostname = d.name
				   LEFT JOIN {$n} n ON n.resource_id = d.matched_ref
				  WHERE d.source = 'zonefile'
				    AND d.target NOT LIKE '%%edgekey.net'
				    AND d.target NOT LIKE '%%edgesuite.net'
				    AND d.target NOT LIKE 'internal-%%'
				    AND ( w.hostname IS NULL OR w.covered = 0 )
				    AND (
				          d.matched_kind = 'apigw'
				       OR (
				            d.matched_kind = 'elb'
				            AND LOCATE('internet-facing', n.detail) > 0
				            AND ( LOCATE('http/', n.detail) > 0 OR LOCATE('/443', n.detail) > 0 OR LOCATE('/80', n.detail) > 0 )
				          )
				       OR (
				            d.matched_kind IN ('instance','eni','eip')
				            AND EXISTS (
				                  SELECT 1 FROM {$r} rr
				                   WHERE rr.direction = 'in'
				                     AND rr.source IN ('0.0.0.0/0', '::/0')
				                     AND ( 80 BETWEEN rr.from_port AND rr.to_port OR 443 BETWEEN rr.from_port AND rr.to_port )
				                     AND FIND_IN_SET( rr.group_id, REPLACE( n.sg_ids, ' ', '' ) ) > 0
				                )
				          )
				    )
				  ORDER BY d.zone, d.name LIMIT %d",
				$limit
			),
			ARRAY_A
		);
	}

	/**
	 * Headline counts for both imports.
	 *
	 * @return array<string,int|string>
	 */
	public static function summary(): array {
		global $wpdb;

		$d = VulnHub_AWS_Domains::table();
		$w = self::waf_table();

		return array(
			'zone_records' => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$d} WHERE source = 'zonefile'" ), // phpcs:ignore WordPress.DB
			'zones'        => (int) $wpdb->get_var( "SELECT COUNT(DISTINCT zone) FROM {$d} WHERE source = 'zonefile'" ), // phpcs:ignore WordPress.DB
			'matched'      => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$d} WHERE source = 'zonefile' AND matched_kind <> ''" ), // phpcs:ignore WordPress.DB
			'waf_hosts'    => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$w}" ), // phpcs:ignore WordPress.DB
			'waf_covered'  => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$w} WHERE covered = 1" ), // phpcs:ignore WordPress.DB
			'imported_at'  => (string) $wpdb->get_var( "SELECT MAX(imported_at) FROM {$w}" ), // phpcs:ignore WordPress.DB
		);
	}
}

