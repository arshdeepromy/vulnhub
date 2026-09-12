<?php
/**
 * Vendors in the estate, and where to reach their security teams.
 *
 * A vendor is the organisation behind a thing we run -- hardware (from an
 * asset's manufacturer) or software (from a finding's product). This maps the
 * many raw strings a scan produces ("Hewlett-Packard", "HP", "VMware, Inc")
 * onto one canonical vendor, joins that to a curated registry (address,
 * verified security-advisory URL, public risk-rating link, local logo), and
 * aggregates our own exposure per vendor so the two sit side by side.
 *
 * The registry ships as data/vendors.json; advisory URLs in it were checked
 * live and blanked where no public page could be confirmed.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VH_Vendor {

	/** @var array<string,array<string,mixed>>|null */
	private static $registry = null;

	/** The curated registry, slug => record. */
	public static function registry(): array {
		if ( null !== self::$registry ) {
			return self::$registry;
		}
		$file = VULNHUB_DIR . 'data/vendors.json';
		$raw  = is_readable( $file ) ? (string) file_get_contents( $file ) : '[]'; // phpcs:ignore WordPress.WP.AlternativeFunctions
		$rows = json_decode( $raw, true );
		$out  = array();
		if ( is_array( $rows ) ) {
			foreach ( $rows as $r ) {
				if ( ! empty( $r['slug'] ) ) {
					$out[ (string) $r['slug'] ] = $r;
				}
			}
		}
		self::$registry = $out;
		return $out;
	}

	public static function known( string $slug ): bool {
		return isset( self::registry()[ $slug ] );
	}

	/** Hardware manufacturer (+model, to split HP Inc from HPE) -> vendor slug. */
	public static function hardware_vendor( string $manufacturer, string $model = '' ): string {
		$m = strtolower( trim( $manufacturer ) );
		if ( '' === $m || 'unknown' === $m ) {
			return '';
		}

		// HP family: servers and the ambiguous legacy "Hewlett-Packard" go to
		// HPE; PCs and printers to HP Inc.
		if ( preg_match( '/^(hp|hp inc\.?|hewlett[- ]?packard)( enterprise)?/', $m ) ) {
			if ( str_contains( $m, 'enterprise' ) ) {
				return 'hpe';
			}
			$mod = strtolower( $model );
			$pc  = 'laserjet|officejet|deskjet|designjet|elitebook|probook|pavilion|envy|spectre|zbook|elitedesk|prodesk|elite |pro |z2|z4|z6|z8|workstation|notebook|laptop|desktop|all-in-one|omen|victus';
			$srv = 'proliant|bladesystem|synergy|apollo|superdome|integrity|msa|nimble|alletra|primera|3par|storeonce|storeeasy| dl|dl3|dl5|dl9|ml3|ml1|sl2|sl4';
			if ( '' !== $mod && preg_match( '/(' . $pc . ')/', $mod ) ) {
				return 'hp';
			}
			if ( '' !== $mod && preg_match( '/(' . $srv . ')/', $mod ) ) {
				return 'hpe';
			}
			return 'hpe'; // legacy/ambiguous -> HPE (mostly servers here).
		}

		$map = array(
			'vmware' => 'vmware', 'vmware, inc' => 'vmware', 'vmware inc' => 'vmware',
			'amazon' => 'amazon', 'amazon ec2' => 'amazon', 'amazon.com' => 'amazon', 'amazon web services' => 'amazon',
			'dell' => 'dell', 'dell inc.' => 'dell', 'dell inc' => 'dell', 'clariion' => 'dell',
			'cisco' => 'cisco', 'cisco systems' => 'cisco',
			'polycom' => 'poly', 'poly' => 'poly', 'plantronics' => 'poly',
			'microsoft' => 'microsoft', 'microsoft corporation' => 'microsoft',
			'mellanox technologies, inc.' => 'nvidia', 'mellanox' => 'nvidia', 'nvidia' => 'nvidia',
			'check point software technologies' => 'checkpoint',
			'pure storage' => 'purestorage',
			'ricoh' => 'ricoh', 'netgear' => 'netgear',
			'asustek computer inc.' => 'asus', 'asus' => 'asus',
			'tp-link technologies co.,ltd.' => 'tplink', 'tp-link' => 'tplink', 'tp-link systems inc.' => 'tplink',
			'xen' => 'citrix', 'crestron' => 'crestron',
			'inner range pty. ltd.' => 'innerrange', 'quantum corporation' => 'quantum',
			'fs forth-systeme gmbh' => 'forth', 'brother' => 'brother', 'avm' => 'avm',
			'audiocodes' => 'audiocodes', 'tsc' => 'tsc', 'ring llc' => 'ring', 'epson' => 'epson',
		);
		return $map[ $m ] ?? '';
	}

	/**
	 * Software product -> vendor slug, by keyword. Ordered: the specific rules
	 * come before the broad "microsoft/windows" and "oracle" catch-alls so a
	 * bundled name ("Oracle WebLogic ... Apache Log4j", "Azul Zulu OpenJDK")
	 * lands on the product's real owner.
	 */
	public static function software_vendor( string $product ): string {
		$p = strtolower( $product );
		if ( '' === $p ) {
			return '';
		}
		$rules = array(
			'azul'       => array( 'azul', 'zulu' ),
			'amazon'     => array( 'amazon', 'aws', 'corretto', 'kiro', 'athena' ),
			'redhat'     => array( 'rhel', 'red hat' ),
			'rockylinux' => array( 'rockylinux', 'rocky' ),
			'oracle'     => array( 'oracle', 'weblogic', 'coherence', 'jdeveloper', 'openjdk', 'mysql' ),
			'apache'     => array( 'apache', 'log4j', 'struts', 'tomcat', 'tika', 'shiro', 'subversion', 'commons' ),
			'ibm'        => array( 'ibm' ),
			'jetbrains'  => array( 'jetbrains', 'intellij', 'pycharm' ),
			'github'     => array( 'github', 'copilot' ),
			'git'        => array( 'git for windows' ),
			'docker'     => array( 'docker' ),
			'nodejs'     => array( 'node.js' ),
			'openssl'    => array( 'openssl' ),
			'postgresql' => array( 'postgresql', 'pgadmin' ),
			'sqlite'     => array( 'sqlite' ),
			'python'     => array( 'python', 'jinja2', 'numpy', 'pandas', 'aiohttp', 'urllib3', 'certifi', 'tornado', 'sqlparse', 'jupyter', 'brotli', 'pyopenssl' ),
			'zoom'       => array( 'zoom' ),
			'teamviewer' => array( 'teamviewer' ),
			'tenable'    => array( 'tenable', 'nessus' ),
			'splunk'     => array( 'splunk' ),
			'anthropic'  => array( 'anthropic', 'claude' ),
			'anysphere'  => array( 'cursor' ),
			'vmware'     => array( 'vmware', 'spring', 'rabbitmq' ),
			'nvidia'     => array( 'nvidia' ),
			'intel'      => array( 'intel' ),
			'foxit'      => array( 'foxit' ),
			'keepassxc'  => array( 'keepassxc' ),
			'notepadpp'  => array( 'notepad' ),
			'videolan'   => array( 'vlc' ),
			'wireshark'  => array( 'wireshark' ),
			'putty'      => array( 'putty' ),
			'winscp'     => array( 'winscp' ),
			'7zip'       => array( '7-zip' ),
			'autodesk'   => array( 'autodesk' ),
			'devolutions'=> array( 'devolutions' ),
			'firebird'   => array( 'firebird' ),
			'poly'       => array( 'plantronics' ),
			'ruby'       => array( 'ruby' ),
			'rproject'   => array( 'r programming' ),
			'ollama'     => array( 'ollama' ),
			'pnpm'       => array( 'pnpm' ),
			'rclone'     => array( 'rclone' ),
			'greenshot'  => array( 'greenshot' ),
			'mobatek'    => array( 'mobaxterm' ),
			'progress'   => array( 'telerik' ),
			'podman'     => array( 'podman' ),
			'curl'       => array( 'libcurl', 'curl' ),
			'foxit'      => array( 'foxit' ),
			'hp'         => array( 'hp hotkey' ),
			'google'     => array( 'google chrome', 'android', 'chromium' ),
			'mozilla'    => array( 'mozilla', 'firefox' ),
			'adobe'      => array( 'adobe' ),
			'microsoft'  => array( 'microsoft', 'windows', 'ms kb', '.net', 'asp.net', 'visual studio', 'sysinternals', 'snip', 'silverlight', 'xml parser', 'malicious software' ),
		);
		foreach ( $rules as $slug => $kws ) {
			foreach ( $kws as $kw ) {
				if ( str_contains( $p, $kw ) ) {
					return $slug;
				}
			}
		}
		return '';
	}

	/**
	 * Every vendor present in the estate, with our own exposure and the
	 * registry metadata, ranked by exposure. `$scope`:
	 *   ''        both hardware and software vendors
	 *   'hardware'/'software'  one side only
	 *   'uncovered' hardware vendors with assets missing Tenable + Defender + CMDB.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function vendors( string $scope = '' ): array {
		global $wpdb;
		$a = vh_table( 'assets' );
		$f = vh_table( 'findings' );
		$v = vh_table( 'vulns' );

		$acc = array(); // slug => metrics

		$row = static function ( array &$acc, string $slug ): void {
			if ( ! isset( $acc[ $slug ] ) ) {
				$acc[ $slug ] = array(
					'hw_assets' => 0, 'uncovered' => 0, 'archived' => 0,
					'products' => 0, 'findings' => 0, 'crit' => 0, 'high' => 0, 'med' => 0,
				);
			}
		};

		// Hardware side: every asset, so archived-but-scanned kit still shows
		// its vendor. An asset is "uncovered" when Tenable has not scanned it,
		// Defender is not onboarded, and there is no CMDB record.
		$assets = $wpdb->get_results(
			"SELECT manufacturer, model, coverage_state, defender_coverage_state, cmdb_id, lifecycle_status
			 FROM {$a}",
			ARRAY_A
		);
		$in_service = vh_in_service_statuses();
		foreach ( (array) $assets as $as ) {
			$slug = self::hardware_vendor( (string) $as['manufacturer'], (string) $as['model'] );
			if ( '' === $slug ) {
				continue;
			}
			$row( $acc, $slug );
			$acc[ $slug ]['hw_assets']++;
			$uncov = ( 'covered' !== (string) $as['coverage_state'] )
				&& ( 'onboarded' !== (string) $as['defender_coverage_state'] )
				&& ( '' === trim( (string) $as['cmdb_id'] ) );
			if ( $uncov ) {
				$acc[ $slug ]['uncovered']++;
			}
			if ( ! in_array( (string) $as['lifecycle_status'], $in_service, true ) ) {
				$acc[ $slug ]['archived']++;
			}
		}

		// Software side: one row per product with severity split.
		$prods = $wpdb->get_results(
			"SELECT v.product AS product,
				COUNT(*) AS findings,
				SUM( f.severity = 'critical' ) AS crit,
				SUM( f.severity = 'high' )     AS high,
				SUM( f.severity = 'medium' )   AS med
			 FROM {$f} f
			 INNER JOIN {$v} v ON v.id = f.vuln_id
			 INNER JOIN {$a} s ON s.id = f.asset_id
			 WHERE f.state IN ('open','reopened') AND f.exception_id = 0
			   AND s.lifecycle_status IN (" . vh_reportable_sql() . ")
			   AND v.product <> ''
			 GROUP BY v.product",
			ARRAY_A
		);
		foreach ( (array) $prods as $pr ) {
			$slug = self::software_vendor( (string) $pr['product'] );
			if ( '' === $slug ) {
				continue;
			}
			$row( $acc, $slug );
			$acc[ $slug ]['products']++;
			$acc[ $slug ]['findings'] += (int) $pr['findings'];
			$acc[ $slug ]['crit']     += (int) $pr['crit'];
			$acc[ $slug ]['high']     += (int) $pr['high'];
			$acc[ $slug ]['med']      += (int) $pr['med'];
		}

		$reg  = self::registry();
		$out  = array();
		foreach ( $acc as $slug => $m ) {
			$meta  = $reg[ $slug ] ?? array();
			$score = 10 * $m['crit'] + 4 * $m['high'] + $m['med'] + 3 * $m['uncovered'];
			$out[] = array(
				'slug'      => $slug,
				'name'      => (string) ( $meta['name'] ?? ucfirst( $slug ) ),
				'kind'      => (string) ( $meta['kind'] ?? ( $m['hw_assets'] > 0 ? 'hardware' : 'software' ) ),
				'hq'        => (string) ( $meta['hq'] ?? '' ),
				'advisory'  => (string) ( $meta['advisory'] ?? '' ),
				'ratings'   => (string) ( $meta['ratings'] ?? '' ),
				'domain'    => (string) ( $meta['domain'] ?? '' ),
				'in_registry' => isset( $reg[ $slug ] ),
				'hw_assets' => (int) $m['hw_assets'],
				'uncovered' => (int) $m['uncovered'],
				'archived'  => (int) $m['archived'],
				'products'  => (int) $m['products'],
				'findings'  => (int) $m['findings'],
				'crit'      => (int) $m['crit'],
				'high'      => (int) $m['high'],
				'med'       => (int) $m['med'],
				'score'     => (int) $score,
				'band'      => self::band( (int) $score ),
			);
		}

		// scope filter
		if ( 'hardware' === $scope ) {
			$out = array_filter( $out, static fn( $r ): bool => $r['hw_assets'] > 0 );
		} elseif ( 'software' === $scope ) {
			$out = array_filter( $out, static fn( $r ): bool => $r['products'] > 0 );
		} elseif ( 'uncovered' === $scope ) {
			$out = array_filter( $out, static fn( $r ): bool => $r['uncovered'] > 0 );
		}

		usort(
			$out,
			static fn( array $x, array $y ): int => $y['score'] <=> $x['score']
				?: ( ( $y['hw_assets'] + $y['findings'] ) <=> ( $x['hw_assets'] + $x['findings'] ) )
		);
		return array_values( $out );
	}

	/** Exposure band from the internal score. */
	public static function band( int $score ): string {
		if ( $score <= 0 )   { return 'none'; }
		if ( $score < 15 )   { return 'low'; }
		if ( $score < 60 )   { return 'moderate'; }
		if ( $score < 250 )  { return 'high'; }
		return 'critical';
	}

	public static function band_label( string $band ): string {
		$m = array( 'none' => 'None', 'low' => 'Low', 'moderate' => 'Moderate', 'high' => 'High', 'critical' => 'Critical' );
		return $m[ $band ] ?? ucfirst( $band );
	}

	/* =================================================================
	 * Drill-down: the lists behind a vendor's numbers.
	 *
	 * A vendor is matched by a set of raw strings (manufacturers for hardware,
	 * product names for software) that the normalisers above map onto its slug.
	 * We resolve that set once, filter with a WHERE ... IN (), and for hardware
	 * re-check each row through hardware_vendor() so the HP/HPE model split
	 * still holds. Everything is paginated and server-side searchable so the
	 * modal and the CSV can never disagree with the card's totals.
	 * ============================================================== */

	/** @var array<string,int>|null distinct manufacturer strings in the estate. */
	private static $mfr_cache = null;
	/** @var array<int,string>|null distinct product strings in the estate. */
	private static $prod_cache = null;

	private static function distinct_manufacturers(): array {
		if ( null === self::$mfr_cache ) {
			global $wpdb;
			self::$mfr_cache = (array) $wpdb->get_col(
				"SELECT DISTINCT manufacturer FROM " . vh_table( 'assets' ) . " WHERE manufacturer <> ''"
			);
		}
		return self::$mfr_cache;
	}

	private static function distinct_products(): array {
		if ( null === self::$prod_cache ) {
			global $wpdb;
			self::$prod_cache = (array) $wpdb->get_col(
				"SELECT DISTINCT product FROM " . vh_table( 'vulns' ) . " WHERE product <> ''"
			);
		}
		return self::$prod_cache;
	}

	/** The manufacturer strings that can map to this vendor (HP family kept whole). */
	public static function manufacturers_for( string $slug ): array {
		$out = array();
		foreach ( self::distinct_manufacturers() as $m ) {
			if ( 'hp' === $slug || 'hpe' === $slug ) {
				// Empty-model normalisation sends the whole HP family to hpe;
				// include those raw strings for both, and let the per-asset
				// model check decide which side each machine lands on.
				if ( 'hpe' === self::hardware_vendor( (string) $m, '' )
					|| preg_match( '/^(hp|hewlett[- ]?packard)/i', (string) $m ) ) {
					$out[] = (string) $m;
				}
			} elseif ( self::hardware_vendor( (string) $m, '' ) === $slug ) {
				$out[] = (string) $m;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/** The product strings that map to this vendor. */
	public static function products_for( string $slug ): array {
		$out = array();
		foreach ( self::distinct_products() as $p ) {
			if ( self::software_vendor( (string) $p ) === $slug ) {
				$out[] = (string) $p;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Rows behind one of a vendor's numbers.
	 *
	 * @param string $slug   Vendor slug.
	 * @param string $metric assets|uncovered|archived|products|findings|critical.
	 * @param array  $args   page (1-based), per (0 = all), q, severity.
	 * @return array{title:string,columns:array<int,array{key:string,label:string}>,rows:array<int,array<string,mixed>>,total:int,page:int,per:int}
	 */
	public static function drill( string $slug, string $metric, array $args = array() ): array {
		$page = max( 1, (int) ( $args['page'] ?? 1 ) );
		$per  = isset( $args['per'] ) ? (int) $args['per'] : 25;
		$q    = trim( (string) ( $args['q'] ?? '' ) );
		$sev  = (string) ( $args['severity'] ?? '' );

		switch ( $metric ) {
			case 'products':
				return self::drill_products( $slug, $q, $page, $per );
			case 'findings':
			case 'critical':
				if ( 'critical' === $metric && '' === $sev ) {
					$sev = 'critical';
				}
				return self::drill_findings( $slug, $sev, $q, $page, $per );
			case 'assets':
			case 'uncovered':
			case 'archived':
			default:
				return self::drill_assets( $slug, in_array( $metric, array( 'uncovered', 'archived' ), true ) ? $metric : 'assets', $q, $page, $per );
		}
	}

	private static function in_placeholders( array $vals ): string {
		return implode( ',', array_fill( 0, max( 1, count( $vals ) ), '%s' ) );
	}

	private static function paginate( array $rows, int $page, int $per ): array {
		$total = count( $rows );
		if ( $per > 0 ) {
			$rows = array_slice( $rows, ( $page - 1 ) * $per, $per );
		}
		return array( array_values( $rows ), $total );
	}

	private static function drill_assets( string $slug, string $metric, string $q, int $page, int $per ): array {
		global $wpdb;
		$cands = self::manufacturers_for( $slug );
		$cols  = array(
			array( 'key' => 'hostname', 'label' => __( 'Host', 'vulnhub' ) ),
			array( 'key' => 'ipv4', 'label' => __( 'IPv4', 'vulnhub' ) ),
			array( 'key' => 'asset_type', 'label' => __( 'Type', 'vulnhub' ) ),
			array( 'key' => 'operating_system', 'label' => __( 'Operating system', 'vulnhub' ) ),
			array( 'key' => 'tenable', 'label' => __( 'Tenable', 'vulnhub' ) ),
			array( 'key' => 'defender', 'label' => __( 'Defender', 'vulnhub' ) ),
			array( 'key' => 'cmdb', 'label' => __( 'CMDB', 'vulnhub' ) ),
			array( 'key' => 'lifecycle', 'label' => __( 'Lifecycle', 'vulnhub' ) ),
		);
		$title = __( 'Assets', 'vulnhub' );
		if ( 'uncovered' === $metric ) { $title = __( 'Uncovered assets', 'vulnhub' ); }
		if ( 'archived' === $metric )  { $title = __( 'Archived assets', 'vulnhub' ); }
		if ( ! $cands ) {
			return array( 'title' => $title, 'columns' => $cols, 'rows' => array(), 'total' => 0, 'page' => $page, 'per' => $per );
		}

		$ph  = self::in_placeholders( $cands );
		$raw = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, hostname, fqdn, ipv4, asset_type, operating_system, model, manufacturer,
					coverage_state, defender_coverage_state, cmdb_id, lifecycle_status
				 FROM " . vh_table( 'assets' ) . " WHERE manufacturer IN ($ph)", // phpcs:ignore
				...$cands
			),
			ARRAY_A
		);

		$in_service = vh_in_service_statuses();
		$life_lbl   = function_exists( 'vh_lifecycle_statuses' ) ? vh_lifecycle_statuses() : array();
		$rows = array();
		foreach ( (array) $raw as $r ) {
			if ( self::hardware_vendor( (string) $r['manufacturer'], (string) $r['model'] ) !== $slug ) {
				continue;
			}
			$uncov = ( 'covered' !== (string) $r['coverage_state'] )
				&& ( 'onboarded' !== (string) $r['defender_coverage_state'] )
				&& ( '' === trim( (string) $r['cmdb_id'] ) );
			$arch  = ! in_array( (string) $r['lifecycle_status'], $in_service, true );
			if ( 'uncovered' === $metric && ! $uncov ) { continue; }
			if ( 'archived' === $metric && ! $arch ) { continue; }
			if ( '' !== $q ) {
				$hay = strtolower( (string) $r['hostname'] . ' ' . $r['fqdn'] . ' ' . $r['ipv4'] . ' ' . $r['operating_system'] );
				if ( false === strpos( $hay, strtolower( $q ) ) ) { continue; }
			}
			$rows[] = array(
				'hostname'         => (string) ( $r['hostname'] ?: $r['fqdn'] ),
				'ipv4'             => (string) $r['ipv4'],
				'asset_type'       => vh_asset_type_label( (string) $r['asset_type'] ),
				'operating_system' => (string) $r['operating_system'],
				'tenable'          => 'covered' === (string) $r['coverage_state'] ? __( 'Covered', 'vulnhub' ) : __( 'Not scanned', 'vulnhub' ),
				'defender'         => 'onboarded' === (string) $r['defender_coverage_state'] ? __( 'Onboarded', 'vulnhub' ) : __( 'Absent', 'vulnhub' ),
				'cmdb'             => '' !== trim( (string) $r['cmdb_id'] ) ? (string) $r['cmdb_id'] : '—',
				'lifecycle'        => (string) ( $life_lbl[ (string) $r['lifecycle_status'] ]['label'] ?? $r['lifecycle_status'] ),
			);
		}
		usort( $rows, static fn( $a, $b ): int => strcasecmp( (string) $a['hostname'], (string) $b['hostname'] ) );
		list( $paged, $total ) = self::paginate( $rows, $page, $per );
		return array( 'title' => $title, 'columns' => $cols, 'rows' => $paged, 'total' => $total, 'page' => $page, 'per' => $per );
	}

	private static function drill_products( string $slug, string $q, int $page, int $per ): array {
		global $wpdb;
		$cols = array(
			array( 'key' => 'product', 'label' => __( 'Product', 'vulnhub' ) ),
			array( 'key' => 'kind', 'label' => __( 'Kind', 'vulnhub' ) ),
			array( 'key' => 'findings', 'label' => __( 'Open findings', 'vulnhub' ) ),
			array( 'key' => 'crit', 'label' => __( 'Critical', 'vulnhub' ) ),
			array( 'key' => 'high', 'label' => __( 'High', 'vulnhub' ) ),
			array( 'key' => 'assets', 'label' => __( 'Assets', 'vulnhub' ) ),
		);
		$prods = self::products_for( $slug );
		if ( ! $prods ) {
			return array( 'title' => __( 'Products', 'vulnhub' ), 'columns' => $cols, 'rows' => array(), 'total' => 0, 'page' => $page, 'per' => $per );
		}
		$ph  = self::in_placeholders( $prods );
		$raw = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT v.product AS product, MAX(v.product_kind) AS kind,
					COUNT(*) AS findings, COUNT(DISTINCT f.asset_id) AS assets,
					SUM( f.severity = 'critical' ) AS crit, SUM( f.severity = 'high' ) AS high
				 FROM " . vh_table( 'findings' ) . " f
				 INNER JOIN " . vh_table( 'vulns' ) . " v ON v.id = f.vuln_id
				 INNER JOIN " . vh_table( 'assets' ) . " a ON a.id = f.asset_id
				 WHERE f.state IN ('open','reopened') AND f.exception_id = 0
				   AND a.lifecycle_status IN (" . vh_reportable_sql() . ")
				   AND v.product IN ($ph)
				 GROUP BY v.product", // phpcs:ignore
				...$prods
			),
			ARRAY_A
		);
		$rows = array();
		foreach ( (array) $raw as $r ) {
			if ( '' !== $q && false === stripos( (string) $r['product'], $q ) ) { continue; }
			$rows[] = array(
				'product'  => (string) $r['product'],
				'kind'     => (string) $r['kind'],
				'findings' => (int) $r['findings'],
				'crit'     => (int) $r['crit'],
				'high'     => (int) $r['high'],
				'assets'   => (int) $r['assets'],
			);
		}
		usort( $rows, static fn( $a, $b ): int => $b['findings'] <=> $a['findings'] );
		list( $paged, $total ) = self::paginate( $rows, $page, $per );
		return array( 'title' => __( 'Products', 'vulnhub' ), 'columns' => $cols, 'rows' => $paged, 'total' => $total, 'page' => $page, 'per' => $per );
	}

	private static function drill_findings( string $slug, string $severity, string $q, int $page, int $per ): array {
		global $wpdb;
		$cols = array(
			array( 'key' => 'hostname', 'label' => __( 'Asset', 'vulnhub' ) ),
			array( 'key' => 'ipv4', 'label' => __( 'IPv4', 'vulnhub' ) ),
			array( 'key' => 'product', 'label' => __( 'Product', 'vulnhub' ) ),
			array( 'key' => 'severity', 'label' => __( 'Severity', 'vulnhub' ) ),
			array( 'key' => 'title', 'label' => __( 'Vulnerability', 'vulnhub' ) ),
			/*
			 * Owner, not the Tenable plugin id. The id identifies the check
			 * that fired, which the vulnerability title already says in
			 * words; what this list is missing is who has to act on the row.
			 * The estate's ownership rule -- a workstation or mobile device
			 * resolves to a person, everything else to a team -- means the
			 * useful answer is the person when there is one and the owning
			 * team otherwise. plugin_id is still selected and still carried
			 * in the row, so the CSV can offer it and search still matches
			 * on it.
			 */
			array( 'key' => 'owner', 'label' => __( 'Owner', 'vulnhub' ) ),
			array( 'key' => 'cvss3', 'label' => __( 'CVSS v3', 'vulnhub' ) ),
			array( 'key' => 'first_found', 'label' => __( 'First found', 'vulnhub' ) ),
		);
		$title = 'critical' === $severity ? __( 'Critical findings', 'vulnhub' ) : __( 'Open findings', 'vulnhub' );
		$prods = self::products_for( $slug );
		if ( ! $prods ) {
			return array( 'title' => $title, 'columns' => $cols, 'rows' => array(), 'total' => 0, 'page' => $page, 'per' => $per );
		}
		$ph     = self::in_placeholders( $prods );
		$params = $prods;
		$where  = "f.state IN ('open','reopened') AND f.exception_id = 0
			AND a.lifecycle_status IN (" . vh_reportable_sql() . ")
			AND v.product IN ($ph)";
		if ( in_array( $severity, array( 'critical', 'high', 'medium', 'low', 'info' ), true ) ) {
			$where   .= " AND f.severity = %s";
			$params[] = $severity;
		}
		if ( '' !== $q ) {
			$like     = '%' . $wpdb->esc_like( $q ) . '%';
			$where   .= " AND ( a.hostname LIKE %s OR a.ipv4 LIKE %s OR v.product LIKE %s OR v.title LIKE %s
				OR v.plugin_id LIKE %s OR p.display_name LIKE %s OR t.name LIKE %s )";
			$params[] = $like; $params[] = $like; $params[] = $like; $params[] = $like;
			$params[] = $like; $params[] = $like; $params[] = $like;
		}
		$base = " FROM " . vh_table( 'findings' ) . " f
			INNER JOIN " . vh_table( 'vulns' ) . " v ON v.id = f.vuln_id
			INNER JOIN " . vh_table( 'assets' ) . " a ON a.id = f.asset_id
			LEFT JOIN " . vh_table( 'people' ) . " p ON p.id = a.owner_person_id
			LEFT JOIN " . vh_table( 'teams' ) . " t ON t.id = a.team_id
			WHERE $where";

		$total = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*)" . $base, ...$params ) ); // phpcs:ignore

		$sql = "SELECT a.hostname, a.fqdn, a.ipv4, v.product, f.severity, v.title, v.plugin_id, v.cvss3_base, f.first_found,
			p.display_name AS owner_name, t.name AS team_name"
			. $base . " ORDER BY FIELD(f.severity,'critical','high','medium','low','info'), f.first_found DESC";
		$qp  = $params;
		if ( $per > 0 ) {
			$sql   .= " LIMIT %d OFFSET %d";
			$qp[]   = $per;
			$qp[]   = ( $page - 1 ) * $per;
		}
		$raw = $wpdb->get_results( $wpdb->prepare( $sql, ...$qp ), ARRAY_A ); // phpcs:ignore

		$rows = array();
		foreach ( (array) $raw as $r ) {
			$rows[] = array(
				'hostname'    => (string) ( $r['hostname'] ?: $r['fqdn'] ),
				'ipv4'        => (string) $r['ipv4'],
				'product'     => (string) $r['product'],
				'severity'    => (string) $r['severity'],
				'title'       => (string) $r['title'],
				'plugin_id'   => (string) $r['plugin_id'],
				'owner'       => (string) ( $r['owner_name'] ?: $r['team_name'] ?: '' ),
				'owner_name'  => (string) $r['owner_name'],
				'team_name'   => (string) $r['team_name'],
				'cvss3'       => (string) $r['cvss3_base'],
				'first_found' => (string) $r['first_found'],
			);
		}
		return array( 'title' => $title, 'columns' => $cols, 'rows' => $rows, 'total' => $total, 'page' => $page, 'per' => $per );
	}

}
