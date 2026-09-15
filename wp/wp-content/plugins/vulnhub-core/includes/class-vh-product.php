<?php
/**
 * Work out which product a vulnerability is really about, from its title.
 *
 * Tenable ships no CPE and an empty CVE list on this feed, so the only signal
 * for "what software is this" is the plugin title, with the family as a coarse
 * pre-filter. The scan of 2026-09-09 showed the titles are strongly
 * structured, and this reproduces the classifier validated there:
 *
 *   native Linux   families "* Local Security Checks", distro-prefixed titles,
 *                  advisory ids (RHSA/USN/ALAS...), and "Linux Distros
 *                  Unpatched" (89% of all findings — 39 hosts missing OS
 *                  patches, the single biggest lever on the number).
 *   native Windows KB / MS bulletins / .NET+Windows update strings.
 *   third party    everything else, product taken from the title prefix up to
 *                  the first version token, operator or "(".
 *
 * Pure and side-effect-free: the same call classifies a row on import, in the
 * back-fill, and at read time, so the three can never disagree.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VH_Product {

	public const OS_LINUX   = 'os_linux';
	public const OS_WINDOWS = 'os_windows';
	public const THIRD      = 'third_party';

	/**
	 * Classify one vulnerability.
	 *
	 * @param string $title  Plugin title.
	 * @param string $family Tenable plugin family.
	 * @return array{class:string,product:string,kind:string,package:string,slug:string}
	 */
	public static function classify( string $title, string $family = '', string $description = '' ): array {
		$title = trim( $title );

		if ( self::is_linux( $title, $family ) ) {
			return self::pack( self::OS_LINUX, self::linux_group( $title, $family ), 'os_package', self::linux_package( $title ) );
		}
		if ( self::is_windows( $title, $family ) ) {
			return self::pack( self::OS_WINDOWS, 'Windows / Microsoft updates', 'os_update', '' );
		}

		$product = self::extract_product( $title );
		if ( '' === $product ) {
			// Never leave a finding unlabelled — the title's first word beats nothing.
			$product = ucfirst( strtok( $title, ' ' ) ?: __( 'Unclassified', 'vulnhub' ) );
		}
		return self::pack( self::THIRD, $product, self::kind_of( $product ), '' );
	}

	/* ---------------------------------------------------------------- native */

	private static function is_linux( string $t, string $fam ): bool {
		if ( false !== stripos( $fam, 'Local Security Checks' ) ) {
			return true;
		}
		if ( preg_match( '/^Linux Distros Unpatched/i', $t ) ) {
			return true;
		}
		if ( preg_match( '/^(RHEL|Red Hat|CentOS|Rocky ?Linux|AlmaLinux|Alma|Oracle Linux|Amazon Linux|Ubuntu|Debian|SUSE|SLES|openSUSE|Fedora|Photon ?OS)\b/i', $t ) ) {
			return true;
		}
		return (bool) preg_match( '/\b(RHSA|RHBA|RHEA|ALAS[0-9]*|USN|DSA|DLA|ELSA|SUSE-SU|openSUSE-SU|CESA)\b/i', $t );
	}

	private static function linux_group( string $t, string $fam ): string {
		if ( preg_match( '/^Linux Distros Unpatched/i', $t ) ) {
			return 'Linux: unpatched CVEs (no vendor fix)';
		}
		if ( preg_match( '/^(RHEL|Red Hat|CentOS|Rocky ?Linux|AlmaLinux|Oracle Linux|Amazon Linux|Ubuntu|Debian|SUSE|openSUSE|Fedora)\b/i', $t, $m ) ) {
			return 'Linux: ' . self::tidy_distro( $m[1] );
		}
		if ( false !== stripos( $fam, 'Local Security Checks' ) ) {
			return 'Linux: ' . trim( str_ireplace( 'Local Security Checks', '', $fam ) );
		}
		return 'Linux: other';
	}

	private static function tidy_distro( string $d ): string {
		$d = preg_replace( '/\s+/', ' ', trim( $d ) );
		return array( 'rhel' => 'RHEL', 'red hat' => 'RHEL' )[ strtolower( $d ) ] ?? $d;
	}

	private static function linux_package( string $t ): string {
		// "RHEL 9 : kernel (RHSA-2026:49870)" -> kernel
		if ( preg_match( '/:\s*([a-z0-9][a-z0-9._+\-]*)\s*(?:\(|$)/i', $t, $m ) ) {
			return strtolower( $m[1] );
		}
		return '';
	}

	private static function is_windows( string $t, string $fam ): bool {
		if ( 'Windows : Microsoft Bulletins' === $fam ) {
			return true;
		}
		if ( preg_match( '/^KB\d{6,7}\b/i', $t ) || preg_match( '/\bMS\d\d-\d{2,3}\b/', $t ) ) {
			return true;
		}
		if ( preg_match( '/^(Windows (Server )?\d|Windows \d\d? Version|Security Updates? for (Microsoft )?\.NET|Microsoft \.NET Core)/i', $t ) ) {
			return true;
		}
		// Windows platform configuration / detection checks — a property of the
		// OS, not a third-party product. Otherwise "Windows Speculative
		// Execution Configuration Check" reads as an app in the widget.
		return (bool) preg_match( '/^(Windows (Speculative|Defender|Package Manager)|WinVerifyTrust|Untrusted Microsoft|Unquoted|Microsoft Windows (SMB|Unquoted|Defender))/i', $t );
	}

	/* ---------------------------------------------------------- third party */

	/**
	 * Descriptor words that end the product name once at least one real token
	 * has been seen. "Oracle Java SE Multiple Vulnerabilities" -> "Oracle Java SE".
	 */
	private static function stopwords(): array {
		static $s = null;
		if ( null === $s ) {
			$s = array_flip( array_map( 'strtolower', array(
				'Multiple', 'Unsupported', 'Detection', 'Installed', 'Vulnerability', 'Vulnerabilities',
				'Security', 'Update', 'Updates', 'Remote', 'Local', 'Denial', 'Information', 'Improper',
				'Cross-Site', 'Cross-Origin', 'Cross-Proxy', 'Use-After-Free', 'Heap', 'Memory', 'Buffer',
				'SSL', 'TLS', 'Wrong', 'Stale', 'Native', 'Persistent', 'QUIC', 'HTTP', 'HTTP/2', 'HTTP/3',
				'WebSocket', 'SASL', 'SSH', 'Netrc', 'Super', 'and', 'End', 'EOL', 'SEoL', 'End-of-Life',
				'affected', 'running', 'Signature', 'Config', 'Configuration', 'Check',
			) ) );
		}
		return $s;
	}

	private static function is_version( string $tok ): bool {
		return (bool) preg_match( '/^[<>]=?$/', $tok )
			|| (bool) preg_match( '/^v?\d+([._]\d+)*([._-]?(x|M\d+|rc\d*|beta\d*|alpha\d*|p\d+|b\d+))?$/i', $tok )
			|| (bool) preg_match( '/^\d+\.x$/i', $tok );
	}

	private static function extract_product( string $title ): string {
		// "Security Update(s) for [Microsoft] X (date)" -> X
		if ( preg_match( '/^Security Updates? for (?:Microsoft )?(.+?)\s*(?:\(|Products|C2R|$)/i', $title, $m ) ) {
			$name = trim( $m[1], " -:," );
			return self::canon( 0 === stripos( $name, 'microsoft' ) ? $name : 'Microsoft ' . $name );
		}

		$stop = self::stopwords();
		$out  = array();
		foreach ( preg_split( '/\s+/', $title ) as $tok ) {
			$low = strtolower( trim( $tok, ',:;' ) );
			if ( self::is_version( $tok ) || '(' === substr( $tok, 0, 1 ) ) {
				break;
			}
			if ( isset( $stop[ $low ] ) ) {
				if ( $out ) {
					break;
				}
				return '';
			}
			$out[] = trim( $tok, ',:' );
			if ( count( $out ) >= 5 ) {
				break;
			}
		}
		if ( ! $out ) {
			return '';
		}
		$name = trim( implode( ' ', $out ), " -:/," );
		// Cut anything from a version-looking token onward (Java 1.7.0_331, Tomcat 9.0.0.M1).
		$name = preg_replace( '/\s+v?\d[\w._-]*.*$/i', '', $name );
		$name = preg_replace( '/\s+(app|Code|Base3D.*|Module .*|Access.*|Trust.*|DataFrame.*|GPU.*)$/i', '', $name );
		$name = trim( (string) $name, " -:/," );

		return '' === $name ? '' : self::canon( $name );
	}

	/**
	 * Merge vendor spelling variants. Filterable so new products are data.
	 */
	private static function canon( string $name ): string {
		$map = (array) apply_filters(
			'vulnhub_product_aliases',
			array(
				'apache log4j' => 'Apache Log4j', 'log4j' => 'Apache Log4j',
				'oracle java se' => 'Oracle Java SE', 'java se' => 'Oracle Java SE', 'oracle java' => 'Oracle Java SE',
				'google chrome' => 'Google Chrome', 'chrome' => 'Google Chrome',
				'mozilla firefox' => 'Mozilla Firefox', 'firefox' => 'Mozilla Firefox',
				'zoom workplace' => 'Zoom', 'zoom' => 'Zoom', 'zoom client' => 'Zoom',
				'libcurl' => 'libcurl', 'curl' => 'libcurl',
				'microsoft .net core' => 'Microsoft .NET', '.net core' => 'Microsoft .NET',
				'microsoft .net' => 'Microsoft .NET', 'microsoft .net framework' => 'Microsoft .NET',
				'azul zulu java' => 'Azul Zulu (Java)', 'openjdk' => 'OpenJDK',
				'apache tomcat' => 'Apache Tomcat', 'oracle weblogic server' => 'Oracle WebLogic',
				'oracle database server' => 'Oracle Database', 'microsoft edge' => 'Microsoft Edge',
				'node.js' => 'Node.js', '7-zip' => '7-Zip', 'microsoft 3d viewer' => 'Microsoft 3D Viewer',
				'pandas' => 'Pandas', 'microsoft office' => 'Microsoft Office',
			)
		);
		$key = strtolower( $name );
		return $map[ $key ] ?? $name;
	}

	private static function kind_of( string $name ): string {
		$libs = array_map( 'strtolower', (array) apply_filters(
			'vulnhub_known_libraries',
			array(
				'libcurl', 'curl', 'openssl', 'sqlite', 'zlib', 'log4j', 'apache log4j', 'libxml2',
				'libpng', 'glibc', 'pcre', 'pcre2', 'expat', 'libssh', 'libssh2', 'nghttp2', 'c-ares',
				'libarchive', 'openssh', 'ncurses', 'gnutls', 'libtiff', 'freetype', 'libjpeg',
				'libwebp', 'nettle', 'busybox', 'spring framework', 'apache commons fileupload',
			)
		) );
		$k = strtolower( $name );
		return ( in_array( $k, $libs, true ) || 0 === strpos( $k, 'lib' ) ) ? 'library' : 'application';
	}

	/* --------------------------------------------------------------- helpers */

	private static function pack( string $class, string $product, string $kind, string $package ): array {
		return array(
			'class'   => $class,
			'product' => $product,
			'kind'    => $kind,
			'package' => $package,
			'slug'    => self::slug( $product ),
		);
	}

	/**
	 * The application a bundled library actually ships inside, from a scan path.
	 *
	 * A libcurl or Log4j finding is noise until you know *which app* carries the
	 * vulnerable copy: on Windows the vendor drops its own libcurl.dll inside its
	 * install folder, so the finding is the app's dependency, not an OS library.
	 * The install path names the app -- `Program Files\<App>\...`, an MSIX
	 * package under `WindowsApps\<Package>_...`, or the folder a loose jar sits
	 * in. This reads that out of Tenable's plugin output so the fix becomes
	 * "update Microsoft Teams", not "patch libcurl everywhere".
	 *
	 * Returns '' when the path is a system location (a real OS library) or when
	 * no usable path is present -- those keep their library/OS attribution.
	 *
	 * @param string $output Tenable plugin output for one finding.
	 * @return string Application name, or '' when it is not app-bundled.
	 */
	public static function app_from_output( string $output ): string {
		if ( '' === $output ) {
			return '';
		}

		/*
		 * One path parser, one knowledge base. This used to inline a Windows
		 * branch, a Unix branch and a folder-picking heuristic, each with its
		 * own idea of what a product looks like -- which is how
		 * "...\Zoom\tmp_bin\libcurl.dll" became "Tmp_bin". install_path()
		 * already knows how to read every shape this scanner emits, and
		 * product_from_path() owns what a path means.
		 */
		$path = self::install_path( $output );

		if ( '' !== $path ) {
			// A genuine OS library belongs to the library, not to an app.
			$low = strtolower( str_replace( '\\', '/', $path ) );
			if ( preg_match( '#/windows/|/system32/|/syswow64/|^/(usr/)?lib(64)?/|^/(usr/)?s?bin/|^/usr/share/|^/usr/libexec/#', $low ) ) {
				return '';
			}

			$product = self::product_from_path( $path );

			if ( '' !== $product ) {
				return $product;
			}
		}

		// No usable path: a distro package list names the thing to update.
		return self::app_from_package_list( $output );
	}

	/**
	 * The source package behind a distro sub-package list.
	 *
	 * A distro splits one source package into many binaries -- kernel,
	 * kernel-core, kernel-devel, kernel-modules, python3-perf -- and a CVE
	 * lists whichever of them are installed. There is one thing to update, so
	 * the suffixes and language prefixes come off and the name that covers the
	 * rest of the list wins: that list is a kernel update, not eleven.
	 */
	/** The path knowledge base, loaded once. */
	private static function path_kb(): array {
		static $kb = null;

		if ( null === $kb ) {
			$file = VULNHUB_DIR . 'data/product-paths.php';
			$kb   = is_readable( $file ) ? (array) require $file : array();

			$kb['structure'] = array_flip( array_map( 'strtolower', (array) ( $kb['structure'] ?? array() ) ) );
			$kb['anchors']   = (array) ( $kb['anchors'] ?? array() );
			$kb['aliases']   = (array) ( $kb['aliases'] ?? array() );

			/**
			 * Filters the install-path knowledge base.
			 *
			 * @param array $kb structure / anchors / aliases.
			 */
			$kb = (array) apply_filters( 'vulnhub_product_path_kb', $kb );
		}

		return $kb;
	}

	/** A folder name reduced to a comparison key. */
	private static function path_key( string $segment ): string {
		return strtolower( (string) preg_replace( '/[^a-z0-9]+/i', '', $segment ) );
	}

	/** Whether a path segment is install structure rather than a product. */
	private static function is_structure( string $segment ): bool {
		$kb  = self::path_kb();
		$low = strtolower( trim( $segment ) );

		if ( isset( $kb['structure'][ $low ] ) ) {
			return true;
		}

		// Pure version or build directories: 152.0.4191.66, 12.2.1.4, v1.2.4,
		// 37852500, x64. None of them name a product.
		if ( preg_match( '/^v?[\d._-]+$/', $low ) ) {
			return true;
		}

		// A date-stamped working copy: backup20260401, 20240625.
		if ( preg_match( '/^(backup|copy|old|tmp|temp)?[\s_-]*\d{6,}$/', $low ) ) {
			return true;
		}

		return false;
	}

	/**
	 * The product an install path belongs to, or '' when nothing is credible.
	 *
	 * Resolution order, most trustworthy first:
	 *
	 *   1. A vendor layout anchor. `/u01/jde920/e920/system/bin64/openssl` is
	 *      only readable as JD Edwards if you know what a JDE deployment root
	 *      looks like; no amount of folder-picking gets there.
	 *   2. An MSIX package name, which carries the product properly:
	 *      Microsoft.Todos_2.176.7601.0_x64__8wekyb3d8bbwe.
	 *   3. A folder whose name is a known alias -- sqldeveloper_23 -> Oracle
	 *      SQL Developer -- searched left to right so the product root wins
	 *      over a nested copy of itself.
	 *   4. A folder that matches something actually installed in the estate,
	 *      taken from the CPE inventory. A positive signal only: the inventory
	 *      covers 216 products and rejecting everything outside it would throw
	 *      away correct names like "HP One Agent".
	 *   5. Otherwise the first non-structural folder after the install root.
	 *
	 * Returning '' is a valid answer and better than a guess. "Configuration"
	 * and "Tmp_bin" were rows in the exposure widget that nobody could act on.
	 */
	public static function product_from_path( string $path ): string {
		$path = trim( $path );

		if ( '' === $path ) {
			return '';
		}

		$kb = self::path_kb();

		/*
		 * Collapse repeated separators before anything else. Scanner output
		 * escapes backslashes inconsistently, so "Microsoft\\EdgeWebView"
		 * arrives as "Microsoft//EdgeWebView" once flattened -- and then a
		 * layout pattern looking for "/Microsoft/EdgeWebView" does not match
		 * and the path falls through to a guess. install_path() already
		 * normalises, but this has to hold for any caller.
		 */
		$norm = (string) preg_replace( '#/{2,}#', '/', str_replace( '\\', '/', $path ) );
		$norm = '/' . ltrim( $norm, '/' );

		// 1. Vendor layout.
		foreach ( $kb['anchors'] as $pattern => $product ) {
			if ( '' !== $product && preg_match( $pattern, $norm ) ) {
				return $product;
			}
		}

		$segments = array_values( array_filter( explode( '/', $norm ), static fn( $x ): bool => '' !== $x ) );

		/*
		 * 2. MSIX / Store package.
		 *
		 * Not simply the segment after WindowsApps: Windows stages packages
		 * pending removal under "WindowsApps\Deleted\<package>", so that
		 * segment was "Deleted" for 23 findings that are really Teams and
		 * Office. Scan forward instead for the first segment shaped like a
		 * package identifier -- Publisher.Name_version_arch__hash.
		 */
		foreach ( $segments as $i => $segment ) {
			if ( 0 !== strcasecmp( $segment, 'WindowsApps' ) ) {
				continue;
			}

			for ( $j = $i + 1; $j < count( $segments ) && $j <= $i + 3; $j++ ) {
				if ( false === strpos( $segments[ $j ], '_' ) ) {
					continue;   // "Deleted", "MutableBackup" and friends.
				}

				$app = self::app_clean( self::msix_app( $segments[ $j ] ) );

				if ( '' !== $app ) {
					return $app;
				}
			}
		}

		// The file itself is not a folder.
		$folders = array_slice( $segments, 0, -1 );

		// 3. A known alias, product root first.
		foreach ( $folders as $segment ) {
			$key = self::path_key( self::app_strip_version( $segment ) );
			if ( '' !== $key && isset( $kb['aliases'][ $key ] ) ) {
				return $kb['aliases'][ $key ];
			}
		}

		// 4. Something the estate actually has installed.
		$known = self::installed_vocabulary();
		foreach ( $folders as $segment ) {
			if ( self::is_structure( $segment ) ) {
				continue;
			}
			$key = self::path_key( self::app_strip_version( $segment ) );
			if ( '' !== $key && isset( $known[ $key ] ) ) {
				return $known[ $key ];
			}
		}

		/*
		 * A file under a scratch location has no install root to read. A
		 * folder in %TEMP% or a user profile is a project directory, a ticket
		 * number or somebody's surname -- "C:\temp\corrossion\_internal\
		 * sqlite3.dll" is not a product called Corrossion. Steps 1 to 4 can
		 * still name it from real evidence; step 5's guess is refused here.
		 */
		if ( preg_match( '#^/([A-Za-z]:?/)?(temp|tmp|users|home|programdata/temp)(/|$)#i', $norm )
			|| preg_match( '#/(appdata|downloads)/#i', $norm ) ) {
			return '';
		}

		// 5. First non-structural folder, left to right: the install root
		//    names the product, the folder next to the file does not.
		foreach ( $folders as $segment ) {
			if ( self::is_structure( $segment ) ) {
				continue;
			}
			$name = self::app_clean( self::app_strip_version( $segment ) );
			if ( '' !== $name && strlen( self::path_key( $name ) ) >= 3 ) {
				return $name;
			}
		}

		return '';
	}

	/**
	 * Products the estate actually has installed, from the CPE inventory.
	 *
	 * Tenable reports installed software as cpe:/a:vendor:product:version, so
	 * this is evidence rather than a guess -- but only 216 products wide, so
	 * it is used to confirm a folder name and never to reject one.
	 *
	 * @return array<string,string> comparison key => display name.
	 */
	public static function installed_vocabulary(): array {
		static $vocab = null;

		if ( null !== $vocab ) {
			return $vocab;
		}

		$cached = get_transient( 'vh_installed_vocab' );

		if ( is_array( $cached ) ) {
			$vocab = $cached;
			return $vocab;
		}

		global $wpdb;
		$vocab = array();

		$rows = (array) $wpdb->get_col(
			'SELECT software_json FROM ' . vh_table( 'assets' )
			. " WHERE software_json <> '' AND software_json <> '[]'" // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		);

		foreach ( $rows as $json ) {
			$list = json_decode( (string) $json, true );

			if ( ! is_array( $list ) ) {
				continue;
			}

			foreach ( $list as $cpe ) {
				$parts = explode( ':', str_replace( '\\', '', (string) $cpe ) );

				if ( count( $parts ) < 4 || '' === $parts[3] ) {
					continue;
				}

				$display = ucwords( str_replace( array( '_', '-' ), ' ', $parts[3] ) );
				$key     = self::path_key( $display );

				if ( strlen( $key ) >= 4 && ! isset( $vocab[ $key ] ) ) {
					$vocab[ $key ] = $display;
				}
			}
		}

		set_transient( 'vh_installed_vocab', $vocab, DAY_IN_SECONDS );

		return $vocab;
	}

	private static function app_from_package_list( string $output ): string {
		$names = array();

		// Shape one, the unpatched-CVE plugins: a bare bulleted list.
		if ( preg_match_all( '/^\s*-\s*([A-Za-z0-9][A-Za-z0-9._+-]*)\s*$/m', $output, $m ) ) {
			$names = $m[1];
		}

		/*
		 * Shape two, the vendor advisory plugins (RHSA, USN, DSA), which print
		 * the installed and wanted versions instead of a list:
		 *
		 *   Remote package installed : curl-7.76.1-35.el9_7.3
		 *   Should be                : curl-7.76.1-40.el9_8.5
		 *
		 * The version is everything from the first "-<digit>", so the name is
		 * what precedes it. These were the last generic Linux row, 4,928
		 * findings still grouped as "Linux: RHEL".
		 */
		if ( preg_match_all( '/Remote package installed\s*:\s*(\S+)/i', $output, $mp ) ) {
			foreach ( $mp[1] as $nvr ) {
				$names[] = preg_match( '/^(.+?)-\d/', $nvr, $nm ) ? $nm[1] : $nvr;
			}
		}

		if ( ! $names ) {
			return '';
		}

		$m = array( 1 => $names );

		$suffix = '/-(core|devel|headers|libs?|tools|modules|common|utils|docs?|debuginfo|debugsource|static|bin|dev|data|selinux|minimal|enhanced|filesystem|X11)$/i';
		$bases  = array();

		foreach ( $m[1] as $name ) {
			$name = strtolower( trim( $name ) );
			$name = (string) preg_replace( '/^(python3?|perl|ruby|php|golang|rust)-/', '', $name );

			do {
				$before = $name;
				$name   = (string) preg_replace( $suffix, '', $name );
			} while ( $name !== $before );

			if ( '' !== $name ) {
				$bases[ $name ] = ( $bases[ $name ] ?? 0 ) + 1;
			}
		}

		if ( ! $bases ) {
			return '';
		}

		arsort( $bases );

		/*
		 * Cast back to string. PHP turns a numeric array key into an int, and
		 * distros really do ship packages named like that -- "389" survives
		 * from 389-ds, "7zip" from p7zip -- so array_keys() can hand back
		 * integers and strpos() then fails with a TypeError mid-sync.
		 */
		$names = array_map( 'strval', array_keys( $bases ) );

		// A name that prefixes most of the others is the source package.
		foreach ( $names as $candidate ) {
			$covers = 0;
			foreach ( $names as $other ) {
				if ( 0 === strpos( $other, $candidate ) ) {
					++$covers;
				}
			}
			if ( $covers > count( $names ) / 2 ) {
				return $candidate;
			}
		}

		return (string) $names[0];
	}

	private static function app_from_unix_path( string $path ): string {
		$low = strtolower( $path );
		if ( preg_match( '#^/(usr/lib(64)?|lib(64)?|usr/bin|bin|usr/sbin|sbin|usr/share|usr/libexec)/#', $low ) ) {
			return '';
		}
		$segs = array_values( array_filter( explode( '/', $path ) ) );
		if ( count( $segs ) < 2 ) {
			return '';
		}
		array_pop( $segs );
		$roots = array( 'opt', 'usr', 'local', 'u01', 'u02', 'u03', 'app', 'apps', 'home', 'srv', 'data', 'mnt', 'export', 'var', 'oracle_home' );
		$i = 0;
		while ( $i < count( $segs ) && in_array( strtolower( $segs[ $i ] ), $roots, true ) ) {
			$prev = strtolower( $segs[ $i ] );
			++$i;
			if ( 'home' === $prev && $i < count( $segs ) ) {
				++$i;
			}
		}
		for ( $j = $i; $j < count( $segs ); $j++ ) {
			$seg = $segs[ $j ];
			if ( self::app_is_noise( $seg ) ) {
				continue;
			}
			if ( isset( self::app_vendors()[ strtolower( $seg ) ] ) && isset( $segs[ $j + 1 ] ) && ! self::app_is_noise( $segs[ $j + 1 ] ) ) {
				$prod = $segs[ $j + 1 ];
				return 'oracle' === strtolower( $seg ) ? 'Oracle ' . ucfirst( $prod ) : $prod;
			}
			return $seg;
		}
		return '';
	}

	private static function app_vendors(): array {
		static $v = null;
		if ( null === $v ) {
			$v = array_flip( array_map( 'strtolower', array(
				'Microsoft', 'HP', 'HPE', 'Hewlett-Packard', 'Amazon', 'Google', 'Oracle', 'Adobe',
				'Dell', 'Lenovo', 'Intel', 'NVIDIA', 'NVIDIA Corporation', 'VMware', 'Citrix', 'Cisco',
				'IBM', 'SmartBear', 'Precisely', 'Logitech', 'Salesforce', 'Common Files', 'Java', 'Zoom',
			) ) );
		}
		return $v;
	}

	private static function app_is_noise( string $f ): bool {
		$g = array( 'lib', 'libs', 'lib64', 'bin', 'plugins', 'plugin', 'jre', 'jdk', 'runtime', 'app',
			'resources', 'modules', 'node_modules', 'x64', 'x86', 'win64', 'win32', 'program', 'common',
			'sdk', 'tools', 'users', 'downloads', 'desktop', 'documents', 'temp', 'tmp', 'appdata',
			'local', 'roaming', 'mingw64' );
		$l = strtolower( trim( $f ) );
		return '' === $l || in_array( $l, $g, true ) || (bool) preg_match( '/^v?\d/', $l ) || (bool) preg_match( '/^[a-z]:$/i', $l );
	}

	private static function app_from_segments( string $tail ): string {
		$folders = array_values( array_filter( explode( '\\', $tail ) ) );
		$fname   = array_pop( $folders );

		if ( ! $folders ) {
			return self::app_strip_version( (string) $fname );
		}

		$first = $folders[0];

		if ( isset( self::app_vendors()[ strtolower( $first ) ] ) && count( $folders ) >= 2 ) {
			$prod = $folders[1];
			if ( 'microsoft' === strtolower( $first ) && 0 !== stripos( $prod, 'microsoft' ) ) {
				return $first . ' ' . $prod;
			}
			return $prod;
		}

		if ( ! self::app_is_noise( $first ) ) {
			return $first;
		}

		foreach ( $folders as $f ) {
			if ( ! self::app_is_noise( $f ) ) {
				return $f;
			}
		}
		return self::app_strip_version( (string) $fname );
	}

	private static function msix_app( string $pkg ): string {
		$base = strtok( $pkg, '_' );
		$key  = strtolower( str_replace( ' ', '', (string) $base ) );

		$map = (array) apply_filters( 'vulnhub_msix_apps', array(
			'msteams' => 'Microsoft Teams', 'microsoft.microsoftofficehub' => 'Microsoft Office',
			'microsoft.windows.photos' => 'Microsoft Photos', 'microsoft.windowsstore' => 'Microsoft Store',
			'microsoft.edge' => 'Microsoft Edge', 'microsoftpowerbidesktop' => 'Microsoft Power BI Desktop',
			'microsoft.crossdevice' => 'Microsoft Phone Link', 'microsoftcopilot' => 'Microsoft Copilot',
		) );
		if ( isset( $map[ $key ] ) ) {
			return $map[ $key ];
		}
		if ( 0 === stripos( (string) $base, 'zoom' ) ) {
			return 'Zoom';
		}
		if ( false !== stripos( (string) $base, 'crossdevice' ) ) {
			return 'Microsoft Phone Link';
		}

		/*
		 * Try the map again with the publisher stripped. A package identifier
		 * carries its publisher -- Microsoft.MicrosoftPowerBIDesktop,
		 * MicrosoftWindows.CrossDevice -- and keying only on the whole string
		 * meant the map missed both of those even though the product names
		 * were sitting in it. Strip one dotted segment at a time, longest
		 * remainder first, so an exact full-key hit still wins.
		 */
		$parts = explode( '.', (string) $base );

		for ( $i = 1; $i < count( $parts ); $i++ ) {
			$try = strtolower( implode( '', array_slice( $parts, $i ) ) );

			if ( isset( $map[ $try ] ) ) {
				return $map[ $try ];
			}
		}

		/*
		 * Nothing known: keep the publisher rather than drop it. The last
		 * dotted segment alone turned Microsoft.Todos into "Todos", which
		 * reads like a to-do list somebody left on the disk rather than a
		 * Microsoft application.
		 */
		$name   = self::app_spacecase( (string) end( $parts ) );
		$vendor = self::app_spacecase( (string) $parts[0] );

		if ( count( $parts ) > 1 && '' !== $name && 0 !== stripos( $name, $vendor ) ) {
			// "MicrosoftWindows" and "Microsoft" both mean Microsoft here.
			$vendor = preg_replace( '/^Microsoft\s*Windows$/i', 'Microsoft', $vendor );
			return trim( $vendor . ' ' . $name );
		}

		return $name;
	}

	private static function app_spacecase( string $x ): string {
		$x = (string) preg_replace( '/(?<=[a-z0-9])(?=[A-Z])/', ' ', $x );
		return trim( (string) preg_replace( '/\s+/', ' ', $x ) );
	}

	private static function app_strip_version( string $fn ): string {
		$fn = (string) preg_replace( '/\.(dll|jar|exe|so|node)$/i', '', $fn );
		$fn = (string) preg_replace( '/[-_]v?\d[\d._()+-]*(?:[-_][a-z0-9]+)*$/i', '', $fn );

		/*
		 * A version glued straight onto the name, no separator: Python310,
		 * Office16, SOA12. The stem has to be at least three letters, which
		 * keeps "log4j" (digits in the middle, ends in a letter) and "e920"
		 * (stem too short to mean anything) out of it.
		 */
		if ( preg_match( '/^([A-Za-z][A-Za-z._ -]{2,})\d+$/', trim( $fn ), $m ) ) {
			$fn = $m[1];
		}

		return trim( $fn, " -_" );
	}

	/** Final tidy: strip a trailing version and normalise obvious variants. */
	private static function app_clean( string $name ): string {
		$name = self::app_strip_version( trim( $name ) );
		$fix  = array(
			'microsoft edgecore' => 'Microsoft Edge', 'edgecore' => 'Microsoft Edge',
			'sqldeveloper' => 'Oracle SQL Developer', 'dataloader' => 'Salesforce Data Loader',
			'awscliv2' => 'AWS CLI', 'log4j-core' => 'Apache Log4j', 'spring-core' => 'Spring Framework',
			'cross device' => 'Microsoft Phone Link', 'zoomvdipluginmanagement' => 'Zoom',
		);
		$k = strtolower( $name );
		if ( isset( $fix[ $k ] ) ) {
			return $fix[ $k ];
		}
		// A path folder that is all lower-case (Linux) should read the same as
		// its Windows twin: 'commvault' -> 'Commvault'. Mixed-case names
		// (iTunes, MapInfo, "Microsoft Office") are left as they are.
		if ( '' !== $name && $name === strtolower( $name ) && ! str_contains( $name, ' ' ) ) {
			return ucfirst( $name );
		}
		return $name;
	}

	/**
	 * A user's Downloads folder, in every notation this scanner emits.
	 *
	 *   C:\Users\<u>\Downloads\...    canonical Windows
	 *   C:\\Users\<u>\Downloads\...   doubled separators
	 *   /C/Users/<u>/Downloads/...    a Windows drive written with slashes
	 *   /home/<u>/Downloads/...       Linux
	 *   /root/Downloads/...           Linux, root's own
	 *   /Users/<u>/Downloads/...      macOS
	 *
	 * Anchored on a user profile deliberately. A file share that happens to
	 * contain a directory called "Downloads" several levels down is not
	 * somebody's download folder, and counting it would inflate the number
	 * that is supposed to mean "software someone downloaded and ran from
	 * where it landed".
	 */
	private const DOWNLOADS_RE = '#(?:[A-Za-z]:[\\\\/]+Users[\\\\/]+[^\\\\/\r\n]+[\\\\/]+Downloads(?:[\\\\/][^\r\n]*)?)
		|(?:/[A-Za-z]/Users/[^/\r\n]+/Downloads(?:/[^\r\n]*)?)
		|(?:/home/[^/\r\n]+/Downloads(?:/[^\r\n]*)?)
		|(?:/root/Downloads(?:/[^\r\n]*)?)
		|(?:/Users/[^/\r\n]+/Downloads(?:/[^\r\n]*)?)#xi';

	/**
	 * Any absolute path, labelled "Path :" or standing on its own.
	 *
	 * The lookbehind matters: a drive letter is one letter, and without it
	 * "https://host/x" matches at "s://host/x" and every URL in the output
	 * gets reported as an install path.
	 */
	private const ANY_PATH_RE = '#(?:(?<![A-Za-z])[A-Za-z]:[\\\\/]+[^\r\n]+)|(?:/(?:home|root|Users|opt|usr|var|srv|etc)/[^\r\n]+)#i';

	/**
	 * Trim a path captured to end-of-line back to just the path.
	 *
	 * Scanner output packs several labelled fields onto one line -- "Name :
	 * Apache Log4j Path : C:\... Version : unknown" -- so a match that ran to
	 * the line end can have the next label glued onto it. Two or more spaces
	 * is how the padded multi-line format separates its columns, and
	 * " Word : " is how the single-line format does.
	 */
	private static function trim_path( string $path ): string {
		$path = trim( $path );
		$path = (string) preg_split( '/\s{2,}/', $path )[0];
		/*
		 * Drop a following "Label : value" field first. The single-line format
		 * runs them together with one space -- "...\jdk\ Installed version :
		 * 17.0.13" -- so this has to happen before the spaced-colon split
		 * below, which would otherwise consume the colon this anchors on and
		 * leave "\jdk\ Installed version" behind.
		 */
		$path = (string) preg_replace( '/\s+[A-Z][A-Za-z ]{2,24}\s*:.*$/', '', $path );
		/*
		 * Then any remaining spaced colon. A path never contains one: the only
		 * colon in a Windows path is the drive's, which has no space either
		 * side, and Unix paths have none at all. So " : " is always a field
		 * separator, whichever side the label sits on -- "Path : c2wts :
		 * C:\..." puts it before, the registry listings
		 * ("...\mpasdesc.dll,-242 : Helps guard against...") after.
		 */
		$path = (string) preg_split( '/\s+:\s+/', $path )[0];
		return trim( $path );
	}

	/** Collapse doubled separators so C:\\Users reads like C:\Users. */
	private static function normalise_output( string $output ): string {
		return (string) preg_replace( '#\\\\{2,}#', '\\', $output );
	}

	/**
	 * The install path out of a finding's plugin output, Windows or Unix.
	 *
	 * The one line a patch engineer needs to find the vulnerable copy on the
	 * box. Empty when the scan gave no path.
	 *
	 * This used to require the path to end in .dll/.jar/.exe/.so/.node, which
	 * silently dropped the majority of them: a directory install like
	 * "C:\Users\x\Downloads\sqldeveloper-24.3.1\sqldeveloper\jdk\" has no
	 * extension to match, and on this estate that rejected 2,008 of 2,132
	 * paths -- the Install path column was empty for almost every row that
	 * actually had one. It now takes the path as the line gives it.
	 */
	public static function install_path( string $output ): string {
		if ( '' === $output ) {
			return '';
		}

		$text = self::normalise_output( $output );

		/*
		 * A labelled path is the most reliable, so try that first -- but take
		 * the absolute path from inside the label's value, not the value
		 * itself. Tenable's "Unquoted Service Path" plugin writes
		 * "Path : c2wts : C:\Program Files\...", so a naive capture of
		 * everything after "Path :" returns the service name glued to the
		 * path.
		 */
		if ( preg_match( '/Path\s*:\s*([^\r\n]+)/i', $text, $m ) ) {
			if ( preg_match( self::ANY_PATH_RE, self::trim_path( $m[1] ), $p ) ) {
				return self::trim_path( $p[0] );
			}
		}

		// Otherwise take the first thing in the blob that looks absolute.
		if ( preg_match( self::ANY_PATH_RE, $text, $m ) ) {
			return self::trim_path( $m[0] );
		}

		return '';
	}

	/**
	 * The first user-Downloads path in a finding's output, or ''.
	 *
	 * Separate from install_path() on purpose: a finding can report several
	 * paths and only some of them sit in a download folder, so "is any of
	 * this running out of Downloads" is its own question and has to search
	 * the whole blob rather than trust whichever path happened to come first.
	 */
	public static function downloads_path( string $output ): string {
		if ( '' === $output || ! preg_match( self::DOWNLOADS_RE, self::normalise_output( $output ), $m ) ) {
			return '';
		}
		return self::trim_path( $m[0] );
	}

	/**
	 * Which notable directory a finding's files sit in, with the path.
	 *
	 * Stored on the finding at write time rather than parsed per render, so a
	 * dashboard can count and filter on it without scanning a 600MB text
	 * column. Returns a zone slug ('' when nothing notable) and the path that
	 * earned it. Kept as a slug rather than a boolean so later zones -- temp
	 * directories, removable drives -- need no migration.
	 *
	 * @return array{zone:string,path:string}
	 */
	public static function path_zone( string $output ): array {
		$downloads = self::downloads_path( $output );
		if ( '' !== $downloads ) {
			return array( 'zone' => 'downloads', 'path' => $downloads );
		}
		return array( 'zone' => '', 'path' => '' );
	}

	/** Stable slug for filters and icon lookup. */
	/** Stable slug for filters and icon lookup. */
	public static function slug( string $product ): string {
		$s = strtolower( $product );
		$s = str_replace( array( '.', '+', '#' ), array( '-', '-plus', '-sharp' ), $s );
		$s = preg_replace( '/[^a-z0-9]+/', '-', $s );
		return trim( (string) $s, '-' );
	}

	/**
	 * The highest "fixed in" version across a set of scanner texts.
	 *
	 * A scanner reports one finding per version threshold it knows about --
	 * "Firefox < 154.0", "Firefox < 146.0", and so on -- so a single outdated
	 * browser lights up a dozen separate rows. For remediation only the
	 * newest of those thresholds matters: install that or later and every one
	 * of them is fixed at once. This pulls the version out of a `< X` title or
	 * an "Upgrade to X" / "X or later" solution and returns the maximum.
	 *
	 * @param array<int,string> $texts Titles and/or solution strings.
	 * @return string The highest version seen, or '' if none parsed.
	 */
	public static function latest_fixed_version( array $texts ): string {
		$best = '';

		foreach ( $texts as $text ) {
			$text = (string) $text;

			// Prefer an explicit fix threshold; fall back to any dotted number
			// that is not obviously a CVE year (four digits followed by '-').
			if ( preg_match_all( '/(?:<|upgrade to|update to|fixed in|version)\s*[^\d]{0,12}?(\d+(?:\.\d+)+)/i', $text, $m ) ) {
				$candidates = $m[1];
			} elseif ( preg_match_all( '/\b(\d+(?:\.\d+)+)\b/', $text, $m ) ) {
				$candidates = $m[1];
			} else {
				continue;
			}

			foreach ( $candidates as $version ) {
				if ( '' === $best || version_compare( $version, $best, '>' ) ) {
					$best = $version;
				}
			}
		}

		return $best;
	}
}
