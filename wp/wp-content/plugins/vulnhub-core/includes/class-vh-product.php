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

		// Windows path first, then a Unix path -- Linux hosts bundle libraries
		// under /opt/<app>, /u01/<app>, /usr/local/<app> just as Windows does,
		// and Tenable prints either shape after "Path :".
		if ( ! preg_match(  '/Path\s*:?\s*([A-Za-z]:\\\\.+?\.(?:dll|jar|exe|so|node))/i', $output, $m ) ) {
			if ( preg_match( '#Path\s*:?\s*(/[^\s]+)#', $output, $mu ) ) {
				return self::app_clean( self::app_from_unix_path( $mu[1] ) );
			}
			return '';
		}
		$path = $m[1];
		$low  = strtolower( $path );

		// A genuine OS library: leave it attributed to the library.
		if ( str_contains( $low, '\\windows\\' ) || str_contains( $low, 'system32' ) || str_contains( $low, 'syswow64' ) ) {
			return '';
		}

		// MSIX / Store app: WindowsApps\<Publisher>.<App>_<ver>_<arch>__<hash>.
		if ( preg_match( '/WindowsApps\\\\+([^\\\\]+)/i', $path, $w ) ) {
			return self::app_clean( self::msix_app( $w[1] ) );
		}

		// Classic install under Program Files (x86 too): the app is the first
		// folder, or the product folder when the first is a known vendor.
		if ( preg_match( '/Program Files(?: \(x86\))?\\\\+(.+)$/i', $path, $pf ) ) {
			return self::app_clean( self::app_from_segments( $pf[1] ) );
		}

		// Loose location (a jar in Downloads, temp, a profile): the nearest
		// meaningful folder above the file names the app.
		$segs    = array_values( array_filter( explode( '\\', $path ) ) );
		$folders = array_slice( $segs, 0, -1 );
		$fname   = end( $segs );
		foreach ( array_reverse( $folders ) as $f ) {
			if ( ! self::app_is_noise( $f ) ) {
				return self::app_clean( $f );
			}
		}
		return self::app_clean( self::app_strip_version( $fname ) );
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
		if ( 0 === stripos( (string) $base, 'crossdevice' ) ) {
			return 'Microsoft Phone Link';
		}
		$name = (string) strrchr( (string) $base, '.' );
		$name = '' !== $name ? substr( $name, 1 ) : (string) $base;
		return self::app_spacecase( $name );
	}

	private static function app_spacecase( string $x ): string {
		$x = (string) preg_replace( '/(?<=[a-z0-9])(?=[A-Z])/', ' ', $x );
		return trim( (string) preg_replace( '/\s+/', ' ', $x ) );
	}

	private static function app_strip_version( string $fn ): string {
		$fn = (string) preg_replace( '/\.(dll|jar|exe|so|node)$/i', '', $fn );
		$fn = (string) preg_replace( '/[-_]v?\d[\d._()+-]*(?:[-_][a-z0-9]+)*$/i', '', $fn );
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
}
