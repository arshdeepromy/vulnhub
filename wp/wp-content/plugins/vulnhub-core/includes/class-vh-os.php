<?php
/**
 * Making sense of the operating-system string.
 *
 * Vendors write this field for people, not for software: "Microsoft Windows 11
 * Enterprise 23H2", "Red Hat Enterprise Linux release 9.3 (Plow)", "Amazon
 * Linux 2, Linux Kernel 5.10.262-262.1063.amzn2.x86_64 on Amazon Linux 2".
 * Three products, three shapes, and nothing in common but the column they
 * arrive in.
 *
 * This class turns that into a family, a clean display name and a version --
 * which is what a table wants to show, what end-of-life matching needs to
 * compare against, and what nothing else in the platform should be
 * re-implementing with its own regular expression.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Operating-system parsing, naming and iconography.
 */
final class Os {

	/** Where a licensed vendor logo may be dropped in. */
	public const ICON_DIR = 'assets/os';

	/**
	 * The families we recognise, in match order.
	 *
	 * Order matters: "Red Hat Enterprise Linux" has to be tested before the
	 * generic "linux", and "Windows Server" before "Windows".
	 *
	 * `match` is tried against the lower-cased raw string. `label` is the
	 * product name without the marketing; the version is added separately.
	 *
	 * @return array<string,array{label:string,vendor:string,match:string[],mono:string,tone:string,kind:string}>
	 */
	public static function families(): array {
		return array(
			'windows_server' => array(
				'label'  => 'Windows Server',
				'vendor' => 'Microsoft',
				'match'  => array( 'windows server' ),
				'mono'   => 'WS',
				'tone'   => 'azure',
				'kind'   => 'server',
			),
			'windows'        => array(
				'label'  => 'Windows',
				'vendor' => 'Microsoft',
				'match'  => array( 'windows', 'microsoft windows' ),
				'mono'   => 'Wi',
				'tone'   => 'azure',
				'kind'   => 'desktop',
			),
			'rhel'           => array(
				'label'  => 'Red Hat Enterprise Linux',
				'vendor' => 'Red Hat',
				'match'  => array( 'red hat enterprise linux', 'redhat enterprise', 'rhel', 'red hat' ),
				'mono'   => 'RH',
				'tone'   => 'crimson',
				'kind'   => 'server',
			),
			'rocky'          => array(
				'label'  => 'Rocky Linux',
				'vendor' => 'Rocky Enterprise Software Foundation',
				'match'  => array( 'rocky linux', 'rocky' ),
				'mono'   => 'Ro',
				'tone'   => 'forest',
				'kind'   => 'server',
			),
			'alma'           => array(
				'label'  => 'AlmaLinux',
				'vendor' => 'AlmaLinux OS Foundation',
				'match'  => array( 'almalinux', 'alma linux' ),
				'mono'   => 'Al',
				'tone'   => 'forest',
				'kind'   => 'server',
			),
			'centos'         => array(
				'label'  => 'CentOS',
				'vendor' => 'The CentOS Project',
				'match'  => array( 'centos' ),
				'mono'   => 'Ce',
				'tone'   => 'violet',
				'kind'   => 'server',
			),
			'amazon'         => array(
				'label'  => 'Amazon Linux',
				'vendor' => 'Amazon',
				'match'  => array( 'amazon linux', 'amzn', 'amazon' ),
				'mono'   => 'AL',
				'tone'   => 'amber',
				'kind'   => 'server',
			),
			'ubuntu'         => array(
				'label'  => 'Ubuntu',
				'vendor' => 'Canonical',
				'match'  => array( 'ubuntu' ),
				'mono'   => 'Ub',
				'tone'   => 'ember',
				'kind'   => 'server',
			),
			'debian'         => array(
				'label'  => 'Debian',
				'vendor' => 'The Debian Project',
				'match'  => array( 'debian' ),
				'mono'   => 'De',
				'tone'   => 'crimson',
				'kind'   => 'server',
			),
			'suse'           => array(
				'label'  => 'SUSE Linux Enterprise',
				'vendor' => 'SUSE',
				'match'  => array( 'suse linux enterprise', 'sles', 'opensuse', 'suse' ),
				'mono'   => 'SU',
				'tone'   => 'forest',
				'kind'   => 'server',
			),
			/*
			 * Network and hypervisor platforms come before Apple's, because
			 * "Cisco IOS XE 17.9" contains the substring "os x" and was
			 * confidently reported as macOS 17.9 until it did not.
			 */
			'ios_xe'         => array(
				'label'  => 'Cisco IOS XE',
				'vendor' => 'Cisco',
				'match'  => array( 'cisco ios xe', 'ios xe', 'cisco ios', 'nx-os' ),
				'mono'   => 'IOS',
				'tone'   => 'azure',
				'kind'   => 'network',
			),
			'esxi'           => array(
				'label'  => 'VMware ESXi',
				'vendor' => 'Broadcom',
				'match'  => array( 'vmware esxi', 'esxi', 'vmware' ),
				'mono'   => 'ESX',
				'tone'   => 'slate',
				'kind'   => 'hypervisor',
			),
			'macos'          => array(
				'label'  => 'macOS',
				'vendor' => 'Apple',
				'match'  => array( 'macos', 'mac os x', 'darwin' ),
				'mono'   => 'mac',
				'tone'   => 'slate',
				'kind'   => 'desktop',
			),
			'ipados'         => array(
				'label'  => 'iPadOS',
				'vendor' => 'Apple',
				'match'  => array( 'ipados' ),
				'mono'   => 'iPd',
				'tone'   => 'slate',
				'kind'   => 'mobile',
			),
			'ios'            => array(
				'label'  => 'iOS',
				'vendor' => 'Apple',
				'match'  => array( 'iphone os', 'apple ios' ),
				'mono'   => 'iOS',
				'tone'   => 'slate',
				'kind'   => 'mobile',
			),
			'android'        => array(
				'label'  => 'Android',
				'vendor' => 'Google',
				'match'  => array( 'android' ),
				'mono'   => 'An',
				'tone'   => 'forest',
				'kind'   => 'mobile',
			),
			'linux'          => array(
				'label'  => 'Linux',
				'vendor' => '',
				'match'  => array( 'linux', 'gnu/linux' ),
				'mono'   => 'Lx',
				'tone'   => 'slate',
				'kind'   => 'server',
			),
		);
	}

	/**
	 * Single words left behind by the old whitespace splitter.
	 *
	 * Until the platform was fixed, "Red Hat Enterprise Linux 9.3" was stored
	 * as "Red" and "Microsoft Windows 11 Enterprise" as "Microsoft". Those
	 * rows cannot repair themselves -- the rest of the string is gone -- and
	 * they stay that way until the connector next writes over them.
	 *
	 * The family is still recoverable from the fragment, so the table can say
	 * "Red Hat Enterprise Linux" instead of "Red". The version is not, and
	 * the parse is flagged `truncated` so the UI says so rather than implying
	 * we know which release it is.
	 *
	 * @return array<string,string>
	 */
	private static function salvage(): array {
		return array(
			'red'       => 'rhel',
			'redhat'    => 'rhel',
			'microsoft' => 'windows',
			'windows'   => 'windows',
			'amazon'    => 'amazon',
			'amzn'      => 'amazon',
			'rocky'     => 'rocky',
			'ubuntu'    => 'ubuntu',
			'debian'    => 'debian',
			'centos'    => 'centos',
			'alma'      => 'alma',
			'almalinux' => 'alma',
			'suse'      => 'suse',
			'linux'     => 'linux',
		);
	}

	/**
	 * Break an operating-system string into its parts.
	 *
	 * Never throws and never returns null: an unrecognised string still comes
	 * back with its own text as the name, because showing the vendor's words
	 * beats showing "Unknown".
	 *
	 * @param string $raw Whatever the connector stored.
	 * @return array{family:string,label:string,name:string,version:string,edition:string,vendor:string,mono:string,tone:string,kind:string,raw:string}
	 */
	public static function parse( string $raw ): array {
		$raw   = trim( $raw );
		$blank = array(
			'family'  => 'unknown',
			'label'   => __( 'Unknown', 'vulnhub' ),
			'name'    => __( 'Unknown', 'vulnhub' ),
			'version' => '',
			'edition' => '',
			'vendor'  => '',
			'mono'    => '?',
			'tone'    => 'muted',
			'kind'      => 'unknown',
			'truncated' => false,
			'raw'       => '',
		);

		if ( '' === $raw ) {
			return $blank;
		}

		/*
		 * Some exports append the running kernel: "Amazon Linux 2, Linux
		 * Kernel 5.10.262-... on Amazon Linux 2". The part before the first
		 * comma is the product; the rest is detail for the asset page.
		 */
		$head  = trim( (string) ( explode( ',', $raw )[0] ?? $raw ) );
		$lower = strtolower( $head );

		$found     = null;
		$key       = 'unknown';
		$truncated = false;

		/*
		 * A bare single word is a casualty of the old splitter, not a product
		 * name. Recover the family from it and say the version is unknown.
		 */
		if ( ! str_contains( $head, ' ' ) ) {
			$salvaged = self::salvage()[ $lower ] ?? '';

			if ( '' !== $salvaged ) {
				$found     = self::families()[ $salvaged ];
				$key       = $salvaged;
				$truncated = true;
			}
		}

		foreach ( $found ? array() : self::families() as $family => $def ) {
			foreach ( $def['match'] as $needle ) {
				if ( str_contains( $lower, $needle ) ) {
					$found = $def;
					$key   = $family;
					break 2;
				}
			}
		}

		if ( ! $found ) {
			$out          = $blank;
			$out['name']  = vh_trim( $head, 60 );
			$out['label'] = $out['name'];
			$out['raw']   = $raw;
			return $out;
		}


		return array(
			'family'    => $key,
			'label'     => $found['label'],
			'name'      => $truncated ? $found['label'] : self::display_name( $found['label'], $head, $key ),
			'version'   => $truncated ? '' : self::version( $head, $key ),
			'edition'   => $truncated ? '' : self::edition( $head, $key ),
			'vendor'    => $found['vendor'],
			'mono'      => $found['mono'],
			'tone'      => $found['tone'],
			'kind'      => $found['kind'],
			'truncated' => $truncated,
			'raw'       => $raw,
		);
	}

	/**
	 * The version number, as the product itself writes it.
	 *
	 * Windows is the awkward one: "Windows 11" is the product and "23H2" is
	 * the build, so the number after the name is part of the name and the
	 * build is the version.
	 */
	private static function version( string $head, string $family ): string {
		if ( 'windows' === $family || 'windows_server' === $family ) {
			// 23H2, 22H2 -- the feature-update code.
			if ( preg_match( '/\b(\d{2}H\d)\b/i', $head, $m ) ) {
				return strtoupper( $m[1] );
			}
			return '';
		}

		if ( preg_match( '/\b(\d+(?:\.\d+)*)\b/', $head, $m ) ) {
			return $m[1];
		}

		return '';
	}

	/**
	 * Enterprise, Professional, Datacenter, Home -- the SKU.
	 *
	 * Windows only. "Enterprise" is a SKU there and a load-bearing part of
	 * the product name in "Red Hat Enterprise Linux", where reporting it as
	 * an edition says nothing and reads as a mistake.
	 */
	private static function edition( string $head, string $family ): string {
		if ( 'windows' !== $family && 'windows_server' !== $family ) {
			return '';
		}

		foreach ( array( 'Enterprise', 'Datacenter', 'Professional', 'Education', 'Standard', 'Home', 'Pro' ) as $sku ) {
			if ( stripos( $head, $sku ) !== false ) {
				return $sku;
			}
		}
		return '';
	}

	/**
	 * What the table cell should say.
	 *
	 * "Microsoft Windows 11 Enterprise" is four words of which one is the
	 * vendor and one is the SKU. A column of them is unreadable, so the cell
	 * gets "Windows 11" and the SKU rides underneath.
	 */
	private static function display_name( string $label, string $head, string $family ): string {
		if ( 'windows' === $family || 'windows_server' === $family ) {
			if ( preg_match( '/windows\s+server\s+(\d{4}(?:\s*R\d)?)/i', $head, $m ) ) {
				return 'Windows Server ' . trim( $m[1] );
			}
			if ( preg_match( '/windows\s+(11|10|8\.1|8|7)\b/i', $head, $m ) ) {
				return 'Windows ' . $m[1];
			}
			return $label;
		}

		$version = self::version( $head, $family );

		return '' !== $version ? $label . ' ' . $version : $label;
	}

	/**
	 * A licensed vendor logo, if somebody has dropped one in.
	 *
	 * VulnHub ships no vendor logos: they are trademarked artwork and not
	 * ours to redistribute. What it ships is the slot. Drop
	 * `windows.svg`, `rhel.svg`, `ubuntu.svg` (named for the family key) into
	 * `vulnhub-core/assets/os/` and the monogram gives way to the real mark.
	 *
	 * @param string $family Family key.
	 * @return string URL, or empty when there is no file.
	 */
	public static function icon_url( string $family ): string {
		static $cache = array();
		static $db    = null;

		if ( isset( $cache[ $family ] ) ) {
			return $cache[ $family ];
		}

		/*
		 * Real vendor logos live in the database (option `vulnhub_os_logos`,
		 * family => PNG data URI), fetched and stored once. Preferred over the
		 * bundled files so an operator can refresh the set without a deploy.
		 * Falls back to a shipped assets/os/<family>.svg|png|webp when a family
		 * has no stored logo.
		 */
		if ( null === $db ) {
			$db = get_option( 'vulnhub_os_logos', array() );
			$db = is_array( $db ) ? $db : array();
		}
		if ( ! empty( $db[ $family ] ) && is_string( $db[ $family ] ) ) {
			return $cache[ $family ] = $db[ $family ];
		}

		$cache[ $family ] = '';

		foreach ( array( 'svg', 'png', 'webp' ) as $ext ) {
			$file = VULNHUB_DIR . self::ICON_DIR . '/' . $family . '.' . $ext;

			if ( is_readable( $file ) ) {
				$cache[ $family ] = VULNHUB_URL . self::ICON_DIR . '/' . $family . '.' . $ext;
				break;
			}
		}

		return $cache[ $family ];
	}

	/**
	 * The badge shown beside an operating-system name.
	 *
	 * @param string $raw   Raw OS string.
	 * @param bool   $label Whether to print the name beside the badge.
	 * @return string Escaped HTML.
	 */
	/**
	 * Render an operating system, correcting the name from the build number.
	 *
	 * `$version` is the asset's os_version, and passing it is what turns this
	 * from a label into an answer. 21 assets in this estate are recorded as
	 * "Microsoft Windows 11 Enterprise" and are running build 19045, which is
	 * Windows 10 22H2 -- out of support since October 2025. Another 191
	 * arrived with the OS string truncated to "Microsoft" or "Windows" and no
	 * release at all, and their build says exactly which Server they are.
	 *
	 * Where the build disagrees with the label, the build wins and the badge
	 * says so rather than quietly swapping the name: somebody reading a list
	 * filtered to Windows 10 needs to see why a row labelled Windows 11 is in
	 * it, or the filter looks broken.
	 *
	 * Called without `$version` it behaves exactly as before.
	 */
	public static function badge( string $raw, bool $label = true, string $version = '', string $asset_type = '' ): string {
		$os   = self::parse( $raw );
		$icon = self::icon_url( $os['family'] );
		$fix  = self::from_build( $raw, $version, $asset_type );

		$name      = $fix ? (string) $fix['name'] : $os['name'];
		$corrected = $fix && (string) $fix['name'] !== $os['name'];

		$title = $os['raw'] ?: $os['name'];

		if ( $corrected ) {
			$title = sprintf(
				/* translators: 1: what the inventory recorded, 2: the build number, 3: the release that build actually is. */
				__( 'The inventory records this as "%1$s". Build %2$s is %3$s.', 'vulnhub' ),
				$os['raw'],
				(string) $fix['build'],
				(string) $fix['name']
			);
		}

		$out = '<span class="vh-os" title="' . esc_attr( $title ) . '">';

		if ( '' !== $icon ) {
			// A DB-stored logo is a data: URI, which esc_url() strips (not in
			// its protocol whitelist); it is our own generated base64, so
			// escape it as an attribute. File-based icons stay on esc_url().
			$icon_src = 0 === strpos( $icon, 'data:' ) ? esc_attr( $icon ) : esc_url( $icon );
			$out .= '<img class="vh-os__logo" src="' . $icon_src . '" alt="" width="16" height="16" loading="lazy">';
		} else {
			$out .= '<span class="vh-os__mono vh-os__mono--' . esc_attr( $os['tone'] ) . '" aria-hidden="true">'
				. esc_html( $os['mono'] ) . '</span>';
		}

		if ( $label ) {
			$out .= '<span class="vh-os__text"><span class="vh-os__name">' . esc_html( $name ) . '</span>';

			// The release off the build is better than the one off the label,
			// because on Windows the label frequently does not carry one.
			$release = $fix ? (string) $fix['release'] : $os['version'];
			$detail  = trim( $os['edition'] . ( '' !== $release && '' !== $os['edition'] ? ' · ' : '' ) . $release );

			if ( $corrected ) {
				$out .= '<span class="vh-os__detail vh-os__detail--fixed">'
					. esc_html( trim( $detail . ' ' . sprintf( '(build %s)', (string) $fix['build'] ) ) )
					. '</span>';
			} elseif ( ! empty( $os['truncated'] ) && ! $fix ) {
				$out .= '<span class="vh-os__detail vh-os__detail--unknown" title="'
					. esc_attr__( 'This record was stored before the operating-system field was parsed correctly. The next connector sync will fill in the release.', 'vulnhub' )
					. '">' . esc_html__( 'release unknown', 'vulnhub' ) . '</span>';
			} elseif ( '' !== $detail ) {
				$out .= '<span class="vh-os__detail">' . esc_html( $detail ) . '</span>';
			}

			$out .= '</span>';
		}

		return $out . '</span>';
	}

	/**
	 * What the build number says this release is, or null.
	 *
	 * Delegates to the lifecycle table rather than keeping a second build map
	 * here: that table already has to know which build is which release in
	 * order to date it, and two maps would eventually name the same build
	 * differently on the chart and in the list.
	 *
	 * @return array{name:string,release:string,build:string}|null
	 */
	private static function from_build( string $raw, string $version, string $asset_type ): ?array {
		if ( '' === trim( $version ) || ! class_exists( Eol::class ) ) {
			return null;
		}

		$family = self::parse( $raw )['family'];

		if ( 'windows' !== $family && 'windows_server' !== $family ) {
			return null;
		}

		$row = Eol::match_os(
			array(
				'operating_system' => $raw,
				'os_version'       => $version,
				'asset_type'       => $asset_type,
			)
		);

		if ( ! $row || '' === (string) $row['build'] ) {
			return null;
		}

		return array(
			'name'    => (string) $row['product'],
			'release' => (string) $row['release'],
			'build'   => (string) $row['build'],
		);
	}

	/**
	 * The broad platforms a family belongs to.
	 *
	 * Families are specific ("ubuntu", "rocky"); a platform is the question a
	 * dashboard actually asks ("how much of this is Linux"). Keyed by platform
	 * so the membership is readable in one place and a new distro only has to
	 * be added to the family list and to one line here.
	 *
	 * @return array<string,array<int,string>>
	 */
	public static function platforms(): array {
		return array(
			'windows' => array( 'windows', 'windows_server' ),
			'linux'   => array( 'rhel', 'rocky', 'alma', 'centos', 'amazon', 'ubuntu', 'debian', 'suse', 'linux' ),
			'macos'   => array( 'macos' ),
			'mobile'  => array( 'ios', 'ipados', 'android' ),
			'other'   => array( 'esxi', 'ios_xe', 'unknown' ),
		);
	}

	/** Human label for a platform slug. */
	public static function platform_label( string $platform ): string {
		$labels = array(
			'windows' => __( 'Windows', 'vulnhub' ),
			'linux'   => __( 'Linux', 'vulnhub' ),
			'macos'   => __( 'macOS', 'vulnhub' ),
			'mobile'  => __( 'Mobile', 'vulnhub' ),
			'other'   => __( 'Other', 'vulnhub' ),
		);
		return $labels[ $platform ] ?? $platform;
	}

	/** The platform an operating-system string belongs to. */
	public static function platform( string $raw ): string {
		$family = self::parse( $raw )['family'];
		foreach ( self::platforms() as $platform => $families ) {
			if ( in_array( $family, $families, true ) ) {
				return $platform;
			}
		}
		return 'other';
	}

	/**
	 * A SQL condition selecting one platform, for `$col`.
	 *
	 * Built from the same `match` strings parse() uses, so the list of things
	 * that count as Linux lives in exactly one place. Filtering in SQL is not
	 * optional for a paginated list -- classifying in PHP after the fact would
	 * make LIMIT/OFFSET return the wrong rows -- but duplicating the family
	 * table into hand-written SQL would guarantee the two drift apart.
	 *
	 * Returns '' for an unknown platform, which callers should read as
	 * "no filter".
	 */
	public static function platform_sql( string $platform, string $col = 'a.operating_system' ): string {
		$families = self::platforms()[ $platform ] ?? array();
		if ( ! $families ) {
			return '';
		}

		$all = self::families();
		$needles = array();
		foreach ( $families as $family ) {
			foreach ( (array) ( $all[ $family ]['match'] ?? array() ) as $needle ) {
				$needles[ strtolower( (string) $needle ) ] = true;
			}
		}
		if ( ! $needles ) {
			return '';
		}

		$parts = array();
		foreach ( array_keys( $needles ) as $needle ) {
			$parts[] = sprintf( "%s LIKE '%%%s%%'", $col, esc_sql( $needle ) );
		}

		$sql = '( ' . implode( ' OR ', $parts ) . ' )';

		/*
		 * "Windows" also matches inside other vendors' strings, but the real
		 * problem is the other direction: a Linux box whose OS string mentions
		 * Windows (a Samba banner, say) would count as both. Platforms are
		 * meant to partition the estate, so everything after the first listed
		 * platform excludes the ones before it.
		 */
		$order = array_keys( self::platforms() );
		$mine  = array_search( $platform, $order, true );
		if ( false !== $mine && $mine > 0 ) {
			foreach ( array_slice( $order, 0, (int) $mine ) as $earlier ) {
				$prior = self::platform_sql_needles( $earlier, $col );
				if ( '' !== $prior ) {
					$sql .= ' AND NOT ' . $prior;
				}
			}
		}

		return $sql;
	}

	/** The bare OR-list for a platform, without the exclusions. */
	private static function platform_sql_needles( string $platform, string $col ): string {
		$families = self::platforms()[ $platform ] ?? array();
		$all      = self::families();
		$needles  = array();
		foreach ( $families as $family ) {
			foreach ( (array) ( $all[ $family ]['match'] ?? array() ) as $needle ) {
				$needles[ strtolower( (string) $needle ) ] = true;
			}
		}
		if ( ! $needles ) {
			return '';
		}
		$parts = array();
		foreach ( array_keys( $needles ) as $needle ) {
			$parts[] = sprintf( "%s LIKE '%%%s%%'", $col, esc_sql( $needle ) );
		}
		return '( ' . implode( ' OR ', $parts ) . ' )';
	}

	/**
	 * How many assets the estate holds per platform.
	 *
	 * Lets a dashboard tell "0 because nothing was found" from "0 because
	 * there is nothing of that kind here". Linux showing zero download-folder
	 * findings is a real answer worth drawing; a macOS tile on an estate with
	 * no Macs is just noise.
	 *
	 * @return array<string,int>
	 */
	public static function estate_platforms(): array {
		$out = array();
		foreach ( array_keys( self::platforms() ) as $platform ) {
			$out[ $platform ] = 0;
		}

		foreach ( self::estate() as $row ) {
			$family = (string) ( $row['family'] ?? '' );
			foreach ( self::platforms() as $platform => $families ) {
				if ( in_array( $family, $families, true ) ) {
					$out[ $platform ] += (int) ( $row['assets'] ?? 0 );
					break;
				}
			}
		}

		return $out;
	}

	/**
	 * Group the estate by operating-system family.
	 *
	 * @return array<int,array{family:string,label:string,mono:string,tone:string,assets:int}>
	 */
	public static function estate(): array {
		global $wpdb;

		$rows = (array) $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			'SELECT operating_system AS os, COUNT(*) AS n FROM ' . vh_table( 'assets' )
			. ' WHERE lifecycle_status IN (' . vh_in_service_sql() . ') GROUP BY operating_system', // phpcs:ignore
			ARRAY_A
		);

		$out = array();

		foreach ( $rows as $row ) {
			$os  = self::parse( (string) $row['os'] );
			$key = $os['family'];

			if ( ! isset( $out[ $key ] ) ) {
				$out[ $key ] = array(
					'family' => $key,
					'label'  => $os['label'],
					'mono'   => $os['mono'],
					'tone'   => $os['tone'],
					'assets' => 0,
				);
			}

			$out[ $key ]['assets'] += (int) $row['n'];
		}

		uasort( $out, static fn( array $a, array $b ): int => $b['assets'] <=> $a['assets'] );

		return array_values( $out );
	}
}

