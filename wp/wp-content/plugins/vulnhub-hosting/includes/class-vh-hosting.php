<?php
/**
 * Server hosting environment: cloud vs on-prem, OS split and exposure.
 *
 * A server's environment is worked out from the data we already hold, most
 * reliable signal first: a cloud instance id or a cloud location => cloud
 * (AWS / Azure / GCP); an `ec2amaz-*` hostname => AWS; a "Vendor" location =>
 * on-prem data centre; any other named location => on-prem office/site; nothing
 * => unclassified. The widget then reports each environment's server count, its
 * Linux-vs-Windows split, and its open findings by severity.
 *
 * @package VulnHub\Hosting
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The hosting-environment widget.
 */
final class VulnHub_Hosting {

	public const WIDGET = 'server_hosting';

	public static function init(): void {
		add_filter( 'vulnhub_dashboard_widgets', array( __CLASS__, 'register_widget' ) );
		add_filter( 'vulnhub_dashboard_default_layout', array( __CLASS__, 'place_widget' ) );

		// Make `hosting` a findings dimension so every number in the widget can
		// drill into the exact list (the CSV export routes here too).
		add_filter( 'vulnhub_findings_query', array( __CLASS__, 'findings_query' ), 10, 2 );
	}

	/**
	 * Asset ids of the servers in one hosting environment.
	 *
	 * @return int[]
	 */
	public static function hosting_asset_ids( string $env ): array {
		global $wpdb;

		if ( ! isset( self::environments()[ $env ] ) ) {
			return array();
		}

		$a  = vh_table( 'assets' );
		$l  = vh_table( 'locations' );
		$pk = self::placement_case();

		return array_map(
			'intval',
			(array) $wpdb->get_col( // phpcs:ignore WordPress.DB
				$wpdb->prepare(
					"SELECT a.id FROM {$a} a LEFT JOIN {$l} l ON l.id = a.location_id
					 WHERE a.asset_type IN ('server','cloud') AND ( {$pk} ) = %s", // phpcs:ignore WordPress.DB
					$env
				)
			)
		);
	}

	/**
	 * Teach the central findings query about a `hosting` argument.
	 *
	 * @param array<string,mixed> $ext  Extension clauses.
	 * @param array<string,mixed> $args Query args.
	 * @return array<string,mixed>
	 */
	public static function findings_query( array $ext, array $args ): array {
		$env = isset( $args['hosting'] ) ? sanitize_key( (string) $args['hosting'] ) : '';

		if ( '' === $env || ! isset( self::environments()[ $env ] ) ) {
			return $ext;
		}

		$ids = self::hosting_asset_ids( $env );

		$ext['where'][] = $ids ? 'f.asset_id IN (' . implode( ',', $ids ) . ')' : '1=0';

		return $ext;
	}

	/* =================================================================
	 * Classification SQL (shared by the asset and finding queries)
	 * ============================================================== */

	/**
	 * The CASE that maps one server row to an environment key.
	 *
	 * Signals, most decisive first: a cloud instance id / cloud location, then
	 * AWS by EC2 hostname or Amazon/Xen hardware; then on-prem by a named
	 * location, by server/appliance hardware (VMware, HP, Dell, CLARiiON,
	 * Mellanox, Check Point, Hyper-V…), or by a private (RFC1918) address.
	 */
	private static function placement_case(): string {
		return "CASE
			WHEN a.cloud_provider <> '' OR a.aws_instance_id <> '' OR a.azure_vm_id <> '' OR a.gcp_instance_id <> '' OR l.name IN ('AWS Cloud','Azure Cloud','GCP Cloud')
				THEN CASE
					WHEN a.cloud_provider = 'azure' OR a.azure_vm_id <> '' OR l.name = 'Azure Cloud' THEN 'azure'
					WHEN a.gcp_instance_id <> '' OR l.name = 'GCP Cloud'                              THEN 'gcp'
					WHEN a.cloud_provider = 'aws' OR a.aws_instance_id <> '' OR l.name = 'AWS Cloud'  THEN 'aws'
					ELSE 'cloud'
				END
			WHEN a.hostname LIKE 'ec2amaz%' OR a.manufacturer LIKE 'Amazon%' OR a.manufacturer LIKE '%EC2%' OR a.manufacturer = 'Xen'
				THEN 'aws'
			WHEN l.name IS NOT NULL AND l.name <> ''
				THEN 'onprem'
			WHEN a.manufacturer LIKE '%VMware%' OR a.manufacturer LIKE 'HP%' OR a.manufacturer LIKE '%Hewlett%' OR a.manufacturer LIKE 'Dell%'
				OR a.manufacturer LIKE 'Lenovo%' OR a.manufacturer LIKE 'Cisco%' OR a.manufacturer LIKE 'Supermicro%' OR a.manufacturer LIKE '%CLARIION%'
				OR a.manufacturer LIKE '%Mellanox%' OR a.manufacturer LIKE '%Check Point%' OR a.manufacturer LIKE '%Hitachi%' OR a.manufacturer LIKE '%Inner Range%'
				OR a.manufacturer LIKE 'Microsoft%'
				THEN 'onprem'
			WHEN a.ipv4 REGEXP '^(10[.]|192[.]168[.]|172[.](1[6-9]|2[0-9]|3[01])[.])'
				THEN 'onprem'
			ELSE 'unknown'
		END";
	}

	private static function os_windows_sql(): string {
		return "(a.operating_system LIKE '%windows%' OR a.operating_system LIKE '%microsoft%')";
	}

	private static function os_linux_sql(): string {
		return "(a.operating_system LIKE '%linux%' OR a.operating_system LIKE '%rhel%' OR a.operating_system LIKE '%red hat%'
			OR a.operating_system LIKE '%centos%' OR a.operating_system LIKE '%ubuntu%' OR a.operating_system LIKE '%debian%'
			OR a.operating_system LIKE '%suse%' OR a.operating_system LIKE '%rocky%' OR a.operating_system LIKE '%alma%'
			OR a.operating_system LIKE '%oracle linux%' OR a.operating_system LIKE '%amazon linux%')";
	}

	/** Environment keys, in display order, with a label and a cloud/on-prem kind. */
	private static function environments(): array {
		return array(
			'aws'     => array( 'label' => __( 'Cloud — AWS', 'vulnhub' ),   'kind' => 'cloud' ),
			'azure'   => array( 'label' => __( 'Cloud — Azure', 'vulnhub' ), 'kind' => 'cloud' ),
			'gcp'     => array( 'label' => __( 'Cloud — GCP', 'vulnhub' ),   'kind' => 'cloud' ),
			'cloud'   => array( 'label' => __( 'Cloud — other', 'vulnhub' ), 'kind' => 'cloud' ),
			'onprem'  => array( 'label' => __( 'On-prem', 'vulnhub' ),       'kind' => 'onprem' ),
			'unknown' => array( 'label' => __( 'Unclassified', 'vulnhub' ),  'kind' => 'unknown' ),
		);
	}

	/* =================================================================
	 * Data
	 * ============================================================== */

	/**
	 * Per-environment: server count, OS split, and open-finding severity counts.
	 *
	 * @return array<string,array<string,int>> keyed by environment key.
	 */
	public static function rows(): array {
		/*
		 * Two GROUP BYs over the server estate and the whole findings table.
		 * Memoised in an epoch-keyed transient the way Exposure-by-product and
		 * the department widget cache theirs: computed once per data epoch,
		 * shared across hosts and the widget's drill-downs, and rotated
		 * automatically whenever a sync or import calls bust().
		 */
		$epoch = class_exists( 'VulnHub_Dash_Widgets' ) ? VulnHub_Dash_Widgets::epoch() : '';
		$ck    = 'vh_hosting_rows_' . md5( $epoch );
		$hit   = get_transient( $ck );

		if ( is_array( $hit ) ) {
			return $hit;
		}

		global $wpdb;

		$a   = vh_table( 'assets' );
		$l   = vh_table( 'locations' );
		$f   = vh_table( 'findings' );
		$pk  = self::placement_case();
		$win = self::os_windows_sql();
		$lin = self::os_linux_sql();

		$out = array();
		foreach ( array_keys( self::environments() ) as $key ) {
			$out[ $key ] = array(
				'servers' => 0, 'linux' => 0, 'windows' => 0, 'other' => 0,
				'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0, 'total' => 0,
			);
		}

		// Servers + OS split (assets only; distinct machines).
		$assets = (array) $wpdb->get_results( // phpcs:ignore WordPress.DB
			"SELECT {$pk} AS pk, COUNT(*) AS servers,
				SUM(CASE WHEN {$win} THEN 1 ELSE 0 END) AS windows,
				SUM(CASE WHEN {$win} THEN 0 WHEN {$lin} THEN 1 ELSE 0 END) AS linux,
				SUM(CASE WHEN {$win} OR {$lin} THEN 0 ELSE 1 END) AS other
			 FROM {$a} a LEFT JOIN {$l} l ON l.id = a.location_id
			 WHERE a.asset_type IN ('server','cloud')
			 GROUP BY pk", // phpcs:ignore WordPress.DB
			ARRAY_A
		);
		foreach ( $assets as $r ) {
			$k = (string) $r['pk'];
			if ( ! isset( $out[ $k ] ) ) {
				continue;
			}
			$out[ $k ]['servers'] = (int) $r['servers'];
			$out[ $k ]['linux']   = (int) $r['linux'];
			$out[ $k ]['windows'] = (int) $r['windows'];
			$out[ $k ]['other']   = (int) $r['other'];
		}

		// Open findings by severity on those servers.
		$finds = (array) $wpdb->get_results( // phpcs:ignore WordPress.DB
			"SELECT {$pk} AS pk,
				SUM(f.severity='critical') AS critical, SUM(f.severity='high') AS high,
				SUM(f.severity='medium') AS medium, SUM(f.severity='low') AS low,
				SUM(f.severity='info') AS info, COUNT(*) AS total
			 FROM {$f} f
			 INNER JOIN {$a} a ON a.id = f.asset_id
			 LEFT JOIN {$l} l ON l.id = a.location_id
			 WHERE a.asset_type IN ('server','cloud') AND f.state IN ('open','reopened') AND f.exception_id = 0
			 GROUP BY pk", // phpcs:ignore WordPress.DB
			ARRAY_A
		);
		foreach ( $finds as $r ) {
			$k = (string) $r['pk'];
			if ( ! isset( $out[ $k ] ) ) {
				continue;
			}
			foreach ( array( 'critical', 'high', 'medium', 'low', 'info', 'total' ) as $c ) {
				$out[ $k ][ $c ] = (int) $r[ $c ];
			}
		}

		// Drop environments with no servers.
		$out = array_filter( $out, static fn( array $r ): bool => $r['servers'] > 0 );

		$ttl = class_exists( 'VulnHub_Dash_Widgets' ) ? VulnHub_Dash_Widgets::stale_ttl() : HOUR_IN_SECONDS;
		set_transient( $ck, $out, $ttl );

		return $out;
	}

	/* =================================================================
	 * Widget
	 * ============================================================== */

	/**
	 * @param array<string,array<string,mixed>> $w Registry.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_widget( array $w ): array {
		$w[ self::WIDGET ] = array(
			'label'   => __( 'Servers by hosting environment', 'vulnhub' ),
			'summary' => __( 'Cloud vs on-prem server counts, the Linux / Windows split, and how exposed each environment is.', 'vulnhub' ),
			'group'   => 'exposure',
			'width'   => 12,
			'depends' => array( 'assets', 'findings' ),
			'render'  => array( __CLASS__, 'render_widget' ),
			'data'    => array( __CLASS__, 'data_widget' ),
		);

		return $w;
	}

	/**
	 * @param array<int,array{id:string,width:int}> $layout Default layout.
	 * @return array<int,array{id:string,width:int}>
	 */
	public static function place_widget( array $layout ): array {
		foreach ( $layout as $entry ) {
			if ( self::WIDGET === ( $entry['id'] ?? '' ) ) {
				return $layout;
			}
		}
		$layout[] = array( 'id' => self::WIDGET, 'width' => 12 );

		return $layout;
	}

	/** A small brand mark per environment (inline SVG, CSP-safe). */
	private static function icon( string $key ): string {
		switch ( $key ) {
			case 'aws':
				$svg = '<path fill="#FF9900" d="M18.4 10.6a5 5 0 0 0-9.5-1.8A4.3 4.3 0 1 0 5.5 17.5h12.2a3.5 3.5 0 0 0 .7-6.9z"/>';
				break;
			case 'azure':
				$svg = '<path fill="#0089D6" d="M10.6 4 4.2 20h4.2L13 7.2z"/><path fill="#0089D6" d="M11.3 12.2 8.6 20H20z"/>';
				break;
			case 'onprem':
				$svg = '<g fill="none" stroke="#4ade80" stroke-width="1.6"><rect x="4.5" y="5" width="15" height="6" rx="1.5"/><rect x="4.5" y="13" width="15" height="6" rx="1.5"/></g>'
					. '<circle cx="7.6" cy="8" r="1" fill="#4ade80"/><circle cx="7.6" cy="16" r="1" fill="#4ade80"/>';
				break;
			default:
				$svg = '<path fill="#7d8aa3" d="M18.4 10.6a5 5 0 0 0-9.5-1.8A4.3 4.3 0 1 0 5.5 17.5h12.2a3.5 3.5 0 0 0 .7-6.9z"/>';
		}

		return '<span style="display:inline-flex;width:18px;height:18px;margin-right:9px;vertical-align:middle;flex:none">'
			. '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">' . $svg . '</svg></span>';
	}

	/** Drill URL: the findings on this environment's servers, optionally narrowed. */
	private static function url( string $env, array $extra = array() ): string {
		return VulnHub_Dash_Portal::portal_url(
			'vulnerabilities',
			array_merge( array( 'hosting' => $env, 'state' => 'open_any' ), $extra )
		);
	}

	public static function render_widget(): void {
		$rows = self::rows();
		$meta = self::environments();

		if ( ! $rows ) {
			echo class_exists( 'VulnHub_Dash_Charts' )
				? VulnHub_Dash_Charts::empty_state( __( 'No servers in the inventory yet.', 'vulnhub' ) ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				: '<p class="vh-chart-empty">' . esc_html__( 'No servers in the inventory yet.', 'vulnhub' ) . '</p>';
			return;
		}

		$max      = 1;
		$t_srv    = 0;
		$t_lin    = 0;
		$t_win    = 0;
		$t_oth    = 0;
		foreach ( $rows as $r ) {
			$max    = max( $max, (int) $r['total'] );
			$t_srv += (int) $r['servers'];
			$t_lin += (int) $r['linux'];
			$t_win += (int) $r['windows'];
			$t_oth += (int) $r['other'];
		}

		echo '<div class="vh-hosting"><div class="vh-tableview__scroll"><table class="vh-table" style="min-width:640px">';
		echo '<thead><tr>'
			. '<th>' . esc_html__( 'Hosting environment', 'vulnhub' ) . '</th>'
			. '<th style="text-align:right">' . esc_html__( 'Servers', 'vulnhub' ) . '</th>'
			. '<th>' . esc_html__( 'Operating system', 'vulnhub' ) . '</th>'
			. '<th>' . esc_html__( 'Open findings by severity', 'vulnhub' ) . '</th>'
			. '<th style="text-align:right">' . esc_html__( 'Total', 'vulnhub' ) . '</th>'
			. '</tr></thead><tbody>';

		foreach ( $rows as $key => $r ) {
			$label = (string) ( $meta[ $key ]['label'] ?? $key );
			$kind  = (string) ( $meta[ $key ]['kind'] ?? 'unknown' );
			$total = (int) $r['total'];

			// OS split — each count links to that environment + OS.
			$os = array();
			if ( $r['linux'] > 0 ) {
				$os[] = '<a href="' . esc_url( self::url( $key, array( 'platform' => 'linux' ) ) ) . '">'
					. esc_html( sprintf( /* translators: %s: count. */ __( 'Linux %s', 'vulnhub' ), number_format_i18n( (int) $r['linux'] ) ) ) . '</a>';
			}
			if ( $r['windows'] > 0 ) {
				$os[] = '<a href="' . esc_url( self::url( $key, array( 'platform' => 'windows' ) ) ) . '">'
					. esc_html( sprintf( /* translators: %s: count. */ __( 'Windows %s', 'vulnhub' ), number_format_i18n( (int) $r['windows'] ) ) ) . '</a>';
			}
			if ( $r['other'] > 0 ) {
				$os[] = '<a class="vh-muted" href="' . esc_url( self::url( $key ) ) . '">'
					. esc_html( sprintf( /* translators: %s: count. */ __( 'Other %s', 'vulnhub' ), number_format_i18n( (int) $r['other'] ) ) ) . '</a>';
			}

			// Severity bar, scaled to the busiest environment so lengths compare;
			// each segment links to that environment + severity.
			$bar = '<span class="vh-minibar" style="width:' . ( $total > 0 ? round( $total / $max * 100 ) : 0 ) . '%">';
			foreach ( array( 'critical', 'high', 'medium', 'low', 'info' ) as $sev ) {
				$n = (int) $r[ $sev ];
				if ( $n > 0 ) {
					$bar .= '<a href="' . esc_url( self::url( $key, array( 'severity' => $sev ) ) ) . '"'
						. ' style="flex:' . $n . ';background:' . esc_attr( VulnHub_Dash_Charts::severity_var( $sev ) ) . '"'
						. ' data-vh-tip="' . esc_attr( sprintf( '%s: %s', vh_severity_label( $sev ), number_format_i18n( $n ) ) ) . '"></a>';
				}
			}
			$bar .= '</span>';

			$env_url = esc_url( self::url( $key ) );

			echo '<tr>'
				. '<td><a href="' . $env_url . '">' . self::icon( $key ) . esc_html( $label ) . '</a></td>' // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				. '<td style="text-align:right" class="vh-num"><a href="' . $env_url . '">' . esc_html( number_format_i18n( (int) $r['servers'] ) ) . '</a></td>'
				. '<td style="font-size:12.5px">' . implode( ' <span class="vh-muted">·</span> ', $os ) . '</td>' // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				. '<td style="width:38%">' . $bar . '</td>' // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				. '<td style="text-align:right" class="vh-num"><a href="' . $env_url . '">' . esc_html( number_format_i18n( $total ) ) . '</a></td>'
				. '</tr>';
		}

		echo '</tbody></table></div>';
		echo VulnHub_Dash_Charts::severity_legend(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		printf(
			'<p class="vh-sub" style="margin-top:10px">%s</p>',
			esc_html(
				sprintf(
					/* translators: 1: total servers, 2: Linux count, 3: Windows count, 4: other-OS count. */
					__( '%1$s servers in total — %2$s Linux, %3$s Windows, %4$s other. Cloud is tagged from cloud instance ids, cloud locations, EC2 naming and Amazon/Xen hardware; on-prem from data-centre and office locations, server/appliance hardware (VMware, HP, Dell, CLARiiON…) and private addressing.', 'vulnhub' ),
					number_format_i18n( $t_srv ),
					number_format_i18n( $t_lin ),
					number_format_i18n( $t_win ),
					number_format_i18n( $t_oth )
				)
			)
		);

		echo '</div>';
	}

	/**
	 * @return array{headers:string[],rows:array<int,array<int,scalar>>}
	 */
	public static function data_widget(): array {
		$meta = self::environments();
		$out  = array();

		foreach ( self::rows() as $key => $r ) {
			$out[] = array(
				(string) ( $meta[ $key ]['label'] ?? $key ),
				(int) $r['servers'],
				(int) $r['linux'],
				(int) $r['windows'],
				(int) $r['other'],
				(int) $r['critical'],
				(int) $r['high'],
				(int) $r['medium'],
				(int) $r['low'],
				(int) $r['total'],
			);
		}

		return array(
			'headers' => array(
				__( 'Hosting environment', 'vulnhub' ),
				__( 'Servers', 'vulnhub' ),
				__( 'Linux', 'vulnhub' ),
				__( 'Windows', 'vulnhub' ),
				__( 'Other OS', 'vulnhub' ),
				__( 'Critical', 'vulnhub' ),
				__( 'High', 'vulnhub' ),
				__( 'Medium', 'vulnhub' ),
				__( 'Low', 'vulnhub' ),
				__( 'Open findings', 'vulnhub' ),
			),
			'rows'    => $out,
		);
	}
}
