<?php
/**
 * The catalogue of adapters, and the built-in feeds shipped with the plugin.
 *
 * An adapter is a small class that knows how to turn one publisher's format
 * into our normalised alert shape. Feeds are rows referencing an adapter by
 * name, which is what lets somebody add a new free source from a form instead
 * of waiting for a deployment. The two generic adapters exist for exactly that
 * case: point `rss` at any advisory RSS/Atom feed on earth, or `json` at any
 * JSON endpoint plus a handful of field paths, and it works.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Alerts_Registry {

	/**
	 * @return array<string,array{class:string,label:string,help:string,fields:string[]}>
	 */
	public static function adapters(): array {
		$adapters = array(
			'euvd'   => array(
				'class'  => 'VulnHub_Alerts_Adapter_Euvd',
				'label'  => __( 'EUVD (ENISA)', 'vulnhub' ),
				'help'   => __( 'The EU vulnerability database. Structured vendor, product and affected version range on every entry, which makes it the most precisely matchable source available without a key.', 'vulnhub' ),
				'fields' => array( 'url', 'vendors' ),
			),
			'msrc'   => array(
				'class'  => 'VulnHub_Alerts_Adapter_Msrc',
				'label'  => __( 'Microsoft MSRC (CVRF)', 'vulnhub' ),
				'help'   => __( 'Monthly Microsoft security updates with per-product affected builds. Large documents, so this one runs daily rather than hourly.', 'vulnhub' ),
				'fields' => array( 'url' ),
			),
			'cisa'   => array(
				'class'  => 'VulnHub_Alerts_Adapter_Cisa',
				'label'  => __( 'CISA advisories (RSS)', 'vulnhub' ),
				'help'   => __( 'Narrative advisories and emergency directives. Rarely carries machine-readable product data, so matches here lean on CVE ids and text.', 'vulnhub' ),
				'fields' => array( 'url' ),
			),
			'osv'    => array(
				'class'  => 'VulnHub_Alerts_Adapter_Osv',
				'label'  => __( 'OSV / GitHub advisories', 'vulnhub' ),
				'help'   => __( 'Open-source package advisories. Relevant to the OpenSSL, SQLite, libcurl and .NET components in the software inventory.', 'vulnhub' ),
				'fields' => array( 'url', 'ecosystems' ),
			),
			'redhat' => array(
				'class'  => 'VulnHub_Alerts_Adapter_RedHat',
				'label'  => __( 'Red Hat security data', 'vulnhub' ),
				'help'   => __( 'RHSA advisories with affected package lists and severity.', 'vulnhub' ),
				'fields' => array( 'url' ),
			),
			'ubuntu' => array(
				'class'  => 'VulnHub_Alerts_Adapter_Ubuntu',
				'label'  => __( 'Ubuntu security notices', 'vulnhub' ),
				'help'   => __( 'USN notices with affected releases and packages.', 'vulnhub' ),
				'fields' => array( 'url' ),
			),
			'rss'    => array(
				'class'  => 'VulnHub_Alerts_Adapter_Rss',
				'label'  => __( 'Any RSS or Atom feed', 'vulnhub' ),
				'help'   => __( 'Point this at any vendor advisory feed. Title, link, date and description are read from the feed; CVE ids are extracted from the text; products are matched against the estate by name. This is how a new free source gets added without code.', 'vulnhub' ),
				'fields' => array( 'url' ),
			),
			'json'   => array(
				'class'  => 'VulnHub_Alerts_Adapter_Json',
				'label'  => __( 'Any JSON endpoint', 'vulnhub' ),
				'help'   => __( 'For a source that publishes JSON rather than RSS. Give the path to the array of items and which keys hold the id, title, summary, link and date; everything else is derived.', 'vulnhub' ),
				'fields' => array( 'url', 'items_path', 'map' ),
			),
		);

		/**
		 * Third-party adapters. A plugin can add a format without touching
		 * this file.
		 *
		 * @param array $adapters Adapter definitions keyed by name.
		 */
		return (array) apply_filters( 'vulnhub_alert_adapters', $adapters );
	}

	public static function adapter_class( string $name ): string {
		$all = self::adapters();

		return isset( $all[ $name ] ) ? (string) $all[ $name ]['class'] : '';
	}

	public static function adapter_label( string $name ): string {
		$all = self::adapters();

		return isset( $all[ $name ] )
			? (string) $all[ $name ]['label']
			: ( '' !== $name ? $name : __( 'Unknown', 'vulnhub' ) );
	}

	/**
	 * The feeds installed on activation.
	 *
	 * Every one of these was reachable without an API key when this was
	 * written. Two are shipped disabled: Ubuntu because there are no Ubuntu
	 * hosts in the inventory yet, and the CISA ICS feed because an estate
	 * with no OT gets nothing but noise from it. Both are one toggle away.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function builtin_feeds(): array {
		$feeds = array(
			array(
				'slug'     => 'euvd',
				'label'    => __( 'EUVD — European Vulnerability Database', 'vulnhub' ),
				'adapter'  => 'euvd',
				'url'      => 'https://euvdservices.enisa.europa.eu/api/search',
				'interval' => 240,
				'config'   => array(
					// Left empty on purpose: the vendor list is built from the
					// estate at poll time, so it follows the inventory instead
					// of drifting out of date in a config blob.
					'vendors'   => array(),
					'max_pages' => 3,
				),
			),
			array(
				'slug'     => 'msrc',
				'label'    => __( 'Microsoft Security Updates (MSRC)', 'vulnhub' ),
				'adapter'  => 'msrc',
				'url'      => 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/',
				'interval' => 1440,
				'config'   => array( 'months_back' => 2 ),
			),
			array(
				'slug'     => 'cisa-all',
				'label'    => __( 'CISA advisories and alerts', 'vulnhub' ),
				'adapter'  => 'cisa',
				'url'      => 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
				'interval' => 120,
			),
			array(
				'slug'     => 'cisa-ics',
				'label'    => __( 'CISA ICS advisories', 'vulnhub' ),
				'adapter'  => 'cisa',
				'url'      => 'https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml',
				'interval' => 360,
				'enabled'  => 0,
			),
			array(
				'slug'     => 'ghsa',
				'label'    => __( 'GitHub Advisory Database', 'vulnhub' ),
				'adapter'  => 'osv',
				'url'      => 'https://api.github.com/advisories',
				'interval' => 360,
				'config'   => array( 'per_page' => 100, 'severities' => array( 'critical', 'high' ) ),
			),
			array(
				'slug'     => 'redhat',
				'label'    => __( 'Red Hat security advisories', 'vulnhub' ),
				'adapter'  => 'redhat',
				'url'      => 'https://access.redhat.com/hydra/rest/securitydata/cve.json',
				'interval' => 720,
				'config'   => array( 'severities' => array( 'critical', 'important' ) ),
			),
			array(
				'slug'     => 'ubuntu',
				'label'    => __( 'Ubuntu security notices', 'vulnhub' ),
				'adapter'  => 'ubuntu',
				'url'      => 'https://ubuntu.com/security/notices.json',
				'interval' => 720,
				'enabled'  => 0,
			),
		);

		return (array) apply_filters( 'vulnhub_alert_builtin_feeds', $feeds );
	}

	/** Severity vocabulary, worst first, shared by every adapter. */
	public static function severities(): array {
		return array(
			'critical' => array( 'label' => __( 'Critical', 'vulnhub' ), 'rank' => 5, 'min' => 9.0 ),
			'high'     => array( 'label' => __( 'High', 'vulnhub' ),     'rank' => 4, 'min' => 7.0 ),
			'medium'   => array( 'label' => __( 'Medium', 'vulnhub' ),   'rank' => 3, 'min' => 4.0 ),
			'low'      => array( 'label' => __( 'Low', 'vulnhub' ),      'rank' => 2, 'min' => 0.1 ),
			'unknown'  => array( 'label' => __( 'Unrated', 'vulnhub' ),  'rank' => 1, 'min' => 0.0 ),
		);
	}

	public static function severity_for_score( float $score ): string {
		foreach ( self::severities() as $key => $def ) {
			if ( 'unknown' !== $key && $score >= (float) $def['min'] ) {
				return $key;
			}
		}

		return 'unknown';
	}
}
