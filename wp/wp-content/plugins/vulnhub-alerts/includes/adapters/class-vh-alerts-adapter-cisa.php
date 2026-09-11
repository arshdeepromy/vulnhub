<?php
/**
 * CISA advisories and alerts.
 *
 * Structurally an RSS feed, so it reuses that adapter, but CISA is the source
 * that carries emergency directives and "exploited in the wild" language, and
 * those deserve to outrank a routine advisory regardless of what CVSS says.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Alerts_Adapter_Cisa extends VulnHub_Alerts_Adapter_Rss {

	protected function entry( string $title, string $link, string $guid, string $desc, string $date, SimpleXMLElement $raw ): ?array {
		$row = parent::entry( $title, $link, $guid, $desc, $date, $raw );

		if ( null === $row ) {
			return null;
		}

		$text = strtolower( $title . ' ' . $desc );

		// CISA does not publish a machine-readable exploited flag on the RSS
		// feed, but it is consistent in its wording, and an advisory saying
		// something is being exploited right now is the whole reason this
		// page exists.
		foreach ( array( 'exploited in the wild', 'actively exploited', 'known exploited', 'emergency directive' ) as $phrase ) {
			if ( str_contains( $text, $phrase ) ) {
				$row['kev']      = 1;
				$row['severity'] = 'critical';
				break;
			}
		}

		return $row;
	}
}
