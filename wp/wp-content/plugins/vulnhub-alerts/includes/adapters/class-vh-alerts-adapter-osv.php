<?php
/**
 * GitHub Advisory Database (OSV-shaped).
 *
 * Covers the open-source components that show up in the software inventory --
 * OpenSSL, SQLite, libcurl, 7-Zip -- which the vendor feeds do not advertise
 * because nobody "ships" them as a product.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Alerts_Adapter_Osv extends VulnHub_Alerts_Adapter {

	public function fetch(): array {
		$url = add_query_arg(
			array(
				'per_page' => min( 100, max( 1, (int) $this->cfg( 'per_page', 100 ) ) ),
				'sort'     => 'published',
				'direction'=> 'desc',
			),
			$this->url()
		);

		$severities = array_map( 'strtolower', (array) $this->cfg( 'severities', array() ) );

		$data = $this->get_json( $url, array( 'Accept' => 'application/vnd.github+json' ) );

		if ( ! empty( $data['__not_modified'] ) ) {
			$this->note( __( 'Unchanged since the last poll.', 'vulnhub' ) );

			return array();
		}

		unset( $data['__etag'], $data['__modified'] );

		$out     = array();
		$skipped = 0;

		foreach ( $data as $adv ) {
			if ( ! is_array( $adv ) || ! isset( $adv['ghsa_id'] ) ) {
				continue;
			}

			$severity = strtolower( (string) ( $adv['severity'] ?? '' ) );

			if ( $severities && ! in_array( $severity, $severities, true ) ) {
				++$skipped;
				continue;
			}

			$products = array();
			foreach ( (array) ( $adv['vulnerabilities'] ?? array() ) as $v ) {
				if ( ! is_array( $v ) || ! isset( $v['package']['name'] ) ) {
					continue;
				}

				$products[] = $this->product(
					(string) ( $v['package']['ecosystem'] ?? '' ),
					(string) $v['package']['name'],
					(string) ( $v['vulnerable_version_range'] ?? '' )
				);
			}

			$cves = array();
			if ( ! empty( $adv['cve_id'] ) ) {
				$cves[] = (string) $adv['cve_id'];
			}

			$out[] = $this->row(
				array(
					'external_id'  => (string) $adv['ghsa_id'],
					'title'        => (string) ( $adv['summary'] ?? $adv['ghsa_id'] ),
					'summary'      => vh_trim( wp_strip_all_tags( (string) ( $adv['description'] ?? '' ) ), 2000 ),
					'url'          => (string) ( $adv['html_url'] ?? '' ),
					'severity'     => $severity,
					'cvss'         => (float) ( $adv['cvss']['score'] ?? $adv['cvss_severities']['cvss_v3']['score'] ?? 0 ),
					'epss'         => (float) ( $adv['epss']['percentage'] ?? 0 ),
					'cves'         => $cves,
					'products'     => $products,
					'published_at' => $this->to_mysql( $adv['published_at'] ?? null ),
					'updated_at'   => $this->to_mysql( $adv['updated_at'] ?? null ),
					'raw'          => $adv,
				)
			);
		}

		$this->note(
			sprintf(
				/* translators: 1: kept count, 2: skipped count */
				__( '%1$d advisories kept, %2$d below the configured severity floor.', 'vulnhub' ),
				count( $out ),
				$skipped
			)
		);

		return $out;
	}
}
