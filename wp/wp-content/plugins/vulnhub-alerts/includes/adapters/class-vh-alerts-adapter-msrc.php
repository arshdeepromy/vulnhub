<?php
/**
 * Microsoft Security Response Center, CVRF 3.0.
 *
 * Worth the extra parsing: the ProductTree carries real CPE 2.3 strings, so
 * Microsoft advisories match the estate on the same identifier the scanner
 * uses rather than on a product name somebody typed. Given how much of this
 * fleet is Windows, this is the highest-yield source here.
 *
 * The documents are large -- ~15MB and about 1,200 vulnerabilities a month --
 * so this feed defaults to daily, and only the months in the configured
 * window are fetched.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Alerts_Adapter_Msrc extends VulnHub_Alerts_Adapter {

	/** CVRF ProductStatuses Type 3 is "Known Affected". */
	private const STATUS_KNOWN_AFFECTED = 3;

	public function fetch(): array {
		$months = max( 1, min( 12, (int) $this->cfg( 'months_back', 2 ) ) );
		$out    = array();

		for ( $i = 0; $i < $months; $i++ ) {
			$slug = gmdate( 'Y-M', strtotime( "-{$i} month" ) );

			try {
				$rows = $this->month( $slug );
			} catch ( RuntimeException $e ) {
				// The current month's document does not exist until Patch
				// Tuesday, so a 404 early in the month is expected and must
				// not mark the whole feed as broken.
				$this->note(
					sprintf(
						/* translators: 1: month, 2: error */
						__( '%1$s: %2$s', 'vulnhub' ),
						$slug,
						$e->getMessage()
					)
				);
				continue;
			}

			foreach ( $rows as $row ) {
				$out[ $row['external_id'] ] = $row;
			}

			$this->note(
				sprintf(
					/* translators: 1: count, 2: month */
					__( '%1$d vulnerabilities in the %2$s update.', 'vulnhub' ),
					count( $rows ),
					$slug
				)
			);
		}

		return array_values( $out );
	}

	/** @return array<int,array<string,mixed>> */
	private function month( string $slug ): array {
		$doc = $this->get_json( untrailingslashit( $this->url() ) . '/' . $slug, array(), false );

		$tree     = array();
		$products = $doc['ProductTree']['FullProductName'] ?? array();

		foreach ( (array) $products as $p ) {
			if ( isset( $p['ProductID'] ) ) {
				$tree[ (string) $p['ProductID'] ] = array(
					'name' => (string) ( $p['Value'] ?? '' ),
					'cpe'  => (string) ( $p['CPE'] ?? '' ),
				);
			}
		}

		$released = (string) ( $doc['DocumentTracking']['CurrentReleaseDate'] ?? '' );
		$out      = array();

		foreach ( (array) ( $doc['Vulnerability'] ?? array() ) as $v ) {
			if ( ! is_array( $v ) || empty( $v['CVE'] ) ) {
				continue;
			}

			$row = $this->vulnerability( $v, $tree, $released );

			if ( $row ) {
				$out[] = $row;
			}
		}

		return $out;
	}

	private function vulnerability( array $v, array $tree, string $released ): ?array {
		$cve = (string) $v['CVE'];

		// Only the products Microsoft says are affected. The status list also
		// carries fixed and unaffected builds, and treating those as hits is
		// how you end up telling somebody their patched machine is at risk.
		$affected = array();
		foreach ( (array) ( $v['ProductStatuses'] ?? array() ) as $status ) {
			if ( (int) ( $status['Type'] ?? 0 ) !== self::STATUS_KNOWN_AFFECTED ) {
				continue;
			}
			foreach ( (array) ( $status['ProductID'] ?? array() ) as $pid ) {
				$affected[ (string) $pid ] = true;
			}
		}

		$seen     = array();
		$products = array();

		foreach ( array_keys( $affected ) as $pid ) {
			$entry = $tree[ $pid ] ?? null;

			if ( ! $entry || '' === $entry['name'] ) {
				continue;
			}

			// One CVE routinely lists the same product across a dozen builds
			// and editions; the matcher only needs the product once.
			if ( isset( $seen[ $entry['name'] ] ) ) {
				continue;
			}
			$seen[ $entry['name'] ] = true;

			$products[] = array(
				'vendor'  => 'Microsoft',
				'product' => $entry['name'],
				'range'   => '',
				'cpe'     => $entry['cpe'],
			);
		}

		if ( ! $products ) {
			return null;
		}

		$score = 0.0;
		foreach ( (array) ( $v['CVSSScoreSets'] ?? array() ) as $set ) {
			$score = max( $score, (float) ( $set['BaseScore'] ?? 0 ) );
		}

		return $this->row(
			array(
				'external_id'  => $cve,
				'title'        => (string) ( $v['Title']['Value'] ?? $cve ),
				'summary'      => $this->summary( $v ),
				'url'          => 'https://msrc.microsoft.com/update-guide/vulnerability/' . rawurlencode( $cve ),
				'cvss'         => $score,
				'cves'         => array( $cve ),
				'products'     => $products,
				'published_at' => $this->to_mysql( $v['ReleaseDate'] ?? $released ),
				'raw'          => array(
					'cve'      => $cve,
					'cwe'      => $v['CWE'] ?? null,
					'products' => array_column( $products, 'product' ),
				),
			)
		);
	}

	private function summary( array $v ): string {
		foreach ( (array) ( $v['Notes'] ?? array() ) as $note ) {
			$text = trim( wp_strip_all_tags( (string) ( $note['Value'] ?? '' ) ) );

			if ( '' !== $text ) {
				return vh_trim( $text, 2000 );
			}
		}

		return '';
	}
}
