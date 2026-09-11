<?php
/**
 * EUVD — the EU vulnerability database.
 *
 * The most useful free source for this job, because every entry carries
 * structured vendor, product and affected version range rather than prose.
 * That is what turns "a Chrome bug exists" into "these 41 machines are on an
 * affected build".
 *
 * Queried per vendor rather than by pulling the whole window, because the
 * vendor list comes from our own inventory: asking only about software we
 * actually run is both far less traffic for them and far less noise for us.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Alerts_Adapter_Euvd extends VulnHub_Alerts_Adapter {

	public function fetch(): array {
		$vendors = (array) $this->cfg( 'vendors', array() );

		if ( ! $vendors ) {
			$vendors = VulnHub_Alerts_Inventory::top_vendors( (int) $this->cfg( 'max_vendors', 25 ) );
		}

		if ( ! $vendors ) {
			$this->note( __( 'No software inventory to build a vendor list from, so there was nothing to ask about.', 'vulnhub' ) );

			return array();
		}

		$since = $this->since();
		$out   = array();

		foreach ( $vendors as $vendor ) {
			try {
				$found = $this->vendor_window( (string) $vendor, $since );
			} catch ( RuntimeException $e ) {
				// One vendor failing is not the feed failing. Record it and
				// keep going, or a single bad query costs us every other
				// vendor's advisories for this run.
				$this->note(
					sprintf(
						/* translators: 1: vendor, 2: error */
						__( '%1$s: %2$s', 'vulnhub' ),
						$vendor,
						$e->getMessage()
					)
				);
				continue;
			}

			foreach ( $found as $row ) {
				$out[ $row['external_id'] ] = $row;
			}
		}

		$this->note(
			sprintf(
				/* translators: 1: advisory count, 2: vendor count, 3: date */
				__( '%1$d advisories across %2$d vendors published since %3$s.', 'vulnhub' ),
				count( $out ),
				count( $vendors ),
				$since
			)
		);

		return array_values( $out );
	}

	/**
	 * How far back to ask.
	 *
	 * A first run wants a fortnight so the page is not empty; after that,
	 * back to the last success with a day of overlap, because an advisory
	 * updated after publication should be re-read.
	 */
	private function since(): string {
		$last = (string) ( $this->feed['last_ok_at'] ?? '' );

		$ts = $last ? strtotime( $last . ' UTC' ) : 0;
		$ts = $ts ? $ts - DAY_IN_SECONDS : time() - ( 14 * DAY_IN_SECONDS );

		return gmdate( 'Y-m-d', $ts );
	}

	/** @return array<int,array<string,mixed>> */
	private function vendor_window( string $vendor, string $since ): array {
		$url = add_query_arg(
			array(
				'vendor'   => rawurlencode( str_replace( ' ', '+', $vendor ) ),
				'fromDate' => $since,
				'size'     => 100,
				'page'     => 0,
			),
			$this->url()
		);

		// Conditional headers are per-feed, and this adapter issues one
		// request per vendor -- an ETag from the Microsoft query would
		// wrongly 304 the Adobe one.
		$data = $this->get_json( $url, array(), false );

		$items = isset( $data['items'] ) && is_array( $data['items'] ) ? $data['items'] : array();
		$out   = array();

		foreach ( $items as $item ) {
			if ( is_array( $item ) ) {
				$out[] = $this->normalise( $item );
			}
		}

		return $out;
	}

	private function normalise( array $item ): array {
		$id = (string) ( $item['id'] ?? '' );

		// EUVD packs aliases into one newline-delimited string, and the CVE
		// id in there is what ties this to scanner findings and to KEV.
		$aliases = preg_split( '/\s+/', (string) ( $item['aliases'] ?? '' ) ) ?: array();
		$cves    = array_values(
			array_filter(
				$aliases,
				static fn( string $a ): bool => (bool) preg_match( '/^CVE-\d{4}-\d+$/i', $a )
			)
		);

		$products = array();
		foreach ( (array) ( $item['enisaIdProduct'] ?? array() ) as $p ) {
			if ( ! is_array( $p ) || ! isset( $p['product']['name'] ) ) {
				continue;
			}

			$products[] = $this->product(
				(string) ( $p['product']['vendor']['name'] ?? '' ),
				(string) $p['product']['name'],
				(string) ( $p['product_version'] ?? '' )
			);
		}

		$refs = preg_split( '/\s+/', trim( (string) ( $item['references'] ?? '' ) ) ) ?: array();
		$link = $refs[0] ?? '';

		if ( '' === $link && '' !== $id ) {
			$link = 'https://euvd.enisa.europa.eu/enisa/' . rawurlencode( $id );
		}

		// EPSS arrives as a percentage here and as a probability everywhere
		// else in VulnHub. Store the probability so the two agree.
		$epss = (float) ( $item['epss'] ?? 0 );
		if ( $epss > 1 ) {
			$epss = $epss / 100;
		}

		return $this->row(
			array(
				'external_id'  => $id,
				'title'        => $this->title_for( $item, $products ),
				'summary'      => (string) ( $item['description'] ?? '' ),
				'url'          => $link,
				'cvss'         => (float) ( $item['baseScore'] ?? 0 ),
				'epss'         => $epss,
				'cves'         => $cves,
				'products'     => $products,
				'published_at' => $this->to_mysql( $item['datePublished'] ?? null ),
				'updated_at'   => $this->to_mysql( $item['dateUpdated'] ?? null ),
				'raw'          => $item,
			)
		);
	}

	/**
	 * EUVD entries have no title field, only a description, so build one.
	 * "Microsoft Windows 11 Version 23H2 — CVE-2026-68877" reads better in a
	 * list than the first 80 characters of a CVE description.
	 */
	private function title_for( array $item, array $products ): string {
		$bits = array();

		if ( $products ) {
			$names = array_values( array_unique( array_column( $products, 'product' ) ) );
			$first = (string) ( $names[0] ?? '' );

			if ( count( $names ) > 1 ) {
				$first .= sprintf(
					/* translators: %d: number of further affected products */
					_n( ' and %d other product', ' and %d other products', count( $names ) - 1, 'vulnhub' ),
					count( $names ) - 1
				);
			}

			$bits[] = $first;
		}

		$aliases = preg_split( '/\s+/', (string) ( $item['aliases'] ?? '' ) ) ?: array();
		foreach ( $aliases as $a ) {
			if ( preg_match( '/^CVE-\d{4}-\d+$/i', $a ) ) {
				$bits[] = strtoupper( $a );
				break;
			}
		}

		if ( ! $bits ) {
			return vh_trim( (string) ( $item['description'] ?? $item['id'] ?? '' ), 120 );
		}

		return implode( ' — ', $bits );
	}
}
