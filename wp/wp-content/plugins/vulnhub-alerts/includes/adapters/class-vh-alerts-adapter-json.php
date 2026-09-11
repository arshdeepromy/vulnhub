<?php
/**
 * Any JSON endpoint, described rather than coded.
 *
 * The companion to the RSS adapter: give it the path to the array of items
 * and which keys hold id, title, summary, link and date, and a new source is
 * a form submission. Dotted paths walk nested objects, so `data.items` and
 * `result.advisories.list` both work.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Alerts_Adapter_Json extends VulnHub_Alerts_Adapter {

	public function fetch(): array {
		$data = $this->get_json( $this->url() );

		if ( ! empty( $data['__not_modified'] ) ) {
			$this->note( __( 'Unchanged since the last poll.', 'vulnhub' ) );

			return array();
		}

		$items = $this->dig( $data, (string) $this->cfg( 'items_path', '' ) );

		if ( ! is_array( $items ) ) {
			throw new RuntimeException(
				sprintf(
					/* translators: %s: configured path */
					__( 'No array of items at "%s". Check the path to the list.', 'vulnhub' ),
					(string) $this->cfg( 'items_path', '(root)' )
				)
			);
		}

		$map = (array) $this->cfg(
			'map',
			array(
				'id'      => 'id',
				'title'   => 'title',
				'summary' => 'summary',
				'url'     => 'url',
				'date'    => 'published',
			)
		);

		$out = array();

		foreach ( $items as $item ) {
			if ( ! is_array( $item ) ) {
				continue;
			}

			$title = (string) $this->dig( $item, (string) ( $map['title'] ?? 'title' ) );
			$body  = (string) $this->dig( $item, (string) ( $map['summary'] ?? 'summary' ) );
			$id    = (string) $this->dig( $item, (string) ( $map['id'] ?? 'id' ) );

			if ( '' === $title && '' === $id ) {
				continue;
			}

			$out[] = $this->row(
				array(
					'external_id'  => $id ?: md5( $title ),
					'title'        => $title ?: $id,
					'summary'      => vh_trim( wp_strip_all_tags( $body ), 2000 ),
					'url'          => (string) $this->dig( $item, (string) ( $map['url'] ?? 'url' ) ),
					'cvss'         => (float) $this->dig( $item, (string) ( $map['cvss'] ?? 'cvss' ) ),
					'severity'     => strtolower( (string) $this->dig( $item, (string) ( $map['severity'] ?? 'severity' ) ) ),
					'cves'         => $this->cves_in( $title . ' ' . $body . ' ' . $id ),
					'products'     => array_map(
						fn( array $h ): array => $this->product( $h['vendor'], $h['product'], '' ),
						VulnHub_Alerts_Inventory::products_named_in( $title . ' ' . $body )
					),
					'published_at' => $this->to_mysql( $this->dig( $item, (string) ( $map['date'] ?? 'published' ) ) ),
					'raw'          => $item,
				)
			);
		}

		$this->note(
			sprintf(
				/* translators: %d: number of items */
				_n( '%d item in the response.', '%d items in the response.', count( $out ), 'vulnhub' ),
				count( $out )
			)
		);

		return $out;
	}

	/**
	 * Walk a dotted path. An empty path returns the value itself, so a feed
	 * whose response *is* the array needs no items_path at all.
	 *
	 * @param mixed $node Current node.
	 * @return mixed
	 */
	private function dig( $node, string $path ) {
		$path = trim( $path );

		if ( '' === $path ) {
			return $node;
		}

		foreach ( explode( '.', $path ) as $segment ) {
			if ( ! is_array( $node ) || ! array_key_exists( $segment, $node ) ) {
				return null;
			}
			$node = $node[ $segment ];
		}

		return $node;
	}
}
