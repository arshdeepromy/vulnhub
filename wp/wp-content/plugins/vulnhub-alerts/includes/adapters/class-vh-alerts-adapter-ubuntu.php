<?php
/**
 * Ubuntu security notices.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Alerts_Adapter_Ubuntu extends VulnHub_Alerts_Adapter {

	public function fetch(): array {
		$data = $this->get_json( add_query_arg( array( 'limit' => 50 ), $this->url() ) );

		if ( ! empty( $data['__not_modified'] ) ) {
			$this->note( __( 'Unchanged since the last poll.', 'vulnhub' ) );

			return array();
		}

		$out = array();

		foreach ( (array) ( $data['notices'] ?? array() ) as $n ) {
			if ( ! is_array( $n ) || empty( $n['id'] ) ) {
				continue;
			}

			$products = array();
			$seen     = array();

			foreach ( (array) ( $n['release_packages'] ?? array() ) as $release => $packages ) {
				foreach ( (array) $packages as $pkg ) {
					$name = (string) ( $pkg['name'] ?? '' );

					if ( '' === $name || isset( $seen[ $name ] ) ) {
						continue;
					}

					$seen[ $name ] = true;
					$products[]    = $this->product( 'Canonical', $name, (string) $release );
				}
			}

			$cves = array_map( 'strval', (array) ( $n['cves'] ?? array() ) );

			$out[] = $this->row(
				array(
					'external_id'  => (string) $n['id'],
					'title'        => (string) ( $n['title'] ?? $n['id'] ),
					'summary'      => vh_trim( wp_strip_all_tags( (string) ( $n['summary'] ?? '' ) ), 2000 ),
					'url'          => 'https://ubuntu.com/security/notices/' . rawurlencode( (string) $n['id'] ),
					'cves'         => $cves,
					'products'     => $products,
					'published_at' => $this->to_mysql( $n['published'] ?? null ),
					'raw'          => $n,
				)
			);
		}

		$this->note(
			sprintf(
				/* translators: %d: notice count */
				_n( '%d notice.', '%d notices.', count( $out ), 'vulnhub' ),
				count( $out )
			)
		);

		return $out;
	}
}
