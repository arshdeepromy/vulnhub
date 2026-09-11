<?php
/**
 * Red Hat security data.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Alerts_Adapter_RedHat extends VulnHub_Alerts_Adapter {

	public function fetch(): array {
		// The elvis operator binds looser than it looks: with no previous
		// run, `'' ?: time() - N` handed strtotime() an int and the whole
		// feed threw. Resolve the timestamp first, then format it.
		$last = (string) ( $this->feed['last_ok_at'] ?? '' );
		$ts   = '' !== $last ? (int) strtotime( $last . ' UTC' ) : 0;
		$ts   = $ts ? $ts - DAY_IN_SECONDS : time() - ( 14 * DAY_IN_SECONDS );

		$after = gmdate( 'Y-m-d', $ts );

		$url = add_query_arg(
			array( 'after' => $after, 'per_page' => 200 ),
			$this->url()
		);

		$data = $this->get_json( $url );

		if ( ! empty( $data['__not_modified'] ) ) {
			$this->note( __( 'Unchanged since the last poll.', 'vulnhub' ) );

			return array();
		}

		unset( $data['__etag'], $data['__modified'] );

		$wanted = array_map( 'strtolower', (array) $this->cfg( 'severities', array() ) );
		$out    = array();
		$skip   = 0;

		foreach ( $data as $cve ) {
			if ( ! is_array( $cve ) || empty( $cve['CVE'] ) ) {
				continue;
			}

			$severity = strtolower( (string) ( $cve['severity'] ?? '' ) );

			if ( $wanted && ! in_array( $severity, $wanted, true ) ) {
				++$skip;
				continue;
			}

			$products = array();
			foreach ( (array) ( $cve['affected_packages'] ?? array() ) as $pkg ) {
				$products[] = $this->product( 'Red Hat', $this->package_name( (string) $pkg ), (string) $pkg );
			}

			$out[] = $this->row(
				array(
					'external_id'  => (string) $cve['CVE'],
					'title'        => vh_trim( (string) ( $cve['bugzilla_description'] ?? $cve['CVE'] ), 480 ),
					'summary'      => (string) ( $cve['bugzilla_description'] ?? '' ),
					'url'          => (string) ( $cve['resource_url'] ?? '' ),
					// Red Hat's own words: "important" is their high.
					'severity'     => 'important' === $severity ? 'high' : $severity,
					'cvss'         => (float) ( $cve['cvss3_score'] ?? 0 ),
					'cves'         => array( (string) $cve['CVE'] ),
					'products'     => $products,
					'published_at' => $this->to_mysql( $cve['public_date'] ?? null ),
					'raw'          => $cve,
				)
			);
		}

		$this->note(
			sprintf(
				/* translators: 1: kept, 2: skipped, 3: date */
				__( '%1$d advisories since %3$s, %2$d below the severity floor.', 'vulnhub' ),
				count( $out ),
				$skip,
				$after
			)
		);

		return $out;
	}

	/**
	 * "openssl-1:3.0.7-27.el9" is an NVR, and only the leading name is any
	 * use for matching.
	 */
	private function package_name( string $nvr ): string {
		$name = preg_replace( '/-\d+:.*$/', '', $nvr );
		$name = preg_replace( '/-\d[\d.]*-.*$/', '', (string) $name );

		return trim( (string) $name ) ?: $nvr;
	}
}
