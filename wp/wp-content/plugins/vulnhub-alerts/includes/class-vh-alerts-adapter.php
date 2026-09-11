<?php
/**
 * What every adapter has to provide, and the plumbing none of them should
 * have to write twice.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

abstract class VulnHub_Alerts_Adapter {

	/** @var array<string,mixed> The feed row this instance is polling. */
	protected array $feed;

	/** @var array<string,mixed> Decoded config_json. */
	protected array $config;

	/** @var string[] Human-readable notes surfaced in the feed's run log. */
	protected array $notes = array();

	public function __construct( array $feed ) {
		$this->feed   = $feed;
		$decoded      = json_decode( (string) ( $feed['config_json'] ?? '' ), true );
		$this->config = is_array( $decoded ) ? $decoded : array();
	}

	/**
	 * Pull the current window of advisories.
	 *
	 * Returns normalised rows; the caller stores and matches them. An adapter
	 * throws on transport failure and returns an empty array on "nothing new",
	 * because those two need to look different in the run log.
	 *
	 * @return array<int,array<string,mixed>>
	 * @throws RuntimeException On a transport or parse failure.
	 */
	abstract public function fetch(): array;

	/** @return string[] */
	public function notes(): array {
		return $this->notes;
	}

	protected function note( string $text ): void {
		$this->notes[] = $text;
	}

	protected function url(): string {
		return (string) ( $this->feed['url'] ?? '' );
	}

	protected function cfg( string $key, $default = null ) {
		return $this->config[ $key ] ?? $default;
	}

	/* =================================================================
	 * HTTP
	 * ============================================================== */

	/**
	 * A GET with the conditional headers this feed last saw.
	 *
	 * Publishers care about this. Sending If-None-Match means a feed polled
	 * every two hours costs them a 304 and us nothing, which is the difference
	 * between being a good citizen and being rate-limited.
	 *
	 * @return array{status:int,body:string,etag:string,modified:string}
	 * @throws RuntimeException
	 */
	protected function get( string $url, array $headers = array(), bool $conditional = true ): array {
		$headers = array_merge(
			array(
				'Accept'     => 'application/json',
				'User-Agent' => 'VulnHub/1.0 (+advisory monitor)',
			),
			$headers
		);

		if ( $conditional ) {
			if ( '' !== (string) ( $this->feed['http_etag'] ?? '' ) ) {
				$headers['If-None-Match'] = (string) $this->feed['http_etag'];
			}
			if ( '' !== (string) ( $this->feed['http_modified'] ?? '' ) ) {
				$headers['If-Modified-Since'] = (string) $this->feed['http_modified'];
			}
		}

		if ( '' !== (string) ( $this->feed['auth_key'] ?? '' ) ) {
			$headers['Authorization'] = 'Bearer ' . (string) $this->feed['auth_key'];
		}

		$response = wp_remote_get(
			$url,
			array(
				'timeout'     => 45,
				'redirection' => 3,
				'headers'     => $headers,
			)
		);

		if ( is_wp_error( $response ) ) {
			throw new RuntimeException( $response->get_error_message() );
		}

		$status = (int) wp_remote_retrieve_response_code( $response );

		if ( $status >= 400 ) {
			throw new RuntimeException(
				sprintf(
					/* translators: 1: HTTP status, 2: URL */
					__( 'HTTP %1$d from %2$s', 'vulnhub' ),
					$status,
					$url
				)
			);
		}

		return array(
			'status'   => $status,
			'body'     => (string) wp_remote_retrieve_body( $response ),
			'etag'     => (string) wp_remote_retrieve_header( $response, 'etag' ),
			'modified' => (string) wp_remote_retrieve_header( $response, 'last-modified' ),
		);
	}

	/**
	 * @return array<mixed>
	 * @throws RuntimeException
	 */
	protected function get_json( string $url, array $headers = array(), bool $conditional = true ): array {
		$r = $this->get( $url, $headers, $conditional );

		if ( 304 === $r['status'] ) {
			return array( '__not_modified' => true );
		}

		$data = json_decode( $r['body'], true );

		if ( ! is_array( $data ) ) {
			throw new RuntimeException(
				sprintf(
					/* translators: %s: URL */
					__( 'Response from %s was not JSON.', 'vulnhub' ),
					$url
				)
			);
		}

		$data['__etag']     = $r['etag'];
		$data['__modified'] = $r['modified'];

		return $data;
	}

	/* =================================================================
	 * Normalisation helpers
	 * ============================================================== */

	/**
	 * The shape every adapter returns. Filling in the defaults here means an
	 * adapter only writes the fields its source actually has.
	 *
	 * @return array<string,mixed>
	 */
	protected function row( array $fields ): array {
		$defaults = array(
			'external_id'  => '',
			'title'        => '',
			'summary'      => '',
			'url'          => '',
			'severity'     => '',
			'cvss'         => 0.0,
			'epss'         => 0.0,
			'kev'          => 0,
			'cves'         => array(),
			'products'     => array(),
			'published_at' => null,
			'updated_at'   => null,
			'raw'          => null,
		);

		$row = array_merge( $defaults, $fields );

		$row['cves'] = array_values( array_unique( array_map( 'strtoupper', (array) $row['cves'] ) ) );

		// A source that gives a score but no severity word, and vice versa.
		if ( '' === (string) $row['severity'] && (float) $row['cvss'] > 0 ) {
			$row['severity'] = VulnHub_Alerts_Registry::severity_for_score( (float) $row['cvss'] );
		}
		if ( '' === (string) $row['severity'] ) {
			$row['severity'] = 'unknown';
		}

		$row['title'] = vh_trim( wp_strip_all_tags( (string) $row['title'] ), 480 );

		return $row;
	}

	/**
	 * Every CVE id in a blob of text.
	 *
	 * Advisories mention CVEs in prose far more often than they carry them in
	 * a field, so for the RSS-shaped sources this is the only identifier we
	 * get, and it is worth having.
	 *
	 * @return string[]
	 */
	protected function cves_in( string $text ): array {
		if ( ! preg_match_all( '/CVE-\d{4}-\d{4,7}/i', $text, $m ) ) {
			return array();
		}

		return array_values( array_unique( array_map( 'strtoupper', $m[0] ) ) );
	}

	/**
	 * One product claim, in the shape the matcher expects.
	 *
	 * @param string $vendor  Vendor name as the source spells it.
	 * @param string $product Product name as the source spells it.
	 * @param string $range   Affected version expression, free text.
	 */
	protected function product( string $vendor, string $product, string $range = '' ): array {
		return array(
			'vendor'  => trim( $vendor ),
			'product' => trim( $product ),
			'range'   => trim( $range ),
		);
	}

	protected function to_mysql( $value ): ?string {
		if ( empty( $value ) ) {
			return null;
		}

		$ts = is_numeric( $value ) ? (int) $value : strtotime( (string) $value );

		return $ts ? gmdate( 'Y-m-d H:i:s', $ts ) : null;
	}
}
