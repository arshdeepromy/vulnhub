<?php
/**
 * A small read-only client for the Plerion REST API.
 *
 * One Bearer key, a region-based host, and the two pagination styles the API
 * uses: page/perPage for assets (with a `meta` block) and an opaque `cursor`
 * for findings. Core's Http already retries 429/5xx and honours Retry-After,
 * so this stays thin.
 *
 * @package VulnHub\Plerion
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Signed (Bearer) requests to Plerion.
 */
final class VulnHub_Plerion_Client {

	private \VulnHub\Core\Http $http;
	private string $key;
	private string $base;
	private int $requests = 0;

	public function __construct( string $region, string $key, ?callable $log = null ) {
		$region     = trim( $region );
		$region     = '' !== $region ? $region : 'us';
		$this->base = sprintf( 'https://%s.api.plerion.com', $region );
		$this->key  = $key;
		$this->http = new \VulnHub\Core\Http( 'VulnHub-Plerion/' . VULNHUB_PLERION_VERSION, $log );
	}

	public function requests(): int {
		return $this->requests;
	}

	/**
	 * GET a path and return the decoded body, or throw on a non-2xx.
	 *
	 * @param array<string,scalar> $query Query parameters.
	 * @return array<string,mixed>
	 */
	public function get( string $path, array $query = array() ): array {
		++$this->requests;

		$res = $this->http->get(
			$this->base . $path,
			$query,
			array(
				'Authorization' => 'Bearer ' . $this->key,
				'Accept'        => 'application/json',
			)
		);

		if ( ! $res->ok() ) {
			throw new RuntimeException(
				sprintf(
					/* translators: 1: path, 2: HTTP status, 3: error. */
					esc_html__( 'Plerion %1$s failed (HTTP %2$d): %3$s', 'vulnhub' ),
					esc_html( $path ),
					(int) $res->status,
					esc_html( $res->error_message() )
				)
			);
		}

		return (array) $res->data();
	}

	/**
	 * Walk the page/perPage asset list, handing each row to $cb.
	 *
	 * @param array<string,scalar> $query Base query (filters).
	 * @param callable             $cb    Called with each asset row.
	 * @return int Rows seen.
	 */
	public function each_asset( array $query, callable $cb ): int {
		$page  = 1;
		$seen  = 0;
		$per   = 500;
		$total = PHP_INT_MAX;

		// Driven by meta.total, not meta.hasNextPage: the API only sets
		// hasNextPage on the first page, so trusting it stops pagination early.
		do {
			$body = $this->get( '/v1/tenant/assets', array_merge( $query, array( 'page' => $page, 'perPage' => $per ) ) );
			$rows = (array) ( $body['data'] ?? array() );

			foreach ( $rows as $row ) {
				$cb( (array) $row );
				++$seen;
			}

			$meta  = (array) ( $body['meta'] ?? array() );
			// total is only reported on the first page, so capture it once.
			if ( PHP_INT_MAX === $total && isset( $meta['total'] ) ) {
				$total = (int) $meta['total'];
			}
			++$page;
		} while ( $rows && $seen < $total && $page <= 10000 );

		return $seen;
	}

	/**
	 * Every integration: one per connected cloud account, with the name it
	 * was onboarded under and the provider's account number.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public function integrations(): array {
		// Cursor-paged like findings: `page` is refused as an unknown
		// property, and a full page still carries a cursor on the last one,
		// so the loop stops on an empty page or a repeated cursor.
		$out    = array();
		$cursor = '';
		$pages  = 0;

		do {
			$q = array( 'perPage' => 100 );
			if ( '' !== $cursor ) {
				$q['cursor'] = $cursor;
			}

			$body = $this->get( '/v1/tenant/integrations', $q );
			$rows = (array) ( $body['data'] ?? array() );

			foreach ( $rows as $row ) {
				$out[] = (array) $row;
			}

			$next   = (string) ( ( (array) ( $body['meta'] ?? array() ) )['cursor'] ?? '' );
			$stop   = ! $rows || '' === $next || $next === $cursor;
			$cursor = $next;
			++$pages;
		} while ( ! $stop && $pages < 50 );

		return $out;
	}

	/**
	 * Walk the cursor-paginated findings list, handing each row to $cb.
	 *
	 * @param array<string,scalar> $query Base query (filters).
	 * @param callable             $cb    Called with each finding row.
	 * @param int                  $max   Stop after this many (0 = no cap).
	 * @return int Rows seen.
	 */
	public function each_finding( array $query, callable $cb, int $max = 0 ): int {
		$cursor = '';
		$seen   = 0;
		$pages  = 0;
		$total  = PHP_INT_MAX;

		// Cursor-driven, bounded by meta.total: the findings API sets
		// hasNextPage only on the first page, so continue while a cursor comes
		// back, rows keep arriving, and we have not reached the reported total.
		do {
			$q = array_merge( $query, array( 'perPage' => 200 ) );

			if ( '' !== $cursor ) {
				$q['cursor'] = $cursor;
			}

			$body = $this->get( '/v1/tenant/findings', $q );
			$rows = (array) ( $body['data'] ?? array() );

			foreach ( $rows as $row ) {
				$cb( (array) $row );
				++$seen;

				if ( $max > 0 && $seen >= $max ) {
					return $seen;
				}
			}

			$meta   = (array) ( $body['meta'] ?? array() );
			$cursor = (string) ( $meta['cursor'] ?? '' );
			++$pages;

			// The API zeroes meta.total and drops hasNextPage on cursor pages, so
			// the only reliable signal is: rows came back and a cursor for more.
		} while ( $rows && '' !== $cursor && $pages <= 100000 );

		return $seen;
	}
}
