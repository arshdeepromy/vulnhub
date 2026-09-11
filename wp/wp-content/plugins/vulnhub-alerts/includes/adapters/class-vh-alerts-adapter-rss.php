<?php
/**
 * Any RSS or Atom advisory feed.
 *
 * This is the adapter that makes the feature open-ended: nearly every vendor
 * publishes advisories as RSS, so pointing this at a URL adds a source without
 * a deployment. What it cannot do is tell you *which version* is affected --
 * RSS carries prose, not a product model -- so matches from here land at
 * "probable" or "possible" and say so.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class VulnHub_Alerts_Adapter_Rss extends VulnHub_Alerts_Adapter {

	public function fetch(): array {
		$r = $this->get( $this->url(), array( 'Accept' => 'application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.8' ) );

		if ( 304 === $r['status'] ) {
			$this->note( __( 'Unchanged since the last poll.', 'vulnhub' ) );

			return array();
		}

		$items = $this->parse( $r['body'] );

		$this->note(
			sprintf(
				/* translators: %d: number of entries */
				_n( '%d entry in the feed.', '%d entries in the feed.', count( $items ), 'vulnhub' ),
				count( $items )
			)
		);

		return $items;
	}

	/**
	 * @return array<int,array<string,mixed>>
	 * @throws RuntimeException
	 */
	protected function parse( string $xml ): array {
		if ( '' === trim( $xml ) ) {
			return array();
		}

		// A malformed feed is a data problem, not a reason to emit warnings
		// into the page. Collect the errors and report them as one message.
		$previous = libxml_use_internal_errors( true );
		libxml_clear_errors();

		$doc = simplexml_load_string( $xml, 'SimpleXMLElement', LIBXML_NOCDATA | LIBXML_NONET );

		$errors = libxml_get_errors();
		libxml_clear_errors();
		libxml_use_internal_errors( $previous );

		if ( false === $doc ) {
			throw new RuntimeException(
				sprintf(
					/* translators: %s: first XML parser error */
					__( 'That did not parse as RSS or Atom: %s', 'vulnhub' ),
					$errors ? trim( (string) $errors[0]->message ) : __( 'unknown parse error', 'vulnhub' )
				)
			);
		}

		$entries = array();

		if ( isset( $doc->channel->item ) ) {
			foreach ( $doc->channel->item as $item ) {
				$entries[] = $this->from_rss( $item );
			}
		} elseif ( isset( $doc->entry ) ) {
			foreach ( $doc->entry as $entry ) {
				$entries[] = $this->from_atom( $entry );
			}
		} elseif ( isset( $doc->item ) ) {
			foreach ( $doc->item as $item ) {
				$entries[] = $this->from_rss( $item );
			}
		}

		return array_values( array_filter( $entries ) );
	}

	protected function from_rss( SimpleXMLElement $item ): ?array {
		$title = trim( (string) $item->title );
		$link  = trim( (string) $item->link );
		$guid  = trim( (string) $item->guid );
		$desc  = trim( (string) $item->description );
		$date  = (string) ( $item->pubDate ?? '' );

		return $this->entry( $title, $link, $guid, $desc, $date, $item );
	}

	protected function from_atom( SimpleXMLElement $entry ): ?array {
		$link = '';
		foreach ( $entry->link as $l ) {
			$rel = (string) $l['rel'];
			if ( '' === $rel || 'alternate' === $rel ) {
				$link = (string) $l['href'];
				break;
			}
		}

		$body = trim( (string) ( $entry->content ?? '' ) );
		if ( '' === $body ) {
			$body = trim( (string) ( $entry->summary ?? '' ) );
		}

		return $this->entry(
			trim( (string) $entry->title ),
			$link,
			trim( (string) $entry->id ),
			$body,
			(string) ( $entry->updated ?? $entry->published ?? '' ),
			$entry
		);
	}

	protected function entry( string $title, string $link, string $guid, string $desc, string $date, SimpleXMLElement $raw ): ?array {
		if ( '' === $title && '' === $link ) {
			return null;
		}

		$text  = $title . ' ' . $desc;
		$clean = trim( wp_strip_all_tags( $desc ) );

		return $this->row(
			array(
				'external_id'  => $guid ?: $link ?: md5( $title ),
				'title'        => $title,
				'summary'      => vh_trim( $clean, 2000 ),
				'url'          => $link,
				'cves'         => $this->cves_in( $text ),
				'severity'     => $this->severity_in( $text ),
				'products'     => $this->products_in( $title ),
				'published_at' => $this->to_mysql( $date ),
				'raw'          => array( 'xml' => vh_trim( $raw->asXML() ?: '', 8000 ) ),
			)
		);
	}

	/**
	 * Severity from the words in the advisory, since RSS has no field for it.
	 * Deliberately conservative: only the explicit phrasings count, so an
	 * advisory that merely uses the word "critical" in a sentence does not
	 * get promoted to the top of somebody's morning.
	 */
	protected function severity_in( string $text ): string {
		$t = strtolower( $text );

		foreach ( array(
			'critical' => array( 'critical severity', 'severity: critical', 'rated critical', 'emergency directive' ),
			'high'     => array( 'high severity', 'severity: high', 'rated important', 'actively exploited', 'exploited in the wild' ),
			'medium'   => array( 'medium severity', 'severity: medium', 'rated moderate' ),
			'low'      => array( 'low severity', 'severity: low' ),
		) as $level => $needles ) {
			foreach ( $needles as $needle ) {
				if ( str_contains( $t, $needle ) ) {
					return $level;
				}
			}
		}

		return '';
	}

	/**
	 * Guess at products by looking for names we actually run.
	 *
	 * Backwards from the usual approach on purpose. Parsing a vendor's title
	 * into a product name is guesswork; testing a title against the 222
	 * products in our own inventory is a lookup, and it cannot invent a
	 * product we do not have.
	 *
	 * @return array<int,array<string,string>>
	 */
	protected function products_in( string $title ): array {
		$hits = VulnHub_Alerts_Inventory::products_named_in( $title );
		$out  = array();

		foreach ( $hits as $hit ) {
			$out[] = $this->product( $hit['vendor'], $hit['product'], '' );
		}

		return $out;
	}
}
