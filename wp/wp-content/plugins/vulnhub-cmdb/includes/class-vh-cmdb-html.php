<?php
/**
 * HTML table extraction for Confluence storage-format bodies.
 *
 * Confluence returns a page body as XHTML with Confluence-specific namespaced
 * elements mixed in (`ac:structured-macro`, `ri:user`, …). That is close
 * enough to HTML for libxml's HTML parser, and nowhere near regular enough for
 * a regular expression: a single `<td>` can hold a nested table, a user
 * mention macro, or a `<br/>`-separated list.
 *
 * So: DOMDocument, with libxml's error buffer switched on so the unknown
 * namespaces do not raise PHP warnings, and network entity loading disabled.
 *
 * @package VulnHub\Cmdb
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Turns a Confluence storage-format body into header/row arrays.
 */
final class VulnHub_Cmdb_Html {

	/**
	 * Hard ceiling on rows taken from one page, so a runaway page cannot
	 * exhaust memory during a scheduled sync.
	 */
	private const MAX_ROWS = 5000;

	/**
	 * Extract every table in a storage-format body.
	 *
	 * Only top-level tables are returned; a table nested inside a cell of
	 * another table is treated as cell content, because that is what it means
	 * on the page.
	 *
	 * @param string $storage Storage-format (XHTML) body.
	 * @return array<int,array{headers:array<int,string>,rows:array<int,array<string,string>>}>
	 */
	public static function tables( string $storage ): array {
		$storage = trim( $storage );

		if ( '' === $storage ) {
			return array();
		}

		$previous = libxml_use_internal_errors( true );
		$document = new DOMDocument( '1.0', 'UTF-8' );

		/*
		 * The HTML parser needs a document shell with an explicit charset, or
		 * it assumes ISO-8859-1 and mangles any non-ASCII site name. LIBXML_NONET
		 * refuses to fetch external entities; the storage format should never
		 * contain a DTD, but a body is untrusted input from a wiki page.
		 */
		$loaded = $document->loadHTML(
			'<!DOCTYPE html><html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body>'
				. $storage
				. '</body></html>',
			LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET
		);

		libxml_clear_errors();
		libxml_use_internal_errors( $previous );

		if ( ! $loaded ) {
			return array();
		}

		$xpath  = new DOMXPath( $document );
		$tables = $xpath->query( '//table' );
		$out    = array();

		if ( ! $tables instanceof DOMNodeList ) {
			return array();
		}

		foreach ( $tables as $table ) {
			if ( ! $table instanceof DOMElement ) {
				continue;
			}
			// Skip tables that live inside another table — see above.
			if ( self::has_table_ancestor( $table ) ) {
				continue;
			}

			$parsed = self::parse_table( $xpath, $table );

			if ( $parsed['headers'] && $parsed['rows'] ) {
				$out[] = $parsed;
			}
		}

		return $out;
	}

	/**
	 * Is this table nested inside another table?
	 */
	private static function has_table_ancestor( DOMElement $table ): bool {
		$node = $table->parentNode;

		while ( $node instanceof DOMElement ) {
			if ( 'table' === strtolower( $node->nodeName ) ) {
				return true;
			}
			$node = $node->parentNode;
		}

		return false;
	}

	/**
	 * Read one table into a header list and a list of header => value rows.
	 *
	 * @param DOMXPath   $xpath Document xpath.
	 * @param DOMElement $table Table element.
	 * @return array{headers:array<int,string>,rows:array<int,array<string,string>>}
	 */
	private static function parse_table( DOMXPath $xpath, DOMElement $table ): array {
		$rows = $xpath->query( './/tr', $table );

		if ( ! $rows instanceof DOMNodeList || 0 === $rows->length ) {
			return array(
				'headers' => array(),
				'rows'    => array(),
			);
		}

		$headers = array();
		$data    = array();

		foreach ( $rows as $row ) {
			if ( ! $row instanceof DOMElement ) {
				continue;
			}
			// A nested table's rows are not our rows.
			$owner = self::closest_table( $row );
			if ( ! $owner instanceof DOMElement || ! $owner->isSameNode( $table ) ) {
				continue;
			}

			$cells = $xpath->query( './th|./td', $row );

			if ( ! $cells instanceof DOMNodeList || 0 === $cells->length ) {
				continue;
			}

			$values = array();
			foreach ( $cells as $cell ) {
				$values[] = self::cell_text( $cell );
			}

			if ( ! $headers ) {
				// Confluence marks a header row with <th>; when an author used
				// plain cells, the first row is still the header row.
				$headers = self::unique_headers( $values );
				continue;
			}

			if ( count( $data ) >= self::MAX_ROWS ) {
				break;
			}

			// Ignore a row that is entirely empty (Confluence leaves trailing
			// blank rows behind constantly).
			if ( '' === trim( implode( '', $values ) ) ) {
				continue;
			}

			$assoc = array();
			foreach ( $headers as $index => $header ) {
				$assoc[ $header ] = (string) ( $values[ $index ] ?? '' );
			}

			$data[] = $assoc;
		}

		return array(
			'headers' => $headers,
			'rows'    => $data,
		);
	}

	/**
	 * The nearest table ancestor of a node, if any.
	 */
	private static function closest_table( DOMNode $node ): ?DOMElement {
		$current = $node->parentNode;

		while ( $current instanceof DOMElement ) {
			if ( 'table' === strtolower( $current->nodeName ) ) {
				return $current;
			}
			$current = $current->parentNode;
		}

		return null;
	}

	/**
	 * Readable text for one cell.
	 *
	 * `<br/>` and list items become spaces rather than running words together,
	 * and Confluence user-mention macros contribute the account id they carry
	 * so an "Owner" column full of mentions is not silently blank.
	 */
	private static function cell_text( DOMNode $cell ): string {
		$text = '';

		foreach ( $cell->childNodes as $child ) {
			$text .= self::node_text( $child );
		}

		if ( '' === trim( $text ) && $cell instanceof DOMElement ) {
			// A macro-only cell: fall back to any user/account identifier.
			foreach ( array( 'ri:userkey', 'ri:username', 'ri:account-id' ) as $attribute ) {
				$found = self::first_attribute( $cell, $attribute );
				if ( '' !== $found ) {
					$text = $found;
					break;
				}
			}
		}

		return VulnHub_Cmdb_Schema::clean( $text );
	}

	/**
	 * Recursive text extraction that turns block breaks into spaces.
	 */
	private static function node_text( DOMNode $node ): string {
		if ( XML_TEXT_NODE === $node->nodeType || XML_CDATA_SECTION_NODE === $node->nodeType ) {
			return (string) $node->nodeValue;
		}

		if ( ! $node instanceof DOMElement ) {
			return '';
		}

		$name = strtolower( $node->nodeName );

		if ( in_array( $name, array( 'br', 'hr' ), true ) ) {
			return ' ';
		}

		$text = '';
		foreach ( $node->childNodes as $child ) {
			$text .= self::node_text( $child );
		}

		if ( in_array( $name, array( 'p', 'li', 'div', 'tr' ), true ) ) {
			$text .= ' ';
		}

		return $text;
	}

	/**
	 * Find the first occurrence of an attribute anywhere below an element.
	 */
	private static function first_attribute( DOMElement $element, string $attribute ): string {
		if ( $element->hasAttribute( $attribute ) ) {
			return trim( $element->getAttribute( $attribute ) );
		}

		foreach ( $element->childNodes as $child ) {
			if ( $child instanceof DOMElement ) {
				$found = self::first_attribute( $child, $attribute );
				if ( '' !== $found ) {
					return $found;
				}
			}
		}

		return '';
	}

	/**
	 * Guarantee unique, non-empty header names so rows can be keyed by them.
	 *
	 * @param array<int,string> $values Raw header cells.
	 * @return array<int,string>
	 */
	private static function unique_headers( array $values ): array {
		$headers = array();
		$seen    = array();

		foreach ( $values as $index => $value ) {
			$header = trim( (string) $value );

			if ( '' === $header ) {
				/* translators: %d: column number. */
				$header = sprintf( __( 'Column %d', 'vulnhub' ), (int) $index + 1 );
			}

			$base    = $header;
			$counter = 2;
			while ( isset( $seen[ $header ] ) ) {
				$header = $base . ' (' . $counter . ')';
				++$counter;
			}

			$seen[ $header ] = true;
			$headers[]       = $header;
		}

		return $headers;
	}
}

