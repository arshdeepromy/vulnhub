<?php
/**
 * Atlassian Document Format builder.
 *
 * Jira Cloud REST API v3 does NOT accept plain text (or wiki markup) in rich
 * text fields. `description`, `comment.body` and the `comment.add.body` inside
 * a transition payload must all be an ADF document:
 *
 *     { "type": "doc", "version": 1, "content": [ …block nodes… ] }
 *
 * Verified against developer.atlassian.com/cloud/jira/platform/apis/document/structure
 * (September 2026). The node shapes this class emits are exactly the ones the
 * vendor documents:
 *
 *   paragraph   { "type":"paragraph", "content":[ inline… ] }
 *   text        { "type":"text", "text":"…", "marks":[ … ] }
 *   link mark   { "type":"link", "attrs":{ "href":"…" } }
 *   strong mark { "type":"strong" }
 *   bulletList  { "type":"bulletList", "content":[ { "type":"listItem",
 *                 "content":[ { "type":"paragraph", "content":[ inline… ] } ] } ] }
 *   codeBlock   { "type":"codeBlock", "attrs":{ "language":"…" },
 *                 "content":[ { "type":"text", "text":"…" } ] }
 *   heading     { "type":"heading", "attrs":{ "level":1-6 }, "content":[ inline… ] }
 *   rule        { "type":"rule" }
 *
 * Two rules the API enforces and this class therefore enforces too:
 *   1. a `text` node's `text` may never be an empty string;
 *   2. a block node that takes `content` must not carry an empty array.
 * Both are silently dropped rather than being sent and rejected with a 400.
 *
 * @package VulnHub\Jira
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Fluent builder for a single ADF document.
 */
final class VulnHub_Jira_Adf {

	/**
	 * Top-level block nodes.
	 *
	 * @var array<int,array<string,mixed>>
	 */
	private array $content = array();

	/**
	 * Start a new document.
	 */
	public static function doc(): self {
		return new self();
	}

	/* =================================================================
	 * Inline nodes
	 * ============================================================== */

	/**
	 * A plain text node. Returns an empty array when the text is blank, which
	 * callers filter out — ADF rejects zero-length text nodes.
	 *
	 * @param string                          $text  Literal text.
	 * @param array<int,array<string,mixed>>  $marks Marks to apply.
	 * @return array<string,mixed>
	 */
	public static function text( string $text, array $marks = array() ): array {
		$text = self::clean( $text );

		if ( '' === $text ) {
			return array();
		}

		$node = array(
			'type' => 'text',
			'text' => $text,
		);

		if ( $marks ) {
			$node['marks'] = array_values( $marks );
		}

		return $node;
	}

	/**
	 * Bold text.
	 *
	 * @return array<string,mixed>
	 */
	public static function strong( string $text ): array {
		return self::text( $text, array( array( 'type' => 'strong' ) ) );
	}

	/**
	 * Monospaced text.
	 *
	 * @return array<string,mixed>
	 */
	public static function code( string $text ): array {
		return self::text( $text, array( array( 'type' => 'code' ) ) );
	}

	/**
	 * A hyperlink.
	 *
	 * @param string $text Anchor text.
	 * @param string $href Absolute URL.
	 * @return array<string,mixed>
	 */
	public static function link( string $text, string $href ): array {
		$href = esc_url_raw( $href );

		if ( '' === $href ) {
			return self::text( $text );
		}

		return self::text(
			$text,
			array(
				array(
					'type'  => 'link',
					'attrs' => array( 'href' => $href ),
				),
			)
		);
	}

	/* =================================================================
	 * Block nodes
	 * ============================================================== */

	/**
	 * Append a paragraph.
	 *
	 * @param string|array<int,array<string,mixed>> $parts A string, or a list of inline nodes.
	 */
	public function paragraph( string|array $parts ): self {
		$inline = is_string( $parts ) ? array( self::text( $parts ) ) : $parts;
		$inline = self::inline_list( $inline );

		if ( ! $inline ) {
			return $this;
		}

		$this->content[] = array(
			'type'    => 'paragraph',
			'content' => $inline,
		);

		return $this;
	}

	/**
	 * Append a heading.
	 *
	 * @param string $text  Heading text.
	 * @param int    $level 1-6.
	 */
	public function heading( string $text, int $level = 3 ): self {
		$inline = self::inline_list( array( self::text( $text ) ) );

		if ( ! $inline ) {
			return $this;
		}

		$this->content[] = array(
			'type'    => 'heading',
			'attrs'   => array( 'level' => max( 1, min( 6, $level ) ) ),
			'content' => $inline,
		);

		return $this;
	}

	/**
	 * Append a bulleted list.
	 *
	 * @param array<int,string|array<int,array<string,mixed>>> $items Each item is a string or a list of inline nodes.
	 */
	public function bullets( array $items ): self {
		$list = array();

		foreach ( $items as $item ) {
			$inline = is_string( $item ) ? array( self::text( $item ) ) : (array) $item;
			$inline = self::inline_list( $inline );

			if ( ! $inline ) {
				continue;
			}

			$list[] = array(
				'type'    => 'listItem',
				'content' => array(
					array(
						'type'    => 'paragraph',
						'content' => $inline,
					),
				),
			);
		}

		if ( ! $list ) {
			return $this;
		}

		$this->content[] = array(
			'type'    => 'bulletList',
			'content' => $list,
		);

		return $this;
	}

	/**
	 * Append a fenced code block.
	 *
	 * @param string $text     Body.
	 * @param string $language Optional syntax hint.
	 */
	public function code_block( string $text, string $language = 'text' ): self {
		$text = self::clean( $text, false );

		if ( '' === $text ) {
			return $this;
		}

		$node = array(
			'type'    => 'codeBlock',
			'attrs'   => array( 'language' => $language ?: 'text' ),
			'content' => array(
				array(
					'type' => 'text',
					'text' => $text,
				),
			),
		);

		$this->content[] = $node;

		return $this;
	}

	/**
	 * Append a horizontal rule.
	 */
	public function rule(): self {
		$this->content[] = array( 'type' => 'rule' );

		return $this;
	}

	/* =================================================================
	 * Output
	 * ============================================================== */

	/**
	 * Is there anything in the document?
	 */
	public function is_empty(): bool {
		return array() === $this->content;
	}

	/**
	 * The finished ADF document.
	 *
	 * @return array<string,mixed>
	 */
	public function to_array(): array {
		return array(
			'type'    => 'doc',
			'version' => 1,
			'content' => $this->content ?: array( array( 'type' => 'paragraph' ) ),
		);
	}

	/**
	 * Render a document back to readable plain text.
	 *
	 * Used for the ticket summary line and for the mock site, which stores what
	 * a human would see rather than the node tree.
	 *
	 * @param array<string,mixed> $doc ADF document or node.
	 */
	public static function to_text( array $doc ): string {
		$out = '';

		if ( isset( $doc['type'] ) && 'text' === $doc['type'] ) {
			return (string) ( $doc['text'] ?? '' );
		}

		foreach ( (array) ( $doc['content'] ?? array() ) as $node ) {
			if ( ! is_array( $node ) ) {
				continue;
			}

			$chunk = self::to_text( $node );

			$out .= match ( (string) ( $node['type'] ?? '' ) ) {
				'paragraph', 'heading', 'codeBlock' => $chunk . "\n",
				'listItem'                          => '- ' . trim( $chunk ) . "\n",
				'rule'                              => "----\n",
				default                             => $chunk,
			};
		}

		return $out;
	}

	/* =================================================================
	 * Internals
	 * ============================================================== */

	/**
	 * Drop the empty nodes that `text()` returns for blank input.
	 *
	 * @param array<int,array<string,mixed>> $nodes Candidate inline nodes.
	 * @return array<int,array<string,mixed>>
	 */
	private static function inline_list( array $nodes ): array {
		return array_values(
			array_filter(
				$nodes,
				static fn( $node ): bool => is_array( $node ) && ! empty( $node['type'] )
			)
		);
	}

	/**
	 * Normalise text for ADF: strip control characters, collapse whitespace and
	 * bound the length so one runaway scanner plugin output cannot blow past
	 * Jira's 32 767 character field limit.
	 *
	 * @param string $text            Raw text.
	 * @param bool   $collapse_lines  Collapse newlines into spaces.
	 */
	private static function clean( string $text, bool $collapse_lines = true ): string {
		$text = (string) preg_replace( '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $text );

		if ( $collapse_lines ) {
			$text = (string) preg_replace( '/\s+/u', ' ', $text );
		} else {
			$text = str_replace( "\r\n", "\n", $text );
		}

		$text = trim( $text );

		if ( mb_strlen( $text ) > 8000 ) {
			$text = mb_substr( $text, 0, 8000 ) . '…';
		}

		return $text;
	}
}

