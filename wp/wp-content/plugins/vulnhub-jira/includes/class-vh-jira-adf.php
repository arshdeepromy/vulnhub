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
		// clean() trims, which glued inline pieces together ("host— detail"
		// for a bold host followed by " — detail"). Keep one space at either
		// edge when the caller put one there.
		$lead = preg_match( '/^\s/u', $text ) ? ' ' : '';
		$tail = preg_match( '/\s$/u', $text ) ? ' ' : '';
		$text = self::clean( $text );

		if ( '' === $text ) {
			return array();
		}

		$text = $lead . $text . $tail;

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

	/**
	 * A document as plain text a person can edit, and read back by
	 * from_editable() into the same nodes.
	 *
	 * The markup is the small set this builder emits: `## Heading`,
	 * `- bullet`, `---` for a rule, fenced ``` code blocks, and inline
	 * `**bold**`, `` `code` `` and `[text](https://link)`. Blocks are separated
	 * by a blank line.
	 *
	 * @param array<string,mixed> $doc ADF document.
	 */
	public static function to_editable( array $doc ): string {
		$blocks = array();

		foreach ( (array) ( $doc['content'] ?? array() ) as $node ) {
			if ( ! is_array( $node ) ) {
				continue;
			}

			switch ( (string) ( $node['type'] ?? '' ) ) {
				case 'heading':
					$blocks[] = str_repeat( '#', max( 1, min( 6, (int) ( $node['attrs']['level'] ?? 3 ) - 1 ) ) ) . ' ' . self::inline_editable( (array) ( $node['content'] ?? array() ) );
					break;
				case 'paragraph':
					$text = self::inline_editable( (array) ( $node['content'] ?? array() ) );
					if ( '' !== trim( $text ) ) {
						$blocks[] = $text;
					}
					break;
				case 'bulletList':
					$items = array();
					foreach ( (array) ( $node['content'] ?? array() ) as $item ) {
						$parts = array();
						foreach ( (array) ( $item['content'] ?? array() ) as $child ) {
							$parts[] = self::inline_editable( (array) ( $child['content'] ?? array() ) );
						}
						$items[] = '- ' . str_replace( "\n", ' ', trim( implode( ' ', $parts ) ) );
					}
					$blocks[] = implode( "\n", $items );
					break;
				case 'codeBlock':
					$blocks[] = "```\n" . self::to_text( $node ) . "\n```";
					break;
				case 'rule':
					$blocks[] = '---';
					break;
				default:
					$text = trim( self::to_text( $node ) );
					if ( '' !== $text ) {
						$blocks[] = $text;
					}
			}
		}

		return implode( "\n\n", $blocks );
	}

	/**
	 * @param array<int,array<string,mixed>> $inline Inline nodes.
	 */
	private static function inline_editable( array $inline ): string {
		$out = '';

		foreach ( $inline as $node ) {
			if ( 'hardBreak' === ( $node['type'] ?? '' ) ) {
				$out .= "\n";
				continue;
			}

			$text = (string) ( $node['text'] ?? '' );

			foreach ( (array) ( $node['marks'] ?? array() ) as $mark ) {
				$text = match ( (string) ( $mark['type'] ?? '' ) ) {
					'strong' => '**' . $text . '**',
					'code'   => '`' . $text . '`',
					'link'   => '[' . $text . '](' . (string) ( $mark['attrs']['href'] ?? '' ) . ')',
					default  => $text,
				};
			}

			$out .= $text;
		}

		return $out;
	}

	/**
	 * Read edited text (see to_editable()) back into a document.
	 */
	public static function from_editable( string $text ): array {
		$doc   = self::doc();
		$lines = preg_split( '/\R/', str_replace( "\t", '    ', $text ) ) ?: array();
		$para  = array();
		$list  = array();
		$code  = null;

		$flush = static function () use ( &$para, &$list, $doc ): void {
			if ( $para ) {
				$doc->paragraph( self::inline_from_editable( implode( ' ', $para ) ) );
				$para = array();
			}
			if ( $list ) {
				$doc->bullets( array_map( array( self::class, 'inline_from_editable' ), $list ) );
				$list = array();
			}
		};

		foreach ( $lines as $line ) {
			if ( null !== $code ) {
				if ( preg_match( '/^\s*```\s*$/', $line ) ) {
					$doc->code_block( implode( "\n", $code ) );
					$code = null;
				} else {
					$code[] = $line;
				}
				continue;
			}

			$trim = trim( $line );

			if ( preg_match( '/^```/', $trim ) ) {
				$flush();
				$code = array();
			} elseif ( '' === $trim ) {
				$flush();
			} elseif ( preg_match( '/^(#{1,5})\s+(.+)$/', $trim, $m ) ) {
				$flush();
				$doc->heading( $m[2], strlen( $m[1] ) + 1 );
			} elseif ( preg_match( '/^(-{3,}|\*{3,})$/', $trim ) ) {
				$flush();
				$doc->rule();
			} elseif ( preg_match( '/^[-*•]\s+(.+)$/u', $trim, $m ) ) {
				if ( $para ) {
					$doc->paragraph( self::inline_from_editable( implode( ' ', $para ) ) );
					$para = array();
				}
				$list[] = $m[1];
			} elseif ( $list ) {
				// A line under a bullet continues that bullet.
				$list[ count( $list ) - 1 ] .= ' ' . $trim;
			} else {
				$para[] = $trim;
			}
		}

		if ( null !== $code ) {
			$doc->code_block( implode( "\n", $code ) );
		}

		$flush();

		return $doc->to_array();
	}

	/**
	 * Inline markup to text nodes: **bold**, `code`, [text](https://link).
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function inline_from_editable( string $text ): array {
		// Built here rather than through text(), which trims: "foo **bar**
		// baz" must keep the spaces either side of the bold word.
		$text = trim( (string) preg_replace( '/\s+/u', ' ', (string) preg_replace( '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $text ) ) );
		$out  = array();
		$pos  = 0;
		$node = static function ( string $chunk, array $marks = array() ): array {
			if ( '' === $chunk ) {
				return array();
			}
			$n = array( 'type' => 'text', 'text' => mb_substr( $chunk, 0, 8000 ) );
			if ( $marks ) {
				$n['marks'] = $marks;
			}
			return $n;
		};

		if ( preg_match_all( '/\*\*(.+?)\*\*|`([^`]+)`|\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/', $text, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER ) ) {
			foreach ( $matches as $m ) {
				if ( $m[0][1] > $pos ) {
					$out[] = $node( substr( $text, $pos, $m[0][1] - $pos ) );
				}

				if ( isset( $m[4] ) && '' !== $m[4][0] && '' !== esc_url_raw( $m[4][0] ) ) {
					$out[] = $node( $m[3][0], array( array( 'type' => 'link', 'attrs' => array( 'href' => esc_url_raw( $m[4][0] ) ) ) ) );
				} elseif ( isset( $m[2] ) && '' !== $m[2][0] ) {
					$out[] = $node( $m[2][0], array( array( 'type' => 'code' ) ) );
				} elseif ( '' !== $m[1][0] ) {
					$out[] = $node( $m[1][0], array( array( 'type' => 'strong' ) ) );
				} else {
					$out[] = $node( $m[0][0] );
				}

				$pos = $m[0][1] + strlen( $m[0][0] );
			}
		}

		if ( $pos < strlen( $text ) ) {
			$out[] = $node( substr( $text, $pos ) );
		}

		return array_values( array_filter( $out ) );
	}

	/**
	 * Render a document as HTML, for showing a person what Jira will display
	 * before the ticket is sent.
	 *
	 * Covers the nodes this builder emits (paragraph, heading, bullet list,
	 * code block, rule; strong, code and link marks). Every text value is
	 * escaped here, so the result is safe to insert into a page as-is.
	 *
	 * @param array<string,mixed> $node ADF document or node.
	 */
	public static function to_html( array $node ): string {
		$type = (string) ( $node['type'] ?? '' );

		if ( 'text' === $type ) {
			$html = esc_html( (string) ( $node['text'] ?? '' ) );

			foreach ( (array) ( $node['marks'] ?? array() ) as $mark ) {
				$html = match ( (string) ( $mark['type'] ?? '' ) ) {
					'strong' => '<strong>' . $html . '</strong>',
					'code'   => '<code>' . $html . '</code>',
					'link'   => '<a href="' . esc_url( (string) ( $mark['attrs']['href'] ?? '' ) ) . '" target="_blank" rel="noopener noreferrer">' . $html . '</a>',
					default  => $html,
				};
			}

			return $html;
		}

		$inner = '';

		foreach ( (array) ( $node['content'] ?? array() ) as $child ) {
			if ( is_array( $child ) ) {
				$inner .= self::to_html( $child );
			}
		}

		return match ( $type ) {
			'paragraph'  => '<p>' . $inner . '</p>',
			'heading'    => '<h4>' . $inner . '</h4>',
			'bulletList' => '<ul>' . $inner . '</ul>',
			'listItem'   => '<li>' . $inner . '</li>',
			'codeBlock'  => '<pre><code>' . $inner . '</code></pre>',
			'rule'       => '<hr>',
			default      => $inner,
		};
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

