<?php
/**
 * Getting the English out of a vendor's vulnerability description.
 *
 * A Tenable plugin description is not prose. For a kernel CVE it is one or two
 * useful sentences followed by whatever the upstream commit message dragged
 * along: a syzkaller reproducer, a KASAN report, a full call trace, a register
 * dump and a line of raw opcodes. Rendered as-is it filled the panel with
 * thousands of characters of hex that nobody has ever read, and buried the two
 * sentences that mattered.
 *
 * This finds where the prose stops and the machine output starts, and cuts.
 * Nothing is destroyed -- the untouched vendor text is still there, one click
 * away -- because "the tool hid something" is a worse failure than "the tool
 * showed too much".
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Vendor text, made readable.
 */
final class Prose {

	/**
	 * Markers that begin machine output.
	 *
	 * Everything from the first of these onwards is dropped. They are matched
	 * case-insensitively against the raw text.
	 *
	 * @return string[]
	 */
	private static function cut_markers(): array {
		return array(
			'Found by syzkaller',
			'syz_mount_image',
			'Sample report:',
			'BUG: KASAN',
			'BUG: unable to handle',
			'general protection fault',
			'Call Trace:',
			'Oops:',
			'RIP: ',
			'kernel BUG at',
			'The buggy address',
			'Memory state around',
			'---[ end trace',
			'Reproducer:',
			'POC:',
			'Proof of concept:',
			'stack backtrace:',
		);
	}

	/**
	 * Lines that are machine output wherever they appear.
	 *
	 * Used for the line-by-line sweep after the hard cut, because some
	 * descriptions interleave rather than append.
	 */
	private static function junk_line( string $line ): bool {
		$t = trim( $line );

		if ( '' === $t ) {
			return false;
		}

		// A rule of separator characters.
		if ( preg_match( '/^[=\-_*#~]{8,}$/', $t ) ) {
			return true;
		}

		// Register and address dumps: RAX: 0000..., RIP: 0033:0x7f...
		if ( preg_match( '/^(R[A-Z0-9]{2}|RIP|RSP|RBP|EFLAGS|ORIG_RAX|CR[0-9]|CS|SS|DS|ES|FS|GS):/i', $t ) ) {
			return true;
		}

		// A source path with a line number is a stack frame, not a sentence.
		if ( preg_match( '#^[\w./+-]+\.[ch]:\d+#', $t ) ) {
			return true;
		}

		/*
		 * Mostly-hex lines. A sentence about CVEs has hex in it too, so the
		 * test is the *proportion*: more than 55% hex-and-punctuation over a
		 * long line is a dump, and 40 characters is longer than any real
		 * sentence made only of those.
		 */
		if ( strlen( $t ) > 40 ) {
			$hexish = preg_match_all( '/[0-9a-fx]/i', $t );

			if ( $hexish / strlen( $t ) > 0.55 && ! preg_match( '/\b(the|and|is|are|to|of|in|a)\b/i', $t ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * The readable part of a vendor description.
	 *
	 * @param string $raw   Vendor text.
	 * @param int    $floor Give up and return the whole thing if trimming
	 *                      would leave less than this many characters --
	 *                      better a wall of text than an empty panel.
	 * @return array{text:string,trimmed:bool,removed:int}
	 */
	public static function clean( string $raw, int $floor = 80 ): array {
		$raw = trim( $raw );

		if ( '' === $raw ) {
			return array(
				'text'    => '',
				'trimmed' => false,
				'removed' => 0,
			);
		}

		$text = $raw;
		$cut  = strlen( $text );

		foreach ( self::cut_markers() as $marker ) {
			$at = stripos( $text, $marker );

			if ( false !== $at && $at < $cut ) {
				$cut = $at;
			}
		}

		$text = substr( $text, 0, $cut );

		// Then sweep whatever machine output sat before the first marker.
		$kept = array();

		foreach ( preg_split( '/\R/', $text ) ?: array() as $line ) {
			if ( ! self::junk_line( $line ) ) {
				$kept[] = $line;
			}
		}

		$text = trim( implode( "\n", $kept ) );

		// Collapse the runs of whitespace a stripped block leaves behind.
		$text = (string) preg_replace( '/[ \t]{2,}/', ' ', $text );
		$text = (string) preg_replace( '/\n{3,}/', "\n\n", $text );
		$text = trim( $text );

		if ( strlen( $text ) < $floor ) {
			return array(
				'text'    => $raw,
				'trimmed' => false,
				'removed' => 0,
			);
		}

		$removed = strlen( $raw ) - strlen( $text );

		return array(
			'text'    => $text,
			// Under a couple of hundred characters is tidying, not surgery,
			// and does not deserve a disclosure the reader has to think about.
			'trimmed' => $removed > 200,
			'removed' => max( 0, $removed ),
		);
	}

	/**
	 * Render a vendor description: the prose, and the original behind a
	 * disclosure when there is meaningfully more of it.
	 *
	 * @param string $raw   Vendor text.
	 * @param string $label What the hidden part is called.
	 */
	public static function render( string $raw, string $label = '' ): void {
		$clean = self::clean( $raw );

		if ( '' === $clean['text'] ) {
			return;
		}

		echo '<div class="vh-prose">' . esc_html( $clean['text'] ) . '</div>';

		if ( ! $clean['trimmed'] ) {
			return;
		}

		$label = '' !== $label ? $label : __( 'Show the vendor text in full', 'vulnhub' );

		printf(
			'<details class="vh-rawtext"><summary>%s</summary><pre class="vh-rawtext__body">%s</pre></details>',
			esc_html(
				sprintf(
					/* translators: 1: disclosure label, 2: size of the hidden text. */
					__( '%1$s (%2$s of scanner output)', 'vulnhub' ),
					$label,
					size_format( $clean['removed'] )
				)
			),
			esc_html( $raw )
		);
	}
}

