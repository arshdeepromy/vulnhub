<?php
/**
 * "What are we running that has stopped getting fixes?"
 *
 * This is the chart that does not change week to week and matters more than
 * the ones that do. A machine past its operating system's end of life will
 * not get a patch for the next critical either, so it drops out of the
 * patching conversation entirely and into somebody's project plan — and the
 * only useful thing a dashboard can do is make sure the number is in front
 * of the person who writes those plans, several months before it becomes an
 * incident.
 *
 * Three separate counts, drawn as three separate blocks on purpose:
 * platforms, installed software, and hardware support. Mixing them would
 * produce one impressive number that nobody can act on. See
 * \VulnHub\Core\Eol for where the dates come from and how they are matched.
 *
 * @package VulnHub\Dashboard
 */

declare( strict_types = 1 );

use VulnHub\Core\Eol;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * End-of-life widgets.
 */
final class VulnHub_Dash_Eol {

	/** How many releases to draw before the rest become a "and N more" line. */
	private const SHOWN = 12;

	/**
	 * The assets list, filtered to one release.
	 */
	public static function url( string $key ): string {
		return VulnHub_Dash_Portal::portal_url( 'assets', array( 'eol' => $key, 'life' => 'reportable' ) );
	}

	/* =================================================================
	 * Platforms
	 * ============================================================== */

	public static function render(): void {
		$rows = Eol::estate();

		if ( ! $rows ) {
			echo VulnHub_Dash_Charts::empty_state( esc_html__( 'No in-service assets to check yet.', 'vulnhub' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			return;
		}

		self::headline( Eol::summary() );

		echo VulnHub_Dash_Charts::segment_bars( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			self::bars( array_slice( $rows, 0, self::SHOWN ) ),
			array(
				'unit'   => __( 'assets', 'vulnhub' ),
				'legend' => self::legend(),
			)
		);

		if ( count( $rows ) > self::SHOWN ) {
			printf(
				'<p class="vh-w__note">%s</p>',
				esc_html(
					sprintf(
						/* translators: %s: number of releases. */
						_n(
							'%s further release is in the estate; the full list is in the table below.',
							'%s further releases are in the estate; the full list is in the table below.',
							count( $rows ) - self::SHOWN,
							'vulnhub'
						),
						number_format_i18n( count( $rows ) - self::SHOWN )
					)
				)
			);
		}

		echo VulnHub_Dash_Charts::table_view( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			self::headers(),
			self::table_rows( $rows ),
			__( 'In-service assets only. A release with no published date is counted but not judged.', 'vulnhub' )
		);
	}

	/**
	 * @return array{headers:array<int,string>,rows:array<int,array<int,string>>}
	 */
	public static function data(): array {
		return array(
			'headers' => self::headers(),
			'rows'    => self::table_rows( Eol::estate() ),
		);
	}

	/* =================================================================
	 * Software
	 * ============================================================== */

	public static function render_software(): void {
		$rows = Eol::software();

		if ( ! $rows ) {
			echo VulnHub_Dash_Charts::empty_state( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				esc_html__( 'No installed software has been reported against the lifecycle table yet. Tenable supplies this as CPE strings on the asset.', 'vulnhub' )
			);
			return;
		}

		$counts = array( 'past' => 0, 'soon' => 0, 'supported' => 0, 'unknown' => 0 );

		foreach ( $rows as $row ) {
			$counts[ $row['status'] ] += (int) $row['assets'];
		}

		self::headline(
			$counts,
			__( 'installations', 'vulnhub' ),
			array(
				'past' => __( 'On an unsupported release', 'vulnhub' ),
				'soon' => __( 'Support ends within 6 months', 'vulnhub' ),
			)
		);

		echo VulnHub_Dash_Charts::segment_bars( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			self::bars( array_slice( $rows, 0, self::SHOWN ), false ),
			array(
				'unit'   => __( 'assets', 'vulnhub' ),
				'legend' => self::legend(),
			)
		);

		$vh_retired = 0;
		foreach ( $rows as $vh_row ) {
			if ( 'past' === $vh_row['status'] && ! empty( $vh_row['retired'] ) ) {
				$vh_retired += (int) $vh_row['assets'];
			}
		}

		printf(
			'<p class="vh-w__note">%s</p>',
			esc_html(
				sprintf(
					/* translators: 1: installations needing only a version upgrade, 2: installations whose product has no supported release. */
					__( 'These are release branches the vendor no longer patches, not dead products: %1$s of these installations move to a supported release of the same software, and %2$s are on a product with no supported release left. Counted once per machine, so the number is how many machines to visit. Only products in the lifecycle table are counted.', 'vulnhub' ),
					number_format_i18n( max( 0, $counts['past'] - $vh_retired ) ),
					number_format_i18n( $vh_retired )
				)
			)
		);

		echo VulnHub_Dash_Charts::table_view( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			self::headers(),
			self::table_rows( $rows ),
			__( 'Installed software on in-service assets.', 'vulnhub' )
		);
	}

	/**
	 * @return array{headers:array<int,string>,rows:array<int,array<int,string>>}
	 */
	public static function data_software(): array {
		return array(
			'headers' => self::headers(),
			'rows'    => self::table_rows( Eol::software() ),
		);
	}

	/* =================================================================
	 * Hardware
	 * ============================================================== */

	public static function render_hardware(): void {
		$rows  = Eol::hardware();
		$total = 0;

		foreach ( $rows as $row ) {
			$total += (int) $row['assets'];
		}

		if ( ! $total ) {
			echo VulnHub_Dash_Charts::empty_state( esc_html__( 'No in-service assets to check yet.', 'vulnhub' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			return;
		}

		echo VulnHub_Dash_Charts::segment_bars( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			array(
				array(
					'label'    => __( 'Hardware support', 'vulnhub' ),
					'sub'      => sprintf(
						/* translators: %s: number of assets. */
						_n( '%s in-service asset', '%s in-service assets', $total, 'vulnhub' ),
						number_format_i18n( $total )
					),
					'segments' => array_map(
						static fn( array $r ): array => array(
							'label'  => (string) $r['label'],
							'value'  => (int) $r['assets'],
							'colour' => self::tone_colour( (string) $r['status'] ),
						),
						$rows
					),
				),
			),
			array(
				'unit'   => __( 'assets', 'vulnhub' ),
				'legend' => array_map(
					static fn( array $r ): array => array(
						'label'  => (string) $r['label'],
						'colour' => self::tone_colour( (string) $r['status'] ),
					),
					$rows
				),
			)
		);

		printf(
			'<p class="vh-w__note">%s</p>',
			esc_html__( 'From the CMDB support end date. This is a warranty date, not a security one — a machine out of warranty still gets operating system updates.', 'vulnhub' )
		);
	}

	/* =================================================================
	 * Shared
	 * ============================================================== */

	/**
	 * Four tiles across the top: the number nobody wants first.
	 *
	 * @param array<string,int> $counts Assets per status.
	 */
	private static function headline( array $counts, string $unit = '', array $labels = array() ): void {
		/*
		 * Hardware keeps "past end of life", because a model really does end:
		 * there is no newer release of the same laptop to move to. Software is
		 * release branches, so the software view passes its own wording -- see
		 * render_software().
		 */
		$defs = array(
			'past'      => array( __( 'Past end of life', 'vulnhub' ), 'critical' ),
			'soon'      => array( __( 'Ends within 6 months', 'vulnhub' ), 'warn' ),
			'supported' => array( __( 'Supported', 'vulnhub' ), 'good' ),
			'unknown'   => array( __( 'Release unknown', 'vulnhub' ), 'muted' ),
		);

		foreach ( $labels as $key => $label ) {
			if ( isset( $defs[ $key ] ) ) {
				$defs[ $key ][0] = (string) $label;
			}
		}

		echo '<div class="vh-tiles">';

		foreach ( $defs as $key => [$label, $tone] ) {
			echo VulnHub_Dash_Charts::stat_tile( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				array(
					'label' => $label,
					'value' => number_format_i18n( (int) ( $counts[ $key ] ?? 0 ) ),
					'tone'  => 'past' === $key && ( $counts[ $key ] ?? 0 ) > 0 ? 'critical' : $tone,
					'meta'  => $unit,
				)
			);
		}

		echo '</div>';
	}

	/**
	 * One bar per release, its segment coloured by status.
	 *
	 * A single-segment bar looks odd next to a split one, which is exactly
	 * the point here: the whole population of a release is in one state, and
	 * the bar's colour is the answer.
	 *
	 * @param array<int,array<string,mixed>> $rows Estate rows.
	 * @return array<int,array<string,mixed>>
	 */
	private static function bars( array $rows, bool $link = true ): array {
		$out = array();

		foreach ( $rows as $row ) {
			$sub = (string) $row['release'];

			if ( '' !== (string) $row['eol'] ) {
				$sub = trim( $sub . ' · ' . self::when( $row ) );
			}

			/*
			 * Name the remediation on the row. "OpenSSL 3.0 LTS, ended 5 days
			 * ago" reads as though OpenSSL is finished; it is not, and 3.5 LTS
			 * runs to 2030. Without the target, every expired branch of a
			 * living product looks like a migration rather than an upgrade,
			 * which is both alarming and the wrong instruction.
			 */
			if ( '' !== (string) ( $row['upgrade_to'] ?? '' ) ) {
				$sub = trim(
					$sub . ' · ' . sprintf(
						/* translators: %s: the supported release to move to. */
						__( 'upgrade to %s', 'vulnhub' ),
						(string) $row['upgrade_to']
					)
				);
			} elseif ( ! empty( $row['retired'] ) ) {
				$sub = trim( $sub . ' · ' . __( 'no supported release', 'vulnhub' ) );
			}

			$out[] = array(
				'label'    => (string) $row['label'],
				'sub'      => $sub,
				'href'     => $link ? self::url( (string) $row['key'] ) : '',
				'segments' => array(
					array(
						'label'  => (string) $row['status_label'],
						'value'  => (int) $row['assets'],
						'colour' => self::tone_colour( (string) $row['status'] ),
						'href'   => $link ? self::url( (string) $row['key'] ) : '',
						'title'  => sprintf(
							/* translators: 1: count, 2: product, 3: release, 4: status. */
							_n( '%1$s asset on %2$s %3$s — %4$s', '%1$s assets on %2$s %3$s — %4$s', (int) $row['assets'], 'vulnhub' ),
							number_format_i18n( (int) $row['assets'] ),
							(string) $row['label'],
							(string) $row['release'],
							strtolower( (string) $row['status_label'] )
						),
					),
				),
			);
		}

		return $out;
	}

	/**
	 * "Ended 11 months ago" / "in 63 days" — the part people actually read.
	 *
	 * @param array<string,mixed> $row Estate row.
	 */
	private static function when( array $row ): string {
		$days = $row['days'] ?? null;

		if ( null === $days ) {
			return '';
		}

		$days = (int) $days;

		if ( $days < 0 ) {
			return sprintf(
				/* translators: %s: a human time difference such as "3 months". */
				__( 'ended %s ago', 'vulnhub' ),
				human_time_diff( time() - ( abs( $days ) * DAY_IN_SECONDS ) )
			);
		}

		if ( 0 === $days ) {
			return __( 'ends today', 'vulnhub' );
		}

		return sprintf(
			/* translators: %s: a human time difference such as "3 months". */
			__( 'ends in %s', 'vulnhub' ),
			human_time_diff( time(), time() + ( $days * DAY_IN_SECONDS ) )
		);
	}

	private static function tone_colour( string $status ): string {
		return match ( $status ) {
			'past'      => 'var(--vh-sev-critical)',
			'soon'      => 'var(--vh-sev-high)',
			'supported' => 'var(--vh-good)',
			default     => 'var(--vh-sev-info)',
		};
	}

	/**
	 * @return array<int,array{label:string,colour:string}>
	 */
	private static function legend(): array {
		$out = array();

		foreach ( Eol::statuses() as $key => $def ) {
			$out[] = array(
				'label'  => (string) $def['label'],
				'colour' => self::tone_colour( (string) $key ),
			);
		}

		return $out;
	}

	/** @return array<int,string> */
	private static function headers(): array {
		return array(
			__( 'Platform', 'vulnhub' ),
			__( 'Release', 'vulnhub' ),
			__( 'Status', 'vulnhub' ),
			__( 'End of life', 'vulnhub' ),
			__( 'Mainstream ends', 'vulnhub' ),
			__( 'Days remaining', 'vulnhub' ),
			__( 'Assets', 'vulnhub' ),
		);
	}

	/**
	 * @param array<int,array<string,mixed>> $rows Estate rows.
	 * @return array<int,array<int,string>>
	 */
	private static function table_rows( array $rows ): array {
		return array_map(
			static fn( array $r ): array => array(
				(string) $r['label'],
				(string) $r['release'],
				(string) $r['status_label'],
				(string) $r['eol'],
				(string) ( $r['mainstream'] ?? '' ),
				null === $r['days'] ? '' : (string) $r['days'],
				number_format_i18n( (int) $r['assets'] ),
			),
			$rows
		);
	}
}

