<?php
/**
 * Server-rendered inline SVG charts.
 *
 * No charting library and no external JavaScript: every chart is SVG emitted by
 * PHP, carrying data-* attributes that a small progressive-enhancement script
 * uses for hover. If that script never loads, the chart is still complete and
 * readable — which is the whole reason for rendering it server side.
 *
 * Palette decisions and their validation record live in docs/PALETTE.md.
 *
 * @package VulnHub\Dashboard
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Dash_Charts {

	/**
	 * Severity is a semantic-heat scale, so hue never carries it alone: every
	 * mark also gets its text label, a fixed left-to-right order, and a 2px
	 * surface gap. See docs/PALETTE.md.
	 *
	 * @return array<string,string> CSS custom property names by severity.
	 */
	public static function severity_var( string $severity ): string {
		return 'var(--vh-sev-' . ( array_key_exists( $severity, vh_severities() ) ? $severity : 'info' ) . ')';
	}

	/**
	 * Severity order, worst first. Position encodes severity independently of hue.
	 *
	 * @return string[]
	 */
	public static function severity_order(): array {
		return array( 'critical', 'high', 'medium', 'low', 'info' );
	}

	private static int $uid = 0;

	private static function uid( string $prefix ): string {
		++self::$uid;
		return $prefix . '-' . self::$uid;
	}

	/**
	 * Escape a value for use inside an SVG attribute.
	 */
	private static function n( float $value ): string {
		return (string) round( $value, 2 );
	}

	/* =================================================================
	 * Stat tile — the right form for a single headline number
	 * ============================================================== */

	/**
	 * @param array{
	 *   label:string, value:int|float|string, meta?:string, tone?:string,
	 *   spark?:array<int,float>, href?:string, delta?:string, delta_dir?:string
	 * } $args Tile definition.
	 */
	public static function stat_tile( array $args ): string {
		$tone  = (string) ( $args['tone'] ?? 'neutral' );
		$href  = (string) ( $args['href'] ?? '' );
		$tag   = $href ? 'a' : 'div';
		$attrs = $href ? ' href="' . esc_url( $href ) . '"' : '';

		$out  = '<' . $tag . ' class="vh-tile vh-tile--' . esc_attr( $tone ) . '"' . $attrs . '>';
		$out .= '<span class="vh-tile__label">' . esc_html( (string) $args['label'] ) . '</span>';
		$out .= '<span class="vh-tile__value">' . esc_html( is_numeric( $args['value'] ) ? number_format_i18n( (float) $args['value'] ) : (string) $args['value'] ) . '</span>';

		if ( ! empty( $args['delta'] ) ) {
			$dir = (string) ( $args['delta_dir'] ?? 'flat' );
			$out .= '<span class="vh-tile__delta vh-tile__delta--' . esc_attr( $dir ) . '">'
				. ( 'up' === $dir ? '&uarr; ' : ( 'down' === $dir ? '&darr; ' : '' ) )
				. esc_html( (string) $args['delta'] ) . '</span>';
		}
		if ( ! empty( $args['meta'] ) ) {
			$out .= '<span class="vh-tile__meta">' . esc_html( (string) $args['meta'] ) . '</span>';
		}
		if ( ! empty( $args['spark'] ) && count( (array) $args['spark'] ) > 1 ) {
			$out .= self::sparkline( (array) $args['spark'] );
		}

		$out .= '</' . $tag . '>';
		return $out;
	}

	/**
	 * Tiny trend line inside a stat tile. Decorative context, so it is
	 * aria-hidden — the number beside it is the accessible value.
	 *
	 * @param array<int,float> $values Series.
	 */
	public static function sparkline( array $values, int $w = 160, int $h = 30 ): string {
		$values = array_values( array_map( 'floatval', $values ) );
		$count  = count( $values );
		if ( $count < 2 ) {
			return '';
		}

		$max = max( $values );
		$min = min( $values );
		$rng = max( 0.0001, $max - $min );

		$points = array();
		foreach ( $values as $i => $v ) {
			$x        = ( $i / ( $count - 1 ) ) * ( $w - 2 ) + 1;
			$y        = $h - 3 - ( ( $v - $min ) / $rng ) * ( $h - 6 );
			$points[] = self::n( $x ) . ',' . self::n( $y );
		}

		$last = explode( ',', (string) end( $points ) );

		return '<svg class="vh-spark" viewBox="0 0 ' . $w . ' ' . $h . '" preserveAspectRatio="none" aria-hidden="true" focusable="false">'
			. '<polyline fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" points="' . esc_attr( implode( ' ', $points ) ) . '"/>'
			. '<circle cx="' . esc_attr( $last[0] ) . '" cy="' . esc_attr( $last[1] ) . '" r="2.5" fill="currentColor"/>'
			. '</svg>';
	}

	/* =================================================================
	 * Multi-series trend line
	 * ============================================================== */

	/**
	 * Line chart with a hover crosshair.
	 *
	 * @param array<string,array<string,float>> $series  label => (date => value).
	 * @param array<string,string>              $colours label => CSS colour.
	 * @param array<string,mixed>               $opts    height, title, unit.
	 */
	/**
	 * Format an x-axis label.
	 *
	 * Series are keyed by date, but a caller that hands over a plain list
	 * gets integer keys instead -- so parse defensively and fall back to the
	 * raw label rather than formatting 0 as 1 January 1970.
	 *
	 * @param mixed $label Raw label.
	 */
	private static function axis_label( $label ): string {
		$raw = (string) $label;
		$ts  = '' === $raw ? false : strtotime( $raw );

		return false === $ts ? $raw : (string) wp_date( 'j M', $ts );
	}

	public static function line_chart( array $series, array $colours, array $opts = array() ): string {
		$labels = array();
		foreach ( $series as $points ) {
			$labels = array_merge( $labels, array_keys( $points ) );
		}
		$labels = array_values( array_unique( $labels ) );
		sort( $labels );

		if ( count( $labels ) < 2 ) {
			return self::empty_state( __( 'Not enough history yet — trends appear once the platform has collected a few daily snapshots.', 'vulnhub' ) );
		}

		$w       = 900;
		$h       = (int) ( $opts['height'] ?? 260 );
		$pad_l   = 44;
		$pad_r   = 16;
		$pad_t   = 14;
		$pad_b   = 30;
		$plot_w  = $w - $pad_l - $pad_r;
		$plot_h  = $h - $pad_t - $pad_b;
		$id      = self::uid( 'vhline' );

		$max = 0.0;
		foreach ( $series as $points ) {
			foreach ( $points as $v ) {
				$max = max( $max, (float) $v );
			}
		}
		$max   = max( 1.0, $max );
		$ticks = self::nice_ticks( $max );
		$top   = (float) end( $ticks );

		$x_for = static fn( int $i ): float => $pad_l + ( count( $labels ) > 1 ? ( $i / ( count( $labels ) - 1 ) ) * $plot_w : $plot_w / 2 );
		$y_for = static fn( float $v ): float => $pad_t + $plot_h - ( $v / $top ) * $plot_h;

		$svg  = '<svg class="vh-chart" viewBox="0 0 ' . $w . ' ' . $h . '" role="img" preserveAspectRatio="xMidYMid meet"';
		$svg .= ' aria-label="' . esc_attr( (string) ( $opts['title'] ?? __( 'Trend over time', 'vulnhub' ) ) ) . '" data-vh-chart="line" id="' . esc_attr( $id ) . '">';

		// Hairline grid — solid, one shade off the surface. Never dashed.
		foreach ( $ticks as $t ) {
			$y    = $y_for( (float) $t );
			$svg .= '<line class="vh-grid" x1="' . self::n( (float) $pad_l ) . '" y1="' . self::n( $y ) . '" x2="' . self::n( (float) ( $w - $pad_r ) ) . '" y2="' . self::n( $y ) . '"/>';
			$svg .= '<text class="vh-axis" x="' . self::n( (float) ( $pad_l - 8 ) ) . '" y="' . self::n( $y + 4 ) . '" text-anchor="end">' . esc_html( number_format_i18n( (float) $t ) ) . '</text>';
		}

		// X labels: first, middle and last only, so they never collide.
		$show = array_unique( array( 0, (int) floor( ( count( $labels ) - 1 ) / 2 ), count( $labels ) - 1 ) );
		foreach ( $show as $i ) {
			$svg .= '<text class="vh-axis" x="' . self::n( $x_for( (int) $i ) ) . '" y="' . self::n( (float) ( $h - 10 ) ) . '" text-anchor="middle">'
				. esc_html( self::axis_label( $labels[ $i ] ?? '' ) ) . '</text>';
		}

		$svg .= '<line class="vh-baseline" x1="' . self::n( (float) $pad_l ) . '" y1="' . self::n( $y_for( 0 ) ) . '" x2="' . self::n( (float) ( $w - $pad_r ) ) . '" y2="' . self::n( $y_for( 0 ) ) . '"/>';

		foreach ( $series as $name => $points ) {
			$colour = $colours[ $name ] ?? 'var(--vh-series-1)';
			$coords = array();
			foreach ( $labels as $i => $day ) {
				if ( ! isset( $points[ $day ] ) ) {
					continue;
				}
				$coords[] = array( $x_for( (int) $i ), $y_for( (float) $points[ $day ] ), (float) $points[ $day ], $day );
			}
			if ( count( $coords ) < 2 ) {
				continue;
			}

			$d = '';
			foreach ( $coords as $k => $c ) {
				$d .= ( 0 === $k ? 'M' : 'L' ) . self::n( $c[0] ) . ' ' . self::n( $c[1] ) . ' ';
			}

			$svg .= '<path class="vh-line" fill="none" stroke="' . esc_attr( $colour ) . '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="' . esc_attr( trim( $d ) ) . '"/>';

			// Direct-label the endpoint only — never a number on every point.
			$last = end( $coords );
			$svg .= '<circle cx="' . self::n( $last[0] ) . '" cy="' . self::n( $last[1] ) . '" r="3.5" fill="' . esc_attr( $colour ) . '" stroke="var(--vh-surface)" stroke-width="2"/>';
		}

		// Invisible hover columns drive the crosshair + tooltip.
		foreach ( $labels as $i => $day ) {
			$parts = array();
			foreach ( $series as $name => $points ) {
				if ( isset( $points[ $day ] ) ) {
					$parts[] = $name . '\u{a0}' . number_format_i18n( (float) $points[ $day ] );
				}
			}
			$svg .= '<rect class="vh-hit" x="' . self::n( $x_for( (int) $i ) - ( $plot_w / max( 1, count( $labels ) ) ) / 2 ) . '" y="' . $pad_t . '"'
				. ' width="' . self::n( $plot_w / max( 1, count( $labels ) ) ) . '" height="' . $plot_h . '"'
				. ' data-x="' . self::n( $x_for( (int) $i ) ) . '"'
				. ' data-label="' . esc_attr( wp_date( 'j M Y', (int) strtotime( $day ) ) ) . '"'
				. ' data-values="' . esc_attr( implode( ' · ', $parts ) ) . '"></rect>';
		}

		$svg .= '<line class="vh-crosshair" x1="0" y1="' . $pad_t . '" x2="0" y2="' . self::n( (float) ( $pad_t + $plot_h ) ) . '" hidden/>';
		$svg .= '</svg>';

		return '<div class="vh-chart-wrap">' . $svg . self::legend( array_keys( $series ), $colours ) . '</div>';
	}

	/* =================================================================
	 * Horizontal bars — magnitude comparison across nominal categories
	 * ============================================================== */

	/**
	 * One series, one colour. A value-ramp across nominal categories would
	 * double-encode bar length as hue, so it is deliberately avoided.
	 *
	 * @param array<int,array{label:string,value:float,href?:string,note?:string}> $rows Rows.
	 */
	public static function bar_chart( array $rows, array $opts = array() ): string {
		if ( ! $rows ) {
			return self::empty_state( (string) ( $opts['empty'] ?? __( 'Nothing to show yet.', 'vulnhub' ) ) );
		}

		$max    = max( 1.0, max( array_map( static fn( array $r ): float => (float) $r['value'], $rows ) ) );
		$colour = (string) ( $opts['colour'] ?? 'var(--vh-series-1)' );

		$out = '<div class="vh-bars">';
		foreach ( $rows as $row ) {
			$pct   = ( (float) $row['value'] / $max ) * 100;
			$label = esc_html( (string) $row['label'] );
			if ( ! empty( $row['href'] ) ) {
				$label = '<a href="' . esc_url( (string) $row['href'] ) . '">' . $label . '</a>';
			}

			$out .= '<div class="vh-bars__row">';
			$out .= '<span class="vh-bars__label">' . $label . '</span>';
			$out .= '<span class="vh-bars__track"><span class="vh-bars__fill" style="width:' . self::n( max( 1.2, $pct ) ) . '%;background:' . esc_attr( $colour ) . '"></span></span>';
			$out .= '<span class="vh-bars__value">' . esc_html( number_format_i18n( (float) $row['value'] ) ) . '</span>';
			$out .= '</div>';
		}
		$out .= '</div>';

		return $out;
	}

	/* =================================================================
	 * Stacked severity bar — part-to-whole, fixed severity order
	 * ============================================================== */

	/**
	 * @param array<int,array{label:string,counts:array<string,int>,href?:string}> $rows Rows.
	 */
	public static function severity_stack( array $rows, array $opts = array() ): string {
		if ( ! $rows ) {
			return self::empty_state( (string) ( $opts['empty'] ?? __( 'Nothing to show yet.', 'vulnhub' ) ) );
		}

		$totals = array();
		foreach ( $rows as $row ) {
			$totals[] = array_sum( array_map( 'intval', $row['counts'] ) );
		}
		$max = max( 1, max( $totals ) );

		$out = '<div class="vh-stack">';
		foreach ( $rows as $i => $row ) {
			$total = (int) $totals[ $i ];
			$label = esc_html( (string) $row['label'] );
			if ( ! empty( $row['href'] ) ) {
				$label = '<a href="' . esc_url( (string) $row['href'] ) . '">' . $label . '</a>';
			}

			$out .= '<div class="vh-stack__row">';
			$out .= '<span class="vh-stack__label">' . $label . '</span>';
			$out .= '<span class="vh-stack__track" style="width:' . self::n( ( $total / $max ) * 100 ) . '%">';

			foreach ( self::severity_order() as $sev ) {
				$n = (int) ( $row['counts'][ $sev ] ?? 0 );
				if ( $n <= 0 ) {
					continue;
				}
				$tip = sprintf( '%s: %s', vh_severity_label( $sev ), number_format_i18n( $n ) );

				/*
				 * A segment is the most specific thing on the chart -- "this
				 * team's criticals" -- so it links when the caller supplied a
				 * URL for it. Callers that did not still get a plain span.
				 */
				$seg_href = (string) ( $row['seg_hrefs'][ $sev ] ?? '' );

				$tag  = '' !== $seg_href ? 'a' : 'span';
				$href = '' !== $seg_href ? ' href="' . esc_url( $seg_href ) . '"' : '';

				$out .= '<' . $tag . ' class="vh-stack__seg" style="flex:' . $n . ';background:' . esc_attr( self::severity_var( $sev ) ) . '"'
					. $href
					. ' data-vh-tip="' . esc_attr( $tip ) . '"'
					. ' aria-label="' . esc_attr( $tip ) . '"></' . $tag . '>';
			}

			$out .= '</span>';

			// The total value, optionally a link to the rows behind it.
			$value = esc_html( number_format_i18n( $total ) );
			if ( ! empty( $row['value_href'] ) ) {
				$value = '<a href="' . esc_url( (string) $row['value_href'] ) . '">' . $value . '</a>';
			}
			$out .= '<span class="vh-stack__value">' . $value . '</span>';

			// Optional trailing column, e.g. a device count or an owner, itself
			// optionally a link. Callers that set neither get the usual
			// three-column row unchanged.
			if ( isset( $row['extra'] ) && '' !== (string) $row['extra'] ) {
				$extra = esc_html( (string) $row['extra'] );
				if ( ! empty( $row['extra_href'] ) ) {
					$extra = '<a href="' . esc_url( (string) $row['extra_href'] ) . '">' . $extra . '</a>';
				}
				$out .= '<span class="vh-stack__extra">' . $extra . '</span>';
			}

			$out .= '</div>';
		}
		$out .= '</div>';

		return $out . self::severity_legend();
	}

	/* =================================================================
	 * Legends — always present for 2+ series
	 * ============================================================== */

	/**
	 * @param string[]             $names   Series names in fixed order.
	 * @param array<string,string> $colours Colour by name.
	 */
	public static function legend( array $names, array $colours ): string {
		if ( count( $names ) < 2 ) {
			return '';
		}
		$out = '<div class="vh-legend">';
		foreach ( $names as $name ) {
			$out .= '<span class="vh-legend__item"><span class="vh-legend__swatch" style="background:'
				. esc_attr( $colours[ $name ] ?? 'var(--vh-series-1)' ) . '"></span>'
				. esc_html( $name ) . '</span>';
		}
		return $out . '</div>';
	}

	/**
	 * The scale legend the semantic-heat ramp obliges us to always show.
	 */
	public static function severity_legend(): string {
		$out = '<div class="vh-legend vh-legend--scale" role="list" aria-label="' . esc_attr__( 'Severity scale, most severe first', 'vulnhub' ) . '">';
		foreach ( self::severity_order() as $sev ) {
			$out .= '<span class="vh-legend__item" role="listitem">'
				. '<span class="vh-legend__swatch" style="background:' . esc_attr( self::severity_var( $sev ) ) . '"></span>'
				. esc_html( vh_severity_label( $sev ) ) . '</span>';
		}
		return $out . '</div>';
	}

	/* =================================================================
	 * Meter — a single ratio against a limit
	 * ============================================================== */

	public static function meter( float $value, float $total, string $label, string $tone = 'ok' ): string {
		$pct = $total > 0 ? ( $value / $total ) * 100 : 0;

		return '<div class="vh-meterblock">'
			. '<div class="vh-meterblock__head"><span>' . esc_html( $label ) . '</span>'
			. '<strong>' . esc_html( number_format_i18n( round( $pct ) ) . '%' ) . '</strong></div>'
			. '<div class="vh-meterblock__track" role="meter" aria-valuenow="' . esc_attr( (string) round( $pct ) ) . '" aria-valuemin="0" aria-valuemax="100"'
			. ' aria-label="' . esc_attr( $label ) . '">'
			. '<span class="vh-meterblock__fill vh-meterblock__fill--' . esc_attr( $tone ) . '" style="width:' . self::n( $pct ) . '%"></span></div>'
			. '<div class="vh-meterblock__meta">' . esc_html( sprintf( '%s of %s', number_format_i18n( $value ), number_format_i18n( $total ) ) ) . '</div>'
			. '</div>';
	}

	/* =================================================================
	 * Helpers
	 * ============================================================== */

	public static function empty_state( string $message ): string {
		return '<p class="vh-chart-empty">' . esc_html( $message ) . '</p>';
	}

	/**
	 * Round axis ticks to friendly values.
	 *
	 * @return array<int,float>
	 */
	private static function nice_ticks( float $max, int $count = 4 ): array {
		$raw  = $max / $count;
		$mag  = 10 ** floor( log10( max( 1, $raw ) ) );
		$step = ceil( $raw / $mag ) * $mag;

		$ticks = array();
		for ( $i = 0; $i <= $count; $i++ ) {
			$ticks[] = $i * $step;
		}
		return $ticks;
	}

	/**
	 * A donut. Reads as a part-to-whole where the parts are few and named.
	 *
	 * Hue never carries the meaning on its own here either: every slice is in
	 * the legend with its value, the order is fixed, and the table view below
	 * carries the same numbers for anyone the picture does not serve.
	 *
	 * @param array<int,array{label:string,value:float,color?:string}> $rows  Slices.
	 * @param array<string,mixed>                                     $opts  centre, centre_label, size.
	 */
	public static function donut( array $rows, array $opts = array() ): string {
		$rows = array_values(
			array_filter( $rows, static fn( array $r ): bool => (float) $r['value'] > 0 )
		);

		if ( ! $rows ) {
			return self::empty_state( (string) ( $opts['empty'] ?? __( 'Nothing to show yet.', 'vulnhub' ) ) );
		}

		$total = array_sum( array_map( static fn( array $r ): float => (float) $r['value'], $rows ) );
		$size  = (int) ( $opts['size'] ?? 180 );
		$cx    = $size / 2;
		$cy    = $size / 2;
		$r     = $size * 0.40;
		$inner = $size * 0.26;
		$id    = self::uid( 'vhdonut' );

		$svg = '<svg class="vh-chart vh-donut" viewBox="0 0 ' . $size . ' ' . $size . '" role="img"'
			. ' aria-label="' . esc_attr( (string) ( $opts['title'] ?? __( 'Breakdown', 'vulnhub' ) ) ) . '"'
			. ' id="' . esc_attr( $id ) . '">';

		$angle = -M_PI / 2; // Twelve o'clock.

		foreach ( $rows as $i => $row ) {
			$share = (float) $row['value'] / max( 0.0001, $total );
			$sweep = $share * 2 * M_PI;

			// A single slice covering everything cannot be drawn as an arc.
			if ( $share >= 0.9999 ) {
				$svg .= '<circle cx="' . self::n( $cx ) . '" cy="' . self::n( $cy ) . '" r="' . self::n( ( $r + $inner ) / 2 ) . '"'
					. ' fill="none" stroke="' . esc_attr( (string) ( $row['color'] ?? 'var(--vh-series-1)' ) ) . '"'
					. ' stroke-width="' . self::n( $r - $inner ) . '"/>';
				break;
			}

			$end   = $angle + $sweep;
			$large = $sweep > M_PI ? 1 : 0;

			$x1 = $cx + $r * cos( $angle );
			$y1 = $cy + $r * sin( $angle );
			$x2 = $cx + $r * cos( $end );
			$y2 = $cy + $r * sin( $end );
			$x3 = $cx + $inner * cos( $end );
			$y3 = $cy + $inner * sin( $end );
			$x4 = $cx + $inner * cos( $angle );
			$y4 = $cy + $inner * sin( $angle );

			$d = 'M ' . self::n( $x1 ) . ' ' . self::n( $y1 )
				. ' A ' . self::n( $r ) . ' ' . self::n( $r ) . ' 0 ' . $large . ' 1 ' . self::n( $x2 ) . ' ' . self::n( $y2 )
				. ' L ' . self::n( $x3 ) . ' ' . self::n( $y3 )
				. ' A ' . self::n( $inner ) . ' ' . self::n( $inner ) . ' 0 ' . $large . ' 0 ' . self::n( $x4 ) . ' ' . self::n( $y4 )
				. ' Z';

			$svg .= '<path d="' . esc_attr( $d ) . '"'
				. ' fill="' . esc_attr( (string) ( $row['color'] ?? 'var(--vh-series-1)' ) ) . '"'
				. ' stroke="var(--vh-surface)" stroke-width="2">'
				. '<title>' . esc_html( (string) $row['label'] . ' — ' . number_format_i18n( (float) $row['value'] ) ) . '</title>'
				. '</path>';

			$angle = $end;
			unset( $i );
		}

		if ( isset( $opts['centre'] ) ) {
			$svg .= '<text class="vh-donut__centre" x="' . self::n( $cx ) . '" y="' . self::n( $cy - 1 ) . '" text-anchor="middle">'
				. esc_html( (string) $opts['centre'] ) . '</text>';
			if ( ! empty( $opts['centre_label'] ) ) {
				$svg .= '<text class="vh-donut__centre-label" x="' . self::n( $cx ) . '" y="' . self::n( $cy + 15 ) . '" text-anchor="middle">'
					. esc_html( (string) $opts['centre_label'] ) . '</text>';
			}
		}

		$svg .= '</svg>';

		$legend = '<ul class="vh-legend vh-legend--stack">';
		foreach ( $rows as $row ) {
			$share   = 100 * (float) $row['value'] / max( 0.0001, $total );
			$legend .= '<li><span class="vh-legend__dot" style="background:' . esc_attr( (string) ( $row['color'] ?? 'var(--vh-series-1)' ) ) . '"></span>'
				. '<span class="vh-legend__label">' . esc_html( (string) $row['label'] ) . '</span>'
				. '<span class="vh-legend__value">' . esc_html( number_format_i18n( (float) $row['value'] ) ) . '</span>'
				. '<span class="vh-legend__share">' . esc_html( number_format_i18n( round( $share, 1 ) ) ) . '%</span></li>';
		}
		$legend .= '</ul>';

		$table = self::table_view(
			array( __( 'Segment', 'vulnhub' ), __( 'Count', 'vulnhub' ), __( 'Share', 'vulnhub' ) ),
			array_map(
				static function ( array $row ) use ( $total ): array {
					return array(
						(string) $row['label'],
						number_format_i18n( (float) $row['value'] ),
						number_format_i18n( round( 100 * (float) $row['value'] / max( 0.0001, $total ), 1 ) ) . '%',
					);
				},
				$rows
			),
			(string) ( $opts['caption'] ?? '' )
		);

		return '<div class="vh-donut-wrap">' . $svg . $legend . '</div>' . $table;
	}

	/**
	 * A funnel: successive stages of a pipeline, each narrower than the last.
	 *
	 * @param array<int,array{label:string,value:float,note?:string}> $stages Ordered widest first.
	 */
	public static function funnel( array $stages, array $opts = array() ): string {
		$stages = array_values( $stages );

		if ( ! $stages ) {
			return self::empty_state( (string) ( $opts['empty'] ?? __( 'Nothing to show yet.', 'vulnhub' ) ) );
		}

		$top = max( 1.0, (float) $stages[0]['value'] );
		$out = '<ol class="vh-funnel">';

		foreach ( $stages as $i => $stage ) {
			$value = (float) $stage['value'];
			$share = 100 * $value / $top;
			$width = max( 8.0, $share );

			$out .= '<li class="vh-funnel__step">'
				. '<div class="vh-funnel__head">'
				. '<span class="vh-funnel__label">' . esc_html( (string) $stage['label'] ) . '</span>'
				. '<span class="vh-funnel__value">' . esc_html( number_format_i18n( $value ) ) . '</span>'
				. '</div>'
				. '<div class="vh-funnel__track"><div class="vh-funnel__fill" style="width:' . esc_attr( (string) round( $width, 2 ) ) . '%;'
				. 'opacity:' . esc_attr( (string) round( 1 - ( $i * 0.13 ), 2 ) ) . '"></div></div>'
				. '<p class="vh-funnel__note">' . esc_html( (string) ( $stage['note'] ?? '' ) ) . '</p>'
				. '</li>';
		}

		$out .= '</ol>';

		return $out . self::table_view(
			array( __( 'Stage', 'vulnhub' ), __( 'Count', 'vulnhub' ), __( 'Of first stage', 'vulnhub' ) ),
			array_map(
				static function ( array $stage ) use ( $top ): array {
					return array(
						(string) $stage['label'],
						number_format_i18n( (float) $stage['value'] ),
						number_format_i18n( round( 100 * (float) $stage['value'] / $top, 1 ) ) . '%',
					);
				},
				$stages
			),
			(string) ( $opts['caption'] ?? '' )
		);
	}

	/**
	 * Rows of "label — proportion covered", worst first.
	 *
	 * @param array<int,array{label:string,percent:float,covered:int,total:int,gaps:int}> $rows Rows.
	 */
	/**
	 * A coverage percentage that never rounds away the assets still outstanding.
	 *
	 * 607 of 609 is 99.67%, and number_format_i18n() with no decimals prints
	 * that as "100%" -- directly beside the words "2 gaps". A headline that
	 * says finished while the number next to it says otherwise is exactly the
	 * figure people quote in a status meeting, so it never reaches 100 while
	 * anything is still open, and never reads 0 while anything is done.
	 */
	private static function pct_label( float $pct, int $gaps ): string {
		if ( $gaps > 0 && $pct >= 99.5 ) {
			return number_format_i18n( 99.9, 1 ) . '%';
		}
		if ( $pct > 0 && $pct < 0.5 ) {
			return number_format_i18n( 0.1, 1 ) . '%';
		}
		return number_format_i18n( round( $pct, 1 ) ) . '%';
	}

	/**
	 * Append the out-of-scope count to a coverage chart's caption.
	 *
	 * These assets are excluded from every figure in the chart, which is
	 * correct -- nothing can scan a decommissioned machine -- but an
	 * exclusion nobody states is indistinguishable from data going missing.
	 *
	 * @param array<int,array<string,mixed>> $rows    Chart rows.
	 * @param string                         $caption Caption so far.
	 */
	private static function scope_caption( array $rows, string $caption, ?int $excluded = null, string $note_singular = '', string $note_plural = '' ): string {
		/*
		 * Summing the rows is only right when each asset appears in one row.
		 * The by-source chart counts a machine once per system that knows it,
		 * so its out-of-scope column sums to 344 against an estate holding
		 * 269 -- a number nobody could reconcile against the assets page.
		 * Callers whose rows overlap pass the distinct figure instead.
		 */
		if ( null !== $excluded ) {
			$oos = max( 0, $excluded );
		} else {
			$oos = 0;

			foreach ( $rows as $row ) {
				$oos += (int) ( $row['oos'] ?? 0 );
			}
		}

		if ( $oos < 1 ) {
			return $caption;
		}

		/*
		 * The wording is the caller's, because the reason an asset is held
		 * back is not the same on every chart. Scanning coverage excludes
		 * retired and quarantined kit; endpoint coverage excludes that plus
		 * every printer and switch Defender cannot onboard, and telling a
		 * reader that 517 devices are "retired, spare or quarantined" when
		 * 248 of them are live printers is worse than saying nothing.
		 */
		if ( '' === $note_singular ) {
			$note_singular = __( 'In-scope assets only; %s retired, spare or quarantined asset is excluded.', 'vulnhub' );
			$note_plural   = __( 'In-scope assets only; %s retired, spare or quarantined assets are excluded.', 'vulnhub' );
		}

		$note = sprintf(
			/* translators: %s: number of assets. */
			_n( $note_singular, $note_plural, $oos, 'vulnhub' ), // phpcs:ignore WordPress.WP.I18n
			number_format_i18n( $oos )
		);

		return '' === $caption ? $note : $caption . ' ' . $note;
	}

	public static function coverage_bars( array $rows, array $opts = array() ): string {
		if ( ! $rows ) {
			return self::empty_state( (string) ( $opts['empty'] ?? __( 'Nothing to show yet.', 'vulnhub' ) ) );
		}

		$linked = false;

		foreach ( $rows as $row ) {
			if ( '' !== (string) ( $row['href'] ?? '' ) ) {
				$linked = true;
				break;
			}
		}

		// A modifier rather than `:has()`, so the layout does not depend on
		// selector support to stop looking broken.
		$out = '<ul class="vh-cov' . ( $linked ? ' vh-cov--linked' : '' ) . '">';

		/*
		 * The whole row is the hit target, not just the number on the end.
		 * A reader who has just understood that mobile devices are at 0%
		 * points at the bar, because the bar is the thing that told them.
		 */
		foreach ( $rows as $row ) {
			$pct  = (float) $row['percent'];
			$tone = $pct >= 95 ? 'good' : ( $pct >= 80 ? 'warn' : 'bad' );
			$href = (string) ( $row['href'] ?? '' );
			$gaps = (int) $row['gaps'];
			$unsc = (int) ( $row['unscanned'] ?? 0 );

			$inner = '<span class="vh-cov__label">' . esc_html( (string) $row['label'] ) . '</span>'
				. '<span class="vh-cov__track"><span class="vh-cov__fill vh-cov__fill--' . esc_attr( $tone ) . '"'
				. ' style="width:' . esc_attr( (string) round( max( 0.0, min( 100.0, $pct ) ), 2 ) ) . '%"></span></span>'
				. '<span class="vh-cov__pct">' . esc_html( self::pct_label( $pct, $gaps ) ) . '</span>'
				. '<span class="vh-cov__gap">' . esc_html(
					sprintf(
						/* translators: %s: number of assets. */
						_n( '%s gap', '%s gaps', $gaps, 'vulnhub' ),
						number_format_i18n( $gaps )
					)
				) . '</span>';

			/*
			 * Tenable holding an asset it has never scanned is not a
			 * coverage gap -- the machine is onboarded -- but it is not
			 * nothing either, and folding it silently into "covered"
			 * would lose the only signal that a scan is owed.
			 */
			if ( $unsc > 0 ) {
				$inner .= '<span class="vh-cov__flag">' . esc_html(
					sprintf(
						/* translators: %s: number of assets. */
						__( '%s unscanned', 'vulnhub' ),
						number_format_i18n( $unsc )
					)
				) . '</span>';
			}

			if ( '' !== $href ) {
				$inner = '<a class="vh-cov__link" href="' . esc_url( $href ) . '" title="'
					. esc_attr(
						sprintf(
							/* translators: 1: number of assets, 2: the group, e.g. "workstation". */
							_n( 'Show the %1$s %2$s asset with a coverage gap', 'Show the %1$s %2$s assets with a coverage gap', $gaps, 'vulnhub' ),
							number_format_i18n( $gaps ),
							(string) $row['label']
						)
					) . '">' . $inner . '</a>';
			} else {
				// Unlinked rows carry the same grid wrapper so the row lays out
				// identically -- the bar track fills the card either way.
				$inner = '<span class="vh-cov__link vh-cov__link--static">' . $inner . '</span>';
			}

			$out .= '<li class="vh-cov__row">' . $inner . '</li>';
		}

		$out .= '</ul>';

		/*
		 * Covered + Gaps = Total, because Total is the in-scope population.
		 * Out-of-scope assets are not a third column -- they are not part of
		 * the question a coverage chart asks. Their count goes in the caption
		 * instead, so the exclusion is stated without being counted.
		 */
		return $out . self::table_view(
			array(
				__( 'Group', 'vulnhub' ),
				__( 'Covered', 'vulnhub' ),
				__( 'Gaps', 'vulnhub' ),
				__( 'Total', 'vulnhub' ),
				__( 'Coverage', 'vulnhub' ),
				__( 'Not scanned', 'vulnhub' ),
			),
			array_map(
				static fn( array $row ): array => array(
					(string) $row['label'],
					number_format_i18n( (int) $row['covered'] ),
					number_format_i18n( (int) $row['gaps'] ),
					number_format_i18n( (int) $row['total'] ),
					self::pct_label( (float) $row['percent'], (int) $row['gaps'] ),
					number_format_i18n( (int) ( $row['unscanned'] ?? 0 ) ),
				),
				$rows
			),
			self::scope_caption(
				$rows,
				(string) ( $opts['caption'] ?? '' ),
				isset( $opts['excluded'] ) ? (int) $opts['excluded'] : null,
				(string) ( $opts['excluded_note_1'] ?? '' ),
				(string) ( $opts['excluded_note_n'] ?? '' )
			)
		);
	}

	/* =================================================================
	 * Segmented bar — one row per category, split into named parts
	 * ============================================================== */

	/**
	 * A bar per row, divided into segments that are each their own answer.
	 *
	 * This exists because the two questions it draws are the same shape and
	 * were previously two half-answers: "how many criticals" is a bar, and
	 * "how many of them can actually be patched" is the split inside it.
	 * Drawing them apart makes the reader do the subtraction; drawing them
	 * together makes the important part -- the unpatchable slice -- the
	 * thing the eye lands on.
	 *
	 * Every bar is scaled against the largest row's total rather than its
	 * own, because the alternative is four full-width bars and a chart that
	 * says nothing about proportion. Segments carry their own href, so the
	 * unpatchable slice of "critical" is one click from the list of exactly
	 * those findings.
	 *
	 * @param array<int,array{
	 *   label:string, sub?:string, href?:string,
	 *   segments:array<int,array{label:string,value:int,colour?:string,tone?:string,href?:string,title?:string}>
	 * }>                    $rows Rows.
	 * @param array<string,mixed> $opts empty, legend, caption, unit, scale.
	 */
	public static function segment_bars( array $rows, array $opts = array() ): string {
		$rows = array_values(
			array_filter(
				$rows,
				static fn( array $r ): bool => ! empty( $r['segments'] )
			)
		);

		if ( ! $rows ) {
			return self::empty_state( (string) ( $opts['empty'] ?? __( 'Nothing to show yet.', 'vulnhub' ) ) );
		}

		$totals = array();

		foreach ( $rows as $row ) {
			$totals[] = array_sum(
				array_map(
					static fn( array $seg ): int => max( 0, (int) $seg['value'] ),
					$row['segments']
				)
			);
		}

		$max  = max( 1, max( $totals ) );
		$unit = (string) ( $opts['unit'] ?? '' );

		/*
		 * Two scales, and picking the wrong one throws the chart away.
		 *
		 * `shared` compares rows against each other and is right when
		 * magnitude is the point. `row` gives every row the full width and
		 * is right when the SPLIT is the point -- which it is for patch
		 * availability, where low severity outnumbers critical fifty to
		 * one and a shared scale renders the critical bar as a 2% sliver
		 * with its split invisible. The absolute figure is still on the
		 * right of every row, so nothing is hidden by the choice.
		 */
		$per_row = 'row' === (string) ( $opts['scale'] ?? 'shared' );

		$out = '<div class="vh-segbars">';

		foreach ( $rows as $i => $row ) {
			$total = (int) $totals[ $i ];
			$label = esc_html( (string) $row['label'] );

			if ( ! empty( $row['href'] ) ) {
				$label = '<a href="' . esc_url( (string) $row['href'] ) . '">' . $label . '</a>';
			}

			$sub = (string) ( $row['sub'] ?? '' );

			/*
			 * An optional mark before the label: a vendor logo, a flag, a
			 * status dot. Markup, because an <img> or an <svg> is the point --
			 * so a caller passing it is responsible for escaping it, exactly
			 * as with `segments`. It sits inside the label span so it wraps
			 * with the text rather than floating beside a two-line name.
			 */
			$icon = (string) ( $row['icon'] ?? '' );

			/*
			 * The label is a column (name over sub-line), so a mark dropped
			 * straight into it becomes its own row above the name. Icon and
			 * name share a line of their own, and the sub-line stays beneath
			 * both.
			 */
			$title = '' !== $icon
				? '<span class="vh-segbars__title">' . $icon . $label . '</span>'
				: $label;

			$out .= '<div class="vh-segbars__row">';
			$out .= '<span class="vh-segbars__label">' . $title
				. ( '' !== $sub ? '<span class="vh-segbars__sub">' . esc_html( $sub ) . '</span>' : '' )
				. '</span>';

			// The track is only as wide as this row's share of the largest,
			// so the bars compare; the segments then divide that width.
			$width = $per_row ? 100.0 : ( $total / $max ) * 100;

			$out .= '<span class="vh-segbars__track" style="width:' . self::n( $width ) . '%">';

			foreach ( $row['segments'] as $seg ) {
				$n = max( 0, (int) $seg['value'] );

				if ( $n <= 0 ) {
					continue;
				}

				$colour = (string) ( $seg['colour'] ?? '' );

				if ( '' === $colour ) {
					$tone   = (string) ( $seg['tone'] ?? 'info' );
					$colour = in_array( $tone, array( 'critical', 'high', 'medium', 'low', 'info' ), true )
						? 'var(--vh-sev-' . $tone . ')'
						: 'var(--vh-' . preg_replace( '/[^a-z0-9-]/', '', $tone ) . ')';
				}

				$title = (string) ( $seg['title'] ?? '' );

				if ( '' === $title ) {
					$title = sprintf(
						/* translators: 1: segment name, 2: count, 3: unit such as "findings". */
						_x( '%1$s: %2$s %3$s', 'chart segment tooltip', 'vulnhub' ),
						(string) $seg['label'],
						number_format_i18n( $n ),
						$unit
					);
					$title = trim( $title );
				}

				$href = (string) ( $seg['href'] ?? '' );
				$tag  = '' !== $href ? 'a' : 'span';

				$out .= '<' . $tag . ' class="vh-segbars__seg"'
					. ( '' !== $href ? ' href="' . esc_url( $href ) . '"' : '' )
					. ' style="flex:' . $n . ';background:' . esc_attr( $colour ) . '"'
					. ' data-vh-tip="' . esc_attr( $title ) . '"'
					. ' aria-label="' . esc_attr( $title ) . '">'
					. '<span class="vh-segbars__seg-n">' . esc_html( number_format_i18n( $n ) ) . '</span>'
					. '</' . $tag . '>';
			}

			$out .= '</span>';

			/*
			 * The total is the whole row, so it links to the whole row.
			 *
			 * A split bar makes each half clickable, and the number beside it
			 * then looks like the one part of the row that does nothing --
			 * which is exactly the part somebody reaches for when they want
			 * both halves at once. `total_href` makes it a link; without one
			 * it stays the plain number it has always been.
			 */
			$total_href  = (string) ( $row['total_href'] ?? '' );
			$total_title = (string) ( $row['total_title'] ?? '' );
			$total_text  = esc_html( number_format_i18n( $total ) );

			if ( '' !== $total_href ) {
				if ( '' === $total_title ) {
					$total_title = sprintf(
						/* translators: 1: count, 2: the row's name, 3: unit such as "assets". */
						_x( 'All %1$s %3$s on %2$s', 'chart row total link', 'vulnhub' ),
						number_format_i18n( $total ),
						wp_strip_all_tags( (string) $row['label'] ),
						$unit
					);
					$total_title = trim( preg_replace( '/\s+/', ' ', $total_title ) ?? $total_title );
				}

				$out .= '<a class="vh-segbars__total vh-segbars__total--link" href="' . esc_url( $total_href ) . '"'
					. ' data-vh-tip="' . esc_attr( $total_title ) . '"'
					. ' aria-label="' . esc_attr( $total_title ) . '">' . $total_text . '</a>';
			} else {
				$out .= '<span class="vh-segbars__total">' . $total_text . '</span>';
			}

			$out .= '</div>';
		}

		$out .= '</div>';

		$legend = (array) ( $opts['legend'] ?? array() );

		if ( $legend ) {
			$out .= '<ul class="vh-legend">';

			foreach ( $legend as $item ) {
				$out .= '<li class="vh-legend__item">'
					. '<span class="vh-legend__swatch" style="background:' . esc_attr( (string) $item['colour'] ) . '"></span>'
					. esc_html( (string) $item['label'] )
					. '</li>';
			}

			$out .= '</ul>';
		}

		return $out;
	}

	/**
	 * The table view that every chart owes its reader — this is also the
	 * relief for the sub-3:1 amber step in light mode.
	 *
	 * @param string[]                    $headers Column headers.
	 * @param array<int,array<int,string>> $rows    Body rows (pre-escaped text).
	 */
	public static function table_view( array $headers, array $rows, string $caption = '' ): string {
		if ( ! $rows ) {
			return '';
		}

		$id  = self::uid( 'vhtable' );
		$out  = '<details class="vh-tableview"><summary>' . esc_html__( 'View as table', 'vulnhub' ) . '</summary>';
		// Its own scroller: a five-column table of team names does not fit a
		// 390px phone, and without this it was clipped by the panel instead.
		$out .= '<div class="vh-tableview__scroll">';
		$out .= '<table id="' . esc_attr( $id ) . '">';
		if ( $caption ) {
			$out .= '<caption>' . esc_html( $caption ) . '</caption>';
		}
		$out .= '<thead><tr>';
		foreach ( $headers as $header ) {
			$out .= '<th scope="col">' . esc_html( $header ) . '</th>';
		}
		$out .= '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			$out .= '<tr>';
			foreach ( $row as $cell ) {
				$out .= '<td>' . esc_html( (string) $cell ) . '</td>';
			}
			$out .= '</tr>';
		}
		$out .= '</tbody></table></div></details>';

		return $out;
	}
}

