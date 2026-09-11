<?php
/**
 * Minimal QR Code encoder (ISO/IEC 18004), byte mode only.
 *
 * WHY THIS EXISTS: the obvious way to render an enrolment QR code is to hand
 * the otpauth:// URI to a public chart API. That would transmit the user's
 * TOTP shared secret — the entire second factor — to a third party in a URL
 * that lands in their access logs. So the code is drawn here, in-process, and
 * emitted as inline SVG. Nothing leaves the server.
 *
 * Scope: byte-mode segments, error-correction level M, versions 1-14. That is
 * far more than an otpauth URI needs (~120-160 bytes) while keeping the tables
 * small. Structure follows the standard reference formulation of ISO/IEC 18004
 * (finder/timing/alignment placement, BCH-coded format and version information,
 * Reed-Solomon over GF(2^8) with primitive polynomial 0x11D, block
 * interleaving, the eight data masks and the four penalty rules).
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Encodes a byte string as a QR symbol and renders it as SVG.
 */
final class VulnHub_Auth_QR {

	/** Error-correction level M: 15% recovery, the usual choice for OTP codes. */
	private const ECC_LEVEL = 'M';

	/** Format-information bit pattern per EC level (ISO/IEC 18004 Table 12). */
	private const ECC_FORMAT_BITS = array(
		'L' => 1,
		'M' => 0,
		'Q' => 3,
		'H' => 2,
	);

	/** Highest version this encoder will produce. */
	private const MAX_VERSION = 14;

	/**
	 * Error-correction codewords per block, indexed [level][version].
	 *
	 * @var array<string,array<int,int>>
	 */
	private const ECC_CODEWORDS_PER_BLOCK = array(
		'L' => array( 0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30 ),
		'M' => array( 0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24 ),
		'Q' => array( 0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20 ),
		'H' => array( 0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24 ),
	);

	/**
	 * Number of error-correction blocks, indexed [level][version].
	 *
	 * @var array<string,array<int,int>>
	 */
	private const ECC_BLOCKS = array(
		'L' => array( 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4 ),
		'M' => array( 0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9 ),
		'Q' => array( 0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16 ),
		'H' => array( 0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16 ),
	);

	/** Penalty weights, ISO/IEC 18004 §8.8.2. */
	private const PENALTY_N1 = 3;
	private const PENALTY_N2 = 3;
	private const PENALTY_N3 = 40;
	private const PENALTY_N4 = 10;

	/** Symbol version actually used. */
	private int $version = 1;

	/** Symbol width/height in modules. */
	private int $size = 21;

	/** @var array<int,array<int,bool>> Module colours, [y][x], true = dark. */
	private array $modules = array();

	/** @var array<int,array<int,bool>> Function-pattern mask, [y][x]. */
	private array $is_function = array();

	/** @var array<int,int>|null GF(2^8) exponent table. */
	private static ?array $gf_exp = null;

	/** @var array<int,int>|null GF(2^8) logarithm table. */
	private static ?array $gf_log = null;

	/**
	 * Build a symbol for the given payload.
	 *
	 * @param string $text Payload (treated as raw bytes / UTF-8).
	 * @throws \RuntimeException When the payload is too long for MAX_VERSION.
	 */
	public function __construct( string $text ) {
		$data = $this->encode_byte_segment( $text );
		$this->build( $data );
	}

	/* -----------------------------------------------------------------
	 * Public API
	 * --------------------------------------------------------------- */

	/**
	 * Render the symbol as a standalone SVG element.
	 *
	 * The SVG is a single <path> of black squares on a white background with
	 * the mandatory 4-module quiet zone, so it scales cleanly and contains no
	 * script, no external reference and nothing to escape at the call site
	 * beyond the attributes built here.
	 *
	 * @param int    $scale  Pixels per module.
	 * @param int    $border Quiet-zone width in modules (4 is the minimum).
	 * @param string $alt    Accessible label.
	 * @return string SVG markup.
	 */
	public function to_svg( int $scale = 5, int $border = 4, string $alt = '' ): string {
		$scale  = max( 1, min( 20, $scale ) );
		$border = max( 4, min( 8, $border ) );
		$dim    = ( $this->size + $border * 2 ) * $scale;

		$path = '';
		for ( $y = 0; $y < $this->size; $y++ ) {
			for ( $x = 0; $x < $this->size; $x++ ) {
				if ( $this->modules[ $y ][ $x ] ) {
					$path .= sprintf(
						'M%d %dh%dv%dh-%dz',
						( $x + $border ) * $scale,
						( $y + $border ) * $scale,
						$scale,
						$scale,
						$scale
					);
				}
			}
		}

		return sprintf(
			'<svg xmlns="http://www.w3.org/2000/svg" width="%1$d" height="%1$d" viewBox="0 0 %1$d %1$d" role="img" aria-label="%2$s">'
				. '<rect width="%1$d" height="%1$d" fill="#ffffff"/>'
				. '<path d="%3$s" fill="#000000"/>'
				. '</svg>',
			$dim,
			esc_attr( $alt ),
			esc_attr( $path )
		);
	}

	/**
	 * The chosen symbol version (1-14).
	 */
	public function version(): int {
		return $this->version;
	}

	/**
	 * The module matrix, [y][x], true = dark. Exposed for verification.
	 *
	 * @return array<int,array<int,bool>>
	 */
	public function matrix(): array {
		return $this->modules;
	}

	/* -----------------------------------------------------------------
	 * Data encoding
	 * --------------------------------------------------------------- */

	/**
	 * Encode the payload as a single byte-mode segment and pad it to the data
	 * capacity of the smallest version that fits.
	 *
	 * @param string $text Payload.
	 * @return array<int,int> Data codewords.
	 * @throws \RuntimeException When the payload does not fit.
	 */
	private function encode_byte_segment( string $text ): array {
		$length = strlen( $text );

		// Pick the smallest version whose data capacity holds mode indicator
		// (4 bits) + character count + 8 bits per byte.
		$version = 0;
		for ( $v = 1; $v <= self::MAX_VERSION; $v++ ) {
			$count_bits = $v < 10 ? 8 : 16;
			$needed     = 4 + $count_bits + $length * 8;
			if ( $needed <= self::data_codewords( $v ) * 8 ) {
				$version = $v;
				break;
			}
		}
		if ( 0 === $version ) {
			throw new \RuntimeException( 'QR payload too long for this encoder.' );
		}

		$this->version = $version;
		$this->size    = $version * 4 + 17;

		$count_bits = $version < 10 ? 8 : 16;
		$capacity   = self::data_codewords( $version ) * 8;

		$bits = '';
		$bits .= '0100';                                                        // Byte mode indicator.
		$bits .= str_pad( decbin( $length ), $count_bits, '0', STR_PAD_LEFT );  // Character count.
		for ( $i = 0; $i < $length; $i++ ) {
			$bits .= str_pad( decbin( ord( $text[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}

		// Terminator: up to four zero bits, but no more than the space left.
		$bits .= str_repeat( '0', min( 4, $capacity - strlen( $bits ) ) );
		// Pad to a byte boundary.
		$bits .= str_repeat( '0', ( 8 - strlen( $bits ) % 8 ) % 8 );

		$codewords = array();
		foreach ( str_split( $bits, 8 ) as $byte ) {
			$codewords[] = (int) bindec( $byte );
		}

		// Fill the remainder with the alternating pad codewords 0xEC, 0x11.
		$pad = array( 0xEC, 0x11 );
		for ( $i = 0; count( $codewords ) < self::data_codewords( $version ); $i++ ) {
			$codewords[] = $pad[ $i % 2 ];
		}

		return $codewords;
	}

	/**
	 * Total number of data modules in a version, before function patterns.
	 *
	 * @param int $version Symbol version.
	 * @return int Module count.
	 */
	private static function raw_data_modules( int $version ): int {
		$result = ( 16 * $version + 128 ) * $version + 64;
		if ( $version >= 2 ) {
			$align   = intdiv( $version, 7 ) + 2;
			$result -= ( 25 * $align - 10 ) * $align - 55;
			if ( $version >= 7 ) {
				$result -= 36;
			}
		}
		return $result;
	}

	/**
	 * Data codewords available at this version and EC level.
	 *
	 * @param int $version Symbol version.
	 * @return int Codeword count.
	 */
	private static function data_codewords( int $version ): int {
		$total  = intdiv( self::raw_data_modules( $version ), 8 );
		$blocks = self::ECC_BLOCKS[ self::ECC_LEVEL ][ $version ];
		$ecc    = self::ECC_CODEWORDS_PER_BLOCK[ self::ECC_LEVEL ][ $version ];
		return $total - $ecc * $blocks;
	}

	/* -----------------------------------------------------------------
	 * Reed-Solomon over GF(2^8), primitive polynomial x^8+x^4+x^3+x^2+1
	 * --------------------------------------------------------------- */

	/**
	 * Populate the GF(2^8) log/antilog tables once.
	 */
	private static function init_gf(): void {
		if ( null !== self::$gf_exp ) {
			return;
		}
		$exp = array_fill( 0, 512, 0 );
		$log = array_fill( 0, 256, 0 );
		$x   = 1;
		for ( $i = 0; $i < 255; $i++ ) {
			$exp[ $i ] = $x;
			$log[ $x ] = $i;
			$x        <<= 1;
			if ( $x & 0x100 ) {
				$x ^= 0x11D;
			}
		}
		for ( $i = 255; $i < 512; $i++ ) {
			$exp[ $i ] = $exp[ $i - 255 ];
		}
		self::$gf_exp = $exp;
		self::$gf_log = $log;
	}

	/**
	 * Multiply two field elements.
	 *
	 * @param int $a Left operand.
	 * @param int $b Right operand.
	 * @return int Product.
	 */
	private static function gf_mul( int $a, int $b ): int {
		if ( 0 === $a || 0 === $b ) {
			return 0;
		}
		self::init_gf();
		return self::$gf_exp[ self::$gf_log[ $a ] + self::$gf_log[ $b ] ];
	}

	/**
	 * Generator polynomial coefficients for a given ECC degree.
	 *
	 * @param int $degree Number of EC codewords.
	 * @return array<int,int> Coefficients, highest term omitted (monic).
	 */
	private static function rs_divisor( int $degree ): array {
		$result             = array_fill( 0, $degree, 0 );
		$result[ $degree - 1 ] = 1;

		$root = 1;
		for ( $i = 0; $i < $degree; $i++ ) {
			for ( $j = 0; $j < $degree; $j++ ) {
				$result[ $j ] = self::gf_mul( $result[ $j ], $root );
				if ( $j + 1 < $degree ) {
					$result[ $j ] ^= $result[ $j + 1 ];
				}
			}
			$root = self::gf_mul( $root, 0x02 );
		}

		return $result;
	}

	/**
	 * Compute the Reed-Solomon remainder (the EC codewords) for a block.
	 *
	 * @param array<int,int> $data    Data codewords.
	 * @param array<int,int> $divisor Generator polynomial.
	 * @return array<int,int> EC codewords.
	 */
	private static function rs_remainder( array $data, array $divisor ): array {
		$degree = count( $divisor );
		$result = array_fill( 0, $degree, 0 );

		foreach ( $data as $byte ) {
			$factor = $byte ^ (int) array_shift( $result );
			$result[] = 0;
			foreach ( $divisor as $i => $coefficient ) {
				$result[ $i ] ^= self::gf_mul( $coefficient, $factor );
			}
		}

		return $result;
	}

	/**
	 * Split the data into blocks, append EC codewords and interleave.
	 *
	 * @param array<int,int> $data Data codewords.
	 * @return array<int,int> Final codeword sequence.
	 */
	private function add_ecc_and_interleave( array $data ): array {
		$version   = $this->version;
		$blocks    = self::ECC_BLOCKS[ self::ECC_LEVEL ][ $version ];
		$ecc_len   = self::ECC_CODEWORDS_PER_BLOCK[ self::ECC_LEVEL ][ $version ];
		$raw       = intdiv( self::raw_data_modules( $version ), 8 );
		$short_n   = $blocks - $raw % $blocks;
		$short_len = intdiv( $raw, $blocks );

		$divisor = self::rs_divisor( $ecc_len );
		$built   = array();
		$offset  = 0;

		for ( $i = 0; $i < $blocks; $i++ ) {
			$take  = $short_len - $ecc_len + ( $i < $short_n ? 0 : 1 );
			$chunk = array_slice( $data, $offset, $take );
			$offset += $take;

			$ecc = self::rs_remainder( $chunk, $divisor );
			if ( $i < $short_n ) {
				// Pad short blocks with a placeholder so every block has the
				// same length; the placeholder is skipped when interleaving.
				$chunk[] = 0;
			}
			$built[] = array_merge( $chunk, $ecc );
		}

		$result = array();
		$rows   = count( $built[0] );
		for ( $i = 0; $i < $rows; $i++ ) {
			foreach ( $built as $j => $block ) {
				if ( $i !== $short_len - $ecc_len || $j >= $short_n ) {
					$result[] = $block[ $i ];
				}
			}
		}

		return $result;
	}

	/* -----------------------------------------------------------------
	 * Matrix construction
	 * --------------------------------------------------------------- */

	/**
	 * Draw the whole symbol: function patterns, data, then the best mask.
	 *
	 * @param array<int,int> $data Data codewords.
	 */
	private function build( array $data ): void {
		$this->modules     = array_fill( 0, $this->size, array_fill( 0, $this->size, false ) );
		$this->is_function = array_fill( 0, $this->size, array_fill( 0, $this->size, false ) );

		$this->draw_function_patterns();
		$this->draw_codewords( $this->add_ecc_and_interleave( $data ) );

		// Try all eight masks and keep the one with the lowest penalty, as
		// ISO/IEC 18004 §8.8.2 requires.
		$best       = 0;
		$best_score = PHP_INT_MAX;
		for ( $mask = 0; $mask < 8; $mask++ ) {
			$this->apply_mask( $mask );
			$this->draw_format_bits( $mask );
			$score = $this->penalty_score();
			if ( $score < $best_score ) {
				$best_score = $score;
				$best       = $mask;
			}
			$this->apply_mask( $mask ); // XOR is its own inverse: undo.
		}

		$this->apply_mask( $best );
		$this->draw_format_bits( $best );
	}

	/**
	 * Set a module that belongs to a function pattern.
	 *
	 * @param int  $x    Column.
	 * @param int  $y    Row.
	 * @param bool $dark Colour.
	 */
	private function set_function_module( int $x, int $y, bool $dark ): void {
		$this->modules[ $y ][ $x ]     = $dark;
		$this->is_function[ $y ][ $x ] = true;
	}

	/**
	 * Draw finders, separators, timing patterns, alignment patterns, the dark
	 * module and the reserved format/version areas.
	 */
	private function draw_function_patterns(): void {
		$size = $this->size;

		// Timing patterns: alternating modules along row 6 and column 6.
		for ( $i = 0; $i < $size; $i++ ) {
			$this->set_function_module( 6, $i, 0 === $i % 2 );
			$this->set_function_module( $i, 6, 0 === $i % 2 );
		}

		// Three finder patterns with their separators.
		$this->draw_finder( 3, 3 );
		$this->draw_finder( $size - 4, 3 );
		$this->draw_finder( 3, $size - 4 );

		// Alignment patterns, skipping the three that collide with finders.
		$positions = $this->alignment_positions();
		$count     = count( $positions );
		for ( $i = 0; $i < $count; $i++ ) {
			for ( $j = 0; $j < $count; $j++ ) {
				$corner = ( 0 === $i && 0 === $j )
					|| ( 0 === $i && $count - 1 === $j )
					|| ( $count - 1 === $i && 0 === $j );
				if ( ! $corner ) {
					$this->draw_alignment( $positions[ $i ], $positions[ $j ] );
				}
			}
		}

		// Reserve the format and version areas (real values written later).
		$this->draw_format_bits( 0 );
		$this->draw_version_bits();
	}

	/**
	 * Draw one 7x7 finder pattern plus its separator, centred on (x, y).
	 *
	 * @param int $x Centre column.
	 * @param int $y Centre row.
	 */
	private function draw_finder( int $x, int $y ): void {
		for ( $dy = -4; $dy <= 4; $dy++ ) {
			for ( $dx = -4; $dx <= 4; $dx++ ) {
				$xx = $x + $dx;
				$yy = $y + $dy;
				if ( $xx >= 0 && $xx < $this->size && $yy >= 0 && $yy < $this->size ) {
					$ring = max( abs( $dx ), abs( $dy ) );
					$this->set_function_module( $xx, $yy, 2 !== $ring && 4 !== $ring );
				}
			}
		}
	}

	/**
	 * Draw one 5x5 alignment pattern centred on (x, y).
	 *
	 * @param int $x Centre column.
	 * @param int $y Centre row.
	 */
	private function draw_alignment( int $x, int $y ): void {
		for ( $dy = -2; $dy <= 2; $dy++ ) {
			for ( $dx = -2; $dx <= 2; $dx++ ) {
				$this->set_function_module( $x + $dx, $y + $dy, 1 !== max( abs( $dx ), abs( $dy ) ) );
			}
		}
	}

	/**
	 * Alignment-pattern centre coordinates for this version.
	 *
	 * @return array<int,int> Ascending coordinates.
	 */
	private function alignment_positions(): array {
		$version = $this->version;
		if ( 1 === $version ) {
			return array();
		}

		$count = intdiv( $version, 7 ) + 2;
		$step  = intdiv( intdiv( $version * 4 + $count * 2 + 1, $count * 2 - 2 ), 1 ) * 2;

		$result = array();
		for ( $i = 0; $i < $count - 1; $i++ ) {
			$result[] = $this->size - 7 - $i * $step;
		}
		$result[] = 6;

		return array_reverse( $result );
	}

	/**
	 * Write the 15-bit BCH-coded format information (EC level + mask).
	 *
	 * @param int $mask Mask pattern 0-7.
	 */
	private function draw_format_bits( int $mask ): void {
		$data = ( self::ECC_FORMAT_BITS[ self::ECC_LEVEL ] << 3 ) | $mask;

		// BCH(15,5) error correction, generator 0x537.
		$rem = $data;
		for ( $i = 0; $i < 10; $i++ ) {
			$rem = ( $rem << 1 ) ^ ( ( $rem >> 9 ) * 0x537 );
		}
		// XOR with 0x5412 so an all-zero format never occurs.
		$bits = ( ( $data << 10 ) | $rem ) ^ 0x5412;

		$size = $this->size;

		// First copy: around the top-left finder.
		for ( $i = 0; $i <= 5; $i++ ) {
			$this->set_function_module( 8, $i, $this->bit( $bits, $i ) );
		}
		$this->set_function_module( 8, 7, $this->bit( $bits, 6 ) );
		$this->set_function_module( 8, 8, $this->bit( $bits, 7 ) );
		$this->set_function_module( 7, 8, $this->bit( $bits, 8 ) );
		for ( $i = 9; $i < 15; $i++ ) {
			$this->set_function_module( 14 - $i, 8, $this->bit( $bits, $i ) );
		}

		// Second copy: split between the other two finders.
		for ( $i = 0; $i < 8; $i++ ) {
			$this->set_function_module( $size - 1 - $i, 8, $this->bit( $bits, $i ) );
		}
		for ( $i = 8; $i < 15; $i++ ) {
			$this->set_function_module( 8, $size - 15 + $i, $this->bit( $bits, $i ) );
		}

		// The dark module, always set.
		$this->set_function_module( 8, $size - 8, true );
	}

	/**
	 * Write the 18-bit BCH-coded version information (versions 7 and above).
	 */
	private function draw_version_bits(): void {
		if ( $this->version < 7 ) {
			return;
		}

		// BCH(18,6) error correction, generator 0x1F25.
		$rem = $this->version;
		for ( $i = 0; $i < 12; $i++ ) {
			$rem = ( $rem << 1 ) ^ ( ( $rem >> 11 ) * 0x1F25 );
		}
		$bits = ( $this->version << 12 ) | $rem;

		for ( $i = 0; $i < 18; $i++ ) {
			$bit = $this->bit( $bits, $i );
			$a   = $this->size - 11 + $i % 3;
			$b   = intdiv( $i, 3 );
			$this->set_function_module( $a, $b, $bit );
			$this->set_function_module( $b, $a, $bit );
		}
	}

	/**
	 * Lay the codewords into the symbol in the zigzag order of §8.7.3.
	 *
	 * @param array<int,int> $data Interleaved codewords.
	 */
	private function draw_codewords( array $data ): void {
		$i    = 0;
		$bits = count( $data ) * 8;

		for ( $right = $this->size - 1; $right >= 1; $right -= 2 ) {
			// Column 6 is the vertical timing pattern; skip past it.
			if ( 6 === $right ) {
				$right = 5;
			}
			for ( $vert = 0; $vert < $this->size; $vert++ ) {
				for ( $j = 0; $j < 2; $j++ ) {
					$x      = $right - $j;
					$upward = 0 === ( ( $right + 1 ) & 2 );
					$y      = $upward ? $this->size - 1 - $vert : $vert;

					if ( ! $this->is_function[ $y ][ $x ] && $i < $bits ) {
						$this->modules[ $y ][ $x ] = (bool) ( ( $data[ $i >> 3 ] >> ( 7 - ( $i & 7 ) ) ) & 1 );
						++$i;
					}
					// Any remaining modules stay light, which is correct: the
					// specification defines them as remainder bits set to 0.
				}
			}
		}
	}

	/**
	 * XOR the data region with one of the eight mask patterns.
	 *
	 * @param int $mask Mask pattern 0-7.
	 */
	private function apply_mask( int $mask ): void {
		for ( $y = 0; $y < $this->size; $y++ ) {
			for ( $x = 0; $x < $this->size; $x++ ) {
				if ( $this->is_function[ $y ][ $x ] ) {
					continue;
				}
				switch ( $mask ) {
					case 0:
						$invert = 0 === ( $x + $y ) % 2;
						break;
					case 1:
						$invert = 0 === $y % 2;
						break;
					case 2:
						$invert = 0 === $x % 3;
						break;
					case 3:
						$invert = 0 === ( $x + $y ) % 3;
						break;
					case 4:
						$invert = 0 === ( intdiv( $y, 2 ) + intdiv( $x, 3 ) ) % 2;
						break;
					case 5:
						$invert = 0 === ( $x * $y ) % 2 + ( $x * $y ) % 3;
						break;
					case 6:
						$invert = 0 === ( ( $x * $y ) % 2 + ( $x * $y ) % 3 ) % 2;
						break;
					default:
						$invert = 0 === ( ( $x + $y ) % 2 + ( $x * $y ) % 3 ) % 2;
						break;
				}
				if ( $invert ) {
					$this->modules[ $y ][ $x ] = ! $this->modules[ $y ][ $x ];
				}
			}
		}
	}

	/**
	 * Score the current symbol against the four penalty rules.
	 *
	 * @return int Penalty (lower is better).
	 */
	private function penalty_score(): int {
		$result = 0;
		$size   = $this->size;

		// Rule 1 + rule 3, row-wise.
		for ( $y = 0; $y < $size; $y++ ) {
			$run_colour = false;
			$run_length = 0;
			$history    = array( 0, 0, 0, 0, 0, 0, 0 );
			for ( $x = 0; $x < $size; $x++ ) {
				if ( $this->modules[ $y ][ $x ] === $run_colour ) {
					++$run_length;
					if ( 5 === $run_length ) {
						$result += self::PENALTY_N1;
					} elseif ( $run_length > 5 ) {
						++$result;
					}
				} else {
					$this->finder_history_add( $run_length, $history );
					if ( ! $run_colour ) {
						$result += $this->finder_count( $history ) * self::PENALTY_N3;
					}
					$run_colour = $this->modules[ $y ][ $x ];
					$run_length = 1;
				}
			}
			$result += $this->finder_terminate( $run_colour, $run_length, $history ) * self::PENALTY_N3;
		}

		// Rule 1 + rule 3, column-wise.
		for ( $x = 0; $x < $size; $x++ ) {
			$run_colour = false;
			$run_length = 0;
			$history    = array( 0, 0, 0, 0, 0, 0, 0 );
			for ( $y = 0; $y < $size; $y++ ) {
				if ( $this->modules[ $y ][ $x ] === $run_colour ) {
					++$run_length;
					if ( 5 === $run_length ) {
						$result += self::PENALTY_N1;
					} elseif ( $run_length > 5 ) {
						++$result;
					}
				} else {
					$this->finder_history_add( $run_length, $history );
					if ( ! $run_colour ) {
						$result += $this->finder_count( $history ) * self::PENALTY_N3;
					}
					$run_colour = $this->modules[ $y ][ $x ];
					$run_length = 1;
				}
			}
			$result += $this->finder_terminate( $run_colour, $run_length, $history ) * self::PENALTY_N3;
		}

		// Rule 2: 2x2 blocks of one colour.
		for ( $y = 0; $y < $size - 1; $y++ ) {
			for ( $x = 0; $x < $size - 1; $x++ ) {
				$c = $this->modules[ $y ][ $x ];
				if ( $c === $this->modules[ $y ][ $x + 1 ]
					&& $c === $this->modules[ $y + 1 ][ $x ]
					&& $c === $this->modules[ $y + 1 ][ $x + 1 ] ) {
					$result += self::PENALTY_N2;
				}
			}
		}

		// Rule 4: proportion of dark modules away from 50%.
		$dark = 0;
		foreach ( $this->modules as $row ) {
			foreach ( $row as $module ) {
				if ( $module ) {
					++$dark;
				}
			}
		}
		$total   = $size * $size;
		$k       = intdiv( abs( $dark * 20 - $total * 10 ) + $total - 1, $total ) - 1;
		$result += $k * self::PENALTY_N4;

		return $result;
	}

	/**
	 * Push a run length onto the finder-pattern run history.
	 *
	 * @param int              $run_length Length of the finished run.
	 * @param array<int,int>   $history    Run history (most recent first).
	 */
	private function finder_history_add( int $run_length, array &$history ): void {
		if ( 0 === $history[0] ) {
			// The symbol's edge counts as an unbounded light border.
			$run_length += $this->size;
		}
		array_pop( $history );
		array_unshift( $history, $run_length );
	}

	/**
	 * Close the final run and score it.
	 *
	 * @param bool           $run_colour Colour of the final run.
	 * @param int            $run_length Length of the final run.
	 * @param array<int,int> $history    Run history.
	 * @return int Number of finder-like patterns found.
	 */
	private function finder_terminate( bool $run_colour, int $run_length, array &$history ): int {
		if ( $run_colour ) {
			$this->finder_history_add( $run_length, $history );
			$run_length = 0;
		}
		$run_length += $this->size;
		$this->finder_history_add( $run_length, $history );
		return $this->finder_count( $history );
	}

	/**
	 * Count 1:1:3:1:1 finder-like patterns in the run history.
	 *
	 * @param array<int,int> $history Run history.
	 * @return int 0, 1 or 2.
	 */
	private function finder_count( array $history ): int {
		$n    = $history[1];
		$core = $n > 0
			&& $history[2] === $n && $history[4] === $n && $history[5] === $n
			&& $history[3] === $n * 3;

		return ( $core && $history[0] >= $n * 4 && $history[6] >= $n ? 1 : 0 )
			+ ( $core && $history[6] >= $n * 4 && $history[0] >= $n ? 1 : 0 );
	}

	/**
	 * Read bit $i of $value.
	 *
	 * @param int $value Integer.
	 * @param int $i     Bit index from the least significant end.
	 * @return bool
	 */
	private function bit( int $value, int $i ): bool {
		return 0 !== ( ( $value >> $i ) & 1 );
	}

	/* -----------------------------------------------------------------
	 * Convenience
	 * --------------------------------------------------------------- */

	/**
	 * Render a payload as SVG, returning '' if it cannot be encoded.
	 *
	 * @param string $text   Payload.
	 * @param int    $scale  Pixels per module.
	 * @param string $alt    Accessible label.
	 * @return string SVG markup or ''.
	 */
	public static function svg( string $text, int $scale = 5, string $alt = '' ): string {
		try {
			$qr = new self( $text );
			return $qr->to_svg( $scale, 4, $alt );
		} catch ( \Throwable $e ) {
			return '';
		}
	}
}

