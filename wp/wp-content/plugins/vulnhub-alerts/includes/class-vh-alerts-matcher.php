<?php
/**
 * Decide whether an advisory can touch this estate, and say how sure we are.
 *
 * Three tiers, and the honesty of the labels is the point:
 *
 *   exact     we run the product AND the installed version falls inside the
 *             advisory's affected range. Actionable on its own.
 *   probable  we run the product, but the range was absent or unparseable.
 *             Somebody has to go and look.
 *   possible  only the vendor or the OS family lines up. Context, not a task.
 *
 * Everything is stored, including advisories that match nothing, because
 * "we assessed this and it does not affect us" is an answer worth keeping.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Alerts_Matcher {

	public const EXACT    = 'exact';
	public const PROBABLE = 'probable';
	public const POSSIBLE = 'possible';

	/** @return array<string,array{label:string,rank:int,tone:string,help:string}> */
	public static function confidences(): array {
		return array(
			self::EXACT    => array(
				'label' => __( 'Exact', 'vulnhub' ),
				'rank'  => 3,
				'tone'  => 'critical',
				'help'  => __( 'We run this product and the installed version is inside the affected range.', 'vulnhub' ),
			),
			self::PROBABLE => array(
				'label' => __( 'Probable', 'vulnhub' ),
				'rank'  => 2,
				'tone'  => 'warn',
				'help'  => __( 'We run this product, but the advisory did not give a version range we could compare against.', 'vulnhub' ),
			),
			self::POSSIBLE => array(
				'label' => __( 'Possible', 'vulnhub' ),
				'rank'  => 1,
				'tone'  => 'muted',
				'help'  => __( 'Only the vendor or the operating system family lines up. Context rather than a task.', 'vulnhub' ),
			),
		);
	}

	public static function rank( string $confidence ): int {
		return (int) ( self::confidences()[ $confidence ]['rank'] ?? 0 );
	}

	public static function label( string $confidence ): string {
		return (string) ( self::confidences()[ $confidence ]['label'] ?? $confidence );
	}

	public static function tone( string $confidence ): string {
		return (string) ( self::confidences()[ $confidence ]['tone'] ?? 'muted' );
	}

	/**
	 * Match one normalised advisory against the estate.
	 *
	 * @param array<string,mixed> $alert Normalised adapter row.
	 * @return array<int,array<string,mixed>> Match rows, best confidence first.
	 */
	public static function match( array $alert ): array {
		$index   = VulnHub_Alerts_Inventory::index();
		$matches = array();

		foreach ( (array) ( $alert['products'] ?? array() ) as $claim ) {
			if ( ! is_array( $claim ) ) {
				continue;
			}

			foreach ( self::for_claim( $claim, $index ) as $match ) {
				$key = $match['asset_id'] . '|' . $match['product'];

				// One advisory can name the same product several ways. Keep
				// whichever pass was most certain.
				if ( ! isset( $matches[ $key ] )
					|| self::rank( $match['confidence'] ) > self::rank( $matches[ $key ]['confidence'] ) ) {
					$matches[ $key ] = $match;
				}
			}
		}

		/*
		 * The OS fallback is only allowed when the advisory named no products
		 * at all -- a CISA bulletin, a vendor RSS item, anything narrative.
		 *
		 * If it did name products and none of them are ours, that is a
		 * finished answer: not relevant. Falling through to the OS text was
		 * matching every Microsoft advisory about "Azure Linux 3.0" against
		 * our Red Hat servers on the strength of the word Linux, and it
		 * produced 2,186 alerts that were all wrong in the same way.
		 */
		if ( ! $matches && ! array_filter( (array) ( $alert['products'] ?? array() ) ) ) {
			$matches = self::by_os( $alert, $index );
		}

		$matches = array_values( $matches );

		usort(
			$matches,
			static fn( array $a, array $b ): int => self::rank( $b['confidence'] ) <=> self::rank( $a['confidence'] )
		);

		return $matches;
	}

	/**
	 * @param array<string,mixed> $claim One product claim from an advisory.
	 * @param array<string,mixed> $index Inventory index.
	 * @return array<int,array<string,mixed>>
	 */
	private static function for_claim( array $claim, array $index ): array {
		$product = VulnHub_Alerts_Inventory::normalise( (string) ( $claim['product'] ?? '' ) );
		$vendor  = VulnHub_Alerts_Inventory::normalise( (string) ( $claim['vendor'] ?? '' ) );
		$range   = (string) ( $claim['range'] ?? '' );

		if ( '' === $product ) {
			return array();
		}

		$key = self::resolve( $product, $vendor, $index );

		if ( null === $key ) {
			/*
			 * We do not run this product, so there is nothing to say.
			 *
			 * There was a vendor-level fallback here -- "we do not run the
			 * named product, but we do run other Microsoft software" -- and
			 * it was worse than useless. Microsoft publishes advisories for
			 * Azure Linux packages nobody here has installed, and every one
			 * of them matched on the strength of us owning .NET: 1,921
			 * alerts and roughly 19,000 match rows that told a reader
			 * nothing. A vendor name is not a signal; a product is.
			 */
			return array();
		}

		$entry = $index['products'][ $key ];
		$out   = array();

		foreach ( $entry['versions'] as $version => $asset_ids ) {
			$verdict = self::version_verdict( (string) $version, $range );

			if ( 'out' === $verdict ) {
				continue;
			}

			foreach ( array_keys( $asset_ids ) as $asset_id ) {
				$out[] = array(
					'asset_id'          => (int) $asset_id,
					'confidence'        => 'in' === $verdict ? self::EXACT : self::PROBABLE,
					'matched_on'        => 'cpe',
					'vendor'            => $entry['vendor'],
					'product'           => $entry['product'],
					'installed_version' => (string) $version,
					'affected_range'    => $range,
					'evidence'          => 'in' === $verdict
						? sprintf(
							/* translators: 1: installed version, 2: affected range */
							__( 'Installed %1$s falls inside the affected range %2$s.', 'vulnhub' ),
							$version ?: __( 'version unknown', 'vulnhub' ),
							$range
						)
						: sprintf(
							/* translators: %s: installed version */
							__( 'Product is installed (%s), but the advisory gave no comparable version range.', 'vulnhub' ),
							$version ?: __( 'version not recorded', 'vulnhub' )
						),
				);
			}
		}

		return $out;
	}

	/**
	 * Find the inventory key for a product an advisory named.
	 *
	 * Exact key first, then product name alone, then a contains test in both
	 * directions -- "Windows 11 Version 23H2" has to find "windows 11", and
	 * "acrobat" has to find "acrobat reader".
	 */
	private static function resolve( string $product, string $vendor, array $index ): ?string {
		if ( '' !== $vendor && isset( $index['products'][ $vendor . '|' . $product ] ) ) {
			return $vendor . '|' . $product;
		}

		if ( isset( $index['names'][ $product ] ) ) {
			return $index['names'][ $product ];
		}

		/*
		 * Package-ecosystem advisories get no fuzzy matching at all.
		 *
		 * A GitHub advisory for the NuGet package
		 * "Microsoft.Native.Quic.MsQuic.OpenSSL" < 2.4.19 matched our OpenSSL
		 * library on the strength of the trailing word, and since 1.1.1n is
		 * numerically below 2.4.19 it was reported as an exact hit on 181
		 * machines. A package name and a CPE product name are different
		 * namespaces with different version schemes; only an exact name match
		 * means anything across them.
		 */
		if ( self::is_ecosystem( $vendor ) ) {
			return null;
		}

		$best     = null;
		$best_len = 0;

		foreach ( $index['names'] as $name => $key ) {
			if ( strlen( $name ) < 5 ) {
				continue;
			}

			if ( ! str_contains( $product, $name ) && ! str_contains( $name, $product ) ) {
				continue;
			}

			/*
			 * A partial name only counts when the vendors agree. "Windows 11
			 * Version 23H2" should find our "windows 11", but it should take
			 * Microsoft saying so to do it -- otherwise any advisory whose
			 * product name happens to contain one of our product names
			 * becomes a match.
			 */
			$entry = $index['products'][ $key ] ?? null;

			if ( ! $entry || '' === $vendor || $entry['vendor'] !== $vendor ) {
				continue;
			}

			// Prefer the longest name that fits: "windows 11" beats
			// "windows" for "Windows 11 Version 23H2".
			if ( strlen( $name ) > $best_len ) {
				$best     = $key;
				$best_len = strlen( $name );
			}
		}

		return $best;
	}

	/**
	 * Is this "vendor" actually a package ecosystem?
	 *
	 * OSV-shaped sources put the ecosystem where a vendor would go, and those
	 * names live in their own namespace rather than CPE's.
	 */
	private static function is_ecosystem( string $vendor ): bool {
		$v = strtolower( trim( $vendor ) );

		if ( '' === $v ) {
			return false;
		}

		foreach ( array(
			'nuget', 'npm', 'pypi', 'maven', 'go', 'crates.io', 'rubygems',
			'packagist', 'composer', 'hex', 'pub', 'swifturl', 'conan',
			'debian', 'ubuntu', 'alpine', 'rocky linux', 'almalinux',
			'red hat', 'suse', 'opensuse', 'android', 'linux', 'oss fuzz',
			'github actions', 'bitnami', 'mageia', 'photon os', 'wolfi', 'chainguard',
		) as $eco ) {
			if ( $v === $eco || str_starts_with( $v, $eco . ':' ) ) {
				return true;
			}
		}

		return false;
	}

	/** @return array<int,array<string,mixed>> */
	private static function by_os( array $alert, array $index ): array {
		$text   = strtolower( (string) ( $alert['title'] ?? '' ) . ' ' . (string) ( $alert['summary'] ?? '' ) );
		$family = VulnHub_Alerts_Inventory::os_family( $text );

		if ( '' === $family || empty( $index['os'][ $family ] ) ) {
			return array();
		}

		$assets = array_keys( $index['os'][ $family ] );
		$out    = array();

		// Capped hard. An OS-family match is the weakest signal we record and
		// it must not be able to write nine hundred rows for one advisory.
		foreach ( array_slice( $assets, 0, 25 ) as $asset_id ) {
			$out[] = array(
				'asset_id'          => (int) $asset_id,
				'confidence'        => self::POSSIBLE,
				'matched_on'        => 'os',
				'vendor'            => '',
				'product'           => $family,
				'installed_version' => '',
				'affected_range'    => '',
				'evidence'          => sprintf(
					/* translators: 1: OS family, 2: total assets in that family */
					__( 'Mentions the %1$s platform, which %2$d assets run. No product-level match.', 'vulnhub' ),
					$family,
					count( $assets )
				),
			);
		}

		return $out;
	}

	/* =================================================================
	 * Version ranges
	 * ============================================================== */

	/**
	 * Is an installed version inside an advisory's affected range?
	 *
	 * Returns 'in', 'out', or 'unknown'. The distinction matters: 'unknown'
	 * still produces a match at lower confidence, whereas 'out' means the
	 * advisory has told us this build is fine and we say nothing.
	 *
	 * Handles the shapes that actually turn up: EUVD's "1.2.3 <1.2.9",
	 * GitHub's ">= 1.0, < 2.3.1", and bare "before 1.10.7" prose.
	 */
	public static function version_verdict( string $installed, string $range ): string {
		$installed = trim( $installed );
		$range     = trim( $range );

		if ( '' === $installed || '' === $range ) {
			return 'unknown';
		}

		$clauses = self::clauses( $range );

		if ( ! $clauses || self::degenerate( $clauses ) ) {
			return 'unknown';
		}

		/*
		 * No upper bound means no fixed version, and "affected from 19.0.0
		 * onwards" cannot confirm anything -- every future release satisfies
		 * it. This is not hypothetical: Microsoft publishes ranges shaped
		 * "19.0.0 <https://aka.ms/OfficeSecurityReleases", where the fix is a
		 * link rather than a build, and Office "365" duly tested as greater
		 * than 19 and was reported as an exact hit on 496 machines. Downgrade
		 * to unknown so it lands at probable and a person decides.
		 */
		$ops = array_column( $clauses, 'op' );

		if ( ! array_intersect( $ops, array( '<', '<=', '=' ) ) ) {
			return 'unknown';
		}

		foreach ( $clauses as $clause ) {
			$cmp = version_compare( self::canonical( $installed ), self::canonical( $clause['version'] ) );

			$satisfied = match ( $clause['op'] ) {
				'<'     => $cmp < 0,
				'<='    => $cmp <= 0,
				'>'     => $cmp > 0,
				'>='    => $cmp >= 0,
				'='     => 0 === $cmp,
				default => true,
			};

			if ( ! $satisfied ) {
				return 'out';
			}
		}

		return 'in';
	}

	/**
	 * Break a range expression into comparable clauses.
	 *
	 * @return array<int,array{op:string,version:string}>
	 */
	private static function clauses( string $range ): array {
		$range = strtolower( trim( $range ) );

		// Prose forms first, because "before 1.10.7" carries no operator.
		$range = preg_replace( '/\bbefore\s+/', '<', $range ) ?? $range;
		$range = preg_replace( '/\bprior to\s+/', '<', $range ) ?? $range;
		$range = preg_replace( '/\bthrough\s+/', '<=', $range ) ?? $range;
		$range = preg_replace( '/\bup to and including\s+/', '<=', $range ) ?? $range;

		$out = array();

		/*
		 * A leading bare version is an implicit lower bound.
		 *
		 * EUVD writes ranges as "10.0.22631.0 <10.0.22631.7582", meaning from
		 * that build up to the fix. Reading only the operator clause drops the
		 * floor entirely, and everything below the range then tests as
		 * affected -- which is how Visual Studio 10.0.40219 was reported as
		 * inside "17.14.0 <17.14.40". Anchor it.
		 */
		if ( preg_match( '/^([0-9][0-9a-z.\-_]*)\s*(?=[<>=])/', $range, $lead ) ) {
			$out[] = array( 'op' => '>=', 'version' => $lead[1] );
			$range = substr( $range, strlen( $lead[0] ) );
		}

		if ( ! preg_match_all( '/(<=|>=|<|>|=)\s*([0-9][0-9a-z.\-_]*)/', $range, $m, PREG_SET_ORDER ) ) {
			return $out;
		}

		foreach ( $m as $hit ) {
			$out[] = array(
				'op'      => $hit[1],
				'version' => $hit[2],
			);
		}

		return $out;
	}

	/**
	 * Is this range self-contradictory?
	 *
	 * EUVD publishes plenty of entries shaped "153.0.8010.36 <153.0.8010.36",
	 * where the lower bound and the fix are the same build. Nothing can
	 * satisfy that. Treating it as "not affected" would silently drop real
	 * Chrome advisories, and treating it as "affected" would alert on every
	 * install; saying we cannot tell is the only honest reading, and it lands
	 * the match at probable where a person will look at it.
	 */
	private static function degenerate( array $clauses ): bool {
		$lower = null;
		$upper = null;

		foreach ( $clauses as $c ) {
			if ( '>=' === $c['op'] || '>' === $c['op'] ) {
				$lower = $c['version'];
			}
			if ( '<' === $c['op'] || '<=' === $c['op'] ) {
				$upper = $c['version'];
			}
		}

		if ( null === $lower || null === $upper ) {
			return false;
		}

		return version_compare( self::canonical( $lower ), self::canonical( $upper ) ) >= 0
			&& ! in_array( '<=', array_column( $clauses, 'op' ), true );
	}

	/**
	 * Make a version string comparable.
	 *
	 * version_compare() treats "10.0.26100.0" fine but chokes on the vendor
	 * decorations around it, so strip to the numeric spine.
	 */
	private static function canonical( string $version ): string {
		$version = strtolower( trim( $version ) );
		$version = preg_replace( '/^[^0-9]*/', '', $version ) ?? $version;
		$version = preg_replace( '/[^0-9.].*$/', '', $version ) ?? $version;

		return trim( $version, '.' ) ?: '0';
	}
}
