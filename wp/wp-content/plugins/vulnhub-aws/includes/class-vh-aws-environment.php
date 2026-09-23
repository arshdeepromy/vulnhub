<?php
/**
 * Production or not, worked out from what things are called.
 *
 * AWS records no such flag, so the only evidence is naming, and naming is the
 * customer's own. The vocabulary below is therefore the *generic* half only --
 * prod, dev, test, sit, uat and their obvious spellings -- and everything
 * site-specific goes through `vulnhub_aws_environment_rules`, so an estate
 * with its own codes teaches them to the platform instead of having them
 * hard-coded into a public repository.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_AWS_Environment {

	public const PROD    = 'prod';
	public const NONPROD = 'nonprod';
	public const UNKNOWN = '';

	/**
	 * The patterns, most specific first, and the order is the whole trick.
	 *
	 * "non-prod", "nonprod", "preprod" and "pre-prod" all contain "prod". A
	 * classifier that looks for production first calls every one of them
	 * production -- which is the single worst way to be wrong here, because it
	 * puts test systems on the production diagram and quietly reassures
	 * somebody about a machine nobody is protecting. So the negatives are
	 * tested first, always.
	 *
	 * @return array<int,array{0:string,1:string}> regex, verdict.
	 */
	private static function rules(): array {
		$rules = array(
			// Anything that merely contains "prod" but is not production.
			array( '/(non[-_ ]?prod|pre[-_ ]?prod|preprod)/i', self::NONPROD ),
			// Plainly not production.
			array( '/(^|[-_ ])(dev|devel|development|test|testing|tst|sit|uat|qa|pat|stage|staging|sandbox|sbx|demo|poc|prototype|lab|training|autotest)([-_ ]|$)/i', self::NONPROD ),
			// Plainly production.
			array( '/(^|[-_ ])(prod|production|prd|live)([-_ ]|$)/i', self::PROD ),
		);

		/**
		 * Teach it this estate's own environment codes.
		 *
		 * Each entry is [ regex, VulnHub_AWS_Environment::PROD|NONPROD ] and
		 * they are tested before the generic set, so a site convention always
		 * beats a coincidence in a longer word.
		 *
		 * @param array<int,array{0:string,1:string}> $rules Rules from the setting.
		 */
		$extra = (array) apply_filters( 'vulnhub_aws_environment_rules', self::operator_rules() );

		return array_merge( $extra, $rules );
	}

	/**
	 * The operator's own rules, from the AWS connector setting.
	 *
	 * Read straight from the option rather than through the connector, because
	 * this is asked on page renders where the connector registry may never be
	 * built -- and because it is data, not code. It lives in the database for
	 * the reason recorded on the setting itself: an estate's environment codes
	 * are its own vocabulary and this repository is public.
	 *
	 * @return array<int,array{0:string,1:string}>
	 */
	private static function operator_rules(): array {
		static $cache = null;

		if ( null !== $cache ) {
			return $cache;
		}

		$cache = array();
		$cfg   = (array) get_option( 'vulnhub_cfg_aws', array() );
		$raw   = trim( (string) ( $cfg['environment_rules'] ?? '' ) );

		if ( '' === $raw ) {
			return $cache;
		}

		foreach ( preg_split( '/[\r\n]+/', $raw ) ?: array() as $line ) {
			$line = trim( (string) $line );

			if ( '' === $line || 0 === strpos( $line, '#' ) || ! str_contains( $line, '=' ) ) {
				continue;
			}

			list( $needle, $verdict ) = array_map( 'trim', explode( '=', $line, 2 ) );
			$verdict                  = strtolower( $verdict );

			if ( '' === $needle || ! in_array( $verdict, array( self::PROD, self::NONPROD ), true ) ) {
				continue;
			}

			/*
			 * A bare fragment matches on a word boundary rather than anywhere,
			 * so a short code cannot also match inside a longer word. Somebody
			 * who wants that writes a /regex/ instead.
			 */
			$pattern = ( strlen( $needle ) > 2 && '/' === $needle[0] && '/' === substr( $needle, -1 ) )
				? $needle
				: '/(^|[-_ \/])' . preg_quote( $needle, '/' ) . '([-_ \/]|$)/i';

			if ( false === @preg_match( $pattern, '' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors -- operator-supplied pattern.
				continue;
			}

			$cache[] = array( $pattern, $verdict );
		}

		return $cache;
	}

	/**
	 * Classify from one or more names — a VPC, its account, the resource.
	 *
	 * The first name that yields a verdict wins, so pass them most-specific
	 * first: a VPC called `…-prod-vpc` in an account called `…-nonprod` is
	 * production, and the VPC is the closer fact.
	 *
	 * @param string ...$names Names to read, most specific first.
	 */
	public static function classify( string ...$names ): string {
		foreach ( $names as $name ) {
			$name = trim( $name );

			if ( '' === $name ) {
				continue;
			}

			foreach ( self::rules() as $rule ) {
				if ( preg_match( (string) $rule[0], $name ) ) {
					return (string) $rule[1];
				}
			}
		}

		return self::UNKNOWN;
	}

	/** Label for a verdict, for a heading or a tab. */
	public static function label( string $env ): string {
		return match ( $env ) {
			self::PROD    => __( 'Production', 'vulnhub' ),
			self::NONPROD => __( 'Non-production', 'vulnhub' ),
			default       => __( 'Unclassified', 'vulnhub' ),
		};
	}
}
