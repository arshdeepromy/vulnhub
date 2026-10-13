<?php
/**
 * The cross-account grouping key for Plerion findings.
 *
 * One misconfiguration copied into many accounts arrives as many findings:
 * a vendor connector role deployed by StackSet is the same role in every
 * account it reached, and a function deployed to dev, test and prod is the
 * same code three times. Read one row at a time they look like separate
 * work. They are one fix, made once, at the place that copied it.
 *
 * The key says "same detection, same kind of resource, same name once the
 * parts that only say WHERE it runs are taken out". Those parts are:
 *
 *   - the environment tier (`-dev`, `_uat`, `prod-`, `preprod2`),
 *   - an account id or region embedded in the name,
 *   - a task definition revision (`:14`),
 *   - the random suffix CloudFormation appends (`-A1B2C3D4E5F6`).
 *
 * What is left is the stem. `detection | resource type | stem` hashed is the
 * key, so it is short enough to index and to carry in a URL. The stem and
 * the tier are stored beside it so the Control gaps page can show them.
 *
 * The key is computed on every upsert. When the rules below change, bump
 * RULES: the next request that installs the table re-keys every stored row
 * (a couple of thousand rows, a second or two), so old and new keys never
 * sit side by side.
 *
 * @package VulnHub\Plerion
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Plerion_Cause {

	/** Bump when parse() would give a different answer for a stored row. */
	public const RULES = '1';

	/** Option holding the RULES value the stored keys were built with. */
	public const OPTION = 'vulnhub_plerion_cause_rules';

	/**
	 * Name tokens that only say which environment a resource runs in, mapped
	 * to the tier recorded for it. Matched as whole tokens between - _ . / or
	 * spaces, optionally followed by one or two digits (`preprod2`, `dev1`).
	 * Deliberately short: a word that is sometimes a tier and sometimes part
	 * of a real name ("live", "dr", "np") would merge things that differ.
	 *
	 * @return array<string,string>
	 */
	public static function tiers(): array {
		return (array) apply_filters(
			'vulnhub_plerion_cause_tiers',
			array(
				'dev'         => 'dev',
				'develop'     => 'dev',
				'development' => 'dev',
				'sandbox'     => 'sandbox',
				'sbx'         => 'sandbox',
				'test'        => 'test',
				'tst'         => 'test',
				'qa'          => 'test',
				'sit'         => 'sit',
				'uat'         => 'uat',
				'stg'         => 'staging',
				'stage'       => 'staging',
				'staging'     => 'staging',
				'preprod'     => 'preprod',
				'nonprod'     => 'nonprod',
				'prod'        => 'prod',
				'prd'         => 'prod',
				'production'  => 'prod',
			)
		);
	}

	/**
	 * Work out a finding's key, stem, account and tier.
	 *
	 * @param array<string,mixed> $r A stored or normalised finding.
	 * @return array{cause_key:string,cause_stem:string,cause_account:string,env_tier:string}
	 */
	public static function parse( array $r ): array {
		$detection = (string) ( $r['detection_id'] ?? '' );
		$type      = (string) ( $r['resource_type'] ?? '' );
		$prn       = (string) ( $r['asset_prn'] ?? '' );
		$name      = trim( (string) ( $r['resource_name'] ?? '' ) );

		if ( '' === $name ) {
			$name = self::tail( $prn );
		}

		$account = (string) ( $r['account_id'] ?? '' );

		// IAM findings arrive with no account id of their own; the role's
		// ARN inside the asset PRN carries it.
		if ( '' === $account ) {
			$account = self::arn_account( $prn );
		}

		[ $stem, $tier ] = self::stem( $name );

		if ( '' === $detection && '' === $stem ) {
			return array(
				'cause_key'     => '',
				'cause_stem'    => '',
				'cause_account' => $account,
				'env_tier'      => $tier,
			);
		}

		return array(
			'cause_key'     => md5( $detection . '|' . $type . '|' . $stem ),
			'cause_stem'    => substr( $stem, 0, 191 ),
			'cause_account' => substr( $account, 0, 24 ),
			'env_tier'      => $tier,
		);
	}

	/**
	 * A resource name with everything that only says where it runs removed.
	 *
	 * @return array{0:string,1:string} [ stem, first tier found or '' ].
	 */
	public static function stem( string $name ): array {
		$name = trim( $name );

		/*
		 * CloudFormation's random suffix: an all-capitals run of 8+ letters
		 * and digits after the last separator, on a name that is not itself
		 * all capitals. Checked before lower-casing, because case is the
		 * only thing that tells `-SREYFYNUX` from `-production`.
		 */
		if ( preg_match( '/^(.*[a-z].*?)[-_]([A-Z0-9]{8,14})$/', $name, $m ) && preg_match( '/[A-Z]/', $m[2] ) ) {
			$name = $m[1];
		}

		$s = strtolower( $name );
		$s = (string) preg_replace( '/:\d+$/', '', $s );                          // task definition revision
		$s = (string) preg_replace( '/(?<!\d)\d{12}(?!\d)/', '{acct}', $s );        // account id
		$s = (string) preg_replace( '/\b[a-z]{2}(-gov)?-[a-z]+-\d\b/', '{region}', $s );
		$s = str_replace( array( 'non-prod', 'non_prod', 'pre-prod', 'pre_prod' ), array( 'nonprod', 'nonprod', 'preprod', 'preprod' ), $s );

		$tiers = self::tiers();
		$tier  = '';
		$kept  = array();

		foreach ( (array) preg_split( '/[-_.\s\/]+/', $s, -1, PREG_SPLIT_NO_EMPTY ) as $token ) {
			$token = (string) $token;

			if ( preg_match( '/^([a-z]+)\d{0,2}$/', $token, $t ) && isset( $tiers[ $t[1] ] ) ) {
				if ( '' === $tier ) {
					$tier = (string) $tiers[ $t[1] ];
				}
				continue;
			}

			$kept[] = $token;
		}

		$stem = implode( '-', $kept );

		// A name that was nothing but a tier ("prod") keeps the tier as its
		// stem rather than collapsing every such resource into one group.
		if ( '' === $stem ) {
			$stem = $tier;
		}

		return array( $stem, $tier );
	}

	/** The last segment of an ARN or PRN: after the final `/`, else `:`. */
	private static function tail( string $prn ): string {
		if ( '' === $prn ) {
			return '';
		}

		$slash = strrpos( $prn, '/' );

		if ( false !== $slash ) {
			return substr( $prn, $slash + 1 );
		}

		$colon = strrpos( $prn, ':' );

		return false === $colon ? $prn : substr( $prn, $colon + 1 );
	}

	/** The 12-digit account in the first `arn:aws…::<account>:` found, or ''. */
	private static function arn_account( string $prn ): string {
		return preg_match( '/arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:(\d{12}):/', $prn, $m ) ? (string) $m[1] : '';
	}

	/**
	 * Re-key stored rows whose key, stem, account or tier would now differ.
	 *
	 * @return array{checked:int,changed:int}
	 */
	public static function backfill( bool $dry_run = false ): array {
		global $wpdb;

		$t    = VulnHub_Plerion_Findings::table();
		$rows = (array) $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			"SELECT id, detection_id, resource_type, resource_name, asset_prn, account_id, cause_key, cause_stem, cause_account, env_tier FROM {$t}", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);

		$changed = 0;

		if ( ! $dry_run ) {
			$wpdb->query( 'START TRANSACTION' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		}

		foreach ( $rows as $r ) {
			$k = self::parse( $r );

			if ( $k['cause_key'] === (string) $r['cause_key'] && $k['cause_stem'] === (string) $r['cause_stem']
				&& $k['cause_account'] === (string) $r['cause_account'] && $k['env_tier'] === (string) $r['env_tier'] ) {
				continue;
			}

			++$changed;

			if ( ! $dry_run ) {
				$wpdb->update( $t, $k, array( 'id' => (int) $r['id'] ), array( '%s', '%s', '%s', '%s' ), array( '%d' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			}
		}

		if ( ! $dry_run ) {
			$wpdb->query( 'COMMIT' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			update_option( self::OPTION, self::RULES, false );
		}

		return array( 'checked' => count( $rows ), 'changed' => $changed );
	}

	/** Re-key everything once after RULES changes. Cheap to call often. */
	public static function maybe_backfill(): void {
		if ( self::RULES === (string) get_option( self::OPTION, '' ) ) {
			return;
		}

		self::backfill();
	}

	/**
	 * Cause groups: findings sharing a key, with how far the cause has
	 * spread. Only groups that cross at least one threshold come back.
	 *
	 * Counted over the same rows the Cloud Posture list shows (not
	 * exempted), so a group's finding count is exactly what its
	 * `?cause=` link opens.
	 *
	 * @param array{accounts:int,resources:int,tiers:int} $min Thresholds.
	 * @return array<int,array<string,mixed>>
	 */
	public static function groups( array $min ): array {
		global $wpdb;

		$t = VulnHub_Plerion_Findings::table();

		return (array) $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->prepare(
				"SELECT cause_key, detection_id, source, resource_type,
						MIN(cause_stem) AS stem,
						MIN(message) AS sample,
						COUNT(*) AS findings,
						COUNT(DISTINCT COALESCE(NULLIF(asset_prn,''), finding_prn)) AS resources,
						COUNT(DISTINCT NULLIF(cause_account,'')) AS accounts,
						COUNT(DISTINCT NULLIF(env_tier,'')) AS tiers,
						GROUP_CONCAT(DISTINCT NULLIF(env_tier,'') ORDER BY env_tier SEPARATOR ', ') AS tier_list,
						MIN(FIELD(severity,'CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN')) AS sev_rank
				   FROM {$t}
				  WHERE is_exempted = 0 AND cause_key <> ''
				  GROUP BY cause_key, detection_id, source, resource_type
				 HAVING accounts >= %d OR resources >= %d OR tiers >= %d
				  ORDER BY findings DESC, resources DESC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				max( 1, (int) $min['accounts'] ),
				max( 1, (int) $min['resources'] ),
				max( 1, (int) $min['tiers'] )
			),
			ARRAY_A
		);
	}

	/**
	 * Every detection, with how many distinct causes sit behind its findings.
	 * A detection with 340 findings and 171 causes is 171 fixes, not 340.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function families(): array {
		global $wpdb;

		$t = VulnHub_Plerion_Findings::table();

		return (array) $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			"SELECT detection_id, source,
					GROUP_CONCAT(DISTINCT resource_type ORDER BY resource_type SEPARATOR ', ') AS resource_types,
					MIN(message) AS sample,
					COUNT(*) AS findings,
					COUNT(DISTINCT cause_key) AS causes,
					COUNT(DISTINCT COALESCE(NULLIF(asset_prn,''), finding_prn)) AS resources,
					COUNT(DISTINCT NULLIF(cause_account,'')) AS accounts,
					MIN(FIELD(severity,'CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN')) AS sev_rank
			   FROM {$t}
			  WHERE is_exempted = 0
			  GROUP BY detection_id, source
			  ORDER BY findings DESC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);
	}

	/** Findings not exempted, the denominator for "share in control gaps". */
	public static function total(): int {
		global $wpdb;

		return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . VulnHub_Plerion_Findings::table() . ' WHERE is_exempted = 0' ); // phpcs:ignore
	}

	/** Distinct causes behind the findings not exempted. */
	public static function distinct_causes(): int {
		global $wpdb;

		return (int) $wpdb->get_var( 'SELECT COUNT(DISTINCT cause_key) FROM ' . VulnHub_Plerion_Findings::table() . ' WHERE is_exempted = 0' ); // phpcs:ignore
	}

	/**
	 * One group's label parts, for the banner on a filtered Cloud Posture
	 * list.
	 *
	 * @return array<string,mixed>|null
	 */
	public static function describe( string $key ): ?array {
		global $wpdb;

		if ( ! preg_match( '/^[a-f0-9]{32}$/', $key ) ) {
			return null;
		}

		$row = $wpdb->get_row( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->prepare(
				'SELECT detection_id, resource_type, MIN(cause_stem) AS stem, COUNT(*) AS findings FROM ' . VulnHub_Plerion_Findings::table() . ' WHERE cause_key = %s AND is_exempted = 0 GROUP BY detection_id, resource_type', // phpcs:ignore
				$key
			),
			ARRAY_A
		);

		return $row ? (array) $row : null;
	}
}

