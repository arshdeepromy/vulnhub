<?php
/**
 * AWS account names: which account number is which account.
 *
 * Nothing in AWS's own data plane says what an account is called; the name
 * lives where accounts are administered. Two of our sources can see it:
 *
 *  - Plerion's integrations (`/v1/tenant/integrations`): one per connected
 *    account, named when the account was onboarded. Covers every account
 *    the posture inventory reads, which is most of the estate.
 *  - The AWS sign-in's account list (`/assignment/accounts`): `accountName`
 *    for every account the SSO user can reach.
 *
 * Each source reports through the `vulnhub_aws_account_names` action, so
 * neither plugin depends on the other. Names are merged into one map and
 * kept: an account a later sync no longer sees keeps the name it had, and an
 * empty name never overwrites a real one. See docs/COVERAGE.md, "Account and
 * instance names".
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_AWS_Account_Names {

	public const OPTION = 'vulnhub_aws_account_names';

	public static function init(): void {
		add_action( 'vulnhub_aws_account_names', array( __CLASS__, 'remember' ), 10, 2 );
	}

	/**
	 * Account id => name, for every account any source has ever named.
	 *
	 * @return array<string,string>
	 */
	public static function all(): array {
		$out = array();

		foreach ( (array) get_option( self::OPTION, array() ) as $id => $row ) {
			$name = is_array( $row ) ? (string) ( $row['name'] ?? '' ) : (string) $row;

			if ( '' !== $name ) {
				$out[ (string) $id ] = $name;
			}
		}

		return $out;
	}

	public static function name( string $account_id ): string {
		return self::all()[ $account_id ] ?? '';
	}

	/**
	 * Merge names a source reported, then carry them onto the records.
	 *
	 * @param array<string,string> $names  Account id => name.
	 * @param string               $source Who said so (plerion, aws_sso).
	 * @return int Accounts whose name is new or changed.
	 */
	public static function remember( $names, $source = '' ): int {
		$stored  = (array) get_option( self::OPTION, array() );
		$changed = 0;
		$now     = vh_now();

		foreach ( (array) $names as $id => $name ) {
			$id   = preg_replace( '/\D/', '', (string) $id );
			$name = trim( sanitize_text_field( (string) $name ) );

			// A 12-digit account and a real name, or nothing: an empty
			// report must never erase what an earlier one said.
			if ( 12 !== strlen( (string) $id ) || '' === $name ) {
				continue;
			}

			$was = is_array( $stored[ $id ] ?? null ) ? (string) ( $stored[ $id ]['name'] ?? '' ) : '';

			$stored[ $id ] = array(
				'name'   => mb_substr( $name, 0, 191 ),
				'source' => sanitize_key( (string) $source ),
				'seen'   => $now,
			);

			if ( $was !== $name ) {
				++$changed;
			}
		}

		update_option( self::OPTION, $stored, false );

		self::label_accounts();
		self::stamp_assets();

		return $changed;
	}

	/**
	 * Give configured accounts their real name where the label is still the
	 * placeholder "Add discovered" wrote ("18 known assets") or empty. A
	 * label somebody typed is theirs and is left alone.
	 */
	public static function label_accounts(): int {
		global $wpdb;

		$t = $wpdb->prefix . 'vulnhub_aws_accounts';
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $t ) ) !== $t ) {
			return 0;
		}

		$n = 0;
		foreach ( self::all() as $id => $name ) {
			$n += (int) $wpdb->query( // phpcs:ignore
				$wpdb->prepare(
					"UPDATE {$t} SET label = %s WHERE account_id = %s AND ( label = '' OR label REGEXP '^[0-9]+ known assets?$' )", // phpcs:ignore
					$name,
					$id
				)
			);
		}

		return $n;
	}

	/**
	 * Every asset in a named account carries that name. Additive: a record
	 * whose account no source names keeps whatever it had.
	 */
	public static function stamp_assets(): int {
		global $wpdb;

		$a = vh_table( 'assets' );
		$n = 0;

		foreach ( self::all() as $id => $name ) {
			$n += (int) $wpdb->query( // phpcs:ignore
				$wpdb->prepare(
					"UPDATE {$a} SET aws_account_name = %s, updated_at = %s WHERE cloud_account_id = %s AND aws_account_name <> %s", // phpcs:ignore
					$name,
					vh_now(),
					$id,
					$name
				)
			);
		}

		return $n;
	}
}

