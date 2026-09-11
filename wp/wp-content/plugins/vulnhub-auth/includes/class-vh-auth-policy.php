<?php
/**
 * Multi-factor authentication policy.
 *
 * Answers three questions for any user: is MFA required of them, are they
 * still inside their grace period, and may they remember this browser.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reads and writes the platform MFA policy.
 */
final class VulnHub_Auth_Policy {

	/** Option holding the whole policy. */
	public const OPTION = 'vulnhub_auth_policy';

	/** MFA is switched off for everyone. */
	public const MODE_OFF = 'off';

	/** Users may enrol but nothing is enforced. */
	public const MODE_OPTIONAL = 'optional';

	/** Required for users holding one of the selected roles. */
	public const MODE_ROLES = 'roles';

	/** Required for every user who can sign in. */
	public const MODE_ALL = 'all';

	/**
	 * Policy defaults.
	 *
	 * @return array<string,mixed>
	 */
	public static function defaults(): array {
		return array(
			'mode'              => self::MODE_OPTIONAL,
			'roles'             => array( 'administrator', 'vulnhub_admin' ),
			'grace_days'        => 7,
			'remember_enabled'  => true,
			'remember_days'     => 30,
			'lockout_threshold' => 5,
			'lockout_minutes'   => 15,
			'skip_for_sso'      => true,
			'issuer_label'      => '',
		);
	}

	/**
	 * The whole policy, defaults merged in.
	 *
	 * @return array<string,mixed>
	 */
	public static function all(): array {
		$stored = get_option( self::OPTION, array() );
		return array_merge( self::defaults(), is_array( $stored ) ? $stored : array() );
	}

	/**
	 * One policy value.
	 *
	 * @param string $key     Policy key.
	 * @param mixed  $default Fallback.
	 * @return mixed
	 */
	public static function get( string $key, mixed $default = null ): mixed {
		$all = self::all();
		return array_key_exists( $key, $all ) ? $all[ $key ] : $default;
	}

	/**
	 * Persist a sanitised policy.
	 *
	 * @param array<string,mixed> $input Raw values.
	 * @return array<string,mixed> The stored policy.
	 */
	public static function save( array $input ): array {
		$modes = array( self::MODE_OFF, self::MODE_OPTIONAL, self::MODE_ROLES, self::MODE_ALL );

		$roles = array();
		foreach ( (array) ( $input['roles'] ?? array() ) as $role ) {
			$role = sanitize_key( (string) $role );
			if ( '' !== $role && wp_roles()->is_role( $role ) ) {
				$roles[] = $role;
			}
		}

		$clean = array(
			'mode'              => in_array( (string) ( $input['mode'] ?? '' ), $modes, true ) ? (string) $input['mode'] : self::MODE_OPTIONAL,
			'roles'            => array_values( array_unique( $roles ) ),
			'grace_days'        => max( 0, min( 365, (int) ( $input['grace_days'] ?? 7 ) ) ),
			'remember_enabled'  => ! empty( $input['remember_enabled'] ),
			'remember_days'     => max( 1, min( 365, (int) ( $input['remember_days'] ?? 30 ) ) ),
			'lockout_threshold' => max( 1, min( 50, (int) ( $input['lockout_threshold'] ?? 5 ) ) ),
			'lockout_minutes'   => max( 1, min( 1440, (int) ( $input['lockout_minutes'] ?? 15 ) ) ),
			'skip_for_sso'      => ! empty( $input['skip_for_sso'] ),
			'issuer_label'      => sanitize_text_field( (string) ( $input['issuer_label'] ?? '' ) ),
		);

		update_option( self::OPTION, $clean, false );

		return $clean;
	}

	/* -----------------------------------------------------------------
	 * Decisions
	 * --------------------------------------------------------------- */

	/**
	 * Is MFA enforced at all?
	 */
	public static function enabled(): bool {
		return self::MODE_OFF !== self::get( 'mode' );
	}

	/**
	 * Is MFA required of this user by policy (regardless of enrolment)?
	 *
	 * @param \WP_User $user User.
	 * @return bool
	 */
	public static function required_for( \WP_User $user ): bool {
		$mode = (string) self::get( 'mode' );

		if ( self::MODE_OFF === $mode || self::MODE_OPTIONAL === $mode ) {
			return false;
		}
		if ( self::MODE_ALL === $mode ) {
			return true;
		}

		$required = (array) self::get( 'roles', array() );
		foreach ( (array) $user->roles as $role ) {
			if ( in_array( (string) $role, $required, true ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Is this user still inside the enrolment grace period?
	 *
	 * The clock starts at account registration, so a new starter can sign in
	 * and set up their authenticator instead of being locked out on day one.
	 *
	 * @param \WP_User $user User.
	 * @return bool
	 */
	public static function in_grace_period( \WP_User $user ): bool {
		$days = (int) self::get( 'grace_days', 7 );
		if ( $days <= 0 ) {
			return false;
		}

		$registered = strtotime( (string) $user->user_registered . ' UTC' );
		if ( ! $registered ) {
			return false;
		}

		return time() < $registered + $days * DAY_IN_SECONDS;
	}

	/**
	 * Does this user have to enrol before they can be left alone?
	 *
	 * @param \WP_User $user User.
	 * @return bool
	 */
	public static function must_enrol( \WP_User $user ): bool {
		return self::required_for( $user )
			&& ! VulnHub_Auth_User_MFA::is_enabled( $user->ID )
			&& ! self::in_grace_period( $user );
	}

	/**
	 * The issuer name shown in the authenticator app.
	 *
	 * @return string
	 */
	public static function issuer_label(): string {
		$label = trim( (string) self::get( 'issuer_label', '' ) );
		if ( '' !== $label ) {
			return $label;
		}
		$name = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		return '' !== trim( $name ) ? trim( $name ) : 'VulnHub';
	}

	/**
	 * Human labels for the modes.
	 *
	 * @return array<string,string>
	 */
	public static function modes(): array {
		return array(
			self::MODE_OFF      => __( 'Off — no second factor anywhere', 'vulnhub' ),
			self::MODE_OPTIONAL => __( 'Optional — users may enrol themselves', 'vulnhub' ),
			self::MODE_ROLES    => __( 'Required for selected roles', 'vulnhub' ),
			self::MODE_ALL      => __( 'Required for everyone', 'vulnhub' ),
		);
	}
}

