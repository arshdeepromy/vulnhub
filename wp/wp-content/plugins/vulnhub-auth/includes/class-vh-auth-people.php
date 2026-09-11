<?php
/**
 * People — portal accounts, roles and access.
 *
 * Until this screen existed the only way to create a VulnHub user was
 * wp-admin, which is precisely the place portal administrators are not
 * allowed to go: `VulnHub_Dash_Portal::is_portal_only_user()` bounces anyone
 * holding a `vulnhub_*` role and not `manage_options` straight back to the
 * portal. So the product shipped with a lockout and no door — every new
 * analyst had to be created by a WordPress administrator.
 *
 * Everything here happens at /portal-admin/?section=people, the same way the
 * Rules and Imports screens work: registered on `vulnhub_portal_sections`,
 * rendered from `vulnhub_render_portal_section`, submitted back to the portal
 * URL with a nonce and a real capability check on every action.
 *
 * Two rules shape the rest of the file.
 *
 * WordPress administrators are invisible. Not read-only, not greyed out —
 * absent. They are the accounts that own the machine the product runs on, and
 * a security tool that lists its own escape hatch on a page it hands to
 * customers is doing its operator no favours. `manageable()` filters them out
 * of the query, and every action re-checks `is_manageable()` before touching
 * anything, so a hand-crafted POST cannot reach one either.
 *
 * Suspension is reversible and deletion is not, so they are different verbs.
 * Suspending stashes the role, empties it, destroys every session and blocks
 * authentication outright; the audit trail, ticket attributions and exception
 * approvals that name the person all survive. Deleting is offered because it
 * was asked for, but it is the second option on the row, not the first.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Controller and form handler for the People section.
 */
final class VulnHub_Auth_People {

	/** Section slug inside the portal admin area. */
	public const SECTION = 'people';

	/** Nonce action and field. */
	public const NONCE_ACTION = 'vulnhub_people';
	public const NONCE_FIELD  = 'vh_people_nonce';

	/** Meta holding the role a suspended account had before suspension. */
	public const SUSPENDED_META = 'vulnhub_suspended_role';

	/** Meta marking an account that has been invited but never signed in. */
	public const INVITED_META = 'vulnhub_invited_at';

	/** Profile details the portal keeps about a person, beyond WordPress's own. */
	public const TITLE_META = 'vulnhub_job_title';
	public const PHONE_META = 'vulnhub_phone';
	public const TEAM_META  = 'vulnhub_team_id';

	/**
	 * A one-time invite link to show after a create, when mail is not working.
	 *
	 * @var string
	 */
	private static string $invite_link = '';

	public static function init(): void {
		add_filter( 'vulnhub_portal_sections', array( __CLASS__, 'register_section' ) );
		add_action( 'vulnhub_render_portal_section', array( __CLASS__, 'render_section' ) );
		add_action( 'template_redirect', array( __CLASS__, 'handle' ), 5 );

		// A suspended account must not be able to authenticate at all. Doing
		// this at the authentication stage rather than the portal gate means
		// they are stopped at the sign-in form with a reason, instead of
		// looping through a door that silently refuses to open.
		add_filter( 'wp_authenticate_user', array( __CLASS__, 'block_suspended' ), 10, 1 );

		// First successful sign-in clears the "invited" marker.
		add_action( 'wp_login', array( __CLASS__, 'clear_invited' ), 10, 2 );
	}

	/* -----------------------------------------------------------------
	 * Section registration and rendering
	 * --------------------------------------------------------------- */

	/**
	 * @param array<string,array<string,mixed>> $sections Section definitions.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_section( array $sections ): array {
		if ( isset( $sections[ self::SECTION ] ) ) {
			return $sections;
		}

		$sections[ self::SECTION ] = array(
			'label'   => __( 'People', 'vulnhub' ),
			'cap'     => Caps::MANAGE,
			'group'   => 'platform',
			'order'   => 45,
			'summary' => __( 'Portal accounts, what they can do, and who still has access.', 'vulnhub' ),
		);

		return $sections;
	}

	/**
	 * @param string $section Section slug being rendered.
	 */
	public static function render_section( string $section ): void {
		if ( self::SECTION !== $section || ! current_user_can( Caps::MANAGE ) ) {
			return;
		}

		include VULNHUB_AUTH_DIR . 'admin/views/people.php';
	}

	/**
	 * URL of this section, optionally carrying a notice.
	 *
	 * @param array<string,string> $args Query arguments.
	 */
	public static function section_url( array $args = array() ): string {
		$base = array( 'section' => self::SECTION );

		if ( class_exists( 'VulnHub_Dash_Portal' ) ) {
			return VulnHub_Dash_Portal::portal_url( VulnHub_Dash_Portal::ADMIN_VIEW, array_merge( $base, $args ) );
		}

		return add_query_arg( array_merge( $base, $args ), home_url( '/portal-admin/' ) );
	}

	/* -----------------------------------------------------------------
	 * Who this screen may see and touch
	 * --------------------------------------------------------------- */

	/**
	 * The roles a portal account may hold.
	 *
	 * @return array<string,string> role slug => label.
	 */
	public static function roles(): array {
		$out = array();

		foreach ( Caps::roles() as $slug => $def ) {
			$out[ $slug ] = (string) $def['label'];
		}

		return $out;
	}

	/**
	 * Accounts this screen manages: everyone except WordPress administrators.
	 *
	 * The filter is on the capability rather than the role name, so a custom
	 * role that has been handed `manage_options` is hidden too — the test is
	 * "can this account administer WordPress", not "is it called admin".
	 *
	 * @return array<int,WP_User>
	 */
	public static function manageable(): array {
		$users = get_users(
			array(
				'number'  => 500,
				'orderby' => 'display_name',
				'order'   => 'ASC',
			)
		);

		return array_values(
			array_filter(
				$users,
				static fn( WP_User $user ): bool => ! user_can( $user, 'manage_options' )
			)
		);
	}

	/**
	 * May this screen act on that account?
	 *
	 * @param int $user_id Candidate.
	 */
	public static function is_manageable( int $user_id ): bool {
		if ( $user_id <= 0 ) {
			return false;
		}

		$user = get_userdata( $user_id );

		return $user instanceof WP_User && ! user_can( $user, 'manage_options' );
	}

	/**
	 * How many WordPress administrators exist, for the footnote that explains
	 * why the list is shorter than the account count.
	 */
	public static function hidden_count(): int {
		return count(
			array_filter(
				get_users( array( 'number' => 500 ) ),
				static fn( WP_User $user ): bool => user_can( $user, 'manage_options' )
			)
		);
	}

	/* -----------------------------------------------------------------
	 * Account state
	 * --------------------------------------------------------------- */

	/**
	 * @param WP_User $user Account.
	 */
	public static function is_suspended( WP_User $user ): bool {
		return '' !== (string) get_user_meta( $user->ID, self::SUSPENDED_META, true );
	}

	/**
	 * @param WP_User $user Account.
	 */
	public static function is_invited( WP_User $user ): bool {
		return '' !== (string) get_user_meta( $user->ID, self::INVITED_META, true );
	}

	/**
	 * The role an account holds, or the one it held before suspension.
	 *
	 * @param WP_User $user Account.
	 */
	public static function role_of( WP_User $user ): string {
		if ( self::is_suspended( $user ) ) {
			return (string) get_user_meta( $user->ID, self::SUSPENDED_META, true );
		}

		foreach ( (array) $user->roles as $role ) {
			if ( isset( self::roles()[ $role ] ) ) {
				return (string) $role;
			}
		}

		return '';
	}

	/**
	 * Stop a suspended account at the sign-in form.
	 *
	 * @param WP_User|WP_Error $user Result so far.
	 * @return WP_User|WP_Error
	 */
	public static function block_suspended( $user ) {
		if ( ! $user instanceof WP_User || ! self::is_suspended( $user ) ) {
			return $user;
		}

		return new WP_Error(
			'vulnhub_suspended',
			__( '<strong>Access suspended.</strong> This account has been suspended by an administrator.', 'vulnhub' )
		);
	}

	/**
	 * @param string  $login Username.
	 * @param WP_User $user  Account.
	 */
	public static function clear_invited( $login, $user = null ): void {
		unset( $login );

		if ( $user instanceof WP_User ) {
			delete_user_meta( $user->ID, self::INVITED_META );
		}
	}

	/**
	 * The portal's own profile fields for a person.
	 *
	 * WordPress gives us a name and an email and stops there. A security
	 * portal needs to know who to ring at 2am and which team a finding is
	 * really landing on, so those three live in user meta beside it.
	 *
	 * @param WP_User $user Account.
	 * @return array{title:string,phone:string,team_id:int}
	 */
	public static function profile( WP_User $user ): array {
		return array(
			'title'   => (string) get_user_meta( $user->ID, self::TITLE_META, true ),
			'phone'   => (string) get_user_meta( $user->ID, self::PHONE_META, true ),
			'team_id' => (int) get_user_meta( $user->ID, self::TEAM_META, true ),
		);
	}

	/**
	 * Remediation teams, for the team picker.
	 *
	 * The same table the ownership rules and Jira routing use, so a person
	 * put on a team here is on the team those already know about.
	 *
	 * @return array<int,string> team id => name.
	 */
	public static function teams(): array {
		if ( ! class_exists( '\\VulnHub\\Core\\Repo' ) ) {
			return array();
		}

		$out = array();

		foreach ( \VulnHub\Core\Repo::teams() as $team ) {
			$out[ (int) $team['id'] ] = (string) $team['name'];
		}

		return $out;
	}

	/**
	 * MFA state for a person, or null when the MFA module is unavailable.
	 *
	 * @param WP_User $user Account.
	 * @return array<string,mixed>|null
	 */
	public static function mfa( WP_User $user ): ?array {
		if ( ! class_exists( 'VulnHub_Auth_User_MFA' ) ) {
			return null;
		}

		return VulnHub_Auth_User_MFA::status( (int) $user->ID );
	}

	/* -----------------------------------------------------------------
	 * Invitations
	 * --------------------------------------------------------------- */

	/**
	 * A one-time link that lets somebody set their own password.
	 *
	 * WordPress's reset flow is used rather than a scheme of our own: the key
	 * is hashed in the database, expires on its own, and is invalidated the
	 * moment it is used. The portal's sign-in screen already sends people
	 * here for "forgotten your password", so the page is not a surprise.
	 *
	 * @param WP_User $user Recipient.
	 * @return string URL, or '' when the key could not be generated.
	 */
	public static function invite_link( WP_User $user ): string {
		$key = get_password_reset_key( $user );

		if ( is_wp_error( $key ) ) {
			return '';
		}

		return network_site_url(
			'wp-login.php?action=rp&key=' . rawurlencode( (string) $key ) . '&login=' . rawurlencode( $user->user_login ),
			'login'
		);
	}

	/**
	 * Email the invitation.
	 *
	 * @param WP_User $user    Recipient.
	 * @param string  $link    Invite link.
	 * @param bool    $is_new  New account, or a password reset for an existing one.
	 * @return bool Whether the transport accepted it.
	 */
	public static function send_invite( WP_User $user, string $link, bool $is_new ): bool {
		if ( '' === $link ) {
			return false;
		}

		$org = function_exists( 'vulnhub' )
			? (string) vulnhub()->settings->platform( 'org_name', get_bloginfo( 'name' ) )
			: get_bloginfo( 'name' );

		$subject = $is_new
			/* translators: %s: organisation name. */
			? sprintf( __( 'Your VulnHub account for %s', 'vulnhub' ), $org )
			: __( 'Set a new VulnHub password', 'vulnhub' );

		$body = $is_new
			? sprintf(
				/* translators: 1: organisation, 2: username, 3: link, 4: portal URL. */
				__(
					"An account has been created for you on the %1\$s vulnerability portal.\n\nUsername: %2\$s\n\nChoose a password using the link below. It can only be used once and expires within a day:\n\n%3\$s\n\nAfter that, sign in here:\n%4\$s\n",
					'vulnhub'
				),
				$org,
				$user->user_login,
				$link,
				class_exists( 'VulnHub_Dash_Portal' ) ? VulnHub_Dash_Portal::login_url() : home_url( '/' )
			)
			: sprintf(
				/* translators: 1: username, 2: link. */
				__(
					"A password reset was requested for your VulnHub account.\n\nUsername: %1\$s\n\nSet a new password using the link below. It can only be used once and expires within a day:\n\n%2\$s\n\nIf you did not expect this, tell your security team — the link works for whoever holds it.\n",
					'vulnhub'
				),
				$user->user_login,
				$link
			);

		return (bool) wp_mail( $user->user_email, $subject, $body );
	}

	/**
	 * The invite link to show once, immediately after a create or a resend.
	 */
	public static function pending_invite_link(): string {
		return self::$invite_link;
	}

	/* -----------------------------------------------------------------
	 * Form handling
	 * --------------------------------------------------------------- */

	/**
	 * Handle a submission.
	 *
	 * Runs on template_redirect so every state change can redirect afterwards
	 * — post/redirect/get, so a refresh never re-creates a user.
	 */
	public static function handle(): void {
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
			return;
		}
		if ( ! isset( $_POST['vh_people_action'] ) ) {
			return;
		}

		$nonce = isset( $_POST[ self::NONCE_FIELD ] )
			? sanitize_text_field( wp_unslash( $_POST[ self::NONCE_FIELD ] ) )
			: '';

		if ( ! wp_verify_nonce( $nonce, self::NONCE_ACTION ) ) {
			wp_die( esc_html__( 'That form has expired. Go back, reload the page and try again.', 'vulnhub' ), 403 );
		}
		if ( ! current_user_can( Caps::MANAGE ) ) {
			wp_die( esc_html__( 'You do not have permission to manage portal accounts.', 'vulnhub' ), 403 );
		}

		$action = sanitize_key( wp_unslash( $_POST['vh_people_action'] ) );

		switch ( $action ) {
			case 'create':
				self::do_create();
				return;

			case 'edit':
				self::do_edit();
				return;

			case 'mfa_reset':
				self::do_mfa_reset();
				return;

			case 'suspend':
			case 'reactivate':
				self::do_suspension( 'suspend' === $action );
				return;

			case 'invite':
				self::do_invite();
				return;

			case 'delete':
				self::do_delete();
				return;
		}
	}

	/**
	 * The target account of the current POST, if this screen may touch it.
	 */
	private static function target(): ?WP_User {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in handle().
		$id = isset( $_POST['user_id'] ) ? (int) $_POST['user_id'] : 0;

		if ( ! self::is_manageable( $id ) ) {
			return null;
		}

		$user = get_userdata( $id );

		return $user instanceof WP_User ? $user : null;
	}

	/**
	 * A posted string field. The nonce is verified before any of these run.
	 *
	 * @param string $key Field name.
	 */
	private static function posted( string $key ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		return isset( $_POST[ $key ] ) ? sanitize_text_field( wp_unslash( (string) $_POST[ $key ] ) ) : '';
	}

	private static function do_create(): void {
		$email = sanitize_email( self::posted( 'email' ) );
		$name  = self::posted( 'display_name' );
		$role  = self::posted( 'role' );
		$login = sanitize_user( self::posted( 'username' ), true );

		if ( ! isset( self::roles()[ $role ] ) ) {
			self::redirect( array( 'vh_error' => 'role' ) );
		}
		if ( ! is_email( $email ) ) {
			self::redirect( array( 'vh_error' => 'email' ) );
		}
		if ( email_exists( $email ) ) {
			self::redirect( array( 'vh_error' => 'email_taken' ) );
		}

		// A blank username is normal: most people are invited by email alone,
		// and the local part is a better handle than a random string.
		if ( '' === $login ) {
			$login = sanitize_user( (string) strstr( $email, '@', true ), true );
		}

		$base = $login ?: 'user';
		$try  = $base;
		$n    = 1;

		while ( username_exists( $try ) ) {
			++$n;
			$try = $base . $n;
		}

		$user_id = wp_insert_user(
			array(
				'user_login'   => $try,
				'user_email'   => $email,
				'user_pass'    => wp_generate_password( 32, true, true ),
				'display_name' => '' !== $name ? $name : $try,
				'nickname'     => '' !== $name ? $name : $try,
				'role'         => $role,
			)
		);

		if ( is_wp_error( $user_id ) ) {
			self::redirect(
				array(
					'vh_error'  => 'create',
					'vh_detail' => $user_id->get_error_message(),
				)
			);
		}

		$user = get_userdata( (int) $user_id );

		if ( ! $user instanceof WP_User ) {
			self::redirect( array( 'vh_error' => 'create' ) );
		}

		update_user_meta( $user->ID, self::INVITED_META, (string) time() );

		$link = self::invite_link( $user );
		$sent = self::send_invite( $user, $link, true );

		VulnHub_Auth_Audit::log(
			'user.created',
			sprintf(
				/* translators: 1: username, 2: role label. */
				__( 'Portal account "%1$s" created as %2$s', 'vulnhub' ),
				$user->user_login,
				self::roles()[ $role ]
			),
			$user->ID,
			array(
				'role'         => $role,
				'invite_sent'  => $sent,
				'created_by'   => get_current_user_id(),
			),
			'warning'
		);

		self::redirect(
			array(
				'vh_notice' => $sent ? 'created' : 'created_nomail',
				'vh_user'   => (string) $user->ID,
			)
		);
	}

	private static function do_edit(): void {
		$user = self::target();

		if ( ! $user ) {
			self::redirect( array( 'vh_error' => 'target' ) );
		}

		$name  = self::posted( 'display_name' );
		$email = sanitize_email( self::posted( 'email' ) );
		$role  = self::posted( 'role' );
		$title = self::posted( 'job_title' );
		$phone = self::posted( 'phone' );
		$team  = (int) self::posted( 'team_id' );

		if ( '' !== $email && ! is_email( $email ) ) {
			self::redirect( array( 'vh_error' => 'email', 'vh_edit' => (string) $user->ID ) );
		}

		// email_exists() returns the id of whoever holds it, which may be this
		// very person -- only somebody else's claim is a conflict.
		$holder = $email ? (int) email_exists( $email ) : 0;

		if ( $holder && $holder !== (int) $user->ID ) {
			self::redirect( array( 'vh_error' => 'email_taken', 'vh_edit' => (string) $user->ID ) );
		}

		$changed = array();
		$update  = array( 'ID' => (int) $user->ID );

		if ( '' !== $name && $name !== $user->display_name ) {
			$update['display_name'] = $name;
			$update['nickname']     = $name;
			$changed[]              = 'name';
		}

		if ( '' !== $email && $email !== $user->user_email ) {
			$update['user_email'] = $email;
			$changed[]            = 'email';
		}

		/*
		 * A role is the one field on this form that changes what somebody can
		 * do rather than how they are described, so it is the one field you
		 * cannot apply to yourself -- an administrator demoting themselves by
		 * accident would need another administrator to undo it.
		 */
		$current_role = self::role_of( $user );

		if ( isset( self::roles()[ $role ] ) && $role !== $current_role ) {
			if ( (int) $user->ID === get_current_user_id() ) {
				self::redirect( array( 'vh_error' => 'self_role', 'vh_edit' => (string) $user->ID ) );
			}

			// Changing the role of a suspended account changes the role they
			// will come back to, not their current (empty) one.
			if ( self::is_suspended( $user ) ) {
				update_user_meta( $user->ID, self::SUSPENDED_META, $role );
			} else {
				$user->set_role( $role );
			}

			$changed[] = 'role';
		}

		if ( count( $update ) > 1 ) {
			$result = wp_update_user( $update );

			if ( is_wp_error( $result ) ) {
				self::redirect(
					array(
						'vh_error'  => 'update',
						'vh_detail' => $result->get_error_message(),
						'vh_edit'   => (string) $user->ID,
					)
				);
			}
		}

		foreach ( array(
			self::TITLE_META => $title,
			self::PHONE_META => $phone,
		) as $meta => $value ) {
			if ( (string) get_user_meta( $user->ID, $meta, true ) === $value ) {
				continue;
			}
			if ( '' === $value ) {
				delete_user_meta( $user->ID, $meta );
			} else {
				update_user_meta( $user->ID, $meta, $value );
			}
			$changed[] = self::TITLE_META === $meta ? 'job title' : 'phone';
		}

		if ( (int) get_user_meta( $user->ID, self::TEAM_META, true ) !== $team ) {
			if ( $team > 0 && isset( self::teams()[ $team ] ) ) {
				update_user_meta( $user->ID, self::TEAM_META, $team );
			} else {
				delete_user_meta( $user->ID, self::TEAM_META );
			}
			$changed[] = 'team';
		}

		if ( ! $changed ) {
			self::redirect( array( 'vh_notice' => 'unchanged', 'vh_edit' => (string) $user->ID ) );
		}

		VulnHub_Auth_Audit::log(
			'user.updated',
			sprintf(
				/* translators: 1: username, 2: comma-separated list of fields. */
				__( '"%1$s" updated: %2$s', 'vulnhub' ),
				$user->user_login,
				implode( ', ', $changed )
			),
			$user->ID,
			array(
				'fields'     => $changed,
				'role'       => self::role_of( get_userdata( (int) $user->ID ) ?: $user ),
				'changed_by' => get_current_user_id(),
			),
			in_array( 'role', $changed, true ) || in_array( 'email', $changed, true ) ? 'warning' : 'info'
		);

		self::redirect( array( 'vh_notice' => 'updated', 'vh_edit' => (string) $user->ID ) );
	}

	/**
	 * Clear somebody's second factor so they can enrol a new device.
	 *
	 * The "I have a new phone and the old one is in a drawer" path, which had
	 * no route at all: the secret lives in user meta and only the person
	 * themselves could turn it off -- which they cannot do, because they
	 * cannot get past the challenge to reach the setting.
	 */
	private static function do_mfa_reset(): void {
		$user = self::target();

		if ( ! $user ) {
			self::redirect( array( 'vh_error' => 'target' ) );
		}
		if ( ! class_exists( 'VulnHub_Auth_User_MFA' ) ) {
			self::redirect( array( 'vh_error' => 'mfa', 'vh_edit' => (string) $user->ID ) );
		}

		VulnHub_Auth_User_MFA::disable( (int) $user->ID );

		// Their existing sessions were established under the old factor.
		WP_Session_Tokens::get_instance( (int) $user->ID )->destroy_all();

		VulnHub_Auth_Audit::log(
			'user.mfa_reset',
			sprintf(
				/* translators: %s: username. */
				__( 'Second factor cleared for "%s" — they must enrol again at next sign-in', 'vulnhub' ),
				$user->user_login
			),
			$user->ID,
			array( 'reset_by' => get_current_user_id() ),
			'warning'
		);

		self::redirect( array( 'vh_notice' => 'mfa_reset', 'vh_edit' => (string) $user->ID ) );
	}

	/**
	 * @param bool $suspend True to suspend, false to reactivate.
	 */
	private static function do_suspension( bool $suspend ): void {
		$user = self::target();

		if ( ! $user ) {
			self::redirect( array( 'vh_error' => 'target' ) );
		}
		if ( $suspend && $user->ID === get_current_user_id() ) {
			self::redirect( array( 'vh_error' => 'self_suspend' ) );
		}

		if ( $suspend ) {
			$role = self::role_of( $user );

			update_user_meta( $user->ID, self::SUSPENDED_META, $role );
			$user->set_role( '' );

			// Revoking access has to mean now, not at the next login.
			$tokens = WP_Session_Tokens::get_instance( $user->ID );
			$tokens->destroy_all();
		} else {
			$role = (string) get_user_meta( $user->ID, self::SUSPENDED_META, true );
			$role = isset( self::roles()[ $role ] ) ? $role : 'vulnhub_viewer';

			delete_user_meta( $user->ID, self::SUSPENDED_META );
			$user->set_role( $role );
		}

		VulnHub_Auth_Audit::log(
			$suspend ? 'user.suspended' : 'user.reactivated',
			sprintf(
				$suspend
					/* translators: %s: username. */
					? __( 'Access suspended for "%s"', 'vulnhub' )
					/* translators: %s: username. */
					: __( 'Access restored for "%s"', 'vulnhub' ),
				$user->user_login
			),
			$user->ID,
			array(
				'role'      => $role,
				'actioned_by' => get_current_user_id(),
			),
			'warning'
		);

		self::redirect( array( 'vh_notice' => $suspend ? 'suspended' : 'reactivated' ) );
	}

	private static function do_invite(): void {
		$user = self::target();

		if ( ! $user ) {
			self::redirect( array( 'vh_error' => 'target' ) );
		}

		$link = self::invite_link( $user );
		$sent = self::send_invite( $user, $link, self::is_invited( $user ) );

		VulnHub_Auth_Audit::log(
			'user.invite_sent',
			sprintf(
				/* translators: %s: username. */
				__( 'Password link issued for "%s"', 'vulnhub' ),
				$user->user_login
			),
			$user->ID,
			array(
				'delivered' => $sent,
				'issued_by' => get_current_user_id(),
			),
			'warning'
		);

		self::redirect(
			array(
				'vh_notice' => $sent ? 'invited' : 'invited_nomail',
				'vh_user'   => (string) $user->ID,
			)
		);
	}

	private static function do_delete(): void {
		$user = self::target();

		if ( ! $user ) {
			self::redirect( array( 'vh_error' => 'target' ) );
		}
		if ( $user->ID === get_current_user_id() ) {
			self::redirect( array( 'vh_error' => 'self_delete' ) );
		}
		if ( 'delete' !== self::posted( 'confirm' ) ) {
			self::redirect( array( 'vh_error' => 'confirm' ) );
		}

		$login = $user->user_login;
		$email = $user->user_email;
		$role  = self::role_of( $user );

		require_once ABSPATH . 'wp-admin/includes/user.php';
		wp_delete_user( $user->ID );

		VulnHub_Auth_Audit::log(
			'user.deleted',
			sprintf(
				/* translators: %s: username. */
				__( 'Portal account "%s" deleted', 'vulnhub' ),
				$login
			),
			0,
			array(
				'login'      => $login,
				'email'      => $email,
				'role'       => $role,
				'deleted_by' => get_current_user_id(),
			),
			'critical'
		);

		self::redirect( array( 'vh_notice' => 'deleted' ) );
	}

	/**
	 * @param array<string,string> $args Query arguments carrying the outcome.
	 */
	private static function redirect( array $args ): void {
		wp_safe_redirect( self::section_url( $args ) );
		exit;
	}
}

