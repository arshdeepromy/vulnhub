<?php
/**
 * The Jira routing screen: registration, form handling and rendering.
 *
 * This screen lives in the portal admin area (VulnHub → Jira routing), not in
 * wp-admin, because that is where every other VulnHub configuration task
 * happens. It is registered on the `vulnhub_portal_sections` filter and drawn
 * from `vulnhub_render_portal_section`.
 *
 * All three forms post to `admin-post.php` so the capability check, the nonce
 * check and the sanitising live in one auditable place rather than being
 * scattered through a template.
 *
 * @package VulnHub\Jira
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Portal section for Jira routing.
 */
final class VulnHub_Jira_Routing_Admin {

	/** Portal section slug. */
	public const SLUG = 'jira-routing';

	/**
	 * Register the section, its renderer and its form handlers.
	 */
	public function hooks(): void {
		add_filter( 'vulnhub_portal_sections', array( $this, 'register_section' ) );
		add_action( 'vulnhub_render_portal_section', array( $this, 'render' ) );

		add_action( 'admin_post_vulnhub_jira_routing_defaults', array( $this, 'handle_defaults' ) );
		add_action( 'admin_post_vulnhub_jira_routing_teams', array( $this, 'handle_teams' ) );
		add_action( 'admin_post_vulnhub_jira_routing_refresh', array( $this, 'handle_refresh' ) );
	}

	/**
	 * Add "Jira routing" to the portal admin navigation.
	 *
	 * @param array<string,array<string,mixed>> $sections Registered sections.
	 * @return array<string,array<string,mixed>>
	 */
	public function register_section( array $sections ): array {
		$sections[ self::SLUG ] = array(
			'label'   => __( 'Jira routing', 'vulnhub' ),
			'cap'     => \VulnHub\Core\Caps::MANAGE,
			'group'   => 'data',
			'order'   => 45,
			'summary' => __( 'Which service desk, request type and team a VulnHub ticket lands on.', 'vulnhub' ),
		);

		return $sections;
	}

	/**
	 * Render the section when the portal asks for ours.
	 *
	 * @param string $section Section slug being rendered.
	 */
	public function render( string $section ): void {
		if ( self::SLUG !== $section ) {
			return;
		}

		if ( ! current_user_can( \VulnHub\Core\Caps::MANAGE ) ) {
			echo '<div class="vh-panel"><p class="vh-sub">'
				. esc_html__( 'You do not have permission to change Jira routing.', 'vulnhub' )
				. '</p></div>';
			return;
		}

		vulnhub_jira_load();

		include VULNHUB_JIRA_DIR . 'admin/views/portal-jira-routing.php';
	}

	/* =================================================================
	 * Shared plumbing
	 * ============================================================== */

	/**
	 * Refuse anyone without the platform management capability.
	 */
	private function guard(): void {
		if ( ! current_user_can( \VulnHub\Core\Caps::MANAGE ) ) {
			wp_die(
				esc_html__( 'You do not have permission to change Jira routing.', 'vulnhub' ),
				'',
				array( 'response' => 403 )
			);
		}
	}

	/**
	 * The URL of the routing screen itself.
	 *
	 * @param array<string,mixed> $args Extra query arguments.
	 */
	public static function screen_url( array $args = array() ): string {
		$args = array_merge( array( 'section' => self::SLUG ), $args );

		if ( class_exists( 'VulnHub_Dash_Portal' ) ) {
			return VulnHub_Dash_Portal::portal_url( VulnHub_Dash_Portal::ADMIN_VIEW, $args );
		}

		return add_query_arg( $args, home_url( '/' ) );
	}

	/**
	 * Go back to the screen the form was submitted from, with a notice.
	 *
	 * @param string $message Notice text.
	 * @param string $type    success|warning|error.
	 */
	private function back( string $message, string $type = 'success' ): void {
		$referer = wp_get_referer();
		$base    = $referer ? remove_query_arg( array( 'vh_msg', 'vh_type' ), $referer ) : self::screen_url();

		wp_safe_redirect(
			add_query_arg(
				array(
					'vh_msg'  => rawurlencode( $message ),
					'vh_type' => $type,
				),
				$base
			)
		);
		exit;
	}

	/**
	 * The connector, or a redirect explaining why there is not one.
	 */
	private function connector(): VulnHub_Jira_Connector {
		$connector = vulnhub_jira_connector();

		if ( ! $connector ) {
			$this->back( __( 'The Jira connector is not registered, so there is nothing to configure.', 'vulnhub' ), 'error' );
		}

		return $connector;
	}

	/* =================================================================
	 * Default routing
	 * ============================================================== */

	/**
	 * Save the default service desk, request type, team and Team field id.
	 */
	public function handle_defaults(): void {
		$this->guard();
		check_admin_referer( 'vulnhub_jira_routing_defaults' );

		$connector = $this->connector();

		$desk       = isset( $_POST['default_service_desk'] ) ? sanitize_text_field( wp_unslash( $_POST['default_service_desk'] ) ) : '';
		$type       = isset( $_POST['default_request_type'] ) ? sanitize_text_field( wp_unslash( $_POST['default_request_type'] ) ) : '';
		$team       = isset( $_POST['default_team'] ) ? sanitize_text_field( wp_unslash( $_POST['default_team'] ) ) : '';
		$field      = isset( $_POST['team_field'] ) ? sanitize_text_field( wp_unslash( $_POST['team_field'] ) ) : '';
		$project    = isset( $_POST['project_key'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_POST['project_key'] ) ) ) : '';
		$directory  = new VulnHub_Jira_Directory( $connector );
		$request_ok = true;

		// A request type only means anything inside its own desk, so refuse a
		// pairing that Jira itself would reject at ticket time.
		if ( '' !== $type ) {
			$resolved = $directory->request_type( $type, $desk );

			if ( ! $resolved ) {
				$request_ok = false;
				$type       = '';
			}
		}

		vulnhub()->settings->update(
			$connector->id(),
			array(
				'default_service_desk' => $desk,
				'default_request_type' => $type,
				'default_team'         => $team,
				'team_field'           => $field,
				'project_key'          => $project,
			)
		);

		vulnhub()->logger->audit(
			'jira.routing.defaults',
			sprintf(
				/* translators: 1: service desk id, 2: request type id, 3: team value, 4: project key. */
				__( 'Default Jira routing saved: service desk "%1$s", request type "%2$s", team "%3$s", fallback project "%4$s".', 'vulnhub' ),
				$desk ?: '—',
				$type ?: '—',
				$team ?: '—',
				$project ?: '—'
			),
			'connector',
			0,
			array(
				'service_desk' => $desk,
				'request_type' => $type,
				'team'         => $team,
				'team_field'   => $field,
				'project_key'  => $project,
			)
		);

		if ( ! $request_ok ) {
			$this->back(
				__( 'Saved, but the request type was cleared: it does not belong to the selected service desk.', 'vulnhub' ),
				'warning'
			);
		}

		$this->back( __( 'Default Jira routing saved.', 'vulnhub' ) );
	}

	/* =================================================================
	 * Per-team routing
	 * ============================================================== */

	/**
	 * Save the per-team routing table.
	 *
	 * The project key and issue type are written back to core's `teams` table,
	 * which is where per-team Jira routing already lives and which continues to
	 * win over the defaults. The request type and Team value have no column
	 * there, so they go into this connector's own settings blob.
	 */
	public function handle_teams(): void {
		global $wpdb;

		$this->guard();
		check_admin_referer( 'vulnhub_jira_routing_teams' );

		$connector = $this->connector();

		$projects = isset( $_POST['project'] ) ? (array) wp_unslash( $_POST['project'] ) : array();
		$types    = isset( $_POST['issue_type'] ) ? (array) wp_unslash( $_POST['issue_type'] ) : array();
		$requests = isset( $_POST['request_type'] ) ? (array) wp_unslash( $_POST['request_type'] ) : array();
		$teams    = isset( $_POST['team_value'] ) ? (array) wp_unslash( $_POST['team_value'] ) : array();

		$map     = $connector->team_routing();
		$changed = 0;

		foreach ( \VulnHub\Core\Repo::teams() as $team ) {
			$id = (int) $team['id'];

			$project = isset( $projects[ $id ] ) ? strtoupper( sanitize_text_field( (string) $projects[ $id ] ) ) : '';
			$type    = isset( $types[ $id ] ) ? sanitize_text_field( (string) $types[ $id ] ) : '';
			$request = isset( $requests[ $id ] ) ? sanitize_text_field( (string) $requests[ $id ] ) : '';
			$value   = isset( $teams[ $id ] ) ? sanitize_text_field( (string) $teams[ $id ] ) : '';

			if ( $project !== (string) $team['jira_project_key'] || $type !== (string) $team['jira_issue_type'] ) {
				$wpdb->update(
					vh_table( 'teams' ),
					array(
						'jira_project_key' => $project,
						'jira_issue_type'  => $type,
						'updated_at'       => vh_now(),
					),
					array( 'id' => $id ),
					array( '%s', '%s', '%s' ),
					array( '%d' )
				);

				++$changed;
			}

			// A request type is stored with the desk it belongs to, so the
			// ticketer never has to guess which desk an id came from.
			$desk = '';

			if ( '' !== $request ) {
				$resolved = ( new VulnHub_Jira_Directory( $connector ) )->request_type( $request );
				$desk     = $resolved ? (string) $resolved['desk_id'] : '';

				if ( ! $resolved ) {
					$request = '';
				}
			}

			$before = $map[ $id ] ?? array(
				'service_desk' => '',
				'request_type' => '',
				'team_value'   => '',
			);

			$after = array(
				'service_desk' => $desk,
				'request_type' => $request,
				'team_value'   => $value,
			);

			if ( $before !== $after ) {
				++$changed;
			}

			$map[ $id ] = $after;
		}

		$connector->save_team_routing( $map );

		vulnhub()->logger->audit(
			'jira.routing.teams',
			sprintf(
				/* translators: %d: number of teams whose routing changed. */
				_n(
					'Per-team Jira routing updated: %d change.',
					'Per-team Jira routing updated: %d changes.',
					$changed,
					'vulnhub'
				),
				$changed
			),
			'connector',
			0,
			array( 'changes' => $changed )
		);

		$this->back(
			$changed
				? sprintf(
					/* translators: %d: number of changes. */
					_n( 'Per-team routing saved (%d change).', 'Per-team routing saved (%d changes).', $changed, 'vulnhub' ),
					$changed
				)
				: __( 'Per-team routing saved; nothing had changed.', 'vulnhub' )
		);
	}

	/* =================================================================
	 * Refresh
	 * ============================================================== */

	/**
	 * Throw the cached directory away and fetch it again.
	 */
	public function handle_refresh(): void {
		$this->guard();
		check_admin_referer( 'vulnhub_jira_routing_refresh' );

		$connector = $this->connector();
		$directory = new VulnHub_Jira_Directory( $connector );

		$directory->forget();
		$snapshot = $directory->snapshot( true );

		$desks = count( (array) ( $snapshot['service_desks'] ?? array() ) );
		$types = 0;

		foreach ( (array) ( $snapshot['request_types'] ?? array() ) as $bucket ) {
			$types += count( (array) $bucket );
		}

		if ( ! empty( $snapshot['errors'] ) ) {
			$this->back( vh_trim( implode( ' ', (array) $snapshot['errors'] ), 300 ), 'error' );
		}

		$this->back(
			sprintf(
				/* translators: 1: service desks, 2: request types, 3: projects, 4: team values. */
				__( 'Refreshed from Jira: %1$d service desk(s), %2$d request type(s), %3$d project(s) and %4$d team value(s).', 'vulnhub' ),
				$desks,
				$types,
				count( (array) ( $snapshot['projects'] ?? array() ) ),
				count( (array) ( $snapshot['team_field']['options'] ?? array() ) )
			)
		);
	}
}

