<?php
/**
 * Admin portal: menu, screen routing, form handling.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Admin {

	public const SLUG = 'vulnhub';

	public function __construct() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		// The portal mirrors these screens on the front end, where
		// `admin_enqueue_scripts` never fires -- so the Test and Sync buttons
		// had no JavaScript behind them and did nothing at all when pressed.
		add_action( 'wp_enqueue_scripts', array( $this, 'portal_assets' ) );
		add_action( 'admin_post_vulnhub_save_connector', array( $this, 'handle_save_connector' ) );
		add_action( 'admin_post_vulnhub_save_platform', array( $this, 'handle_save_platform' ) );
		add_action( 'admin_post_vulnhub_save_rule', array( $this, 'handle_save_rule' ) );
		add_action( 'admin_post_vulnhub_delete_rule', array( $this, 'handle_delete_rule' ) );
		add_action( 'admin_post_vulnhub_save_team', array( $this, 'handle_save_team' ) );
		add_action( 'admin_post_vulnhub_save_eol', array( $this, 'handle_save_eol' ) );
		add_action( 'admin_post_vulnhub_delete_eol', array( $this, 'handle_delete_eol' ) );
		add_action( 'admin_post_vulnhub_reset_eol', array( $this, 'handle_reset_eol' ) );
		add_action( 'admin_post_vulnhub_connector_action', array( $this, 'handle_connector_action' ) );
		add_action( 'admin_notices', array( $this, 'notices' ) );
	}

	/**
	 * Screens registered by core. Integration plugins can add more via the
	 * `vulnhub_admin_pages` filter.
	 *
	 * @return array<string,array{title:string,menu:string,cap:string,view:string,position?:int}>
	 */
	public function pages(): array {
		$pages = array(
			'vulnhub'             => array(
				'title' => __( 'VulnHub Overview', 'vulnhub' ),
				'menu'  => __( 'Overview', 'vulnhub' ),
				'cap'   => Caps::VIEW,
				'view'  => 'overview',
			),
			'vulnhub-findings'    => array(
				'title' => __( 'Vulnerabilities', 'vulnhub' ),
				'menu'  => __( 'Vulnerabilities', 'vulnhub' ),
				'cap'   => Caps::VIEW,
				'view'  => 'findings',
			),
			'vulnhub-assets'      => array(
				'title' => __( 'Assets', 'vulnhub' ),
				'menu'  => __( 'Assets', 'vulnhub' ),
				'cap'   => Caps::VIEW,
				'view'  => 'assets',
			),
			'vulnhub-ownership'   => array(
				'title' => __( 'Ownership mapping', 'vulnhub' ),
				'menu'  => __( 'Ownership', 'vulnhub' ),
				'cap'   => Caps::VIEW,
				'view'  => 'ownership',
			),
			'vulnhub-tickets'     => array(
				'title' => __( 'Tickets', 'vulnhub' ),
				'menu'  => __( 'Tickets', 'vulnhub' ),
				'cap'   => Caps::VIEW,
				'view'  => 'tickets',
			),
			'vulnhub-exceptions'  => array(
				'title' => __( 'Exceptions', 'vulnhub' ),
				'menu'  => __( 'Exceptions', 'vulnhub' ),
				'cap'   => Caps::VIEW,
				'view'  => 'exceptions',
			),
			'vulnhub-lifecycle'   => array(
				'title' => __( 'End of life', 'vulnhub' ),
				'menu'  => __( 'End of life', 'vulnhub' ),
				'cap'   => Caps::MANAGE,
				'view'  => 'lifecycle',
			),
			'vulnhub-integrations' => array(
				'title' => __( 'Integrations', 'vulnhub' ),
				'menu'  => __( 'Integrations', 'vulnhub' ),
				'cap'   => Caps::MANAGE,
				'view'  => 'integrations',
			),
			'vulnhub-sync'        => array(
				'title' => __( 'Sync activity', 'vulnhub' ),
				'menu'  => __( 'Sync activity', 'vulnhub' ),
				'cap'   => Caps::VIEW,
				'view'  => 'sync',
			),
			'vulnhub-audit'       => array(
				'title' => __( 'Audit trail', 'vulnhub' ),
				'menu'  => __( 'Audit trail', 'vulnhub' ),
				'cap'   => Caps::VIEW_AUDIT,
				'view'  => 'audit',
			),
			'vulnhub-settings'    => array(
				'title' => __( 'Settings', 'vulnhub' ),
				'menu'  => __( 'Settings', 'vulnhub' ),
				'cap'   => Caps::MANAGE,
				'view'  => 'settings',
			),
		);

		/**
		 * Filters the VulnHub admin screens.
		 *
		 * @param array<string,array<string,mixed>> $pages Screen definitions.
		 */
		return (array) apply_filters( 'vulnhub_admin_pages', $pages );
	}

	public function menu(): void {
		$summary = function_exists( 'vh_table' ) ? Repo::summary() : array();
		$pending = (int) ( $summary['exceptions_open'] ?? 0 ) + (int) ( $summary['verify_failed'] ?? 0 );
		$bubble  = $pending ? sprintf( ' <span class="awaiting-mod"><span class="pending-count">%d</span></span>', $pending ) : '';

		add_menu_page(
			__( 'VulnHub', 'vulnhub' ),
			__( 'VulnHub', 'vulnhub' ) . $bubble,
			Caps::VIEW,
			self::SLUG,
			array( $this, 'render' ),
			'dashicons-shield-alt',
			3
		);

		foreach ( $this->pages() as $slug => $page ) {
			add_submenu_page(
				self::SLUG,
				(string) $page['title'],
				(string) $page['menu'],
				(string) $page['cap'],
				$slug,
				array( $this, 'render' )
			);
		}
	}

	public function assets( string $hook ): void {
		if ( ! str_contains( $hook, 'vulnhub' ) ) {
			return;
		}

		$this->register_assets();
		wp_enqueue_style( 'vulnhub-admin' );
		wp_enqueue_script( 'vulnhub-admin' );
	}

	/**
	 * The same behaviour, on the portal's own admin area.
	 *
	 * `/portal-admin/` renders these very screens through `render_screen()`,
	 * connector cards and all -- but it is a front-end page, so nothing here
	 * was ever enqueued and every Test and Sync button on it was inert:
	 * pressed, and nothing happened, with no error to explain why. Only the
	 * script goes over; the portal has its own stylesheet and admin.css
	 * would fight it.
	 */
	public function portal_assets(): void {
		if ( ! class_exists( 'VulnHub_Dash_Portal' ) || ! class_exists( 'VulnHub_Dash_App' ) ) {
			return;
		}
		if ( \VulnHub_Dash_App::view_for_post( get_post() ) !== \VulnHub_Dash_Portal::ADMIN_VIEW ) {
			return;
		}

		$this->register_assets();
		wp_enqueue_script( 'vulnhub-admin' );
	}

	/**
	 * Register the shared admin assets and their configuration.
	 *
	 * Split out of `assets()` so the portal can enqueue exactly the same
	 * script with exactly the same REST root and nonce.
	 */
	private function register_assets(): void {
		if ( wp_script_is( 'vulnhub-admin', 'registered' ) ) {
			return;
		}

		wp_register_style( 'vulnhub-admin', VULNHUB_URL . 'admin/assets/admin.css', array(), VULNHUB_VERSION );
		wp_register_script( 'vulnhub-admin', VULNHUB_URL . 'admin/assets/admin.js', array( 'wp-api-fetch' ), VULNHUB_VERSION, true );

		wp_localize_script(
			'vulnhub-admin',
			'VulnHubAdmin',
			array(
				'root'     => esc_url_raw( rest_url( Rest::NS ) ),
				'nonce'    => wp_create_nonce( 'wp_rest' ),
				'adminUrl' => admin_url( 'admin.php' ),
				'i18n'     => array(
					'testing'      => __( 'Testing…', 'vulnhub' ),
					'syncing'      => __( 'Syncing…', 'vulnhub' ),
					'genericError' => __( 'Something went wrong. Check the sync log for detail.', 'vulnhub' ),
					'confirmSync'  => __( 'Run a sync now?', 'vulnhub' ),
				),
			)
		);
	}

	public function render(): void {
		$slug  = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : self::SLUG; // phpcs:ignore WordPress.Security.NonceVerification
		$pages = $this->pages();
		$page  = $pages[ $slug ] ?? $pages['vulnhub'];

		if ( ! current_user_can( (string) $page['cap'] ) ) {
			wp_die( esc_html__( 'You do not have permission to view this screen.', 'vulnhub' ) );
		}

		echo '<div class="wrap vulnhub-wrap">';
		$this->header( (string) $page['title'], $slug );
		$this->render_screen( $slug );
		echo '</div>';
	}

	/**
	 * Draw one screen's body, with no wp-admin chrome around it.
	 *
	 * Split out of render() so the front-end portal can mirror a screen
	 * without reimplementing it. Everything VulnHub can be configured from is
	 * therefore configurable from the portal by construction, rather than by
	 * someone remembering to port each new screen across.
	 */
	public function render_screen( string $slug ): void {
		$pages = $this->pages();
		$page  = $pages[ $slug ] ?? null;

		if ( ! $page || ! current_user_can( (string) $page['cap'] ) ) {
			return;
		}

		$view = VULNHUB_DIR . 'admin/views/' . (string) $page['view'] . '.php';

		if ( is_readable( $view ) ) {
			self::load_admin_helpers();
			include $view;
			return;
		}

		/*
		 * A screen belonging to another plugin needs the same wp-admin
		 * furniture core's own views do. Without this the Authentication
		 * screen rendered its whole first half in the portal and then died
		 * on `submit_button()`, because nothing had loaded it.
		 */
		self::load_admin_helpers();

		/**
		 * Lets an integration plugin render its own registered screen.
		 *
		 * @param string $slug Screen slug.
		 */
		do_action( 'vulnhub_render_admin_page', $slug );
	}

	/**
	 * Make wp-admin's view helpers available outside wp-admin.
	 *
	 * The screens under `admin/views/` were written for wp-admin and use its
	 * furniture -- `submit_button()`, `add_settings_error()`, the list-table
	 * base class. WordPress only loads `wp-admin/includes/*` on admin
	 * requests, so mirroring a screen into the portal produced a page that
	 * rendered perfectly until the first `submit_button()` and then died with
	 * a fatal. Loading the two files those helpers live in is far cheaper than
	 * rewriting fifteen screens, and it is scoped to the moment a screen is
	 * actually being drawn.
	 */
	private static function load_admin_helpers(): void {
		if ( function_exists( 'submit_button' ) ) {
			return;
		}

		require_once ABSPATH . 'wp-admin/includes/screen.php';
		require_once ABSPATH . 'wp-admin/includes/template.php';
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/misc.php';
	}

	private function header( string $title, string $slug ): void {
		$summary = Repo::summary();
		?>
		<div class="vh-header">
			<div class="vh-header__title">
				<span class="dashicons dashicons-shield-alt"></span>
				<h1><?php echo esc_html( $title ); ?></h1>
			</div>
			<div class="vh-header__stats">
				<a class="vh-stat vh-stat--critical" href="<?php echo esc_url( vh_admin_url( 'vulnhub-findings', array( 'severity' => 'critical' ) ) ); ?>">
					<strong><?php echo esc_html( number_format_i18n( (int) $summary['critical'] ) ); ?></strong>
					<span><?php esc_html_e( 'Critical', 'vulnhub' ); ?></span>
				</a>
				<a class="vh-stat vh-stat--high" href="<?php echo esc_url( vh_admin_url( 'vulnhub-findings', array( 'severity' => 'high' ) ) ); ?>">
					<strong><?php echo esc_html( number_format_i18n( (int) $summary['high'] ) ); ?></strong>
					<span><?php esc_html_e( 'High', 'vulnhub' ); ?></span>
				</a>
				<a class="vh-stat" href="<?php echo esc_url( vh_admin_url( 'vulnhub-assets' ) ); ?>">
					<strong><?php echo esc_html( number_format_i18n( (int) $summary['assets_total'] ) ); ?></strong>
					<span><?php esc_html_e( 'Assets', 'vulnhub' ); ?></span>
				</a>
				<a class="vh-stat" href="<?php echo esc_url( vh_admin_url( 'vulnhub-tickets' ) ); ?>">
					<strong><?php echo esc_html( number_format_i18n( (int) $summary['tickets_open'] ) ); ?></strong>
					<span><?php esc_html_e( 'Open tickets', 'vulnhub' ); ?></span>
				</a>
				<?php if ( vulnhub()->settings->mock_mode() ) : ?>
					<span class="vh-badge vh-badge--mock" title="<?php esc_attr_e( 'The platform is running on generated sample data. Add real credentials in Integrations to go live.', 'vulnhub' ); ?>">
						<?php esc_html_e( 'Mock data', 'vulnhub' ); ?>
					</span>
				<?php endif; ?>
			</div>
		</div>
		<?php
		unset( $slug );
	}

	/* -----------------------------------------------------------------
	 * Notices
	 * --------------------------------------------------------------- */

	public function notices(): void {
		if ( ! isset( $_GET['page'] ) || ! str_starts_with( sanitize_key( wp_unslash( $_GET['page'] ) ), 'vulnhub' ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			return;
		}

		$message = isset( $_GET['vh_msg'] ) ? sanitize_text_field( wp_unslash( $_GET['vh_msg'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		$type    = isset( $_GET['vh_type'] ) ? sanitize_key( wp_unslash( $_GET['vh_type'] ) ) : 'success'; // phpcs:ignore WordPress.Security.NonceVerification

		if ( $message ) {
			printf(
				'<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>',
				esc_attr( in_array( $type, array( 'success', 'error', 'warning', 'info' ), true ) ? $type : 'info' ),
				esc_html( $message )
			);
		}

		if ( ! Crypto::using_config_key() && current_user_can( Caps::MANAGE ) ) {
			printf(
				'<div class="notice notice-warning"><p><strong>%s</strong> %s</p></div>',
				esc_html__( 'VulnHub:', 'vulnhub' ),
				esc_html__( 'No VULNHUB_ENCRYPTION_KEY is defined in wp-config.php, so connector credentials are encrypted with a key stored in the database. Define the constant and re-enter your credentials for a stronger posture.', 'vulnhub' )
			);
		}
	}

	private function redirect( string $page, string $message, string $type = 'success', array $extra = array() ): void {
		wp_safe_redirect(
			vh_admin_url(
				$page,
				array_merge(
					$extra,
					array(
						'vh_msg'  => $message,
						'vh_type' => $type,
					)
				)
			)
		);
		exit;
	}

	private function guard( string $action, string $cap = Caps::MANAGE ): void {
		if ( ! current_user_can( $cap ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $action );
	}

	/* -----------------------------------------------------------------
	 * Form handlers
	 * --------------------------------------------------------------- */

	public function handle_save_connector(): void {
		$this->guard( 'vulnhub_save_connector' );

		$id        = isset( $_POST['connector'] ) ? sanitize_key( wp_unslash( $_POST['connector'] ) ) : '';
		$connector = vulnhub()->connectors->get( $id );

		if ( ! $connector ) {
			$this->redirect( 'vulnhub-integrations', __( 'Unknown connector.', 'vulnhub' ), 'error' );
		}

		$values = array(
			'enabled'  => isset( $_POST['enabled'] ) ? 1 : 0,
			'mock'     => isset( $_POST['mock'] ) ? 1 : 0,
			'interval' => isset( $_POST['interval'] ) ? sanitize_key( wp_unslash( $_POST['interval'] ) ) : 'vh_hourly',
		);

		foreach ( $connector->fields() as $field ) {
			$key  = (string) $field['key'];
			$name = 'vh_' . $key;

			if ( ! empty( $field['secret'] ) ) {
				if ( isset( $_POST[ 'clear_' . $key ] ) ) {
					vulnhub()->settings->set_secret( $id, $key, null );
					continue;
				}
				if ( isset( $_POST[ $name ] ) ) {
					vulnhub()->settings->set_secret( $id, $key, (string) wp_unslash( $_POST[ $name ] ) );
				}
				continue;
			}

			if ( 'checkbox' === ( $field['type'] ?? 'text' ) ) {
				$values[ $key ] = isset( $_POST[ $name ] ) ? 1 : 0;
				continue;
			}
			if ( ! isset( $_POST[ $name ] ) ) {
				continue;
			}

			$raw = wp_unslash( $_POST[ $name ] );
			switch ( $field['type'] ?? 'text' ) {
				case 'textarea':
					$values[ $key ] = sanitize_textarea_field( (string) $raw );
					break;
				case 'number':
					$values[ $key ] = (int) $raw;
					break;
				case 'url':
					$values[ $key ] = esc_url_raw( (string) $raw );
					break;
				case 'email':
					$values[ $key ] = sanitize_email( (string) $raw );
					break;
				default:
					$values[ $key ] = sanitize_text_field( (string) $raw );
			}
		}

		vulnhub()->settings->update( $id, $values );
		vulnhub()->scheduler->ensure_schedules();

		vulnhub()->logger->audit(
			'connector.saved',
			sprintf(
				/* translators: %s: connector label. */
				__( '%s settings updated', 'vulnhub' ),
				$connector->label()
			),
			'connector',
			$id,
			array(
				'enabled' => $values['enabled'],
				'mock'    => $values['mock'],
			)
		);

		$this->redirect(
			'vulnhub-integrations',
			sprintf(
				/* translators: %s: connector label. */
				__( '%s settings saved.', 'vulnhub' ),
				$connector->label()
			),
			'success',
			array( 'connector' => $id )
		);
	}

	public function handle_connector_action(): void {
		$this->guard( 'vulnhub_connector_action', Caps::RUN_SYNC );

		$id        = isset( $_POST['connector'] ) ? sanitize_key( wp_unslash( $_POST['connector'] ) ) : '';
		$do        = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
		$connector = vulnhub()->connectors->get( $id );

		if ( ! $connector ) {
			$this->redirect( 'vulnhub-integrations', __( 'Unknown connector.', 'vulnhub' ), 'error' );
		}

		if ( 'test' === $do ) {
			$result = $connector->test_connection();
			$this->redirect(
				'vulnhub-integrations',
				(string) $result['message'],
				! empty( $result['ok'] ) ? 'success' : 'error',
				array( 'connector' => $id )
			);
		}

		if ( 'sync' === $do ) {
			$result = $connector->sync(
				array(
					'mode'  => 'manual',
					'force' => true,
				)
			);
			$this->redirect(
				'vulnhub-integrations',
				(string) $result['message'],
				! empty( $result['ok'] ) ? 'success' : 'error',
				array( 'connector' => $id )
			);
		}

		$this->redirect( 'vulnhub-integrations', __( 'Unknown action.', 'vulnhub' ), 'error' );
	}

	public function handle_save_platform(): void {
		$this->guard( 'vulnhub_save_platform' );

		$values = array(
			'mock_mode'          => isset( $_POST['mock_mode'] ) ? 1 : 0,
			'log_retention_days' => isset( $_POST['log_retention_days'] ) ? max( 7, (int) $_POST['log_retention_days'] ) : 120,
			'org_name'           => isset( $_POST['org_name'] ) ? sanitize_text_field( wp_unslash( $_POST['org_name'] ) ) : '',
			'auto_verify_hours'  => isset( $_POST['auto_verify_hours'] ) ? max( 1, (int) $_POST['auto_verify_hours'] ) : 24,
			'require_user_on_workstation' => isset( $_POST['require_user_on_workstation'] ) ? 1 : 0,
			'sla_source'         => isset( $_POST['sla_source'] ) ? sanitize_key( wp_unslash( $_POST['sla_source'] ) ) : 'team',
			'import_date_order'  => isset( $_POST['import_date_order'] ) && in_array( $_POST['import_date_order'], array( 'auto', 'dmy', 'mdy' ), true )
				? sanitize_key( wp_unslash( $_POST['import_date_order'] ) )
				: 'auto',
		);

		/*
		 * Coverage scope and the freshness window both change what every
		 * coverage figure on the platform means, so they are saved together
		 * and the estate is recomputed below rather than drifting until the
		 * next nightly run.
		 */
		$scope = isset( $_POST['coverage_scope'] ) && is_array( $_POST['coverage_scope'] )
			? array_values( array_intersect( array_map( 'sanitize_key', wp_unslash( $_POST['coverage_scope'] ) ), array_keys( vh_lifecycle_statuses() ) ) )
			: array();

		/*
		 * Reporting scope: which assets every widget counts. Saved the same
		 * way and validated against the same vocabulary, but kept as its own
		 * option -- an administrator narrowing what Tenable is expected to
		 * scan must not silently change what the dashboard reports.
		 */
		$reporting = isset( $_POST['reporting_scope'] ) && is_array( $_POST['reporting_scope'] )
			? array_values( array_intersect( array_map( 'sanitize_key', wp_unslash( $_POST['reporting_scope'] ) ), array_keys( vh_lifecycle_statuses() ) ) )
			: array();

		$window  = isset( $_POST['coverage_window_days'] ) ? max( 1, min( 365, (int) $_POST['coverage_window_days'] ) ) : 30;
		$contact = isset( $_POST['contact_window_days'] ) ? max( 1, min( 730, (int) $_POST['contact_window_days'] ) ) : 45;

		$before = array(
			'scope'     => vh_scannable_statuses(),
			'reporting' => vh_reportable_statuses(),
			'window'    => \VulnHub\Core\Coverage::window_days(),
			'contact'   => \VulnHub\Core\Coverage::contact_days(),
		);

		$values['coverage_scope']       = $scope;
		$values['reporting_scope']      = $reporting;
		$values['coverage_window_days'] = $window;
		$values['contact_window_days']  = $contact;

		vulnhub()->settings->update_platform( $values );

		if ( $before['scope'] !== vh_scannable_statuses()
			|| $before['window'] !== \VulnHub\Core\Coverage::window_days()
			|| $before['contact'] !== \VulnHub\Core\Coverage::contact_days() ) {
			\VulnHub\Core\Coverage::recalculate();

			if ( class_exists( 'VulnHub_Dash_Widgets' ) ) {
				\VulnHub_Dash_Widgets::bust();
			}
		}

		/*
		 * The reporting scope needs no coverage recalculation -- it is applied
		 * at query time, not stored on the row -- but every widget has its
		 * rendered markup cached, so without this the board keeps drawing the
		 * old denominator until the cache expires.
		 */
		if ( $before['reporting'] !== vh_reportable_statuses() && class_exists( 'VulnHub_Dash_Widgets' ) ) {
			\VulnHub_Dash_Widgets::bust();
		}
		vulnhub()->logger->audit( 'platform.settings_saved', __( 'Platform settings updated', 'vulnhub' ), 'platform', '', $values );

		$this->redirect( 'vulnhub-settings', __( 'Settings saved.', 'vulnhub' ) );
	}

	public function handle_save_rule(): void {
		global $wpdb;
		$this->guard( 'vulnhub_save_rule' );

		$id  = isset( $_POST['rule_id'] ) ? (int) $_POST['rule_id'] : 0;
		$row = array(
			'name'            => isset( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : '',
			'enabled'         => isset( $_POST['enabled'] ) ? 1 : 0,
			'priority'        => isset( $_POST['priority'] ) ? (int) $_POST['priority'] : 10,
			'match_field'     => isset( $_POST['match_field'] ) ? sanitize_text_field( wp_unslash( $_POST['match_field'] ) ) : 'asset_type',
			'match_operator'  => isset( $_POST['match_operator'] ) ? sanitize_key( wp_unslash( $_POST['match_operator'] ) ) : 'equals',
			'match_value'     => isset( $_POST['match_value'] ) ? sanitize_text_field( wp_unslash( $_POST['match_value'] ) ) : '',
			'assign_type'     => isset( $_POST['assign_type'] ) ? sanitize_key( wp_unslash( $_POST['assign_type'] ) ) : 'team',
			'assign_value'    => isset( $_POST['assign_value'] ) ? sanitize_text_field( wp_unslash( $_POST['assign_value'] ) ) : '',
			'stop_processing' => isset( $_POST['stop_processing'] ) ? 1 : 0,
			'updated_at'      => vh_now(),
		);

		if ( '' === $row['name'] ) {
			$this->redirect( 'vulnhub-ownership', __( 'Give the rule a name.', 'vulnhub' ), 'error' );
		}

		if ( $id ) {
			$wpdb->update( vh_table( 'mapping_rules' ), $row, array( 'id' => $id ) );
		} else {
			$row['created_at'] = vh_now();
			$wpdb->insert( vh_table( 'mapping_rules' ), $row );
			$id = (int) $wpdb->insert_id;
		}

		vulnhub()->logger->audit( 'mapping.rule_saved', sprintf( 'Mapping rule "%s" saved', $row['name'] ), 'mapping_rule', $id, $row );

		$result = ( new Mapping() )->run();

		$this->redirect(
			'vulnhub-ownership',
			sprintf(
				/* translators: 1: assets processed, 2: assets changed. */
				__( 'Rule saved. Re-mapped %1$d assets, %2$d changed.', 'vulnhub' ),
				(int) $result['processed'],
				(int) $result['changed']
			)
		);
	}

	public function handle_delete_rule(): void {
		global $wpdb;
		$this->guard( 'vulnhub_delete_rule' );

		$id = isset( $_POST['rule_id'] ) ? (int) $_POST['rule_id'] : 0;
		if ( $id ) {
			$wpdb->delete( vh_table( 'mapping_rules' ), array( 'id' => $id ) );
			vulnhub()->logger->audit( 'mapping.rule_deleted', 'Mapping rule deleted', 'mapping_rule', $id );
		}

		$this->redirect( 'vulnhub-ownership', __( 'Rule deleted.', 'vulnhub' ) );
	}

	public function handle_save_team(): void {
		global $wpdb;
		$this->guard( 'vulnhub_save_team' );

		$id  = isset( $_POST['team_id'] ) ? (int) $_POST['team_id'] : 0;
		$row = array(
			'name'                  => isset( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : '',
			'jira_project_key'      => isset( $_POST['jira_project_key'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_POST['jira_project_key'] ) ) ) : '',
			'jira_default_assignee' => isset( $_POST['jira_default_assignee'] ) ? sanitize_text_field( wp_unslash( $_POST['jira_default_assignee'] ) ) : '',
			'jira_issue_type'       => isset( $_POST['jira_issue_type'] ) ? sanitize_text_field( wp_unslash( $_POST['jira_issue_type'] ) ) : '',
			'manager_email'         => isset( $_POST['manager_email'] ) ? sanitize_email( wp_unslash( $_POST['manager_email'] ) ) : '',
			'sla_critical_days'     => isset( $_POST['sla_critical_days'] ) ? max( 1, (int) $_POST['sla_critical_days'] ) : 7,
			'sla_high_days'         => isset( $_POST['sla_high_days'] ) ? max( 1, (int) $_POST['sla_high_days'] ) : 30,
			'sla_medium_days'       => isset( $_POST['sla_medium_days'] ) ? max( 1, (int) $_POST['sla_medium_days'] ) : 90,
			'sla_low_days'          => isset( $_POST['sla_low_days'] ) ? max( 1, (int) $_POST['sla_low_days'] ) : 180,
			'updated_at'            => vh_now(),
		);

		if ( '' === $row['name'] ) {
			$this->redirect( 'vulnhub-ownership', __( 'Give the team a name.', 'vulnhub' ), 'error', array( 'tab' => 'teams' ) );
		}

		if ( $id ) {
			$wpdb->update( vh_table( 'teams' ), $row, array( 'id' => $id ) );
		} else {
			$row['slug']       = sanitize_title( $row['name'] );
			$row['created_at'] = vh_now();
			$wpdb->insert( vh_table( 'teams' ), $row );
			$id = (int) $wpdb->insert_id;
		}

		vulnhub()->logger->audit( 'team.saved', sprintf( 'Team "%s" saved', $row['name'] ), 'team', $id, $row );

		$this->redirect( 'vulnhub-ownership', __( 'Team saved.', 'vulnhub' ), 'success', array( 'tab' => 'teams' ) );
	}

	/* =================================================================
	 * End-of-life table
	 * ============================================================== */

	/**
	 * Correct a shipped release, or add one the table has never heard of.
	 *
	 * Both come through here because they are the same write: Eol::save_row()
	 * stores only what differs from the bundled row, and a row with no
	 * bundled counterpart differs in every field.
	 */
	public function handle_save_eol(): void {
		$this->guard( 'vulnhub_save_eol' );

		$new = ! empty( $_POST['new'] );
		$key = isset( $_POST['key'] ) ? sanitize_key( wp_unslash( $_POST['key'] ) ) : '';

		$fields = array();

		foreach ( array( 'kind', 'family', 'edition', 'cpe', 'product', 'release', 'build', 'version', 'eol', 'mainstream', 'note', 'source' ) as $field ) {
			if ( isset( $_POST[ $field ] ) ) {
				$fields[ $field ] = sanitize_text_field( wp_unslash( (string) $_POST[ $field ] ) );
			}
		}

		if ( $new ) {
			$product = (string) ( $fields['product'] ?? '' );

			if ( '' === trim( $product ) ) {
				$this->redirect( 'vulnhub-lifecycle', __( 'Give the release a product name.', 'vulnhub' ), 'error' );
			}

			/*
			 * A row nobody can match is worse than a missing row: it sits in
			 * the table looking authoritative and counts nothing. Refuse it
			 * rather than store it.
			 */
			$os       = 'software' !== ( $fields['kind'] ?? 'os' );
			$targeted = $os
				? ( '' !== (string) ( $fields['family'] ?? '' ) && ( '' !== (string) ( $fields['build'] ?? '' ) || '' !== (string) ( $fields['version'] ?? '' ) ) )
				: ( '' !== (string) ( $fields['cpe'] ?? '' ) && '' !== (string) ( $fields['version'] ?? '' ) );

			if ( ! $targeted ) {
				$this->redirect(
					'vulnhub-lifecycle',
					$os
						? __( 'An operating system release needs a family and either a build number or a version prefix, or nothing will ever match it.', 'vulnhub' )
						: __( 'A software release needs a CPE and a version prefix, or nothing will ever match it.', 'vulnhub' ),
					'error'
				);
			}

			$key = sanitize_key( $product . '-' . (string) ( $fields['release'] ?? '' ) . '-' . (string) ( $fields['version'] ?? $fields['build'] ?? '' ) );
			$key = trim( (string) preg_replace( '/-+/', '-', $key ), '-' );

			if ( '' === $key ) {
				$this->redirect( 'vulnhub-lifecycle', __( 'That product name has no letters or digits in it.', 'vulnhub' ), 'error' );
			}
		}

		if ( '' === $key ) {
			$this->redirect( 'vulnhub-lifecycle', __( 'That release is not in the table.', 'vulnhub' ), 'error' );
		}

		Eol::save_row( $key, $fields );

		vulnhub()->logger->audit(
			'eol.saved',
			sprintf( 'Lifecycle row "%s" saved', $key ),
			'eol',
			$key,
			$fields
		);

		$this->redirect( 'vulnhub-lifecycle', __( 'Lifecycle table updated.', 'vulnhub' ) );
	}

	public function handle_delete_eol(): void {
		$this->guard( 'vulnhub_delete_eol' );

		$key  = isset( $_GET['key'] ) ? sanitize_key( wp_unslash( $_GET['key'] ) ) : '';
		$mode = isset( $_GET['mode'] ) ? sanitize_key( wp_unslash( $_GET['mode'] ) ) : 'revert';

		if ( '' === $key ) {
			$this->redirect( 'vulnhub-lifecycle', __( 'That release is not in the table.', 'vulnhub' ), 'error' );
		}

		if ( 'delete' === $mode ) {
			Eol::delete_row( $key );
			$message = __( 'Release removed.', 'vulnhub' );
		} else {
			// Reverting means dropping the override, which puts the shipped
			// row back -- not hiding the row.
			$store = Eol::overrides();
			unset( $store[ $key ] );
			update_option( Eol::OPTION, $store, false );
			$message = __( 'Release restored to the shipped dates.', 'vulnhub' );
		}

		vulnhub()->logger->audit( 'eol.' . $mode, sprintf( 'Lifecycle row "%s" %s', $key, $mode ), 'eol', $key );

		$this->redirect( 'vulnhub-lifecycle', $message );
	}

	public function handle_reset_eol(): void {
		$this->guard( 'vulnhub_reset_eol' );

		Eol::reset();

		vulnhub()->logger->audit( 'eol.reset', 'Lifecycle table restored to the shipped dates', 'eol', '' );

		$this->redirect( 'vulnhub-lifecycle', __( 'The shipped lifecycle table has been restored.', 'vulnhub' ) );
	}
}

