<?php
/**
 * Plugin Name:       VulnHub Core
 * Plugin URI:        https://github.com/arshdeepromy/vulnhub
 * Description:       Foundation for the VulnHub vulnerability &amp; asset management platform — data model, connector framework, encrypted credential vault, ownership mapping engine, RBAC and REST API. Every VulnHub integration plugin builds on this.
 * Version:           1.0.0
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Romy Sidhu
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_VERSION', '1.0.0' );
define( 'VULNHUB_DB_VERSION', '26' );
define( 'VULNHUB_FILE', __FILE__ );
define( 'VULNHUB_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_URL', plugin_dir_url( __FILE__ ) );
define( 'VULNHUB_BASENAME', plugin_basename( __FILE__ ) );

/**
 * Lightweight PSR-4-ish autoloader for the VulnHub\Core namespace.
 *
 * VH\Core\Repo_Assets  ->  includes/class-vh-repo-assets.php
 */
spl_autoload_register(
	static function ( string $class ): void {
		if ( ! str_starts_with( $class, 'VulnHub\\Core\\' ) ) {
			return;
		}
		$relative = substr( $class, strlen( 'VulnHub\\Core\\' ) );
		$file     = 'class-vh-' . str_replace( '_', '-', strtolower( $relative ) ) . '.php';

		foreach ( array( 'includes/', 'admin/' ) as $dir ) {
			$path = VULNHUB_DIR . $dir . $file;
			if ( is_readable( $path ) ) {
				require_once $path;
				return;
			}
		}
	}
);

require_once VULNHUB_DIR . 'includes/functions.php';
require_once VULNHUB_DIR . 'includes/class-vh-product.php';
require_once VULNHUB_DIR . 'includes/class-vh-vendor.php';

/*
 * Endpoint coverage is recomputed with scanning coverage, never apart from it.
 *
 * The two answer different questions off the same estate, and a dashboard
 * that showed one refreshed and the other from last night's run would invite
 * exactly the comparison it cannot support. Hooked here rather than called
 * from inside `Coverage::recalculate()` so that the scanning path has no
 * knowledge of Defender at all.
 */
add_action(
	'vulnhub_coverage_recalculated',
	static function (): void {
		\VulnHub\Core\Defender_Coverage::recalculate();
	},
	5
);

/*
 * Keep findings in step with the lifecycle of the asset they sit on.
 *
 * A connector sync re-reports whatever the vendor still lists, which for a
 * scanner includes machines retired since the last run. Sweeping on the way
 * out of every sync is what stops a decommissioned asset drifting back into
 * the totals -- the CSV importer does the same in its own finish step.
 */
add_action(
	'vulnhub_sync_complete',
	static function (): void {
		\VulnHub\Core\Lifecycle::sweep_and_recount();
	},
	5
);

/**
 * Main plugin container. Boots subsystems in dependency order.
 */
final class VulnHub_Core {

	private static ?VulnHub_Core $instance = null;

	public \VulnHub\Core\Connectors $connectors;
	public \VulnHub\Core\Logger $logger;
	public \VulnHub\Core\Settings $settings;
	public \VulnHub\Core\Scheduler $scheduler;
	public \VulnHub\Core\Admin $admin;

	public static function instance(): VulnHub_Core {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->settings   = new \VulnHub\Core\Settings();
		$this->logger     = new \VulnHub\Core\Logger();
		$this->connectors = new \VulnHub\Core\Connectors();
		$this->scheduler  = new \VulnHub\Core\Scheduler();

		add_action( 'init', array( $this, 'on_init' ), 20 );
		add_action( 'plugins_loaded', array( $this, 'on_plugins_loaded' ), 5 );
		add_action( 'rest_api_init', array( new \VulnHub\Core\Rest(), 'register_routes' ) );
		add_action( 'admin_init', array( $this, 'maybe_upgrade' ) );

		/*
		 * Built on every request, not just in wp-admin. The screen registry
		 * it holds is what the front-end portal mirrors, so it has to be
		 * readable there too; the wp-admin-only hooks it registers simply
		 * never fire on a front-end request.
		 */
		$this->admin = new \VulnHub\Core\Admin();

		$this->scheduler->hooks();
		( new \VulnHub\Core\Mapping() )->hooks();
	}

	public function on_plugins_loaded(): void {
		/**
		 * Fires once VulnHub Core is available. Integration plugins should
		 * register their connectors on this hook.
		 *
		 * @param \VulnHub\Core\Connectors $connectors Connector registry.
		 */
		do_action( 'vulnhub_register_connectors', $this->connectors );

		/** Fires after the whole VulnHub platform is loaded. */
		do_action( 'vulnhub_loaded', $this );
	}

	public function on_init(): void {
		\VulnHub\Core\Caps::maybe_install_roles();
	}

	public function maybe_upgrade(): void {
		if ( (string) get_option( 'vulnhub_db_version', '0' ) !== VULNHUB_DB_VERSION ) {
			\VulnHub\Core\Install::run();
		}
	}
}

/**
 * Global accessor.
 */
function vulnhub(): VulnHub_Core {
	return VulnHub_Core::instance();
}

register_activation_hook(
	__FILE__,
	static function (): void {
		require_once VULNHUB_DIR . 'includes/class-vh-install.php';
		require_once VULNHUB_DIR . 'includes/class-vh-caps.php';
		\VulnHub\Core\Install::run();
		// Roles carry translated labels, so they are installed on `init`
		// rather than here — calling __() during activation triggers
		// WordPress's "textdomain loaded too early" notice.
		delete_option( 'vulnhub_roles_version' );
		set_transient( 'vulnhub_activated', 1, 60 );
	}
);

register_deactivation_hook(
	__FILE__,
	static function (): void {
		require_once VULNHUB_DIR . 'includes/class-vh-scheduler.php';
		\VulnHub\Core\Scheduler::unschedule_all();
	}
);

/**
 * wp vulnhub classify-products [--dry-run]
 *
 * Stamp component_class / product / product_kind / product_slug onto every
 * vuln row from its title, using the same VH_Product classifier the importer
 * and the widgets use. Idempotent: safe to re-run after a rule change, and it
 * is how existing data catches up with a new alias.
 */
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	WP_CLI::add_command(
		'vulnhub classify-apps',
		static function ( array $args, array $assoc ): void {
			global $wpdb;
			$table = vh_table( 'findings' );
			$dry   = isset( $assoc['dry-run'] );
			$last  = 0;
			$done  = 0;
			$stamped = 0;

			do {
				$rows = $wpdb->get_results(
					$wpdb->prepare(
						"SELECT id, output, bundle_app FROM {$table} WHERE id > %d AND output <> '' ORDER BY id ASC LIMIT 1000",
						$last
					),
					ARRAY_A
				);
				foreach ( $rows as $r ) {
					$last = (int) $r['id'];
					++$done;
					$app = VH_Product::app_from_output( (string) $r['output'] );
					if ( $app !== (string) $r['bundle_app'] ) {
						++$stamped;
						if ( ! $dry ) {
							$wpdb->update(
								$table,
								array( 'bundle_app' => $app, 'bundle_app_slug' => VH_Product::slug( $app ) ),
								array( 'id' => $last )
							);
						}
					}
				}
			} while ( $rows );

			if ( class_exists( 'VulnHub_Dash_Widgets' ) ) {
				VulnHub_Dash_Widgets::bust();
			}
			WP_CLI::success( sprintf( '%s %d findings with output; %d bundling apps %s.', $dry ? 'Scanned' : 'Scanned', $done, $stamped, $dry ? 'would be stamped' : 'stamped' ) );
		}
	);

	WP_CLI::add_command(
		'vulnhub classify-products',
		static function ( array $args, array $assoc ): void {
			global $wpdb;
			$table  = vh_table( 'vulns' );
			$dry    = isset( $assoc['dry-run'] );
			$done   = 0;
			$changed = 0;
			$last   = 0;
			$counts = array();

			do {
				$rows = $wpdb->get_results(
					$wpdb->prepare(
						"SELECT id, title, family, description, component_class, product, product_kind, product_slug
						 FROM {$table} WHERE id > %d ORDER BY id ASC LIMIT 500",
						$last
					),
					ARRAY_A
				);
				foreach ( $rows as $r ) {
					$last = (int) $r['id'];
					$c    = VH_Product::classify( (string) $r['title'], (string) $r['family'], (string) $r['description'] );
					$counts[ $c['class'] ] = ( $counts[ $c['class'] ] ?? 0 ) + 1;
					++$done;
					$dirty = $c['class'] !== $r['component_class'] || $c['product'] !== $r['product']
						|| $c['kind'] !== $r['product_kind'] || $c['slug'] !== $r['product_slug'];
					if ( $dirty ) {
						++$changed;
						if ( ! $dry ) {
							$wpdb->update(
								$table,
								array(
									'component_class' => $c['class'],
									'product'         => $c['product'],
									'product_kind'    => $c['kind'],
									'product_slug'    => $c['slug'],
								),
								array( 'id' => $last )
							);
						}
					}
				}
			} while ( $rows );

			foreach ( $counts as $k => $v ) {
				WP_CLI::log( str_pad( $k, 14 ) . $v );
			}
			if ( class_exists( 'VulnHub_Dash_Widgets' ) ) {
				VulnHub_Dash_Widgets::bust();
			}
			WP_CLI::success( sprintf( '%s %d vulns (%d %s).', $dry ? 'Would classify' : 'Classified', $done, $changed, $dry ? 'would change' : 'updated' ) );
		}
	);
}

/**
 * wp vulnhub merge-duplicates [--dry-run] [--include-clashes]
 *
 * Fold asset rows that are one machine written down twice.
 *
 * Two rows for one machine is the split that makes an estate lie to itself:
 * the Tenable findings land on one row while the owner, site and lifecycle
 * sit on the other, which then reports "Not in Tenable" for a machine being
 * scanned every week. Imports no longer make these -- `Repo::match_asset()`
 * settles which asset a row is about before anything is written, and this
 * same sweep runs at the end of every import -- so this command is for
 * running the clean-up by hand and seeing what it would do first.
 *
 * The survivor is whichever row the inventory knows best: a CMDB number, an
 * owner, a site, a name somebody typed rather than one a scanner truncated.
 * Pairs whose CMDB numbers disagree are two machines that share a name and
 * are reported rather than merged, unless --include-clashes says otherwise.
 */
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	WP_CLI::add_command(
		'vulnhub merge-duplicates',
		static function ( array $args, array $assoc ): void {
			$dry   = isset( $assoc['dry-run'] );
			$force = isset( $assoc['include-clashes'] );

			$result = \VulnHub\Core\Repo::sweep_duplicates( $dry, $force );

			foreach ( $result['merged'] as $line ) {
				WP_CLI::log( ( $dry ? 'Would fold ' : 'Folded ' ) . $line );
			}
			foreach ( $result['skipped'] as $line ) {
				WP_CLI::warning( $line . ' -- left alone (--include-clashes to merge).' );
			}

			if ( ! $dry && $result['merged'] ) {
				\VulnHub\Core\Repo::recalculate_asset_rollups();
				\VulnHub\Core\Coverage::recalculate();

				if ( class_exists( 'VulnHub_Dash_Widgets' ) ) {
					VulnHub_Dash_Widgets::bust();
				}
			}

			WP_CLI::success(
				sprintf(
					'%s %d duplicate row(s); %d left for a person to look at.',
					$dry ? 'Would fold' : 'Folded',
					count( $result['merged'] ),
					count( $result['skipped'] )
				)
			);
		}
	);
}

/**
 * wp vulnhub stale-records [--collect] [--dry-run] [--forget=<name>]
 *
 * Records the CMDB sent that are a name and nothing else.
 *
 * A row with no CI number, no address and no DNS name cannot be scanned,
 * owned or closed. As an asset it is a permanent coverage gap nobody can
 * act on, so imports now hold it here instead of writing it, and release it
 * the moment Tenable or Defender proves the machine is real -- with the
 * team, site and service the CMDB gave it.
 *
 * With no arguments this lists what is being held. --collect applies the
 * same rule to bare rows earlier imports already wrote, moving them out of
 * the inventory; anything with a finding or a ticket against it is left
 * alone. --forget drops a held record entirely.
 */
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	WP_CLI::add_command(
		'vulnhub stale-records',
		static function ( array $args, array $assoc ): void {
			global $wpdb;

			$dry = isset( $assoc['dry-run'] );

			if ( ! empty( $assoc['forget'] ) ) {
				$gone = (int) $wpdb->delete( vh_table( 'stale_records' ), array( 'name' => strtolower( trim( (string) $assoc['forget'] ) ) ) );
				WP_CLI::success( sprintf( 'Forgot %d held record(s).', $gone ) );
				return;
			}

			if ( isset( $assoc['collect'] ) ) {
				$held = \VulnHub\Core\Repo::collect_stale_assets( $dry );

				foreach ( $held as $line ) {
					WP_CLI::log( ( $dry ? 'Would hold ' : 'Held ' ) . $line );
				}

				if ( ! $dry && $held ) {
					\VulnHub\Core\Repo::recalculate_asset_rollups();
					\VulnHub\Core\Coverage::recalculate();

					if ( class_exists( 'VulnHub_Dash_Widgets' ) ) {
						VulnHub_Dash_Widgets::bust();
					}
				}

				WP_CLI::success( sprintf( '%s %d bare CMDB row(s).', $dry ? 'Would hold' : 'Held', count( $held ) ) );
				return;
			}

			$rows = \VulnHub\Core\Repo::stale_records( isset( $assoc['all'] ) );

			if ( ! $rows ) {
				WP_CLI::success( 'Nothing is being held.' );
				return;
			}

			$table = array();

			foreach ( $rows as $row ) {
				$payload = json_decode( (string) $row['payload_json'], true );
				$payload = is_array( $payload ) ? $payload : array();

				$table[] = array(
					'name'      => (string) $row['name'],
					'source'    => (string) $row['source'],
					'lifecycle' => (string) ( $payload['lifecycle_status'] ?? '' ),
					'service'   => (string) ( $payload['business_service'] ?? '' ),
					'seen'      => (string) $row['times_seen'],
					'held'      => (string) $row['first_held_at'],
					'released'  => (string) ( $row['released_at'] ?? '' ),
				);
			}

			WP_CLI\Utils\format_items( 'table', $table, array( 'name', 'source', 'lifecycle', 'service', 'seen', 'held', 'released' ) );
			WP_CLI::success( sprintf( '%d record(s) held out of the inventory.', count( $rows ) ) );
		}
	);
}

vulnhub();
