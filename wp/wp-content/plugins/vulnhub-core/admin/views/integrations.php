<?php
/**
 * Integrations screen — the admin portal where connectors are configured.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

use VulnHub\Core\Connectors;
use VulnHub\Core\Scheduler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$vh_all      = vulnhub()->connectors->all();
$vh_selected = isset( $_GET['connector'] ) ? sanitize_key( wp_unslash( $_GET['connector'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
$vh_active   = $vh_selected ? vulnhub()->connectors->get( $vh_selected ) : null;
?>

<?php if ( ! $vh_all ) : ?>
	<div class="vh-card vh-empty">
		<span class="dashicons dashicons-admin-plugins"></span>
		<h2><?php esc_html_e( 'No integration plugins are active', 'vulnhub' ); ?></h2>
		<p><?php esc_html_e( 'VulnHub Core provides the data model and portal. Each integration ships as its own plugin so it can be updated or disabled independently. Activate the ones you need from the Plugins screen.', 'vulnhub' ); ?></p>
		<a class="button button-primary" href="<?php echo esc_url( admin_url( 'plugins.php' ) ); ?>">
			<?php esc_html_e( 'Go to Plugins', 'vulnhub' ); ?>
		</a>
	</div>
	<?php return; ?>
<?php endif; ?>

<?php if ( $vh_active ) : ?>

	<?php $vh_brand = vh_integration_brand( $vh_active->id() ); ?>
	<p style="margin:0 0 14px">
		<a href="<?php echo esc_url( ! is_admin() && class_exists( 'VulnHub_Dash_Portal' ) ? VulnHub_Dash_Portal::portal_url( VulnHub_Dash_Portal::ADMIN_VIEW, array( 'section' => 'integrations' ) ) : vh_admin_url( 'vulnhub-integrations' ) ); ?>">&larr; <?php esc_html_e( 'All integrations', 'vulnhub' ); ?></a>
	</p>

	<div class="vh-intg__hero" style="--vh-brand: <?php echo esc_attr( $vh_brand['color'] ); ?>">
		<?php if ( '' !== $vh_brand['logo'] ) : ?>
			<span class="vh-intg__logo vh-intg__logo--lg" aria-hidden="true"><img src="<?php echo esc_url( $vh_brand['logo'] ); ?>" alt="" width="36" height="36"></span>
		<?php endif; ?>
		<div>
			<h2><?php echo esc_html( $vh_active->label() ); ?></h2>
			<p class="vh-muted"><?php echo esc_html( $vh_brand['vendor'] ); ?></p>
		</div>
		<?php if ( ! is_admin() && class_exists( 'VulnHub_Dash_Portal' ) ) : ?>
			<nav class="vh-intg__links">
				<?php foreach ( $vh_brand['links'] as $vh_link ) : ?>
					<?php
					$vh_slug = ! empty( $vh_link['page'] ) ? VulnHub_Dash_Portal::section_for_admin_page( (string) $vh_link['page'] ) : (string) ( $vh_link['section'] ?? '' );
					$vh_secs = $vh_secs ?? VulnHub_Dash_Portal::sections();
					if ( ! isset( $vh_secs[ $vh_slug ] ) || ! current_user_can( (string) $vh_secs[ $vh_slug ]['cap'] ) ) {
						continue;
					}
					?>
					<a href="<?php echo esc_url( VulnHub_Dash_Portal::portal_url( VulnHub_Dash_Portal::ADMIN_VIEW, array( 'section' => $vh_slug ) ) ); ?>"><?php echo esc_html( (string) $vh_link['label'] ); ?> <span aria-hidden="true">&rarr;</span></a>
				<?php endforeach; ?>
			</nav>
		<?php endif; ?>
	</div>

	<?php
	$vh_health   = $vh_active->health();
	$vh_last_run = vulnhub()->logger->last_run( $vh_active->id() );
	?>

	<?php
	/*
	 * The configure screen every integration shares.
	 *
	 * Built from the Settings screen's own parts (vh-set, vh-scard, vh-field,
	 * vh-savebar) so the two read as one product, and so dirty tracking, the
	 * save bar and the help toggles come from the same script.
	 *
	 * Guidance is not printed under every input any more. A field whose help
	 * ran to four lines pushed the next input off screen, and on a connector
	 * with twenty settings the form was mostly prose. Each setting now carries
	 * a small "?" beside its name; pressing it shows that setting's guidance in
	 * the Guide panel beside the form (inline under the field on a narrow
	 * screen, and inline for everyone with scripting off).
	 *
	 * `note` fields are different: they are status and instructions somebody
	 * has to act on -- "Not connected. Connect to Jira" -- so they stay visible.
	 */
	$vh_help_n = 0;

	/*
	 * One setting's label, its "?" and its guide.
	 *
	 * Prints the label column and returns the guide bubble for the caller to
	 * place after the input: the bubble spans the whole row when it opens
	 * inline, which it cannot do from inside the narrow label column.
	 */
	$vh_label = static function ( string $for, string $name, string $help = '', bool $required = false ) use ( &$vh_help_n ): string {
		$has_help = '' !== trim( wp_strip_all_tags( $help ) );
		$bubble   = '';

		echo '<div class="vh-field__label"><div class="vh-field__head">';
		printf(
			'<label class="vh-field__name" for="%1$s">%2$s%3$s</label>',
			esc_attr( $for ),
			esc_html( $name ),
			$required ? ' <span class="vh-field__req" title="' . esc_attr__( 'Required', 'vulnhub' ) . '">*</span>' : ''
		);

		if ( $has_help ) {
			++$vh_help_n;
			$id = 'vh-guide-' . $vh_help_n;

			printf(
				'<button type="button" class="vh-help vh-help--q" aria-expanded="false" aria-controls="%1$s" data-vh-guide-title="%2$s" title="%3$s"><span aria-hidden="true">?</span><span class="screen-reader-text">%3$s</span></button>',
				esc_attr( $id ),
				esc_attr( $name ),
				/* translators: %s: setting name. */
				esc_attr( sprintf( __( 'About %s', 'vulnhub' ), $name ) )
			);

			$bubble = sprintf(
				'<div class="vh-bubble vh-bubble--field" id="%1$s" role="note"><span class="vh-bubble__tail" aria-hidden="true"></span><div class="vh-bubble__body">%2$s</div></div>',
				esc_attr( $id ),
				wp_kses_post( wpautop( $help ) )
			);
		}

		echo '</div></div>';

		return $bubble;
	};

	$vh_scheduled = $vh_active->supports_sync() ? Scheduler::next_run( $vh_active->id() ) : null;
	?>

	<div class="vh-set vh-cfg">
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-set__form" data-vh-settings data-vh-nav="integrations" data-vh-guide-form>
			<?php wp_nonce_field( 'vulnhub_save_connector' ); ?>
			<input type="hidden" name="action" value="vulnhub_save_connector">
			<input type="hidden" name="connector" value="<?php echo esc_attr( $vh_active->id() ); ?>">

			<section class="vh-scard">
				<div class="vh-scard__head">
					<h2><?php esc_html_e( 'General', 'vulnhub' ); ?></h2>
					<p><?php echo esc_html( $vh_active->description() ); ?></p>
				</div>

				<div class="vh-field" data-vh-field="<?php esc_attr_e( 'Enabled', 'vulnhub' ); ?>">
					<span class="vh-field__edge" aria-hidden="true"></span>
					<?php $vh_bubble = $vh_label( 'vh-enabled', __( 'Enabled', 'vulnhub' ), __( 'A disabled connector never runs, scheduled or manual. Its settings are kept.', 'vulnhub' ) ); ?>
					<div class="vh-field__body">
						<label class="vh-switch">
							<input type="checkbox" id="vh-enabled" name="enabled" value="1" <?php checked( $vh_active->is_enabled() ); ?>>
							<span class="vh-switch__track" aria-hidden="true"></span>
							<span><?php esc_html_e( 'Run this integration', 'vulnhub' ); ?></span>
						</label>
					</div>
					<?php echo $vh_bubble; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped when built. ?>
				</div>

				<?php if ( $vh_active->supports_mock() ) : ?>
					<div class="vh-field" data-vh-field="<?php esc_attr_e( 'Mock data', 'vulnhub' ); ?>">
						<span class="vh-field__edge" aria-hidden="true"></span>
						<?php $vh_bubble = $vh_label( 'vh-mock', __( 'Mock data', 'vulnhub' ), __( 'Mock mode generates a realistic sample that flows through exactly the same normalisation code as live data. Nothing is sent to the vendor and no credentials are used. Turn it off once the credentials below are in place and tested.', 'vulnhub' ) ); ?>
						<div class="vh-field__body">
							<label class="vh-switch">
								<input type="checkbox" id="vh-mock" name="mock" value="1" <?php checked( $vh_active->is_mock() ); ?>>
								<span class="vh-switch__track" aria-hidden="true"></span>
								<span><?php esc_html_e( 'Use mock data instead of the live API', 'vulnhub' ); ?></span>
							</label>
						</div>
						<?php echo $vh_bubble; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped when built. ?>
					</div>
				<?php endif; ?>

				<?php if ( $vh_active->supports_sync() ) : ?>
					<div class="vh-field" data-vh-field="<?php esc_attr_e( 'Sync schedule', 'vulnhub' ); ?>">
						<span class="vh-field__edge" aria-hidden="true"></span>
						<?php $vh_bubble = $vh_label( 'vh-interval', __( 'Sync schedule', 'vulnhub' ), __( 'How often this connector runs on its own. A manual Sync now always works, whatever is chosen here. The schedule only applies while the connector is enabled.', 'vulnhub' ) ); ?>
						<div class="vh-field__body">
							<div class="vh-field__row">
								<select name="interval" id="vh-interval">
									<?php
									$vh_current = (string) vulnhub()->settings->get( $vh_active->id(), 'interval', $vh_active->default_interval() );
									foreach ( Scheduler::interval_choices() as $vh_key => $vh_ilabel ) :
										?>
										<option value="<?php echo esc_attr( $vh_key ); ?>" <?php selected( $vh_current, $vh_key ); ?>><?php echo esc_html( $vh_ilabel ); ?></option>
									<?php endforeach; ?>
								</select>
								<span class="vh-field__state">
									<?php
									echo $vh_scheduled
										/* translators: %s: relative time. */
										? esc_html( sprintf( __( 'Next run in %s', 'vulnhub' ), human_time_diff( time(), $vh_scheduled ) ) )
										: esc_html__( 'Not currently scheduled', 'vulnhub' );
									?>
								</span>
							</div>
						</div>
						<?php echo $vh_bubble; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped when built. ?>
					</div>
				<?php endif; ?>
			</section>

			<section class="vh-scard">
				<div class="vh-scard__head">
					<h2><?php esc_html_e( 'Connection & behaviour', 'vulnhub' ); ?></h2>
					<p><?php esc_html_e( 'Press ? beside a setting to see what it does. Secrets are stored encrypted and never shown again; leave one blank to keep it.', 'vulnhub' ); ?></p>
				</div>

				<?php foreach ( $vh_active->fields() as $vh_field ) : ?>
					<?php
					$vh_key  = (string) $vh_field['key'];
					$vh_type = (string) ( $vh_field['type'] ?? 'text' );

					/*
					 * `show_when => [ 'source' => [ 'assets' ] ]` means "only while
					 * that setting has that value". Resolved by admin.js; with
					 * scripting off every row stays visible.
					 */
					$vh_when_attr = '';

					foreach ( (array) ( $vh_field['show_when'] ?? array() ) as $vh_ctrl => $vh_vals ) {
						$vh_when_attr = sprintf(
							' data-vh-when-field="%s" data-vh-when-value="%s"',
							esc_attr( 'vh_' . $vh_ctrl ),
							esc_attr( implode( ',', array_map( 'strval', (array) $vh_vals ) ) )
						);
						break;
					}

					if ( 'note' === $vh_type ) {
						printf(
							'<div class="vh-cfg__note"%s>%s</div>',
							$vh_when_attr, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from esc_attr above.
							wp_kses_post( (string) ( $vh_field['help'] ?? '' ) )
						);
						continue;
					}

					$vh_name   = 'vh_' . $vh_key;
					$vh_id     = 'vh-field-' . $vh_key;
					$vh_title  = (string) $vh_field['label'];
					$vh_secret = ! empty( $vh_field['secret'] );
					$vh_value  = $vh_secret ? '' : (string) vulnhub()->settings->get( $vh_active->id(), $vh_key, (string) ( $vh_field['default'] ?? '' ) );
					$vh_hint   = $vh_secret ? vulnhub()->settings->secret_hint( $vh_active->id(), $vh_key ) : '';
					?>
					<div class="vh-field vh-field--<?php echo esc_attr( $vh_type ); ?>" data-vh-field="<?php echo esc_attr( $vh_title ); ?>"<?php echo $vh_when_attr; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from esc_attr above. ?>>
						<span class="vh-field__edge" aria-hidden="true"></span>
						<?php $vh_bubble = $vh_label( $vh_id, $vh_title, (string) ( $vh_field['help'] ?? '' ), ! empty( $vh_field['required'] ) ); ?>

						<div class="vh-field__body">
							<?php if ( 'select' === $vh_type ) : ?>
								<select name="<?php echo esc_attr( $vh_name ); ?>" id="<?php echo esc_attr( $vh_id ); ?>">
									<?php foreach ( (array) ( $vh_field['options'] ?? array() ) as $vh_ok => $vh_ol ) : ?>
										<option value="<?php echo esc_attr( (string) $vh_ok ); ?>" <?php selected( $vh_value, (string) $vh_ok ); ?>><?php echo esc_html( (string) $vh_ol ); ?></option>
									<?php endforeach; ?>
								</select>

							<?php elseif ( 'textarea' === $vh_type ) : ?>
								<textarea name="<?php echo esc_attr( $vh_name ); ?>" id="<?php echo esc_attr( $vh_id ); ?>" rows="4" class="vh-field__text code"
									placeholder="<?php echo esc_attr( (string) ( $vh_field['placeholder'] ?? '' ) ); ?>"><?php echo esc_textarea( $vh_value ); ?></textarea>

							<?php elseif ( 'checkbox' === $vh_type ) : ?>
								<label class="vh-switch">
									<input type="checkbox" name="<?php echo esc_attr( $vh_name ); ?>" id="<?php echo esc_attr( $vh_id ); ?>" value="1"
										<?php checked( vulnhub()->settings->get_bool( $vh_active->id(), $vh_key, (bool) ( $vh_field['default'] ?? false ) ) ); ?>>
									<span class="vh-switch__track" aria-hidden="true"></span>
									<span><?php echo esc_html( (string) ( $vh_field['checkbox_label'] ?? __( 'Enabled', 'vulnhub' ) ) ); ?></span>
								</label>

							<?php elseif ( $vh_secret ) : ?>
								<div class="vh-field__row">
									<input type="password" name="<?php echo esc_attr( $vh_name ); ?>" id="<?php echo esc_attr( $vh_id ); ?>"
										class="vh-field__text" autocomplete="new-password"
										placeholder="<?php echo $vh_hint ? esc_attr( $vh_hint ) : esc_attr( (string) ( $vh_field['placeholder'] ?? '' ) ); ?>">
									<?php if ( $vh_hint ) : ?>
										<span class="vh-chip vh-chip--good"><?php esc_html_e( 'Stored', 'vulnhub' ); ?></span>
										<label class="vh-cfg__clear">
											<input type="checkbox" name="clear_<?php echo esc_attr( $vh_key ); ?>" value="1">
											<?php esc_html_e( 'Clear on save', 'vulnhub' ); ?>
										</label>
									<?php endif; ?>
								</div>

							<?php else : ?>
								<input type="<?php echo esc_attr( in_array( $vh_type, array( 'url', 'email', 'number' ), true ) ? $vh_type : 'text' ); ?>"
									name="<?php echo esc_attr( $vh_name ); ?>" id="<?php echo esc_attr( $vh_id ); ?>"
									value="<?php echo esc_attr( $vh_value ); ?>" class="vh-field__text"
									placeholder="<?php echo esc_attr( (string) ( $vh_field['placeholder'] ?? '' ) ); ?>">
							<?php endif; ?>
						</div>
						<?php echo $vh_bubble; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped when built. ?>
					</div>
				<?php endforeach; ?>
			</section>

			<div class="vh-savebar" data-vh-savebar>
				<span class="vh-savebar__dot" aria-hidden="true"></span>
				<span class="vh-savebar__n" data-vh-savebar-n><?php esc_html_e( 'Unsaved changes', 'vulnhub' ); ?></span>
				<span class="vh-savebar__names" data-vh-savebar-names></span>
				<button type="button" class="vh-btn" data-vh-discard><?php esc_html_e( 'Discard', 'vulnhub' ); ?></button>
				<button type="submit" class="vh-btn vh-btn--primary"><?php esc_html_e( 'Save settings', 'vulnhub' ); ?></button>
			</div>
		</form>

		<aside class="vh-set__rail vh-cfg__rail">
			<div class="vh-rail-card">
				<h2><?php esc_html_e( 'Connection', 'vulnhub' ); ?></h2>
				<div class="vh-rail-card__body">
					<p><span class="vh-health vh-health--<?php echo esc_attr( (string) $vh_health['state'] ); ?>"><?php echo esc_html( (string) $vh_health['label'] ); ?></span></p>
					<?php if ( '' !== (string) $vh_health['detail'] ) : ?>
						<p><?php echo esc_html( (string) $vh_health['detail'] ); ?></p>
					<?php endif; ?>

					<p class="vh-cfg__actions">
						<button type="button" class="vh-btn vh-btn--ghost vh-btn--sm" data-vh-action="test" data-vh-connector="<?php echo esc_attr( $vh_active->id() ); ?>">
							<?php esc_html_e( 'Test connection', 'vulnhub' ); ?>
						</button>
						<?php if ( $vh_active->supports_sync() && current_user_can( 'vulnhub_run_sync' ) ) : ?>
							<button type="button" class="vh-btn vh-btn--primary vh-btn--sm" data-vh-action="sync" data-vh-connector="<?php echo esc_attr( $vh_active->id() ); ?>">
								<?php esc_html_e( 'Sync now', 'vulnhub' ); ?>
							</button>
							<?php if ( $vh_active->supports_full_sync() ) : ?>
								<button type="button" class="vh-btn vh-btn--ghost vh-btn--sm" data-vh-action="sync" data-vh-full="1" data-vh-connector="<?php echo esc_attr( $vh_active->id() ); ?>"
									data-vh-sync-confirm="<?php esc_attr_e( 'Run a full resync? It downloads everything the source holds rather than only what changed, so it takes much longer than a normal sync. It runs in the background.', 'vulnhub' ); ?>">
									<?php esc_html_e( 'Full resync', 'vulnhub' ); ?>
								</button>
							<?php endif; ?>
							<?php if ( method_exists( $vh_active, 'request_assets_only' ) ) : ?>
							<?php
							/*
							 * The cheap half on its own. The inventory changes by the minute
							 * and the findings do not, so asking for the assets without the
							 * multi-gigabyte vulnerability export is the common case here,
							 * not an edge one.
							 */
							?>
							<button type="button" class="vh-btn vh-btn--ghost vh-btn--sm" data-vh-action="sync" data-vh-assets-only="1" data-vh-connector="<?php echo esc_attr( $vh_active->id() ); ?>">
								<?php esc_html_e( 'Sync assets only', 'vulnhub' ); ?>
							</button>
							<?php endif; ?>
						<?php endif; ?>
					</p>

					<?php if ( '' !== $vh_active->full_sync_note() ) : ?>
						<p><?php echo esc_html( $vh_active->full_sync_note() ); ?></p>
					<?php endif; ?>

					<?php if ( class_exists( 'VulnHub_Auth_SSO' ) && in_array( $vh_active->id(), VulnHub_Auth_SSO::provider_ids(), true ) ) : ?>
						<?php
						/*
						 * Moved here from the Authentication screen, which used to
						 * carry a second card per provider just to show this. It is
						 * only needed while setting the provider up.
						 */
						?>
						<p><?php esc_html_e( 'Redirect URI to register with this provider:', 'vulnhub' ); ?></p>
						<div class="vh-log vh-cfg__uri"><?php echo esc_html( VulnHub_Auth_SSO::redirect_uri( $vh_active->id() ) ); ?></div>
					<?php endif; ?>

					<?php if ( $vh_active->supports_sync() ) : ?>
						<div class="vh-sync-progress" data-vh-sync-progress="<?php echo esc_attr( $vh_active->id() ); ?>" hidden></div>
					<?php endif; ?>
				</div>
			</div>

			<?php if ( $vh_last_run ) : ?>
				<div class="vh-rail-card">
					<h2><?php esc_html_e( 'Last run', 'vulnhub' ); ?></h2>
					<div class="vh-rail-card__body">
						<dl class="vh-cfg__dl">
							<dt><?php esc_html_e( 'Status', 'vulnhub' ); ?></dt>
							<dd><span class="vh-health vh-health--<?php echo 'failed' === (string) $vh_last_run['status'] ? 'error' : 'ok'; ?>"><?php echo esc_html( ucfirst( (string) $vh_last_run['status'] ) ); ?></span></dd>
							<dt><?php esc_html_e( 'Started', 'vulnhub' ); ?></dt>
							<dd><?php echo esc_html( vh_date( (string) $vh_last_run['started_at'] ) ); ?></dd>
							<dt><?php esc_html_e( 'Duration', 'vulnhub' ); ?></dt>
							<dd><?php echo esc_html( vh_duration_human( (int) $vh_last_run['duration_ms'] ) ); ?></dd>
							<dt><?php esc_html_e( 'Processed', 'vulnhub' ); ?></dt>
							<dd><?php echo esc_html( number_format_i18n( (int) $vh_last_run['processed'] ) ); ?></dd>
							<dt><?php esc_html_e( 'Created', 'vulnhub' ); ?></dt>
							<dd><?php echo esc_html( number_format_i18n( (int) $vh_last_run['created'] ) ); ?></dd>
							<dt><?php esc_html_e( 'Updated', 'vulnhub' ); ?></dt>
							<dd><?php echo esc_html( number_format_i18n( (int) $vh_last_run['updated'] ) ); ?></dd>
						</dl>
						<?php if ( ! empty( $vh_last_run['log_text'] ) ) : ?>
							<p><a href="#" data-vh-toggle="vh-last-log"><?php esc_html_e( 'Show run log', 'vulnhub' ); ?></a></p>
							<div class="vh-log" id="vh-last-log" hidden><?php echo esc_html( (string) $vh_last_run['log_text'] ); ?></div>
						<?php endif; ?>
					</div>
				</div>
			<?php endif; ?>
			<div class="vh-rail-card vh-cfg__guide" data-vh-guide-panel aria-live="polite">
				<h2 data-vh-guide-heading><?php esc_html_e( 'Guide', 'vulnhub' ); ?></h2>
				<div class="vh-rail-card__body" data-vh-guide-body>
					<p><?php esc_html_e( 'Press ? beside any setting to read what it does and how to fill it in.', 'vulnhub' ); ?></p>
				</div>
			</div>
		</aside>
	</div>

<?php else : ?>

	<?php
	/*
	 * One card per integration, in one grid.
	 *
	 * Grouping by category used to give each group its own full-width row, so
	 * a category with one connector produced a banner the width of the screen
	 * for a single product. The category now rides on the card instead, and
	 * cards sort by category so neighbours are still related.
	 *
	 * Everything that belongs to a product -- its settings, its dashboard, its
	 * routing, its accounts -- is reached from its card. The portal takes
	 * those screens out of the admin navigation for exactly that reason.
	 */
	$vh_cats   = Connectors::categories();
	$vh_rank   = array_flip( array_keys( $vh_cats ) );
	$vh_cards  = $vh_all;
	$vh_counts = array( 'on' => 0, 'bad' => 0, 'off' => 0 );

	uasort(
		$vh_cards,
		static fn( $a, $b ): int => array( $vh_rank[ $a->category() ] ?? 99, (int) ! $a->is_enabled(), $a->label() )
			<=> array( $vh_rank[ $b->category() ] ?? 99, (int) ! $b->is_enabled(), $b->label() )
	);

	$vh_health = array();

	foreach ( $vh_cards as $vh_id => $vh_c ) {
		$vh_health[ $vh_id ] = $vh_c->health();
		$vh_state            = (string) $vh_health[ $vh_id ]['state'];

		if ( 'off' === $vh_state ) {
			++$vh_counts['off'];
		} elseif ( 'error' === $vh_state ) {
			++$vh_counts['bad'];
		} else {
			++$vh_counts['on'];
		}
	}

	/*
	 * Links resolve to the portal when the screen is drawn there. The portal
	 * otherwise relies on the referer to rewrite vh_admin_url(), which a
	 * freshly opened tab does not have.
	 */
	$vh_in_portal = ! is_admin() && class_exists( 'VulnHub_Dash_Portal' );
	$vh_pages     = (array) vulnhub()->admin->pages();
	$vh_sections  = $vh_in_portal ? VulnHub_Dash_Portal::sections() : array();

	$vh_url = static function ( array $link, array $args = array() ) use ( $vh_in_portal, $vh_pages, $vh_sections ): string {
		if ( ! empty( $link['page'] ) ) {
			$page = (string) $link['page'];

			if ( ! isset( $vh_pages[ $page ] ) || ! current_user_can( (string) $vh_pages[ $page ]['cap'] ) ) {
				return '';
			}

			return $vh_in_portal
				? VulnHub_Dash_Portal::portal_url( VulnHub_Dash_Portal::ADMIN_VIEW, array_merge( array( 'section' => VulnHub_Dash_Portal::section_for_admin_page( $page ) ), $args ) )
				: vh_admin_url( $page, $args );
		}

		$section = (string) ( $link['section'] ?? '' );

		if ( ! $vh_in_portal || ! isset( $vh_sections[ $section ] ) || ! current_user_can( (string) $vh_sections[ $section ]['cap'] ) ) {
			return '';
		}

		return VulnHub_Dash_Portal::portal_url( VulnHub_Dash_Portal::ADMIN_VIEW, array( 'section' => $section ) );
	};
	?>

	<p class="vh-intg__summary">
		<span><strong><?php echo esc_html( number_format_i18n( $vh_counts['on'] ) ); ?></strong> <?php esc_html_e( 'active', 'vulnhub' ); ?></span>
		<?php if ( $vh_counts['bad'] > 0 ) : ?>
			<span class="is-bad"><strong><?php echo esc_html( number_format_i18n( $vh_counts['bad'] ) ); ?></strong> <?php esc_html_e( 'failing', 'vulnhub' ); ?></span>
		<?php endif; ?>
		<span class="is-off"><strong><?php echo esc_html( number_format_i18n( $vh_counts['off'] ) ); ?></strong> <?php esc_html_e( 'not enabled', 'vulnhub' ); ?></span>
	</p>

	<div class="vh-intg">
		<?php foreach ( $vh_cards as $vh_id => $vh_c ) : ?>
			<?php
			$vh_h      = $vh_health[ $vh_id ];
			$vh_brand  = vh_integration_brand( (string) $vh_id );
			$vh_off    = 'off' === (string) $vh_h['state'];
			$vh_config = $vh_url( array( 'page' => 'vulnhub-integrations' ), array( 'connector' => (string) $vh_id ) );
			$vh_words  = preg_split( '/[\s&()]+/', $vh_c->label(), -1, PREG_SPLIT_NO_EMPTY );
			$vh_mono   = strtoupper( substr( (string) ( $vh_words[0] ?? '?' ), 0, 1 ) . substr( (string) ( $vh_words[1] ?? '' ), 0, 1 ) );
			?>
			<article class="vh-intg__card<?php echo $vh_off ? ' is-off' : ''; ?> vh-intg__card--<?php echo esc_attr( (string) $vh_h['state'] ); ?>"
				style="--vh-brand: <?php echo esc_attr( $vh_brand['color'] ); ?>"
				data-vh-intg="<?php echo esc_attr( (string) $vh_id ); ?>">

				<header class="vh-intg__head">
					<span class="vh-intg__logo" aria-hidden="true">
						<?php if ( '' !== $vh_brand['logo'] ) : ?>
							<img src="<?php echo esc_url( $vh_brand['logo'] ); ?>" alt="" width="28" height="28" loading="lazy">
						<?php else : ?>
							<span class="vh-intg__mono"><?php echo esc_html( $vh_mono ); ?></span>
						<?php endif; ?>
					</span>
					<div class="vh-intg__title">
						<h3><a href="<?php echo esc_url( $vh_config ); ?>"><?php echo esc_html( $vh_c->label() ); ?></a></h3>
						<p>
							<?php echo esc_html( $vh_brand['vendor'] ); ?>
							<?php if ( '' !== $vh_brand['vendor'] ) : ?>&middot;<?php endif; ?>
							<?php echo esc_html( wp_specialchars_decode( (string) ( $vh_cats[ $vh_c->category() ] ?? $vh_c->category() ) ) ); ?>
						</p>
					</div>
					<span class="vh-health vh-health--<?php echo esc_attr( (string) $vh_h['state'] ); ?>"><?php echo esc_html( (string) $vh_h['label'] ); ?></span>
				</header>

				<p class="vh-intg__desc" title="<?php echo esc_attr( $vh_c->description() ); ?>"><?php echo esc_html( $vh_c->description() ); ?></p>

				<p class="vh-intg__meta">
					<?php if ( ! empty( $vh_h['last'] ) ) : ?>
						<span data-vh-last-sync="<?php echo esc_attr( (string) $vh_id ); ?>" title="<?php echo esc_attr( vh_date( (string) $vh_h['last']['finished_at'], 'j M Y, H:i:s' ) ); ?>">
							<?php
							printf(
								/* translators: 1: relative time, 2: duration. */
								esc_html__( 'Synced %1$s · took %2$s', 'vulnhub' ),
								esc_html( vh_ago( (string) $vh_h['last']['finished_at'] ) ),
								esc_html( vh_duration_human( (int) $vh_h['last']['duration_ms'] ) )
							);
							?>
						</span>
					<?php endif; ?>
					<?php
					/*
					 * Healthy says "Last synced …", which the line above already
					 * says with the duration; Disabled says "Not in use", which
					 * the pill says. Only a state worth reading gets its detail.
					 */
					?>
					<?php if ( '' !== (string) $vh_h['detail'] && ! in_array( (string) $vh_h['state'], array( 'ok', 'off' ), true ) ) : ?>
						<span class="vh-intg__detail"><?php echo esc_html( (string) $vh_h['detail'] ); ?></span>
					<?php endif; ?>
				</p>

				<?php
				$vh_links = array();

				foreach ( $vh_brand['links'] as $vh_link ) {
					$vh_href = $vh_url( (array) $vh_link );

					if ( '' !== $vh_href ) {
						$vh_links[] = array( (string) $vh_link['label'], $vh_href );
					}
				}
				?>
				<?php if ( $vh_links ) : ?>
					<nav class="vh-intg__links" aria-label="<?php echo esc_attr( sprintf( /* translators: %s: integration name. */ __( '%s screens', 'vulnhub' ), $vh_c->label() ) ); ?>">
						<?php foreach ( $vh_links as $vh_link ) : ?>
							<a href="<?php echo esc_url( $vh_link[1] ); ?>"><?php echo esc_html( $vh_link[0] ); ?> <span aria-hidden="true">&rarr;</span></a>
						<?php endforeach; ?>
					</nav>
				<?php endif; ?>

				<footer class="vh-intg__foot">
					<a class="vh-btn vh-btn--sm <?php echo $vh_off ? 'vh-btn--primary' : 'vh-btn--ghost'; ?>" href="<?php echo esc_url( $vh_config ); ?>">
						<?php echo $vh_off ? esc_html__( 'Set up', 'vulnhub' ) : esc_html__( 'Configure', 'vulnhub' ); ?>
					</a>
					<?php if ( ! $vh_off ) : ?>
						<button type="button" class="vh-btn vh-btn--sm vh-btn--ghost" data-vh-action="test" data-vh-connector="<?php echo esc_attr( (string) $vh_id ); ?>">
							<?php esc_html_e( 'Test', 'vulnhub' ); ?>
						</button>
					<?php endif; ?>
					<?php if ( $vh_c->supports_sync() && $vh_c->is_enabled() && current_user_can( 'vulnhub_run_sync' ) ) : ?>
						<button type="button" class="vh-btn vh-btn--sm vh-btn--ghost" data-vh-action="sync" data-vh-connector="<?php echo esc_attr( (string) $vh_id ); ?>">
							<?php esc_html_e( 'Sync now', 'vulnhub' ); ?>
						</button>
						<?php if ( $vh_c->supports_full_sync() ) : ?>
							<?php
							/*
							 * The card is where people actually press these, and it
							 * offered only the incremental sync -- so the one control
							 * that re-reads everything lived a click away on Configure,
							 * where nobody looking at a stale card thinks to go.
							 */
							?>
							<button type="button" class="vh-btn vh-btn--sm vh-btn--ghost" data-vh-action="sync" data-vh-full="1" data-vh-connector="<?php echo esc_attr( (string) $vh_id ); ?>"
								data-vh-sync-confirm="<?php esc_attr_e( 'Run a full resync? It downloads everything the source holds rather than only what changed, so it takes much longer than a normal sync. It runs in the background and you can watch it here.', 'vulnhub' ); ?>">
								<?php esc_html_e( 'Full resync', 'vulnhub' ); ?>
							</button>
						<?php endif; ?>
						<?php if ( method_exists( $vh_c, 'request_assets_only' ) ) : ?>
						<?php
						/*
						 * The cheap half on its own. The inventory changes by the minute
						 * and the findings do not, so asking for the assets without the
						 * multi-gigabyte vulnerability export is the common case here,
						 * not an edge one.
						 */
						?>
						<button type="button" class="vh-btn vh-btn--sm vh-btn--ghost" data-vh-action="sync" data-vh-assets-only="1" data-vh-connector="<?php echo esc_attr( (string) $vh_id ); ?>">
							<?php esc_html_e( 'Sync assets only', 'vulnhub' ); ?>
						</button>
						<?php endif; ?>
					<?php endif; ?>
				</footer>

				<?php if ( $vh_c->supports_sync() ) : ?>
					<div class="vh-sync-progress" data-vh-sync-progress="<?php echo esc_attr( (string) $vh_id ); ?>" hidden></div>
				<?php endif; ?>
			</article>
		<?php endforeach; ?>
	</div>

<?php endif; ?>
