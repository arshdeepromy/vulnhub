<?php
/**
 * Advisory feed management.
 *
 * @package VulnHub\Alerts
 *
 * @var array<string,mixed>|null              $notice
 * @var array<string,mixed>|null              $test
 * @var array<int,array<string,mixed>>        $feeds
 * @var array<string,array<string,int>>       $counts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$vh_adapters = VulnHub_Alerts_Registry::adapters();
$vh_nonce    = wp_create_nonce( VulnHub_Alerts_Admin::NONCE );
?>

<div class="vh-panel">
	<h2><?php esc_html_e( 'Advisory feeds', 'vulnhub' ); ?></h2>
	<p class="vh-sub">
		<?php
		esc_html_e(
			'Each feed is polled on its own schedule, and everything it publishes is matched against the software and operating systems in the inventory. Advisories that match nothing are still recorded, so there is evidence they were assessed.',
			'vulnhub'
		);
		?>
	</p>

	<?php if ( $notice ) : ?>
		<p class="vh-flash vh-flash--<?php echo esc_attr( (string) $notice['tone'] ); ?>">
			<?php echo esc_html( (string) $notice['text'] ); ?>
		</p>
	<?php endif; ?>

	<form method="post" class="vh-alerts__pollall">
		<input type="hidden" name="vh_feeds_nonce" value="<?php echo esc_attr( $vh_nonce ); ?>">
		<input type="hidden" name="vh_action" value="poll_all">
		<button class="vh-btn vh-btn--sm" type="submit"><?php esc_html_e( 'Poll every due feed now', 'vulnhub' ); ?></button>
	</form>

	<div class="vh-tablewrap">
		<table class="vh-table">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Feed', 'vulnhub' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Format', 'vulnhub' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Every', 'vulnhub' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Last run', 'vulnhub' ); ?></th>
					<th scope="col" class="vh-num"><?php esc_html_e( 'Matched', 'vulnhub' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Actions', 'vulnhub' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $feeds as $vh_feed ) : ?>
				<?php
				$vh_slug  = (string) $vh_feed['slug'];
				$vh_stat  = $counts[ $vh_slug ] ?? array( 'total' => 0, 'matched' => 0 );
				$vh_state = (string) $vh_feed['last_status'];
				?>
				<tr class="<?php echo (int) $vh_feed['enabled'] ? '' : 'vh-alerts__feed--off'; ?>">
					<td>
						<strong><?php echo esc_html( (string) $vh_feed['label'] ); ?></strong>
						<?php if ( ! (int) $vh_feed['enabled'] ) : ?>
							<span class="vh-chip"><?php esc_html_e( 'Off', 'vulnhub' ); ?></span>
						<?php endif; ?>
						<?php if ( (int) $vh_feed['builtin'] ) : ?>
							<span class="vh-chip vh-chip--src"><?php esc_html_e( 'Built in', 'vulnhub' ); ?></span>
						<?php endif; ?>
						<div class="vh-meta vh-mono"><?php echo esc_html( vh_trim( (string) $vh_feed['url'], 74 ) ); ?></div>
						<?php if ( 'error' === $vh_state && ! empty( $vh_feed['last_error'] ) ) : ?>
							<div class="vh-meta vh-alerts__error"><?php echo esc_html( vh_trim( (string) $vh_feed['last_error'], 160 ) ); ?></div>
						<?php endif; ?>
					</td>
					<td class="vh-meta"><?php echo esc_html( VulnHub_Alerts_Registry::adapter_label( (string) $vh_feed['adapter'] ) ); ?></td>
					<td class="vh-nowrap vh-meta">
						<?php
						$vh_mins = (int) $vh_feed['interval_minutes'];
						echo esc_html(
							$vh_mins >= 1440
								/* translators: %d: number of days */
								? sprintf( _n( '%d day', '%d days', (int) round( $vh_mins / 1440 ), 'vulnhub' ), (int) round( $vh_mins / 1440 ) )
								/* translators: %d: number of hours */
								: sprintf( _n( '%d hour', '%d hours', max( 1, (int) round( $vh_mins / 60 ) ), 'vulnhub' ), max( 1, (int) round( $vh_mins / 60 ) ) )
						);
						?>
					</td>
					<td class="vh-nowrap">
						<span class="vh-health vh-health--<?php echo esc_attr( 'ok' === $vh_state ? 'ok' : ( 'error' === $vh_state ? 'error' : 'idle' ) ); ?>"></span>
						<span class="vh-meta"><?php echo esc_html( $vh_feed['last_run_at'] ? vh_ago( (string) $vh_feed['last_run_at'] ) : __( 'never', 'vulnhub' ) ); ?></span>
					</td>
					<td class="vh-num">
						<?php echo esc_html( (string) (int) $vh_stat['matched'] ); ?>
						<div class="vh-meta">
							<?php
							echo esc_html(
								sprintf(
									/* translators: %d: total advisories seen */
									__( 'of %d', 'vulnhub' ),
									(int) $vh_stat['total']
								)
							);
							?>
						</div>
					</td>
					<td class="vh-col-act">
						<form method="post" class="vh-alerts__inline">
							<input type="hidden" name="vh_feeds_nonce" value="<?php echo esc_attr( $vh_nonce ); ?>">
							<input type="hidden" name="feed_id" value="<?php echo (int) $vh_feed['id']; ?>">
							<button class="vh-btn vh-btn--sm vh-btn--ghost" type="submit" name="vh_action" value="poll"><?php esc_html_e( 'Poll', 'vulnhub' ); ?></button>
							<button class="vh-btn vh-btn--sm vh-btn--ghost" type="submit" name="vh_action" value="test"><?php esc_html_e( 'Test', 'vulnhub' ); ?></button>
							<button class="vh-btn vh-btn--sm vh-btn--ghost" type="submit" name="vh_action" value="toggle">
								<?php echo (int) $vh_feed['enabled'] ? esc_html__( 'Disable', 'vulnhub' ) : esc_html__( 'Enable', 'vulnhub' ); ?>
							</button>
							<?php if ( ! (int) $vh_feed['builtin'] ) : ?>
								<button class="vh-btn vh-btn--sm vh-btn--danger" type="submit" name="vh_action" value="delete"
									onclick="return confirm('<?php echo esc_js( __( 'Delete this feed and every advisory it contributed?', 'vulnhub' ) ); ?>');">
									<?php esc_html_e( 'Delete', 'vulnhub' ); ?>
								</button>
							<?php endif; ?>
						</form>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>

<?php if ( $test && ! empty( $test['samples'] ) ) : ?>
	<div class="vh-panel">
		<h2><?php esc_html_e( 'Test result', 'vulnhub' ); ?></h2>
		<p class="vh-sub"><?php esc_html_e( 'Nothing below was saved. This is what the feed would contribute if you polled it.', 'vulnhub' ); ?></p>

		<?php foreach ( (array) $test['notes'] as $vh_note ) : ?>
			<p class="vh-meta"><?php echo esc_html( (string) $vh_note ); ?></p>
		<?php endforeach; ?>

		<div class="vh-tablewrap">
			<table class="vh-table">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'Entry', 'vulnhub' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Severity', 'vulnhub' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Products named', 'vulnhub' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Would match', 'vulnhub' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( (array) $test['samples'] as $vh_s ) : ?>
					<tr>
						<td>
							<?php echo esc_html( vh_trim( (string) $vh_s['title'], 90 ) ); ?>
							<?php if ( ! empty( $vh_s['cves'] ) ) : ?>
								<div class="vh-meta vh-mono"><?php echo esc_html( implode( ', ', array_slice( (array) $vh_s['cves'], 0, 3 ) ) ); ?></div>
							<?php endif; ?>
						</td>
						<td class="vh-meta"><?php echo esc_html( (string) $vh_s['severity'] ); ?></td>
						<td class="vh-meta"><?php echo esc_html( implode( ', ', array_slice( (array) $vh_s['products'], 0, 3 ) ) ?: '—' ); ?></td>
						<td>
							<?php if ( (int) $vh_s['matches'] ) : ?>
								<span class="vh-pill vh-pill--<?php echo esc_attr( VulnHub_Alerts_Matcher::tone( (string) $vh_s['confidence'] ) ); ?>">
									<?php echo esc_html( VulnHub_Alerts_Matcher::label( (string) $vh_s['confidence'] ) ); ?>
								</span>
								<span class="vh-meta"><?php echo esc_html( sprintf( /* translators: %d: asset count */ __( '%d assets', 'vulnhub' ), (int) $vh_s['matches'] ) ); ?></span>
							<?php else : ?>
								<span class="vh-muted"><?php esc_html_e( 'No match', 'vulnhub' ); ?></span>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	</div>
<?php endif; ?>

<div class="vh-panel">
	<h2><?php esc_html_e( 'Add a feed', 'vulnhub' ); ?></h2>
	<p class="vh-sub">
		<?php
		esc_html_e(
			'Any free advisory source can go here. Choose "Any RSS or Atom feed" for the usual vendor security feed, or "Any JSON endpoint" and say which keys hold the fields. Test before you save — it fetches and matches without writing anything.',
			'vulnhub'
		);
		?>
	</p>

	<form method="post" class="vh-form vh-alerts__add">
		<input type="hidden" name="vh_feeds_nonce" value="<?php echo esc_attr( $vh_nonce ); ?>">

		<label class="vh-field">
			<span><?php esc_html_e( 'Name', 'vulnhub' ); ?></span>
			<input type="text" name="label" required placeholder="<?php esc_attr_e( 'Cisco security advisories', 'vulnhub' ); ?>">
		</label>

		<label class="vh-field">
			<span><?php esc_html_e( 'Format', 'vulnhub' ); ?></span>
			<select name="adapter">
				<?php foreach ( $vh_adapters as $vh_key => $vh_def ) : ?>
					<option value="<?php echo esc_attr( $vh_key ); ?>" <?php selected( $vh_key, 'rss' ); ?>>
						<?php echo esc_html( (string) $vh_def['label'] ); ?>
					</option>
				<?php endforeach; ?>
			</select>
			<span class="vh-field-help"><?php esc_html_e( 'The built-in formats know their publisher’s structure. The two generic ones work with anything.', 'vulnhub' ); ?></span>
		</label>

		<label class="vh-field">
			<span><?php esc_html_e( 'URL', 'vulnhub' ); ?></span>
			<input type="url" name="url" required placeholder="https://example.com/security/advisories.xml">
		</label>

		<label class="vh-field">
			<span><?php esc_html_e( 'Poll every (minutes)', 'vulnhub' ); ?></span>
			<input type="number" name="interval_minutes" value="360" min="15" max="10080">
			<span class="vh-field-help"><?php esc_html_e( 'Conditional requests are sent, so a feed that has not changed costs the publisher almost nothing.', 'vulnhub' ); ?></span>
		</label>

		<label class="vh-field">
			<span><?php esc_html_e( 'API key, if the source needs one', 'vulnhub' ); ?></span>
			<input type="text" name="auth_key" autocomplete="off" placeholder="<?php esc_attr_e( 'Sent as a bearer token. Leave empty for open feeds.', 'vulnhub' ); ?>">
		</label>

		<fieldset class="vh-alerts__json">
			<legend><?php esc_html_e( 'JSON endpoints only', 'vulnhub' ); ?></legend>
			<label class="vh-field">
				<span><?php esc_html_e( 'Path to the list', 'vulnhub' ); ?></span>
				<input type="text" name="items_path" placeholder="data.advisories">
				<span class="vh-field-help"><?php esc_html_e( 'Dotted path to the array of entries. Leave empty if the response is itself an array.', 'vulnhub' ); ?></span>
			</label>
			<div class="vh-alerts__map">
				<label class="vh-field"><span><?php esc_html_e( 'id key', 'vulnhub' ); ?></span><input type="text" name="map[id]" placeholder="id"></label>
				<label class="vh-field"><span><?php esc_html_e( 'title key', 'vulnhub' ); ?></span><input type="text" name="map[title]" placeholder="title"></label>
				<label class="vh-field"><span><?php esc_html_e( 'summary key', 'vulnhub' ); ?></span><input type="text" name="map[summary]" placeholder="summary"></label>
				<label class="vh-field"><span><?php esc_html_e( 'link key', 'vulnhub' ); ?></span><input type="text" name="map[url]" placeholder="url"></label>
				<label class="vh-field"><span><?php esc_html_e( 'date key', 'vulnhub' ); ?></span><input type="text" name="map[date]" placeholder="published"></label>
				<label class="vh-field"><span><?php esc_html_e( 'severity key', 'vulnhub' ); ?></span><input type="text" name="map[severity]" placeholder="severity"></label>
			</div>
		</fieldset>

		<div class="vh-actions">
			<button class="vh-btn vh-btn--ghost" type="submit" name="vh_action" value="test"><?php esc_html_e( 'Test without saving', 'vulnhub' ); ?></button>
			<button class="vh-btn vh-btn--primary" type="submit" name="vh_action" value="save"><?php esc_html_e( 'Add feed', 'vulnhub' ); ?></button>
		</div>
	</form>
</div>
