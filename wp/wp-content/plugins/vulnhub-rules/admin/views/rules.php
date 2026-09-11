<?php
/**
 * Portal admin view: asset classification rules.
 *
 * Rendered inside the portal admin area by VulnHub_Rules_Admin::render_section().
 * Every form posts back to this same portal URL with a nonce; nothing here
 * links into wp-admin.
 *
 * @package VulnHub\Rules
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! current_user_can( \VulnHub\Core\Caps::MANAGE ) ) {
	return;
}

$vh_rules        = VulnHub_Rules_Repo::rules();
$vh_fields       = VulnHub_Rules_Engine::match_fields();
$vh_operators    = VulnHub_Rules_Engine::operators();
$vh_valueless    = VulnHub_Rules_Engine::valueless_operators();
$vh_environments = VulnHub_Rules_Engine::environments();
$vh_criticality  = VulnHub_Rules_Engine::criticalities();
$vh_asset_types  = vh_asset_types();
$vh_editing      = VulnHub_Rules_Admin::editing_rule();
$vh_error        = VulnHub_Rules_Admin::error();
$vh_notice       = VulnHub_Rules_Admin::notice();
$vh_preview      = VulnHub_Rules_Admin::preview();
$vh_last_run     = VulnHub_Rules_Admin::last_run();
$vh_action_url   = VulnHub_Rules_Admin::section_url();
$vh_editing_id   = (int) ( $vh_editing['id'] ?? 0 );
$vh_order_ids    = implode( ',', array_map( static fn( array $r ): string => (string) (int) $r['id'], $vh_rules ) );
?>

<div class="vh-rules">

	<?php if ( $vh_error ) : ?>
		<p class="vh-warn-note" role="alert"><?php echo esc_html( $vh_error ); ?></p>
	<?php elseif ( $vh_notice ) : ?>
		<p class="<?php echo 'good' === $vh_notice['tone'] ? 'vh-ok-note' : 'vh-warn-note'; ?>" role="status">
			<?php echo esc_html( $vh_notice['text'] ); ?>
		</p>
	<?php endif; ?>

	<div class="vh-panel vh-rules__intro">
		<div class="vh-panel__head vh-rules__introhead">
			<div>
				<h2><?php esc_html_e( 'Asset classification', 'vulnhub' ); ?></h2>
				<p class="vh-sub">
					<?php esc_html_e( 'Rules run top to bottom and set what an asset is — environment, business criticality, type, business service and priority weight. They run automatically after every Tenable, Intune or CMDB sync, before ownership mapping decides who looks after it.', 'vulnhub' ); ?>
				</p>
			</div>
			<form method="post" action="<?php echo esc_url( $vh_action_url ); ?>" class="vh-rules__apply">
				<?php wp_nonce_field( VulnHub_Rules_Admin::NONCE_ACTION, VulnHub_Rules_Admin::NONCE_FIELD ); ?>
				<button type="submit" name="vh_rules_action" value="apply" class="vh-btn vh-btn--primary">
					<?php esc_html_e( 'Apply now', 'vulnhub' ); ?>
				</button>
			</form>
		</div>

		<?php if ( ! empty( $vh_last_run['at'] ) ) : ?>
			<p class="vh-sub vh-sub--foot">
				<?php
				printf(
					/* translators: 1: relative time, 2: trigger, 3: assets examined, 4: assets matched, 5: assets changed. */
					esc_html__( 'Last run %1$s (%2$s): %3$d assets examined, %4$d matched, %5$d changed.', 'vulnhub' ),
					esc_html( vh_ago( (string) $vh_last_run['at'] ) ),
					esc_html( (string) ( $vh_last_run['trigger'] ?? 'manual' ) ),
					(int) ( $vh_last_run['processed'] ?? 0 ),
					(int) ( $vh_last_run['matched'] ?? 0 ),
					(int) ( $vh_last_run['changed'] ?? 0 )
				);
				?>
			</p>
		<?php else : ?>
			<p class="vh-sub vh-sub--foot"><?php esc_html_e( 'These rules have not been applied yet.', 'vulnhub' ); ?></p>
		<?php endif; ?>
	</div>

	<?php /* ---------------------------------------------------------- list. */ ?>
	<form method="post" action="<?php echo esc_url( $vh_action_url ); ?>" id="vh-rules-order" class="vh-rules__orderform">
		<?php wp_nonce_field( VulnHub_Rules_Admin::NONCE_ACTION, VulnHub_Rules_Admin::NONCE_FIELD ); ?>
		<input type="hidden" name="vh_rules_action" value="order">
		<input type="hidden" name="order" id="vh-rules-order-value" value="<?php echo esc_attr( $vh_order_ids ); ?>">
		<noscript><button type="submit" class="vh-btn vh-btn--sm"><?php esc_html_e( 'Save order', 'vulnhub' ); ?></button></noscript>
	</form>

	<div class="vh-tablewrap">
		<table class="vh-table vh-rules__table" id="vh-rules-table">
			<caption class="screen-reader-text"><?php esc_html_e( 'Classification rules in evaluation order', 'vulnhub' ); ?></caption>
			<thead>
				<tr>
					<th scope="col" class="vh-rules__col-order"><?php esc_html_e( 'Order', 'vulnhub' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Rule', 'vulnhub' ); ?></th>
					<th scope="col"><?php esc_html_e( 'When', 'vulnhub' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Then set', 'vulnhub' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Matches', 'vulnhub' ); ?></th>
					<th scope="col" class="vh-col-act"><?php esc_html_e( 'Actions', 'vulnhub' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php if ( ! $vh_rules ) : ?>
				<tr>
					<td colspan="6" class="vh-rules__empty">
						<?php esc_html_e( 'No classification rules yet. Create one below.', 'vulnhub' ); ?>
					</td>
				</tr>
			<?php endif; ?>

			<?php foreach ( $vh_rules as $vh_index => $vh_rule ) : ?>
				<?php $vh_id = (int) $vh_rule['id']; ?>
				<tr draggable="true" data-rule-id="<?php echo esc_attr( (string) $vh_id ); ?>"
					class="vh-rules__row<?php echo empty( $vh_rule['enabled'] ) ? ' is-off' : ''; ?><?php echo $vh_id === $vh_editing_id ? ' is-editing' : ''; ?>">

					<td class="vh-rules__col-order">
						<span class="vh-rules__handle" aria-hidden="true" title="<?php esc_attr_e( 'Drag to reorder', 'vulnhub' ); ?>">⠿</span>
						<span class="vh-rules__pos"><?php echo esc_html( (string) ( $vh_index + 1 ) ); ?></span>

						<span class="vh-rules__arrows">
							<form method="post" action="<?php echo esc_url( $vh_action_url ); ?>">
								<?php wp_nonce_field( VulnHub_Rules_Admin::NONCE_ACTION, VulnHub_Rules_Admin::NONCE_FIELD ); ?>
								<input type="hidden" name="vh_rules_action" value="move">
								<input type="hidden" name="rule_id" value="<?php echo esc_attr( (string) $vh_id ); ?>">
								<input type="hidden" name="delta" value="-1">
								<button type="submit" class="vh-btn vh-btn--sm vh-btn--ghost" <?php disabled( 0 === $vh_index ); ?>
									aria-label="<?php echo esc_attr( sprintf( /* translators: %s: rule name. */ __( 'Move %s earlier', 'vulnhub' ), (string) $vh_rule['name'] ) ); ?>">↑</button>
							</form>
							<form method="post" action="<?php echo esc_url( $vh_action_url ); ?>">
								<?php wp_nonce_field( VulnHub_Rules_Admin::NONCE_ACTION, VulnHub_Rules_Admin::NONCE_FIELD ); ?>
								<input type="hidden" name="vh_rules_action" value="move">
								<input type="hidden" name="rule_id" value="<?php echo esc_attr( (string) $vh_id ); ?>">
								<input type="hidden" name="delta" value="1">
								<button type="submit" class="vh-btn vh-btn--sm vh-btn--ghost" <?php disabled( $vh_index === count( $vh_rules ) - 1 ); ?>
									aria-label="<?php echo esc_attr( sprintf( /* translators: %s: rule name. */ __( 'Move %s later', 'vulnhub' ), (string) $vh_rule['name'] ) ); ?>">↓</button>
							</form>
						</span>
					</td>

					<td>
						<strong><?php echo esc_html( (string) $vh_rule['name'] ); ?></strong>
						<?php if ( ! empty( $vh_rule['description'] ) ) : ?>
							<span class="vh-sub"><?php echo esc_html( (string) $vh_rule['description'] ); ?></span>
						<?php endif; ?>
						<?php if ( ! empty( $vh_rule['stop_processing'] ) ) : ?>
							<span class="vh-chip vh-chip--warn"><?php esc_html_e( 'stops processing', 'vulnhub' ); ?></span>
						<?php endif; ?>
					</td>

					<td class="vh-rules__when">
						<span class="vh-chip"><?php echo 'any' === (string) $vh_rule['match_type'] ? esc_html__( 'match any', 'vulnhub' ) : esc_html__( 'match all', 'vulnhub' ); ?></span>
						<span class="vh-mono"><?php echo esc_html( VulnHub_Rules_Engine::describe_conditions( $vh_rule ) ); ?></span>
					</td>

					<td><?php echo esc_html( VulnHub_Rules_Engine::describe_assignments( $vh_rule ) ); ?></td>

					<td>
						<strong><?php echo esc_html( number_format_i18n( (int) $vh_rule['match_count'] ) ); ?></strong>
						<?php if ( ! empty( $vh_rule['last_matched_at'] ) ) : ?>
							<span class="vh-sub"><?php echo esc_html( vh_ago( (string) $vh_rule['last_matched_at'] ) ); ?></span>
						<?php endif; ?>
					</td>

					<td class="vh-col-act">
						<form method="post" action="<?php echo esc_url( $vh_action_url ); ?>" class="vh-rules__inline">
							<?php wp_nonce_field( VulnHub_Rules_Admin::NONCE_ACTION, VulnHub_Rules_Admin::NONCE_FIELD ); ?>
							<input type="hidden" name="vh_rules_action" value="toggle">
							<input type="hidden" name="rule_id" value="<?php echo esc_attr( (string) $vh_id ); ?>">
							<input type="hidden" name="enabled" value="<?php echo empty( $vh_rule['enabled'] ) ? '1' : '0'; ?>">
							<button type="submit" class="vh-btn vh-btn--sm">
								<?php echo empty( $vh_rule['enabled'] ) ? esc_html__( 'Enable', 'vulnhub' ) : esc_html__( 'Disable', 'vulnhub' ); ?>
							</button>
						</form>

						<a class="vh-btn vh-btn--sm" href="<?php echo esc_url( VulnHub_Rules_Admin::section_url( array( 'edit' => (string) $vh_id ) ) ); ?>#vh-rule-editor">
							<?php esc_html_e( 'Edit', 'vulnhub' ); ?>
						</a>

						<form method="post" action="<?php echo esc_url( $vh_action_url ); ?>" class="vh-rules__inline"
							onsubmit="return confirm('<?php echo esc_js( __( 'Delete this rule? Assets already classified keep their current values.', 'vulnhub' ) ); ?>');">
							<?php wp_nonce_field( VulnHub_Rules_Admin::NONCE_ACTION, VulnHub_Rules_Admin::NONCE_FIELD ); ?>
							<input type="hidden" name="vh_rules_action" value="delete">
							<input type="hidden" name="rule_id" value="<?php echo esc_attr( (string) $vh_id ); ?>">
							<button type="submit" class="vh-btn vh-btn--sm"><?php esc_html_e( 'Delete', 'vulnhub' ); ?></button>
						</form>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	</div>

	<?php /* ------------------------------------------------------- preview. */ ?>
	<?php if ( null !== $vh_preview ) : ?>
		<div class="vh-panel vh-rules__preview" id="vh-rules-preview">
			<div class="vh-panel__head">
				<h2><?php esc_html_e( 'Preview — nothing has been changed', 'vulnhub' ); ?></h2>
				<p class="vh-sub">
					<?php
					printf(
						/* translators: 1: assets matched, 2: assets scanned, 3: assets that would change. */
						esc_html__( '%1$d of %2$d assets match this rule; %3$d of them would change. This is a dry run: no asset, counter or setting has been written.', 'vulnhub' ),
						(int) $vh_preview['matched'],
						(int) $vh_preview['scanned'],
						(int) $vh_preview['changes']
					);
					?>
				</p>
			</div>

			<?php if ( ! $vh_preview['rows'] ) : ?>
				<p class="vh-sub"><?php esc_html_e( 'No asset in the estate matches these conditions.', 'vulnhub' ); ?></p>
			<?php else : ?>
				<div class="vh-tablewrap">
					<table class="vh-table">
						<thead>
							<tr>
								<th scope="col"><?php esc_html_e( 'Asset', 'vulnhub' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Type', 'vulnhub' ); ?></th>
								<th scope="col"><?php esc_html_e( 'IPv4', 'vulnhub' ); ?></th>
								<th scope="col"><?php esc_html_e( 'Would change', 'vulnhub' ); ?></th>
							</tr>
						</thead>
						<tbody>
						<?php foreach ( $vh_preview['rows'] as $vh_row ) : ?>
							<?php $vh_asset = (array) $vh_row['asset']; ?>
							<tr>
								<td>
									<strong class="vh-mono"><?php echo esc_html( (string) ( $vh_asset['hostname'] ?: $vh_asset['fqdn'] ?: '#' . (string) $vh_asset['id'] ) ); ?></strong>
									<?php if ( ! empty( $vh_asset['operating_system'] ) ) : ?>
										<span class="vh-sub"><?php echo esc_html( (string) $vh_asset['operating_system'] ); ?></span>
									<?php endif; ?>
								</td>
								<td><?php echo esc_html( (string) ( $vh_asset_types[ (string) $vh_asset['asset_type'] ] ?? (string) $vh_asset['asset_type'] ) ); ?></td>
								<td class="vh-mono"><?php echo esc_html( (string) $vh_asset['ipv4'] ); ?></td>
								<td>
									<?php if ( ! $vh_row['diff'] ) : ?>
										<span class="vh-chip"><?php esc_html_e( 'already classified this way', 'vulnhub' ); ?></span>
									<?php else : ?>
										<ul class="vh-rules__diff">
										<?php foreach ( (array) $vh_row['diff'] as $vh_column => $vh_change ) : ?>
											<li>
												<span class="vh-rules__diffkey"><?php echo esc_html( $vh_column ); ?></span>
												<span class="vh-mono"><?php echo esc_html( '' === $vh_change['from'] ? '—' : (string) $vh_change['from'] ); ?></span>
												<span aria-hidden="true">→</span>
												<span class="vh-mono"><strong><?php echo esc_html( (string) $vh_change['to'] ); ?></strong></span>
											</li>
										<?php endforeach; ?>
										</ul>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
				</div>
				<?php if ( (int) $vh_preview['matched'] > count( $vh_preview['rows'] ) ) : ?>
					<p class="vh-sub vh-sub--foot">
						<?php
						printf(
							/* translators: 1: rows shown, 2: total matches. */
							esc_html__( 'Showing the first %1$d of %2$d matching assets.', 'vulnhub' ),
							count( $vh_preview['rows'] ),
							(int) $vh_preview['matched']
						);
						?>
					</p>
				<?php endif; ?>
			<?php endif; ?>
		</div>
	<?php endif; ?>

	<?php /* -------------------------------------------------------- editor. */ ?>
	<div class="vh-panel vh-rules__editor" id="vh-rule-editor">
		<div class="vh-panel__head">
			<h2>
				<?php echo $vh_editing_id ? esc_html__( 'Edit rule', 'vulnhub' ) : esc_html__( 'New rule', 'vulnhub' ); ?>
			</h2>
			<p class="vh-sub">
				<?php esc_html_e( 'Conditions read the asset as it stands after the last sync. Preview matches before you save — it reports exactly which assets would change, and changes nothing.', 'vulnhub' ); ?>
			</p>
		</div>

		<form method="post" action="<?php echo esc_url( $vh_action_url ); ?>" class="vh-rules__form">
			<?php wp_nonce_field( VulnHub_Rules_Admin::NONCE_ACTION, VulnHub_Rules_Admin::NONCE_FIELD ); ?>
			<input type="hidden" name="rule[id]" value="<?php echo esc_attr( (string) $vh_editing_id ); ?>">

			<div class="vh-rules__grid">
				<label class="vh-rules__field">
					<span><?php esc_html_e( 'Rule name', 'vulnhub' ); ?></span>
					<input type="text" name="rule[name]" required maxlength="191"
						value="<?php echo esc_attr( (string) $vh_editing['name'] ); ?>"
						placeholder="<?php esc_attr_e( 'Auckland and POD hosts are production', 'vulnhub' ); ?>">
				</label>

				<label class="vh-rules__field">
					<span><?php esc_html_e( 'Description', 'vulnhub' ); ?></span>
					<input type="text" name="rule[description]" maxlength="255"
						value="<?php echo esc_attr( (string) $vh_editing['description'] ); ?>"
						placeholder="<?php esc_attr_e( 'Why this rule exists', 'vulnhub' ); ?>">
				</label>

				<label class="vh-rules__field vh-rules__field--narrow">
					<span><?php esc_html_e( 'Conditions must', 'vulnhub' ); ?></span>
					<select name="rule[match_type]">
						<option value="all" <?php selected( 'any' !== (string) $vh_editing['match_type'] ); ?>><?php esc_html_e( 'all match (AND)', 'vulnhub' ); ?></option>
						<option value="any" <?php selected( 'any' === (string) $vh_editing['match_type'] ); ?>><?php esc_html_e( 'any match (OR)', 'vulnhub' ); ?></option>
					</select>
				</label>
			</div>

			<h3 class="vh-h3"><?php esc_html_e( 'Conditions', 'vulnhub' ); ?></h3>

			<div class="vh-rules__conditions" id="vh-rules-conditions">
				<?php
				$vh_condition_rows = (array) $vh_editing['conditions'];
				if ( ! $vh_condition_rows ) {
					$vh_condition_rows = array(
						array(
							'match_field'    => 'hostname',
							'field_key'      => '',
							'match_operator' => 'contains',
							'match_value'    => '',
						),
					);
				}
				?>
				<?php foreach ( $vh_condition_rows as $vh_i => $vh_condition ) : ?>
					<div class="vh-rules__condition" data-index="<?php echo esc_attr( (string) $vh_i ); ?>">
						<label>
							<span class="screen-reader-text"><?php esc_html_e( 'Field', 'vulnhub' ); ?></span>
							<select name="rule[conditions][<?php echo esc_attr( (string) $vh_i ); ?>][match_field]" class="vh-rules__cfield">
								<?php foreach ( $vh_fields as $vh_key => $vh_label ) : ?>
									<option value="<?php echo esc_attr( $vh_key ); ?>" <?php selected( $vh_key, (string) $vh_condition['match_field'] ); ?>>
										<?php echo esc_html( $vh_label ); ?>
									</option>
								<?php endforeach; ?>
							</select>
						</label>

						<label class="vh-rules__ckey">
							<span class="screen-reader-text"><?php esc_html_e( 'Tag category', 'vulnhub' ); ?></span>
							<input type="text" name="rule[conditions][<?php echo esc_attr( (string) $vh_i ); ?>][field_key]"
								value="<?php echo esc_attr( (string) $vh_condition['field_key'] ); ?>"
								placeholder="<?php esc_attr_e( 'tag category, e.g. Environment', 'vulnhub' ); ?>" maxlength="191">
						</label>

						<label>
							<span class="screen-reader-text"><?php esc_html_e( 'Operator', 'vulnhub' ); ?></span>
							<select name="rule[conditions][<?php echo esc_attr( (string) $vh_i ); ?>][match_operator]" class="vh-rules__cop">
								<?php foreach ( $vh_operators as $vh_key => $vh_label ) : ?>
									<option value="<?php echo esc_attr( $vh_key ); ?>" <?php selected( $vh_key, (string) $vh_condition['match_operator'] ); ?>>
										<?php echo esc_html( $vh_label ); ?>
									</option>
								<?php endforeach; ?>
							</select>
						</label>

						<label class="vh-rules__cvalue">
							<span class="screen-reader-text"><?php esc_html_e( 'Value', 'vulnhub' ); ?></span>
							<input type="text" name="rule[conditions][<?php echo esc_attr( (string) $vh_i ); ?>][match_value]"
								value="<?php echo esc_attr( (string) $vh_condition['match_value'] ); ?>"
								placeholder="<?php esc_attr_e( 'akl', 'vulnhub' ); ?>" maxlength="255">
						</label>

						<button type="button" class="vh-btn vh-btn--sm vh-rules__remove" aria-label="<?php esc_attr_e( 'Remove this condition', 'vulnhub' ); ?>">✕</button>
					</div>
				<?php endforeach; ?>
			</div>

			<p>
				<button type="button" class="vh-btn vh-btn--sm" id="vh-rules-add-condition"><?php esc_html_e( '+ Add condition', 'vulnhub' ); ?></button>
				<span class="vh-sub"><?php esc_html_e( 'Tag category applies to the Tenable tag value field; leave it blank to match any tag.', 'vulnhub' ); ?></span>
			</p>

			<h3 class="vh-h3"><?php esc_html_e( 'Then set', 'vulnhub' ); ?></h3>

			<div class="vh-rules__grid">
				<label class="vh-rules__field">
					<span><?php esc_html_e( 'Environment', 'vulnhub' ); ?></span>
					<select name="rule[set_environment]">
						<option value=""><?php esc_html_e( '— leave unchanged —', 'vulnhub' ); ?></option>
						<?php foreach ( $vh_environments as $vh_key => $vh_label ) : ?>
							<option value="<?php echo esc_attr( $vh_key ); ?>" <?php selected( $vh_key, (string) $vh_editing['set_environment'] ); ?>><?php echo esc_html( $vh_label ); ?></option>
						<?php endforeach; ?>
					</select>
				</label>

				<label class="vh-rules__field">
					<span><?php esc_html_e( 'Business criticality', 'vulnhub' ); ?></span>
					<select name="rule[set_criticality]">
						<option value=""><?php esc_html_e( '— leave unchanged —', 'vulnhub' ); ?></option>
						<?php foreach ( $vh_criticality as $vh_key => $vh_label ) : ?>
							<option value="<?php echo esc_attr( $vh_key ); ?>" <?php selected( $vh_key, (string) $vh_editing['set_criticality'] ); ?>><?php echo esc_html( $vh_label ); ?></option>
						<?php endforeach; ?>
					</select>
				</label>

				<label class="vh-rules__field">
					<span><?php esc_html_e( 'Asset type', 'vulnhub' ); ?></span>
					<select name="rule[set_asset_type]">
						<option value=""><?php esc_html_e( '— leave unchanged —', 'vulnhub' ); ?></option>
						<?php foreach ( $vh_asset_types as $vh_key => $vh_label ) : ?>
							<option value="<?php echo esc_attr( $vh_key ); ?>" <?php selected( $vh_key, (string) $vh_editing['set_asset_type'] ); ?>><?php echo esc_html( $vh_label ); ?></option>
						<?php endforeach; ?>
					</select>
				</label>

				<label class="vh-rules__field">
					<span><?php esc_html_e( 'Business service', 'vulnhub' ); ?></span>
					<input type="text" name="rule[set_business_service]" maxlength="191"
						value="<?php echo esc_attr( (string) $vh_editing['set_business_service'] ); ?>"
						placeholder="<?php esc_attr_e( 'leave blank to keep the current value', 'vulnhub' ); ?>">
				</label>

				<label class="vh-rules__field vh-rules__field--narrow">
					<span><?php esc_html_e( 'Priority weight', 'vulnhub' ); ?></span>
					<input type="number" name="rule[set_priority_weight]" min="0" max="1000" step="1"
						value="<?php echo esc_attr( null === $vh_editing['set_priority_weight'] ? '' : (string) (int) $vh_editing['set_priority_weight'] ); ?>"
						placeholder="<?php esc_attr_e( 'e.g. 200', 'vulnhub' ); ?>">
					<small class="vh-muted"><?php esc_html_e( 'A percentage of normal risk: 200 doubles this asset\'s risk score, 50 halves it. Leave empty to change nothing.', 'vulnhub' ); ?></small>
				</label>
			</div>

			<div class="vh-rules__switches">
				<label class="vh-rules__check">
					<input type="checkbox" name="rule[enabled]" value="1" <?php checked( ! empty( $vh_editing['enabled'] ) ); ?>>
					<?php esc_html_e( 'Enabled', 'vulnhub' ); ?>
				</label>
				<label class="vh-rules__check">
					<input type="checkbox" name="rule[stop_processing]" value="1" <?php checked( ! empty( $vh_editing['stop_processing'] ) ); ?>>
					<?php esc_html_e( 'Stop processing further rules when this one matches', 'vulnhub' ); ?>
				</label>
			</div>

			<div class="vh-rules__actions">
				<button type="submit" name="vh_rules_action" value="save" class="vh-btn vh-btn--primary">
					<?php echo $vh_editing_id ? esc_html__( 'Save rule', 'vulnhub' ) : esc_html__( 'Create rule', 'vulnhub' ); ?>
				</button>
				<button type="submit" name="vh_rules_action" value="preview" class="vh-btn" formnovalidate>
					<?php esc_html_e( 'Preview matches', 'vulnhub' ); ?>
				</button>
				<?php if ( $vh_editing_id ) : ?>
					<a class="vh-btn vh-btn--ghost" href="<?php echo esc_url( $vh_action_url ); ?>#vh-rule-editor"><?php esc_html_e( 'Cancel / new rule', 'vulnhub' ); ?></a>
				<?php endif; ?>
			</div>
		</form>
	</div>

	<details class="vh-panel vh-rules__help">
		<summary><?php esc_html_e( 'How classification rules are evaluated', 'vulnhub' ); ?></summary>
		<ul class="vh-rules__helplist">
			<li><?php esc_html_e( 'Enabled rules run in the order shown, top to bottom, for every asset.', 'vulnhub' ); ?></li>
			<li><?php esc_html_e( 'A rule matches when all of its conditions hold (AND), or any of them do (OR).', 'vulnhub' ); ?></li>
			<li><?php esc_html_e( 'Every rule that matches applies its settings, so a later rule overrides an earlier one on the same attribute. Tick "stop processing" to make a rule final.', 'vulnhub' ); ?></li>
			<li><?php esc_html_e( 'Multi-valued fields — several IP addresses, several Tenable tags — match if any value matches; the negative operators require every value to satisfy them.', 'vulnhub' ); ?></li>
			<li><?php esc_html_e( 'Classification runs automatically after each Tenable, Intune or CMDB sync, before core decides asset ownership.', 'vulnhub' ); ?></li>
		</ul>
	</details>

	<template id="vh-rules-condition-template">
		<div class="vh-rules__condition" data-index="__i__">
			<label>
				<span class="screen-reader-text"><?php esc_html_e( 'Field', 'vulnhub' ); ?></span>
				<select name="rule[conditions][__i__][match_field]" class="vh-rules__cfield">
					<?php foreach ( $vh_fields as $vh_key => $vh_label ) : ?>
						<option value="<?php echo esc_attr( $vh_key ); ?>"><?php echo esc_html( $vh_label ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label class="vh-rules__ckey">
				<span class="screen-reader-text"><?php esc_html_e( 'Tag category', 'vulnhub' ); ?></span>
				<input type="text" name="rule[conditions][__i__][field_key]" value="" placeholder="<?php esc_attr_e( 'tag category, e.g. Environment', 'vulnhub' ); ?>" maxlength="191">
			</label>
			<label>
				<span class="screen-reader-text"><?php esc_html_e( 'Operator', 'vulnhub' ); ?></span>
				<select name="rule[conditions][__i__][match_operator]" class="vh-rules__cop">
					<?php foreach ( $vh_operators as $vh_key => $vh_label ) : ?>
						<option value="<?php echo esc_attr( $vh_key ); ?>"><?php echo esc_html( $vh_label ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label class="vh-rules__cvalue">
				<span class="screen-reader-text"><?php esc_html_e( 'Value', 'vulnhub' ); ?></span>
				<input type="text" name="rule[conditions][__i__][match_value]" value="" maxlength="255">
			</label>
			<button type="button" class="vh-btn vh-btn--sm vh-rules__remove" aria-label="<?php esc_attr_e( 'Remove this condition', 'vulnhub' ); ?>">✕</button>
		</div>
	</template>

	<script type="application/json" id="vh-rules-config">
		<?php
		echo wp_json_encode(
			array(
				'valueless' => array_values( $vh_valueless ),
			)
		);
		?>
	</script>
</div>

