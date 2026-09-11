<?php
/**
 * Form handling for the Automation screen.
 *
 * The screen itself is admin/views/automation.php; this class owns every
 * `admin-post.php` action behind it, so all the sanitising, capability checks
 * and nonce verification live in one auditable place.
 *
 * The rule editor deliberately exposes a fixed set of condition inputs rather
 * than a free-form expression builder. They are stored in the generic
 * `[{field, op, value}]` shape the engine evaluates, so the storage format
 * stays open while the UI stays something an administrator can actually fill
 * in correctly at 4pm on a Friday.
 *
 * @package VulnHub\Jira
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Admin-post handlers for automation rules.
 */
final class VulnHub_Jira_Automation_Admin {

	/**
	 * Register hooks.
	 */
	public function hooks(): void {
		add_action( 'admin_post_vulnhub_jira_save_rule', array( $this, 'handle_save' ) );
		add_action( 'admin_post_vulnhub_jira_delete_rule', array( $this, 'handle_delete' ) );
		add_action( 'admin_post_vulnhub_jira_toggle_rule', array( $this, 'handle_toggle' ) );
		add_action( 'admin_post_vulnhub_jira_run_rule', array( $this, 'handle_run_rule' ) );
		add_action( 'admin_post_vulnhub_jira_run_all', array( $this, 'handle_run_all' ) );
		add_action( 'admin_post_vulnhub_jira_seed_rules', array( $this, 'handle_seed' ) );
	}

	/**
	 * Only administrators of the platform may change automation.
	 */
	private function guard(): void {
		if ( ! current_user_can( \VulnHub\Core\Caps::MANAGE ) ) {
			wp_die( esc_html__( 'You do not have permission to manage automation rules.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}
	}

	/**
	 * Redirect back to the Automation screen with a notice.
	 *
	 * @param string              $message Notice text.
	 * @param string              $type    success|warning|error.
	 * @param array<string,mixed> $args    Extra query args.
	 */
	private function back( string $message, string $type = 'success', array $args = array() ): void {
		wp_safe_redirect(
			vh_admin_url(
				'vulnhub-automation',
				array_merge(
					$args,
					array(
						'vh_msg'  => $message,
						'vh_type' => $type,
					)
				)
			)
		);
		exit;
	}

	/* =================================================================
	 * Save
	 * ============================================================== */

	/**
	 * Create or update a rule.
	 */
	public function handle_save(): void {
		$this->guard();
		check_admin_referer( 'vulnhub_jira_save_rule' );

		$post = wp_unslash( $_POST ); // phpcs:ignore WordPress.Security.NonceVerification.Missing

		$data = array(
			'id'               => isset( $post['rule_id'] ) ? (int) $post['rule_id'] : 0,
			'name'             => isset( $post['name'] ) ? sanitize_text_field( (string) $post['name'] ) : '',
			'description'      => isset( $post['description'] ) ? sanitize_textarea_field( (string) $post['description'] ) : '',
			'enabled'          => ! empty( $post['enabled'] ),
			'priority'         => isset( $post['priority'] ) ? (int) $post['priority'] : 10,
			'trigger_event'    => isset( $post['trigger_event'] ) ? sanitize_text_field( (string) $post['trigger_event'] ) : 'finding.discovered',
			'match_all'        => ! isset( $post['match_mode'] ) || 'all' === $post['match_mode'],
			'grouping'         => isset( $post['grouping'] ) ? sanitize_key( (string) $post['grouping'] ) : 'per_asset_and_severity',
			'throttle_minutes' => isset( $post['throttle_minutes'] ) ? (int) $post['throttle_minutes'] : 0,
			'max_per_run'      => isset( $post['max_per_run'] ) ? (int) $post['max_per_run'] : 25,
			'conditions'       => $this->conditions_from_post( $post ),
			'actions'          => $this->actions_from_post( $post ),
		);

		if ( '' === trim( $data['name'] ) ) {
			$this->back( __( 'Give the rule a name so it can be recognised in the audit trail.', 'vulnhub' ), 'error' );
		}
		if ( ! $data['actions'] ) {
			$this->back( __( 'A rule needs at least one action, otherwise it can only ever do nothing.', 'vulnhub' ), 'error' );
		}

		$engine = vulnhub_jira_automation();
		$id     = $engine->save( $data );

		vulnhub()->logger->audit(
			$data['id'] ? 'automation.updated' : 'automation.created',
			sprintf(
				/* translators: 1: rule name, 2: enabled or disabled. */
				__( 'Automation rule "%1$s" was saved (%2$s).', 'vulnhub' ),
				$data['name'],
				$data['enabled'] ? __( 'enabled', 'vulnhub' ) : __( 'disabled', 'vulnhub' )
			),
			'automation',
			$id,
			array(
				'trigger'    => $data['trigger_event'],
				'grouping'   => $data['grouping'],
				'conditions' => count( $data['conditions'] ),
				'actions'    => array_column( $data['actions'], 'type' ),
				'max_per_run' => $data['max_per_run'],
				'throttle'   => $data['throttle_minutes'],
			)
		);

		$this->back(
			sprintf(
				/* translators: %s: rule name. */
				__( 'Saved the rule "%s". Use Preview matches before you enable it.', 'vulnhub' ),
				$data['name']
			),
			'success',
			array( 'rule' => $id )
		);
	}

	/**
	 * Build the engine's condition list from the fixed form inputs.
	 *
	 * @param array<string,mixed> $post Unslashed POST.
	 * @return array<int,array{field:string,op:string,value:mixed}>
	 */
	private function conditions_from_post( array $post ): array {
		$conditions = array();

		$multi = array(
			'severity'    => array_keys( vh_severities() ),
			'asset_type'  => array_keys( vh_asset_types() ),
			'criticality' => array( 'critical', 'high', 'medium', 'low' ),
		);

		foreach ( $multi as $field => $allowed ) {
			$values = isset( $post[ 'cond_' . $field ] ) ? (array) $post[ 'cond_' . $field ] : array();
			$values = array_values( array_intersect( array_map( 'sanitize_key', array_map( 'strval', $values ) ), $allowed ) );

			if ( $values ) {
				$conditions[] = array(
					'field' => $field,
					'op'    => 'in',
					'value' => $values,
				);
			}
		}

		foreach ( array( 'team_id', 'location_id' ) as $field ) {
			$value = isset( $post[ 'cond_' . $field ] ) ? (int) $post[ 'cond_' . $field ] : 0;

			if ( $value > 0 ) {
				$conditions[] = array(
					'field' => $field,
					'op'    => 'is',
					'value' => $value,
				);
			}
		}

		foreach ( array( 'environment', 'tag' ) as $field ) {
			$value = isset( $post[ 'cond_' . $field ] ) ? sanitize_text_field( (string) $post[ 'cond_' . $field ] ) : '';

			if ( '' !== trim( $value ) ) {
				$conditions[] = array(
					'field' => $field,
					'op'    => 'contains',
					'value' => trim( $value ),
				);
			}
		}

		foreach ( array( 'cvss3_base', 'vpr_score', 'days_open' ) as $field ) {
			$raw = isset( $post[ 'cond_' . $field ] ) ? trim( (string) $post[ 'cond_' . $field ] ) : '';

			if ( '' === $raw || ! is_numeric( $raw ) ) {
				continue;
			}

			$value = (float) $raw;

			if ( $value > 0 ) {
				$conditions[] = array(
					'field' => $field,
					'op'    => 'gte',
					'value' => 'days_open' === $field ? (int) $value : round( $value, 1 ),
				);
			}
		}

		if ( ! empty( $post['cond_exploit_available'] ) ) {
			$conditions[] = array(
				'field' => 'exploit_available',
				'op'    => 'is_true',
				'value' => 1,
			);
		}

		if ( ! empty( $post['cond_has_ticket'] ) ) {
			$conditions[] = array(
				'field' => 'has_ticket',
				'op'    => 'is_false',
				'value' => 0,
			);
		}

		return $conditions;
	}

	/**
	 * Build the engine's action list from the form.
	 *
	 * @param array<string,mixed> $post Unslashed POST.
	 * @return array<int,array<string,mixed>>
	 */
	private function actions_from_post( array $post ): array {
		$actions = array();

		if ( ! empty( $post['act_create_ticket'] ) ) {
			$grouping = isset( $post['act_create_grouping'] ) ? sanitize_key( (string) $post['act_create_grouping'] ) : '';

			$actions[] = array(
				'type'     => 'create_ticket',
				'grouping' => isset( VulnHub_Jira_Connector::grouping_options()[ $grouping ] ) ? $grouping : '',
			);
		}

		if ( ! empty( $post['act_comment'] ) ) {
			$actions[] = array(
				'type' => 'comment',
				'text' => isset( $post['act_comment_text'] ) ? sanitize_textarea_field( (string) $post['act_comment_text'] ) : '',
			);
		}

		if ( ! empty( $post['act_transition'] ) ) {
			$status = isset( $post['act_transition_status'] ) ? sanitize_text_field( (string) $post['act_transition_status'] ) : '';

			if ( '' !== trim( $status ) ) {
				$actions[] = array(
					'type'   => 'transition',
					'status' => trim( $status ),
				);
			}
		}

		if ( ! empty( $post['act_set_priority'] ) ) {
			$priority = isset( $post['act_priority'] ) ? sanitize_text_field( (string) $post['act_priority'] ) : '';

			if ( '' !== trim( $priority ) ) {
				$actions[] = array(
					'type'     => 'set_priority',
					'priority' => trim( $priority ),
				);
			}
		}

		if ( ! empty( $post['act_notify'] ) ) {
			$recipient = isset( $post['act_notify_recipient'] ) ? sanitize_key( (string) $post['act_notify_recipient'] ) : 'team_manager';

			$actions[] = array(
				'type'      => 'notify',
				'recipient' => isset( VulnHub_Jira_Automation::notify_targets()[ $recipient ] ) ? $recipient : 'team_manager',
				'subject'   => isset( $post['act_notify_subject'] ) ? sanitize_text_field( (string) $post['act_notify_subject'] ) : '',
				'message'   => isset( $post['act_notify_message'] ) ? sanitize_textarea_field( (string) $post['act_notify_message'] ) : '',
			);
		}

		return $actions;
	}

	/**
	 * Flatten a stored rule back into the editor's form values.
	 *
	 * @param array<string,mixed>|null $rule Hydrated rule row, or null for a new rule.
	 * @return array<string,mixed>
	 */
	public static function form_values( ?array $rule ): array {
		$values = array(
			'cond_severity'          => array(),
			'cond_asset_type'        => array(),
			'cond_criticality'       => array(),
			'cond_team_id'           => 0,
			'cond_location_id'       => 0,
			'cond_environment'       => '',
			'cond_tag'               => '',
			'cond_cvss3_base'        => '',
			'cond_vpr_score'         => '',
			'cond_days_open'         => '',
			'cond_exploit_available' => false,
			'cond_has_ticket'        => false,
			'act_create_ticket'      => false,
			'act_create_grouping'    => '',
			'act_comment'            => false,
			'act_comment_text'       => '',
			'act_transition'         => false,
			'act_transition_status'  => '',
			'act_set_priority'       => false,
			'act_priority'           => '',
			'act_notify'             => false,
			'act_notify_recipient'   => 'team_manager',
			'act_notify_subject'     => '',
			'act_notify_message'     => '',
		);

		if ( ! $rule ) {
			return $values;
		}

		foreach ( (array) ( $rule['conditions'] ?? array() ) as $condition ) {
			if ( ! is_array( $condition ) || empty( $condition['field'] ) ) {
				continue;
			}

			$field = (string) $condition['field'];
			$value = $condition['value'] ?? '';

			switch ( $field ) {
				case 'severity':
				case 'asset_type':
				case 'criticality':
					$values[ 'cond_' . $field ] = array_map( 'strval', (array) $value );
					break;

				case 'team_id':
				case 'location_id':
					$values[ 'cond_' . $field ] = (int) $value;
					break;

				case 'environment':
				case 'tag':
					$values[ 'cond_' . $field ] = (string) $value;
					break;

				case 'cvss3_base':
				case 'vpr_score':
				case 'days_open':
					$values[ 'cond_' . $field ] = (string) $value;
					break;

				case 'exploit_available':
					$values['cond_exploit_available'] = true;
					break;

				case 'has_ticket':
					$values['cond_has_ticket'] = true;
					break;
			}
		}

		foreach ( (array) ( $rule['actions'] ?? array() ) as $action ) {
			if ( ! is_array( $action ) || empty( $action['type'] ) ) {
				continue;
			}

			switch ( (string) $action['type'] ) {
				case 'create_ticket':
					$values['act_create_ticket']   = true;
					$values['act_create_grouping'] = (string) ( $action['grouping'] ?? '' );
					break;

				case 'comment':
					$values['act_comment']      = true;
					$values['act_comment_text'] = (string) ( $action['text'] ?? '' );
					break;

				case 'transition':
					$values['act_transition']        = true;
					$values['act_transition_status'] = (string) ( $action['status'] ?? '' );
					break;

				case 'set_priority':
					$values['act_set_priority'] = true;
					$values['act_priority']     = (string) ( $action['priority'] ?? '' );
					break;

				case 'notify':
					$values['act_notify']           = true;
					$values['act_notify_recipient'] = (string) ( $action['recipient'] ?? 'team_manager' );
					$values['act_notify_subject']   = (string) ( $action['subject'] ?? '' );
					$values['act_notify_message']   = (string) ( $action['message'] ?? '' );
					break;
			}
		}

		return $values;
	}

	/* =================================================================
	 * Delete / toggle / run
	 * ============================================================== */

	/**
	 * Delete a rule.
	 */
	public function handle_delete(): void {
		$this->guard();
		check_admin_referer( 'vulnhub_jira_delete_rule' );

		$id     = isset( $_POST['rule_id'] ) ? (int) $_POST['rule_id'] : 0;
		$engine = vulnhub_jira_automation();
		$rule   = $engine->rule( $id );

		if ( ! $rule ) {
			$this->back( __( 'That rule no longer exists.', 'vulnhub' ), 'warning' );
		}

		$engine->delete( $id );

		vulnhub()->logger->audit(
			'automation.deleted',
			sprintf(
				/* translators: %s: rule name. */
				__( 'Automation rule "%s" was deleted.', 'vulnhub' ),
				(string) $rule['name']
			),
			'automation',
			$id,
			array(),
			'warning'
		);

		$this->back(
			sprintf(
				/* translators: %s: rule name. */
				__( 'Deleted the rule "%s".', 'vulnhub' ),
				(string) $rule['name']
			)
		);
	}

	/**
	 * Enable or disable a rule.
	 */
	public function handle_toggle(): void {
		$this->guard();
		check_admin_referer( 'vulnhub_jira_toggle_rule' );

		global $wpdb;

		$id     = isset( $_POST['rule_id'] ) ? (int) $_POST['rule_id'] : 0;
		$engine = vulnhub_jira_automation();
		$rule   = $engine->rule( $id );

		if ( ! $rule ) {
			$this->back( __( 'That rule no longer exists.', 'vulnhub' ), 'warning' );
		}

		$enabled = empty( $rule['enabled'] ) ? 1 : 0;

		$wpdb->update(
			VulnHub_Jira_Automation::table(),
			array(
				'enabled'    => $enabled,
				'updated_at' => vh_now(),
			),
			array( 'id' => $id )
		);

		vulnhub()->logger->audit(
			$enabled ? 'automation.enabled' : 'automation.disabled',
			sprintf(
				/* translators: 1: rule name, 2: state. */
				__( 'Automation rule "%1$s" was %2$s.', 'vulnhub' ),
				(string) $rule['name'],
				$enabled ? __( 'enabled', 'vulnhub' ) : __( 'disabled', 'vulnhub' )
			),
			'automation',
			$id,
			array(),
			$enabled ? 'warning' : 'info'
		);

		$this->back(
			$enabled
				/* translators: %s: rule name. */
				? sprintf( __( '"%s" is now live and will run on the next automation pass.', 'vulnhub' ), (string) $rule['name'] )
				/* translators: %s: rule name. */
				: sprintf( __( '"%s" is disabled.', 'vulnhub' ), (string) $rule['name'] ),
			'success',
			array( 'rule' => $id )
		);
	}

	/**
	 * Run one rule immediately.
	 */
	public function handle_run_rule(): void {
		$this->guard();
		check_admin_referer( 'vulnhub_jira_run_rule' );

		$id     = isset( $_POST['rule_id'] ) ? (int) $_POST['rule_id'] : 0;
		$engine = vulnhub_jira_automation();
		$rule   = $engine->rule( $id );

		if ( ! $rule ) {
			$this->back( __( 'That rule no longer exists.', 'vulnhub' ), 'warning' );
		}

		$result = $engine->run_rule( $rule );

		$this->back(
			sprintf(
				/* translators: 1: rule name, 2: findings matched, 3: groups actioned, 4: tickets, 5: emails. */
				__( '"%1$s": %2$d finding(s) matched, %3$d group(s) actioned, %4$d Jira ticket(s) raised, %5$d email(s) sent.', 'vulnhub' ),
				(string) $rule['name'],
				(int) $result['matched'],
				(int) $result['actioned'],
				(int) $result['tickets'],
				(int) $result['emails']
			) . ( $result['messages'] ? ' ' . vh_trim( implode( ' ', $result['messages'] ), 200 ) : '' ),
			$result['failed'] > 0 ? 'warning' : 'success',
			array( 'rule' => $id )
		);
	}

	/**
	 * Run every enabled rule immediately.
	 */
	public function handle_run_all(): void {
		$this->guard();
		check_admin_referer( 'vulnhub_jira_run_all' );

		$summary = vulnhub_jira_automation()->run_scheduled();

		$this->back(
			sprintf(
				/* translators: 1: rules, 2: matched, 3: actioned, 4: tickets, 5: emails, 6: throttled. */
				__( 'Ran %1$d enabled rule(s): %2$d finding(s) matched, %3$d group(s) actioned, %4$d ticket(s) raised, %5$d email(s) sent, %6$d rule(s) throttled.', 'vulnhub' ),
				(int) $summary['rules'],
				(int) $summary['matched'],
				(int) $summary['actioned'],
				(int) $summary['tickets'],
				(int) $summary['emails'],
				(int) $summary['skipped']
			),
			(int) $summary['failed'] > 0 ? 'warning' : 'success'
		);
	}

	/**
	 * Recreate the two example rules.
	 */
	public function handle_seed(): void {
		$this->guard();
		check_admin_referer( 'vulnhub_jira_seed_rules' );

		VulnHub_Jira_Automation::seed_examples();

		$this->back( __( 'Example rules restored. They are disabled — read them, adjust them, preview them, then enable them.', 'vulnhub' ) );
	}
}

