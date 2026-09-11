<?php
/**
 * The automation engine.
 *
 * A rule is: a trigger, a set of conditions, and a set of actions.
 *
 *   trigger     what makes the rule look at anything at all
 *   conditions  which of those findings it cares about (ALL or ANY)
 *   actions     what it does about them
 *
 * Rules live in core's `vh_vulnhub_automations` table and are edited on the
 * Automation screen. The engine runs on core's `vulnhub_run_automations` hook,
 * which fires every fifteen minutes.
 *
 * Three safety properties matter more than any feature here, because this code
 * writes to a production ticketing system on a timer:
 *
 *   1. `max_per_run` caps how many units of work one rule may action in a
 *      single pass, so a rule that accidentally matches ten thousand findings
 *      raises a handful of tickets and stops.
 *   2. `throttle_minutes` caps how often a rule may run at all, independently
 *      of the cron cadence.
 *   3. Every rule can be previewed. `preview()` performs exactly the same
 *      selection, condition evaluation and grouping as `run_rule()` and then
 *      returns what it found without touching Jira — the admin screen's
 *      "Preview matches" button is a genuine dry run, not an estimate.
 *
 * @package VulnHub\Jira
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Evaluates and executes automation rules.
 */
final class VulnHub_Jira_Automation {

	/** Never consider more than this many findings for one rule in one pass. */
	private const CANDIDATE_CEILING = 2000;

	/** Default look-back when a rule has never run. */
	private const FIRST_RUN_HOURS = 24;

	/** How many run summaries to keep for the admin screen. */
	private const HISTORY = 25;

	/**
	 * Register hooks.
	 */
	public function hooks(): void {
		add_action( 'vulnhub_run_automations', array( $this, 'run_scheduled' ), 20 );
	}

	/* =================================================================
	 * Vocabulary
	 * ============================================================== */

	/**
	 * Triggers a rule may fire on.
	 *
	 * @return array<string,array{label:string,help:string}>
	 */
	public static function triggers(): array {
		return array(
			'finding.discovered'      => array(
				'label' => __( 'A finding is discovered', 'vulnhub' ),
				'help'  => __( 'Findings first recorded since the rule last ran.', 'vulnhub' ),
			),
			'finding.reopened'        => array(
				'label' => __( 'A finding is reopened', 'vulnhub' ),
				'help'  => __( 'A vulnerability that was fixed has come back, or a closure was not verified.', 'vulnhub' ),
			),
			'finding.overdue'         => array(
				'label' => __( 'A finding passes its SLA', 'vulnhub' ),
				'help'  => __( 'Open findings whose SLA due date is in the past.', 'vulnhub' ),
			),
			'ticket.closed_unverified' => array(
				'label' => __( 'A closed ticket fails verification', 'vulnhub' ),
				'help'  => __( 'Findings on tickets that were closed but which the scanner still detects.', 'vulnhub' ),
			),
			'schedule'                => array(
				'label' => __( 'On every scheduled pass', 'vulnhub' ),
				'help'  => __( 'Every open finding is considered, every fifteen minutes. Use a throttle.', 'vulnhub' ),
			),
		);
	}

	/**
	 * Condition fields, their operators and how the admin screen renders them.
	 *
	 * @return array<string,array{label:string,type:string,op:string}>
	 */
	public static function condition_fields(): array {
		return array(
			'severity'          => array(
				'label' => __( 'Severity is one of', 'vulnhub' ),
				'type'  => 'severity',
				'op'    => 'in',
			),
			'asset_type'        => array(
				'label' => __( 'Asset type is one of', 'vulnhub' ),
				'type'  => 'asset_type',
				'op'    => 'in',
			),
			'criticality'       => array(
				'label' => __( 'Asset criticality is one of', 'vulnhub' ),
				'type'  => 'criticality',
				'op'    => 'in',
			),
			'team_id'           => array(
				'label' => __( 'Owning team is', 'vulnhub' ),
				'type'  => 'team',
				'op'    => 'is',
			),
			'location_id'       => array(
				'label' => __( 'Location is', 'vulnhub' ),
				'type'  => 'location',
				'op'    => 'is',
			),
			'environment'       => array(
				'label' => __( 'Environment contains', 'vulnhub' ),
				'type'  => 'text',
				'op'    => 'contains',
			),
			'cvss3_base'        => array(
				'label' => __( 'CVSSv3 base score is at least', 'vulnhub' ),
				'type'  => 'number',
				'op'    => 'gte',
			),
			'vpr_score'         => array(
				'label' => __( 'VPR score is at least', 'vulnhub' ),
				'type'  => 'number',
				'op'    => 'gte',
			),
			'exploit_available' => array(
				'label' => __( 'A public exploit exists', 'vulnhub' ),
				'type'  => 'bool',
				'op'    => 'is_true',
			),
			'days_open'         => array(
				'label' => __( 'Days open is at least', 'vulnhub' ),
				'type'  => 'number',
				'op'    => 'gte',
			),
			'has_ticket'        => array(
				'label' => __( 'The finding has no ticket yet', 'vulnhub' ),
				'type'  => 'bool',
				'op'    => 'is_false',
			),
			'tag'               => array(
				'label' => __( 'An asset tag matches', 'vulnhub' ),
				'type'  => 'text',
				'op'    => 'contains',
			),
		);
	}

	/**
	 * Action types a rule may perform.
	 *
	 * @return array<string,string>
	 */
	public static function action_types(): array {
		return array(
			'create_ticket' => __( 'Create a Jira ticket', 'vulnhub' ),
			'comment'       => __( 'Add a comment to the ticket', 'vulnhub' ),
			'transition'    => __( 'Transition the issue', 'vulnhub' ),
			'set_priority'  => __( 'Set the issue priority', 'vulnhub' ),
			'notify'        => __( 'Send an email notification', 'vulnhub' ),
		);
	}

	/**
	 * Who an email notification may go to.
	 *
	 * @return array<string,string>
	 */
	public static function notify_targets(): array {
		return array(
			'owner'        => __( 'The asset owner', 'vulnhub' ),
			'team_manager' => __( 'The team manager', 'vulnhub' ),
			'both'         => __( 'Both the asset owner and the team manager', 'vulnhub' ),
		);
	}

	/* =================================================================
	 * Persistence
	 * ============================================================== */

	/**
	 * The automations table.
	 */
	public static function table(): string {
		return vh_table( 'automations' );
	}

	/**
	 * All rules, most important first.
	 *
	 * @param bool   $enabled_only Only enabled rules.
	 * @param string $trigger      Restrict to one trigger.
	 * @return array<int,array<string,mixed>>
	 */
	public function rules( bool $enabled_only = false, string $trigger = '' ): array {
		global $wpdb;

		$where  = array( '1=1' );
		$params = array();

		if ( $enabled_only ) {
			$where[] = 'enabled = 1';
		}
		if ( '' !== $trigger ) {
			$where[]  = 'trigger_event = %s';
			$params[] = $trigger;
		}

		$sql = 'SELECT * FROM ' . self::table() . ' WHERE ' . implode( ' AND ', $where ) . ' ORDER BY priority ASC, id ASC';

		$rows = $params
			? (array) $wpdb->get_results( $wpdb->prepare( $sql, ...$params ), ARRAY_A ) // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			: (array) $wpdb->get_results( $sql, ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

		return array_map( array( $this, 'hydrate' ), $rows );
	}

	/**
	 * One rule.
	 *
	 * @return array<string,mixed>|null
	 */
	public function rule( int $id ): ?array {
		global $wpdb;

		if ( ! $id ) {
			return null;
		}

		$row = $wpdb->get_row(
			$wpdb->prepare( 'SELECT * FROM ' . self::table() . ' WHERE id = %d', $id ),
			ARRAY_A
		);

		return $row ? $this->hydrate( $row ) : null;
	}

	/**
	 * Decode the JSON columns.
	 *
	 * @param array<string,mixed> $row Raw row.
	 * @return array<string,mixed>
	 */
	private function hydrate( array $row ): array {
		$row['conditions'] = vh_json( (string) ( $row['conditions_json'] ?? '' ) );
		$row['actions']    = vh_json( (string) ( $row['actions_json'] ?? '' ) );

		return $row;
	}

	/**
	 * Create or update a rule.
	 *
	 * @param array<string,mixed> $data Sanitised rule fields.
	 * @return int Rule id.
	 */
	public function save( array $data ): int {
		global $wpdb;

		$triggers = self::triggers();
		$trigger  = (string) ( $data['trigger_event'] ?? 'finding.discovered' );

		$row = array(
			'name'             => vh_trim( (string) ( $data['name'] ?? '' ), 180 ) ?: __( 'Untitled rule', 'vulnhub' ),
			'description'      => vh_trim( (string) ( $data['description'] ?? '' ), 900 ),
			'enabled'          => empty( $data['enabled'] ) ? 0 : 1,
			'priority'         => max( 1, min( 999, (int) ( $data['priority'] ?? 10 ) ) ),
			'trigger_event'    => isset( $triggers[ $trigger ] ) ? $trigger : 'finding.discovered',
			'match_all'        => empty( $data['match_all'] ) ? 0 : 1,
			'conditions_json'  => (string) wp_json_encode( array_values( (array) ( $data['conditions'] ?? array() ) ) ),
			'actions_json'     => (string) wp_json_encode( array_values( (array) ( $data['actions'] ?? array() ) ) ),
			'grouping'         => isset( VulnHub_Jira_Connector::grouping_options()[ (string) ( $data['grouping'] ?? '' ) ] )
				? (string) $data['grouping']
				: 'per_asset_and_severity',
			'throttle_minutes' => max( 0, min( 10080, (int) ( $data['throttle_minutes'] ?? 0 ) ) ),
			'max_per_run'      => max( 1, min( 200, (int) ( $data['max_per_run'] ?? 25 ) ) ),
			'updated_at'       => vh_now(),
		);

		$id = (int) ( $data['id'] ?? 0 );

		if ( $id && $this->rule( $id ) ) {
			$wpdb->update( self::table(), $row, array( 'id' => $id ) );

			return $id;
		}

		$row['created_at'] = vh_now();
		$wpdb->insert( self::table(), $row );

		return (int) $wpdb->insert_id;
	}

	/**
	 * Delete a rule.
	 */
	public function delete( int $id ): void {
		global $wpdb;

		if ( $id ) {
			$wpdb->delete( self::table(), array( 'id' => $id ), array( '%d' ) );
		}
	}

	/**
	 * Seed two disabled example rules on first activation.
	 *
	 * They exist so an administrator can read a working rule rather than guess
	 * at the shape of one, and they are disabled so nothing reaches Jira until
	 * somebody deliberately turns them on.
	 */
	public static function seed_examples(): void {
		global $wpdb;

		$table = self::table();

		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) {
			return;
		}
		if ( (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . $table ) > 0 ) { // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			return;
		}

		$engine = new self();

		$engine->save(
			array(
				'name'             => __( 'Critical vulnerabilities on production servers → raise a ticket immediately', 'vulnhub' ),
				'description'      => __( 'A critical finding on a production server is the case where waiting for a human to notice is the whole problem. This raises one ticket per server per severity as soon as the finding is imported, and only for findings that do not already have a ticket.', 'vulnhub' ),
				'enabled'          => 0,
				'priority'         => 10,
				'trigger_event'    => 'finding.discovered',
				'match_all'        => 1,
				'grouping'         => 'per_asset_and_severity',
				'throttle_minutes' => 0,
				'max_per_run'      => 10,
				'conditions'       => array(
					array(
						'field' => 'severity',
						'op'    => 'in',
						'value' => array( 'critical' ),
					),
					array(
						'field' => 'asset_type',
						'op'    => 'in',
						'value' => array( 'server' ),
					),
					array(
						'field' => 'environment',
						'op'    => 'contains',
						'value' => 'production',
					),
					array(
						'field' => 'has_ticket',
						'op'    => 'is_false',
						'value' => '',
					),
				),
				'actions'          => array(
					array(
						'type'     => 'create_ticket',
						'grouping' => 'per_asset_and_severity',
					),
				),
			)
		);

		$engine->save(
			array(
				'name'             => __( 'Anything past SLA with no ticket → raise a ticket and email the team manager', 'vulnhub' ),
				'description'      => __( 'The SLA has already been missed, so the useful action is to make somebody accountable rather than to keep counting. Raises one ticket per asset and severity and emails the owning team\'s manager. Throttled to once an hour.', 'vulnhub' ),
				'enabled'          => 0,
				'priority'         => 20,
				'trigger_event'    => 'finding.overdue',
				'match_all'        => 1,
				'grouping'         => 'per_asset_and_severity',
				'throttle_minutes' => 60,
				'max_per_run'      => 15,
				'conditions'       => array(
					array(
						'field' => 'has_ticket',
						'op'    => 'is_false',
						'value' => '',
					),
					array(
						'field' => 'severity',
						'op'    => 'in',
						'value' => array( 'critical', 'high', 'medium' ),
					),
				),
				'actions'          => array(
					array(
						'type'     => 'create_ticket',
						'grouping' => 'per_asset_and_severity',
					),
					array(
						'type'      => 'notify',
						'recipient' => 'team_manager',
						'subject'   => __( 'Vulnerability remediation is past its SLA', 'vulnhub' ),
					),
				),
			)
		);
	}

	/* =================================================================
	 * Running
	 * ============================================================== */

	/**
	 * Run every enabled rule. Answers core's fifteen-minute hook.
	 *
	 * @return array<string,mixed>
	 */
	public function run_scheduled(): array {
		$connector = vulnhub_jira_connector();

		$summary = array(
			'rules'    => 0,
			'skipped'  => 0,
			'matched'  => 0,
			'actioned' => 0,
			'tickets'  => 0,
			'emails'   => 0,
			'failed'   => 0,
			'detail'   => array(),
			'at'       => vh_now(),
		);

		if ( ! $connector || ! $connector->is_enabled() ) {
			return $summary;
		}

		foreach ( $this->rules( true ) as $rule ) {
			$result = $this->run_rule( $rule );

			++$summary['rules'];

			if ( ! empty( $result['throttled'] ) ) {
				++$summary['skipped'];
			}

			$summary['matched']  += (int) $result['matched'];
			$summary['actioned'] += (int) $result['actioned'];
			$summary['tickets']  += (int) $result['tickets'];
			$summary['emails']   += (int) $result['emails'];
			$summary['failed']   += (int) $result['failed'];

			$summary['detail'][] = array(
				'id'        => (int) $rule['id'],
				'name'      => (string) $rule['name'],
				'matched'   => (int) $result['matched'],
				'actioned'  => (int) $result['actioned'],
				'tickets'   => (int) $result['tickets'],
				'emails'    => (int) $result['emails'],
				'throttled' => ! empty( $result['throttled'] ),
				'capped'    => ! empty( $result['capped'] ),
			);
		}

		$this->remember( $summary );

		return $summary;
	}

	/**
	 * Evaluate one rule and act on it.
	 *
	 * @param array<string,mixed> $rule    Hydrated rule row.
	 * @param bool                $dry_run Evaluate but do not act.
	 * @return array{matched:int,actioned:int,tickets:int,emails:int,failed:int,throttled:bool,capped:bool,groups:array<string,array<int,array<string,mixed>>>,rows:array<int,array<string,mixed>>,messages:array<int,string>}
	 */
	public function run_rule( array $rule, bool $dry_run = false ): array {
		$out = array(
			'matched'   => 0,
			'actioned'  => 0,
			'tickets'   => 0,
			'emails'    => 0,
			'failed'    => 0,
			'throttled' => false,
			'capped'    => false,
			'groups'    => array(),
			'rows'      => array(),
			'messages'  => array(),
		);

		if ( ! $dry_run && $this->is_throttled( $rule ) ) {
			$out['throttled'] = true;
			$out['messages'][] = sprintf(
				/* translators: %d: throttle in minutes. */
				__( 'Skipped: this rule may run at most once every %d minutes.', 'vulnhub' ),
				(int) $rule['throttle_minutes']
			);

			return $out;
		}

		$rows = $this->candidates( $rule );
		$rows = array_values(
			array_filter(
				$rows,
				fn( array $row ): bool => $this->matches( $rule, $row )
			)
		);

		$out['matched'] = count( $rows );
		$out['rows']    = $rows;

		if ( ! $rows ) {
			if ( ! $dry_run ) {
				$this->stamp_run( $rule, 0 );
			}

			$out['messages'][] = __( 'No findings matched.', 'vulnhub' );

			return $out;
		}

		$grouping = isset( VulnHub_Jira_Connector::grouping_options()[ (string) $rule['grouping'] ] )
			? (string) $rule['grouping']
			: 'per_asset_and_severity';

		$groups = vulnhub_jira_ticketer()->group( $rows, $grouping );
		$cap    = max( 1, (int) $rule['max_per_run'] );

		if ( count( $groups ) > $cap ) {
			$out['capped']     = true;
			$out['messages'][] = sprintf(
				/* translators: 1: groups matched, 2: cap. */
				__( '%1$d groups matched; only the first %2$d will be actioned because of the per-run limit.', 'vulnhub' ),
				count( $groups ),
				$cap
			);

			$groups = array_slice( $groups, 0, $cap, true );
		}

		$out['groups'] = $groups;

		if ( $dry_run ) {
			return $out;
		}

		$executed = $this->execute( $rule, $groups, $grouping );

		$out['actioned'] = $executed['actioned'];
		$out['tickets']  = $executed['tickets'];
		$out['emails']   = $executed['emails'];
		$out['failed']   = $executed['failed'];
		$out['messages'] = array_merge( $out['messages'], $executed['messages'] );

		$this->stamp_run( $rule, $executed['actioned'] );

		if ( $executed['actioned'] > 0 ) {
			vulnhub()->logger->audit(
				'automation.ran',
				sprintf(
					/* translators: 1: rule name, 2: groups actioned, 3: findings matched, 4: tickets raised. */
					__( 'Automation "%1$s" actioned %2$d group(s) from %3$d matching finding(s), raising %4$d Jira ticket(s).', 'vulnhub' ),
					(string) $rule['name'],
					$executed['actioned'],
					count( $rows ),
					$executed['tickets']
				),
				'automation',
				(int) $rule['id'],
				array(
					'trigger'  => (string) $rule['trigger_event'],
					'grouping' => $grouping,
					'matched'  => count( $rows ),
					'actioned' => $executed['actioned'],
					'tickets'  => $executed['tickets'],
					'emails'   => $executed['emails'],
					'capped'   => $out['capped'],
				)
			);
		}

		return $out;
	}

	/**
	 * Dry run: exactly the same selection and grouping, no side effects.
	 *
	 * @param array<string,mixed> $rule Rule row.
	 * @return array<string,mixed>
	 */
	public function preview( array $rule ): array {
		return $this->run_rule( $rule, true );
	}

	/**
	 * Has this rule run too recently?
	 *
	 * @param array<string,mixed> $rule Rule row.
	 */
	private function is_throttled( array $rule ): bool {
		$minutes = (int) $rule['throttle_minutes'];
		$last    = (string) ( $rule['last_run_at'] ?? '' );

		if ( $minutes <= 0 || '' === $last ) {
			return false;
		}

		$ts = strtotime( $last . ' UTC' );

		return false !== $ts && ( time() - $ts ) < ( $minutes * MINUTE_IN_SECONDS );
	}

	/**
	 * Record that a rule ran.
	 *
	 * @param array<string,mixed> $rule     Rule row.
	 * @param int                 $actioned Units of work performed.
	 */
	private function stamp_run( array $rule, int $actioned ): void {
		global $wpdb;

		$wpdb->query(
			$wpdb->prepare(
				'UPDATE ' . self::table() . ' SET last_run_at = %s, run_count = run_count + 1, action_count = action_count + %d, updated_at = %s WHERE id = %d',
				vh_now(),
				max( 0, $actioned ),
				vh_now(),
				(int) $rule['id']
			)
		);
	}

	/* =================================================================
	 * Candidate selection
	 * ============================================================== */

	/**
	 * Findings this rule's trigger puts in front of it.
	 *
	 * @param array<string,mixed> $rule Rule row.
	 * @return array<int,array<string,mixed>> Fully joined finding rows.
	 */
	private function candidates( array $rule ): array {
		global $wpdb;

		$f     = vh_table( 'findings' );
		$since = $this->since( $rule );

		switch ( (string) $rule['trigger_event'] ) {
			case 'finding.reopened':
				$sql = $wpdb->prepare(
					"SELECT id FROM {$f} WHERE state = 'reopened' AND exception_id = 0 AND updated_at >= %s ORDER BY risk_score DESC LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$since,
					self::CANDIDATE_CEILING
				);
				break;

			case 'finding.overdue':
				$sql = $wpdb->prepare(
					"SELECT id FROM {$f} WHERE state IN ('open','reopened') AND exception_id = 0 AND due_at IS NOT NULL AND due_at < %s ORDER BY due_at ASC LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					vh_now(),
					self::CANDIDATE_CEILING
				);
				break;

			case 'ticket.closed_unverified':
				$sql = $wpdb->prepare(
					'SELECT DISTINCT tf.finding_id AS id
					 FROM ' . vh_table( 'ticket_findings' ) . ' tf
					 INNER JOIN ' . vh_table( 'tickets' ) . " tk ON tk.id = tf.ticket_id
					 INNER JOIN {$f} fi ON fi.id = tf.finding_id
					 WHERE tk.verification_state = %s AND fi.exception_id = 0
					 ORDER BY tf.finding_id DESC
					 LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					\VulnHub\Core\Tickets::VERIFY_STILL_OPEN,
					self::CANDIDATE_CEILING
				);
				break;

			case 'schedule':
				$sql = $wpdb->prepare(
					"SELECT id FROM {$f} WHERE state IN ('open','reopened') AND exception_id = 0 ORDER BY risk_score DESC LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					self::CANDIDATE_CEILING
				);
				break;

			case 'finding.discovered':
			default:
				$sql = $wpdb->prepare(
					"SELECT id FROM {$f} WHERE state IN ('open','reopened') AND exception_id = 0 AND created_at >= %s ORDER BY risk_score DESC LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$since,
					self::CANDIDATE_CEILING
				);
				break;
		}

		$ids = array_map( 'intval', (array) $wpdb->get_col( $sql ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

		return $ids ? vulnhub_jira_ticketer()->load_findings( $ids ) : array();
	}

	/**
	 * The look-back point for time-bounded triggers.
	 *
	 * @param array<string,mixed> $rule Rule row.
	 */
	private function since( array $rule ): string {
		$last = (string) ( $rule['last_run_at'] ?? '' );
		$ts   = '' === $last ? false : strtotime( $last . ' UTC' );

		if ( false === $ts ) {
			return gmdate( 'Y-m-d H:i:s', time() - self::FIRST_RUN_HOURS * HOUR_IN_SECONDS );
		}

		return gmdate( 'Y-m-d H:i:s', $ts );
	}

	/* =================================================================
	 * Condition evaluation
	 * ============================================================== */

	/**
	 * Does a finding satisfy the rule's conditions?
	 *
	 * @param array<string,mixed> $rule Rule row.
	 * @param array<string,mixed> $row  Joined finding row.
	 */
	public function matches( array $rule, array $row ): bool {
		$conditions = (array) ( $rule['conditions'] ?? array() );

		if ( ! $conditions ) {
			return true;
		}

		$all = ! empty( $rule['match_all'] );

		foreach ( $conditions as $condition ) {
			if ( ! is_array( $condition ) || empty( $condition['field'] ) ) {
				continue;
			}

			$hit = $this->evaluate( $condition, $row );

			if ( $all && ! $hit ) {
				return false;
			}
			if ( ! $all && $hit ) {
				return true;
			}
		}

		return $all;
	}

	/**
	 * Evaluate one condition against one finding.
	 *
	 * @param array<string,mixed> $condition field/op/value.
	 * @param array<string,mixed> $row       Joined finding row.
	 */
	private function evaluate( array $condition, array $row ): bool {
		$field = (string) $condition['field'];
		$op    = (string) ( $condition['op'] ?? 'is' );
		$value = $condition['value'] ?? '';

		$list = static function ( mixed $v ): array {
			$v = is_array( $v ) ? $v : preg_split( '/\s*,\s*/', (string) $v );

			return array_values( array_filter( array_map( 'strval', (array) $v ), static fn( string $s ): bool => '' !== $s ) );
		};

		switch ( $field ) {
			case 'severity':
				return in_array( (string) $row['severity'], $list( $value ), true );

			case 'asset_type':
				return in_array( (string) $row['asset_type'], $list( $value ), true );

			case 'criticality':
				return in_array( (string) $row['criticality'], $list( $value ), true );

			case 'team_id':
				return (int) $row['team_id'] === (int) $value;

			case 'location_id':
				return (int) $row['location_id'] === (int) $value;

			case 'environment':
				return '' !== (string) $value
					&& false !== stripos( (string) $row['environment'], (string) $value );

			case 'cvss3_base':
				return (float) $row['cvss3_base'] >= (float) $value;

			case 'vpr_score':
				return (float) $row['vpr_score'] >= (float) $value;

			case 'exploit_available':
				return ! empty( $row['exploit_available'] ) === ( 'is_false' !== $op );

			case 'days_open':
				$first = (string) ( $row['first_found'] ?? '' );
				$ts    = '' === $first ? false : strtotime( $first . ' UTC' );

				if ( false === $ts ) {
					return false;
				}

				return ( ( time() - $ts ) / DAY_IN_SECONDS ) >= (float) $value;

			case 'has_ticket':
				$has = (int) ( $row['ticket_id'] ?? 0 ) > 0;

				return 'is_false' === $op ? ! $has : $has;

			case 'tag':
				$needle = trim( (string) $value );

				if ( '' === $needle ) {
					return false;
				}

				foreach ( vh_json( (string) ( $row['tags_json'] ?? '' ) ) as $tag ) {
					$haystack = is_array( $tag )
						? implode( '=', array_map( 'strval', $tag ) )
						: (string) $tag;

					if ( false !== stripos( $haystack, $needle ) ) {
						return true;
					}
				}

				return false;
		}

		return false;
	}

	/* =================================================================
	 * Action execution
	 * ============================================================== */

	/**
	 * Perform a rule's actions over the (already capped) groups.
	 *
	 * @param array<string,mixed>                          $rule     Rule row.
	 * @param array<string,array<int,array<string,mixed>>> $groups   Grouped findings.
	 * @param string                                       $grouping Grouping strategy.
	 * @return array{actioned:int,tickets:int,emails:int,failed:int,messages:array<int,string>}
	 */
	private function execute( array $rule, array $groups, string $grouping ): array {
		$connector = vulnhub_jira_connector();

		$out = array(
			'actioned' => 0,
			'tickets'  => 0,
			'emails'   => 0,
			'failed'   => 0,
			'messages' => array(),
		);

		if ( ! $connector ) {
			return $out;
		}

		$actions = array_values( (array) ( $rule['actions'] ?? array() ) );

		if ( ! $actions ) {
			$out['messages'][] = __( 'The rule has no actions, so nothing was done.', 'vulnhub' );

			return $out;
		}

		// Creation first, so later actions have an issue to work on.
		usort(
			$actions,
			static fn( array $a, array $b ): int =>
				( 'create_ticket' === ( $a['type'] ?? '' ) ? 0 : 1 ) <=> ( 'create_ticket' === ( $b['type'] ?? '' ) ? 0 : 1 )
		);

		foreach ( $groups as $group_rows ) {
			$did_something = false;
			$ticket        = $this->existing_ticket( $group_rows );

			foreach ( $actions as $action ) {
				$type = (string) ( $action['type'] ?? '' );

				switch ( $type ) {
					case 'create_ticket':
						$result = vulnhub_jira_ticketer()->raise(
							array_map( static fn( array $r ): int => (int) $r['id'], $group_rows ),
							array(
								'grouping'      => (string) ( $action['grouping'] ?? $grouping ),
								'created_via'   => 'automation',
								'automation_id' => (int) $rule['id'],
								'created_by'    => 0,
								'note'          => sprintf(
									/* translators: %s: automation rule name. */
									__( 'Raised by the VulnHub automation rule "%s".', 'vulnhub' ),
									(string) $rule['name']
								),
							)
						);

						if ( empty( $result['ok'] ) ) {
							++$out['failed'];
							$out['messages'][] = (string) ( $result['message'] ?? '' );
							break;
						}

						$out['tickets'] += (int) $result['created'];
						$ticket          = is_array( $result['ticket'] ?? null ) ? $result['ticket'] : $ticket;
						$did_something   = true;
						break;

					case 'comment':
						if ( ! $ticket ) {
							break;
						}

						$text = trim( (string) ( $action['text'] ?? '' ) );
						$adf  = VulnHub_Jira_Adf::doc()
							->paragraph(
								array(
									VulnHub_Jira_Adf::strong(
										sprintf(
											/* translators: %s: automation rule name. */
											__( 'VulnHub automation: %s', 'vulnhub' ),
											(string) $rule['name']
										)
									),
								)
							)
							->paragraph( '' !== $text ? $text : __( 'This ticket matched an automation rule on the latest pass.', 'vulnhub' ) )
							->bullets( array_map( array( vulnhub_jira_ticketer(), 'finding_line' ), array_slice( $group_rows, 0, 15 ) ) )
							->to_array();

						$response = $connector->client()->comment( (string) $ticket['external_key'], $adf );

						if ( $response->ok() ) {
							$did_something = true;
						} else {
							++$out['failed'];
						}
						break;

					case 'transition':
						if ( ! $ticket ) {
							break;
						}

						if ( $this->transition_to( $connector, (string) $ticket['external_key'], (string) ( $action['status'] ?? '' ) ) ) {
							$did_something = true;
						} else {
							++$out['failed'];
						}
						break;

					case 'set_priority':
						if ( ! $ticket ) {
							break;
						}

						$priority = trim( (string) ( $action['priority'] ?? '' ) );

						if ( '' === $priority ) {
							break;
						}

						$response = $connector->client()->update_issue(
							(string) $ticket['external_key'],
							array( 'priority' => array( 'name' => $priority ) )
						);

						if ( $response->ok() ) {
							\VulnHub\Core\Tickets::upsert(
								array(
									'provider'     => 'jira',
									'external_key' => (string) $ticket['external_key'],
									'priority'     => $priority,
								)
							);
							$did_something = true;
						} else {
							++$out['failed'];
						}
						break;

					case 'notify':
						$sent = $this->notify( $rule, $group_rows, $ticket, (array) $action );

						$out['emails'] += $sent;

						if ( $sent > 0 ) {
							$did_something = true;
						}
						break;
				}
			}

			if ( $did_something ) {
				++$out['actioned'];
			}
		}

		return $out;
	}

	/**
	 * The ticket already attached to a group, if there is one.
	 *
	 * @param array<int,array<string,mixed>> $rows Finding rows.
	 * @return array<string,mixed>|null
	 */
	private function existing_ticket( array $rows ): ?array {
		foreach ( $rows as $row ) {
			$ticket_id = (int) ( $row['ticket_id'] ?? 0 );

			if ( $ticket_id ) {
				$ticket = \VulnHub\Core\Tickets::get( $ticket_id );

				if ( $ticket && 'jira' === (string) $ticket['provider'] ) {
					return $ticket;
				}
			}
		}

		return null;
	}

	/**
	 * Move an issue to a named status, if the workflow offers that transition.
	 *
	 * @param VulnHub_Jira_Connector $connector Connector.
	 * @param string                 $key       Issue key.
	 * @param string                 $status    Target status name.
	 */
	private function transition_to( VulnHub_Jira_Connector $connector, string $key, string $status ): bool {
		$status = trim( $status );

		if ( '' === $key || '' === $status ) {
			return false;
		}

		$response = $connector->client()->transitions( $key );

		if ( ! $response->ok() ) {
			return false;
		}

		foreach ( (array) ( $response->data()['transitions'] ?? array() ) as $transition ) {
			if ( ! is_array( $transition ) ) {
				continue;
			}

			$to = (string) ( $transition['to']['name'] ?? $transition['name'] ?? '' );

			if ( 0 !== strcasecmp( $to, $status ) ) {
				continue;
			}

			$moved = $connector->client()->transition( $key, (string) $transition['id'] );

			if ( $moved->ok() ) {
				$refreshed = $connector->client()->get_issue( $key );

				if ( $refreshed->ok() ) {
					\VulnHub\Core\Tickets::upsert( $connector->normalise_issue( $refreshed->data() ) );
				}

				return true;
			}

			return false;
		}

		$connector->log( sprintf( 'Automation wanted to move %s to "%s", but the workflow offers no such transition.', $key, $status ) );

		return false;
	}

	/**
	 * Email the asset owner and/or the team manager.
	 *
	 * @param array<string,mixed>            $rule   Rule row.
	 * @param array<int,array<string,mixed>> $rows   Finding rows.
	 * @param array<string,mixed>|null       $ticket Ticket, if one exists.
	 * @param array<string,mixed>            $action Action definition.
	 * @return int Emails sent.
	 */
	private function notify( array $rule, array $rows, ?array $ticket, array $action ): int {
		$target     = (string) ( $action['recipient'] ?? 'team_manager' );
		$recipients = array();
		$first      = $rows[0];

		if ( in_array( $target, array( 'owner', 'both' ), true ) ) {
			$email = (string) ( $first['owner_email'] ?? '' );

			if ( '' === $email ) {
				$email = (string) ( $first['owner_upn'] ?? '' );
			}

			if ( is_email( $email ) ) {
				$recipients[ strtolower( $email ) ] = true;
			}
		}
		if ( in_array( $target, array( 'team_manager', 'both' ), true ) ) {
			$email = (string) ( $first['manager_email'] ?? '' );

			if ( is_email( $email ) ) {
				$recipients[ strtolower( $email ) ] = true;
			}
		}

		if ( ! $recipients ) {
			return 0;
		}

		$subject = trim( (string) ( $action['subject'] ?? '' ) );

		if ( '' === $subject ) {
			$subject = sprintf(
				/* translators: %s: hostname. */
				__( 'VulnHub: vulnerabilities requiring attention on %s', 'vulnhub' ),
				(string) $first['hostname']
			);
		}

		$lines = array();

		$lines[] = sprintf(
			/* translators: %s: automation rule name. */
			__( 'The VulnHub automation rule "%s" matched the findings below.', 'vulnhub' ),
			(string) $rule['name']
		);
		$lines[] = '';

		foreach ( array_slice( $rows, 0, 25 ) as $row ) {
			$lines[] = '- ' . vulnhub_jira_ticketer()->finding_line( $row );
		}

		$lines[] = '';

		if ( $ticket ) {
			$lines[] = sprintf(
				/* translators: 1: issue key, 2: URL. */
				__( 'Jira issue: %1$s — %2$s', 'vulnhub' ),
				(string) $ticket['external_key'],
				(string) $ticket['url']
			);
		}

		$lines[] = sprintf(
			/* translators: %s: URL. */
			__( 'Asset in VulnHub: %s', 'vulnhub' ),
			vh_admin_url( 'vulnhub-assets', array( 'asset' => (int) $first['asset_id'] ) )
		);

		$custom = trim( (string) ( $action['message'] ?? '' ) );

		if ( '' !== $custom ) {
			array_unshift( $lines, $custom, '' );
		}

		$sent = 0;

		foreach ( array_keys( $recipients ) as $to ) {
			if ( wp_mail( $to, $subject, implode( "\n", $lines ) ) ) {
				++$sent;
			}
		}

		return $sent;
	}

	/* =================================================================
	 * Run history
	 * ============================================================== */

	/**
	 * Keep a short history of engine passes for the admin screen.
	 *
	 * @param array<string,mixed> $summary Pass summary.
	 */
	private function remember( array $summary ): void {
		$settings = vulnhub()->settings;
		$log      = $settings->get( 'jira', 'automation_log', array() );
		$log      = is_array( $log ) ? $log : array();

		array_unshift( $log, $summary );

		$settings->set( 'jira', 'automation_log', array_slice( $log, 0, self::HISTORY ) );
	}

	/**
	 * The stored history.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public function history(): array {
		$log = vulnhub()->settings->get( 'jira', 'automation_log', array() );

		return is_array( $log ) ? $log : array();
	}
}

