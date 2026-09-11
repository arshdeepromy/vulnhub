<?php
/**
 * Persistence for classification rules, their conditions and per-asset state.
 *
 * Every query goes through $wpdb->prepare(); every value is sanitised against
 * the engine's vocabulary before it reaches the database, so a rule row can
 * only ever contain a field, operator and assignment the engine understands.
 *
 * @package VulnHub\Rules
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * CRUD for the classification rule set.
 */
final class VulnHub_Rules_Repo {

	/**
	 * Per-request cache of asset priority weights.
	 *
	 * @var array<int,int>|null
	 */
	private static ?array $weights = null;

	/**
	 * Rules table name.
	 */
	public static function rules_table(): string {
		return VulnHub_Rules_Install::table( 'class_rules' );
	}

	/**
	 * Conditions table name.
	 */
	public static function conditions_table(): string {
		return VulnHub_Rules_Install::table( 'class_rule_conditions' );
	}

	/**
	 * Per-asset state table name.
	 */
	public static function state_table(): string {
		return VulnHub_Rules_Install::table( 'class_asset_state' );
	}

	/**
	 * All rules in evaluation order, each with its conditions attached.
	 *
	 * @param bool $enabled_only Only rules that are switched on.
	 * @return array<int,array<string,mixed>>
	 */
	public static function rules( bool $enabled_only = false ): array {
		global $wpdb;

		$sql = 'SELECT * FROM ' . self::rules_table();
		if ( $enabled_only ) {
			$sql .= ' WHERE enabled = 1';
		}
		$sql .= ' ORDER BY priority ASC, id ASC';

		$rules = (array) $wpdb->get_results( $sql, ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		if ( ! $rules ) {
			return array();
		}

		$by_id = array();
		foreach ( $rules as $index => $rule ) {
			$rules[ $index ]['conditions'] = array();
			$by_id[ (int) $rule['id'] ]    = $index;
		}

		$ids        = implode( ',', array_map( 'intval', array_keys( $by_id ) ) );
		$conditions = (array) $wpdb->get_results(
			'SELECT * FROM ' . self::conditions_table() . " WHERE rule_id IN ({$ids}) ORDER BY position ASC, id ASC", // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			ARRAY_A
		);

		foreach ( $conditions as $condition ) {
			$rule_id = (int) $condition['rule_id'];
			if ( isset( $by_id[ $rule_id ] ) ) {
				$rules[ $by_id[ $rule_id ] ]['conditions'][] = $condition;
			}
		}

		return $rules;
	}

	/**
	 * One rule with its conditions.
	 *
	 * @param int $id Rule id.
	 * @return array<string,mixed>|null
	 */
	public static function rule( int $id ): ?array {
		global $wpdb;

		if ( $id <= 0 ) {
			return null;
		}

		$rule = $wpdb->get_row(
			$wpdb->prepare( 'SELECT * FROM ' . self::rules_table() . ' WHERE id = %d', $id ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);

		if ( ! $rule ) {
			return null;
		}

		$rule               = (array) $rule;
		$rule['conditions'] = (array) $wpdb->get_results(
			$wpdb->prepare( 'SELECT * FROM ' . self::conditions_table() . ' WHERE rule_id = %d ORDER BY position ASC, id ASC', $id ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);

		return $rule;
	}

	/**
	 * An empty rule, for the "new rule" form.
	 *
	 * @return array<string,mixed>
	 */
	public static function blank_rule(): array {
		return array(
			'id'                   => 0,
			'name'                 => '',
			'description'          => '',
			'enabled'              => 1,
			'priority'             => 0,
			'match_type'           => 'all',
			'stop_processing'      => 0,
			'set_environment'      => '',
			'set_criticality'      => '',
			'set_asset_type'       => '',
			'set_business_service' => '',
			'set_priority_weight'  => null,
			'match_count'          => 0,
			'last_matched_at'      => null,
			'conditions'           => array(),
		);
	}

	/* -----------------------------------------------------------------
	 * Validation
	 * --------------------------------------------------------------- */

	/**
	 * Validate and normalise submitted form values.
	 *
	 * @param array<string,mixed> $input Already-unslashed raw form values.
	 * @return array{row:array<string,mixed>,conditions:array<int,array<string,mixed>>}|WP_Error
	 */
	public static function prepare( array $input ) {
		$name = sanitize_text_field( (string) ( $input['name'] ?? '' ) );

		if ( '' === trim( $name ) ) {
			return new WP_Error( 'vulnhub_rules_name', __( 'Give the rule a name so it can be recognised in the list.', 'vulnhub' ) );
		}

		$conditions = self::sanitise_conditions( (array) ( $input['conditions'] ?? array() ) );

		if ( is_wp_error( $conditions ) ) {
			return $conditions;
		}
		if ( ! $conditions ) {
			return new WP_Error( 'vulnhub_rules_conditions', __( 'A rule needs at least one complete condition, otherwise it would match every asset.', 'vulnhub' ) );
		}

		$environments = VulnHub_Rules_Engine::environments();
		$criticality  = VulnHub_Rules_Engine::criticalities();
		$types        = vh_asset_types();

		$set_environment = sanitize_key( (string) ( $input['set_environment'] ?? '' ) );
		$set_criticality = sanitize_key( (string) ( $input['set_criticality'] ?? '' ) );
		$set_asset_type  = sanitize_key( (string) ( $input['set_asset_type'] ?? '' ) );
		$set_service     = sanitize_text_field( (string) ( $input['set_business_service'] ?? '' ) );
		$raw_weight      = trim( (string) ( $input['set_priority_weight'] ?? '' ) );

		$set_environment = isset( $environments[ $set_environment ] ) ? $set_environment : '';
		$set_criticality = isset( $criticality[ $set_criticality ] ) ? $set_criticality : '';
		$set_asset_type  = isset( $types[ $set_asset_type ] ) ? $set_asset_type : '';

		$weight = null;
		if ( '' !== $raw_weight ) {
			if ( ! is_numeric( $raw_weight ) ) {
				return new WP_Error( 'vulnhub_rules_weight', __( 'Priority weight must be a number, or empty to leave it alone.', 'vulnhub' ) );
			}
			$weight = max( 0, min( 1000, (int) $raw_weight ) );
		}

		if ( '' === $set_environment && '' === $set_criticality && '' === $set_asset_type && '' === $set_service && null === $weight ) {
			return new WP_Error( 'vulnhub_rules_assign', __( 'A rule has to set at least one attribute — otherwise matching it would do nothing.', 'vulnhub' ) );
		}

		return array(
			'row'        => array(
				'name'                 => $name,
				'description'          => sanitize_text_field( (string) ( $input['description'] ?? '' ) ),
				'enabled'              => empty( $input['enabled'] ) ? 0 : 1,
				'match_type'           => 'any' === (string) ( $input['match_type'] ?? 'all' ) ? 'any' : 'all',
				'stop_processing'      => empty( $input['stop_processing'] ) ? 0 : 1,
				'set_environment'      => $set_environment,
				'set_criticality'      => $set_criticality,
				'set_asset_type'       => $set_asset_type,
				'set_business_service' => $set_service,
				'set_priority_weight'  => $weight,
			),
			'conditions' => $conditions,
		);
	}

	/**
	 * Build an unsaved rule from form values, for "preview matches".
	 *
	 * @param array<string,mixed> $input Raw form values.
	 * @return array<string,mixed>|WP_Error A rule shaped exactly like a stored one.
	 */
	public static function draft( array $input ) {
		$prepared = self::prepare( $input );

		if ( is_wp_error( $prepared ) ) {
			return $prepared;
		}

		return array_merge(
			self::blank_rule(),
			$prepared['row'],
			array(
				'id'         => isset( $input['id'] ) ? (int) $input['id'] : 0,
				'conditions' => $prepared['conditions'],
			)
		);
	}

	/**
	 * Validate and save a rule and its conditions.
	 *
	 * @param array<string,mixed> $input Already-unslashed raw form values.
	 * @return int|WP_Error Rule id on success.
	 */
	public static function save( array $input ) {
		global $wpdb;

		$prepared = self::prepare( $input );

		if ( is_wp_error( $prepared ) ) {
			return $prepared;
		}

		$id  = isset( $input['id'] ) ? (int) $input['id'] : 0;
		$now = vh_now();
		$row = $prepared['row'];

		$row['updated_at'] = $now;

		if ( $id > 0 && self::rule( $id ) ) {
			$wpdb->update( self::rules_table(), $row, array( 'id' => $id ) );
		} else {
			$row['priority']    = self::next_priority();
			$row['created_at']  = $now;
			$row['match_count'] = 0;

			$wpdb->insert( self::rules_table(), $row );
			$id = (int) $wpdb->insert_id;
		}

		if ( ! $id ) {
			return new WP_Error( 'vulnhub_rules_save', __( 'The rule could not be saved.', 'vulnhub' ) );
		}

		$wpdb->delete( self::conditions_table(), array( 'rule_id' => $id ), array( '%d' ) );

		$position = 0;
		foreach ( $prepared['conditions'] as $condition ) {
			$condition['rule_id']  = $id;
			$condition['position'] = $position++;

			$wpdb->insert( self::conditions_table(), $condition );
		}

		return $id;
	}

	/**
	 * Sanitise submitted conditions against the engine vocabulary.
	 *
	 * @param array<int,array<string,mixed>> $raw Submitted condition rows.
	 * @return array<int,array<string,mixed>>|WP_Error
	 */
	private static function sanitise_conditions( array $raw ) {
		$fields    = VulnHub_Rules_Engine::match_fields();
		$operators = VulnHub_Rules_Engine::operators();
		$valueless = VulnHub_Rules_Engine::valueless_operators();
		$out       = array();

		foreach ( $raw as $condition ) {
			if ( ! is_array( $condition ) ) {
				continue;
			}

			$field    = sanitize_key( (string) ( $condition['match_field'] ?? '' ) );
			$operator = sanitize_key( (string) ( $condition['match_operator'] ?? '' ) );
			$key      = sanitize_text_field( (string) ( $condition['field_key'] ?? '' ) );
			$value    = sanitize_text_field( (string) ( $condition['match_value'] ?? '' ) );

			if ( ! isset( $fields[ $field ] ) || ! isset( $operators[ $operator ] ) ) {
				continue;
			}

			$needs_value = ! in_array( $operator, $valueless, true );

			if ( $needs_value && '' === trim( $value ) ) {
				// A blank row is how the form says "I added a row and then
				// changed my mind", so drop it rather than failing the save.
				continue;
			}

			if ( 'regex' === $operator ) {
				$error = VulnHub_Rules_Engine::regex_error( $value );

				if ( '' !== $error ) {
					return new WP_Error(
						'vulnhub_rules_regex',
						sprintf(
							/* translators: 1: the pattern that was typed, 2: the PCRE compiler message. */
							__( 'The regular expression "%1$s" is not valid: %2$s', 'vulnhub' ),
							$value,
							$error
						)
					);
				}
			}

			if ( 'in_cidr' === $operator ) {
				foreach ( VulnHub_Rules_Engine::split_list( $value ) as $cidr ) {
					if ( ! self::valid_cidr( $cidr ) ) {
						return new WP_Error(
							'vulnhub_rules_cidr',
							sprintf(
								/* translators: %s: the CIDR string that was typed. */
								__( '"%s" is not a valid IPv4 network. Use a form like 10.31.40.0/24.', 'vulnhub' ),
								$cidr
							)
						);
					}
				}
			}

			$out[] = array(
				'match_field'    => $field,
				'field_key'      => 'tag' === $field ? $key : '',
				'match_operator' => $operator,
				'match_value'    => $needs_value ? $value : '',
			);
		}

		return $out;
	}

	/**
	 * Is this a usable IPv4 network or address?
	 *
	 * @param string $cidr Candidate network.
	 */
	public static function valid_cidr( string $cidr ): bool {
		$cidr = trim( $cidr );
		$bits = '32';

		if ( str_contains( $cidr, '/' ) ) {
			[ $cidr, $bits ] = explode( '/', $cidr, 2 );
			$cidr            = trim( $cidr );
			$bits            = trim( $bits );
		}

		if ( '' === $bits || ! ctype_digit( $bits ) || (int) $bits > 32 ) {
			return false;
		}

		return (bool) filter_var( $cidr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
	}

	/**
	 * Priority for a rule appended to the end of the list.
	 */
	private static function next_priority(): int {
		global $wpdb;

		$max = (int) $wpdb->get_var( 'SELECT MAX(priority) FROM ' . self::rules_table() ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

		return $max + 10;
	}

	/**
	 * Delete a rule and its conditions.
	 *
	 * @param int $id Rule id.
	 */
	public static function delete( int $id ): void {
		global $wpdb;

		if ( $id <= 0 ) {
			return;
		}

		$wpdb->delete( self::conditions_table(), array( 'rule_id' => $id ), array( '%d' ) );
		$wpdb->delete( self::rules_table(), array( 'id' => $id ), array( '%d' ) );
	}

	/**
	 * Switch a rule on or off.
	 *
	 * @param int  $id      Rule id.
	 * @param bool $enabled Desired state.
	 */
	public static function set_enabled( int $id, bool $enabled ): void {
		global $wpdb;

		if ( $id <= 0 ) {
			return;
		}

		$wpdb->update(
			self::rules_table(),
			array(
				'enabled'    => $enabled ? 1 : 0,
				'updated_at' => vh_now(),
			),
			array( 'id' => $id ),
			array( '%d', '%s' ),
			array( '%d' )
		);
	}

	/**
	 * Move a rule one place up (-1) or down (+1) the evaluation order.
	 *
	 * @param int $id    Rule id.
	 * @param int $delta -1 or 1.
	 */
	public static function move( int $id, int $delta ): void {
		$order = array();
		foreach ( self::rules() as $rule ) {
			$order[] = (int) $rule['id'];
		}

		$index = array_search( $id, $order, true );
		if ( false === $index ) {
			return;
		}

		$target = (int) $index + ( $delta < 0 ? -1 : 1 );
		if ( $target < 0 || $target >= count( $order ) ) {
			return;
		}

		[ $order[ $index ], $order[ $target ] ] = array( $order[ $target ], $order[ $index ] );

		self::set_order( $order );
	}

	/**
	 * Rewrite the evaluation order from a list of rule ids.
	 *
	 * @param int[] $ids Rule ids, first evaluated first.
	 */
	public static function set_order( array $ids ): void {
		global $wpdb;

		$priority = 100;

		foreach ( $ids as $id ) {
			$id = (int) $id;
			if ( $id <= 0 ) {
				continue;
			}

			$wpdb->update(
				self::rules_table(),
				array(
					'priority'   => $priority,
					'updated_at' => vh_now(),
				),
				array( 'id' => $id ),
				array( '%d', '%s' ),
				array( '%d' )
			);

			$priority += 10;
		}
	}

	/**
	 * Add to each rule's lifetime match counter.
	 *
	 * @param array<int,int> $counts Rule id => number of assets matched.
	 */
	public static function bump_match_counts( array $counts ): void {
		global $wpdb;

		$now = vh_now();

		foreach ( $counts as $rule_id => $hits ) {
			if ( (int) $rule_id <= 0 ) {
				continue;
			}

			$wpdb->query(
				$wpdb->prepare(
					'UPDATE ' . self::rules_table() . ' SET match_count = match_count + %d, last_matched_at = %s WHERE id = %d', // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					(int) $hits,
					$now,
					(int) $rule_id
				)
			);
		}
	}

	/**
	 * Record what the engine decided about one asset.
	 *
	 * @param int    $asset_id Asset id.
	 * @param int    $weight   Priority weight in force.
	 * @param string $applied  Names of the rules that matched.
	 */
	public static function save_asset_state( int $asset_id, int $weight, string $applied ): void {
		global $wpdb;

		if ( $asset_id <= 0 ) {
			return;
		}

		$wpdb->query(
			$wpdb->prepare(
				'INSERT INTO ' . self::state_table() . ' (asset_id, priority_weight, rules_applied, classified_at) VALUES (%d, %d, %s, %s) ' // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				. 'ON DUPLICATE KEY UPDATE priority_weight = VALUES(priority_weight), rules_applied = VALUES(rules_applied), classified_at = VALUES(classified_at)',
				$asset_id,
				$weight,
				$applied,
				vh_now()
			)
		);

		if ( null !== self::$weights ) {
			self::$weights[ $asset_id ] = $weight;
		}
	}

	/**
	 * The priority weight last applied to an asset.
	 *
	 * @param int $asset_id Asset id.
	 */
	public static function priority_weight( int $asset_id ): int {
		global $wpdb;

		if ( null === self::$weights ) {
			self::$weights = array();

			$rows = (array) $wpdb->get_results( 'SELECT asset_id, priority_weight FROM ' . self::state_table(), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

			foreach ( $rows as $row ) {
				self::$weights[ (int) $row['asset_id'] ] = (int) $row['priority_weight'];
			}
		}

		return (int) ( self::$weights[ $asset_id ] ?? 0 );
	}

	/**
	 * Drop the cached weights.
	 */
	public static function flush_weight_cache(): void {
		self::$weights = null;
	}
}

