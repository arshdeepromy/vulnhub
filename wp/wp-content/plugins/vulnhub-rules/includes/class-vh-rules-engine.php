<?php
/**
 * Asset classification rule engine.
 *
 * This is deliberately NOT core's ownership mapping. Core's `Mapping` decides
 * who owns an asset (person / team / location). This engine decides what an
 * asset *is*: environment, business criticality, asset type, business service
 * and a numeric priority weight — the signals ownership rules then read.
 *
 * It therefore runs on `vulnhub_sync_complete` at priority 10, ahead of
 * `Mapping::after_sync()` at priority 20.
 *
 * Rules are an ordered list evaluated top to bottom. Every matching rule
 * applies its assignments, so a later rule overrides an earlier one on the
 * same attribute; tick "stop processing" to make a rule final for that asset.
 *
 * @package VulnHub\Rules
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Evaluates classification rules against assets.
 */
final class VulnHub_Rules_Engine {

	/**
	 * Singleton instance.
	 *
	 * @var VulnHub_Rules_Engine|null
	 */
	private static ?VulnHub_Rules_Engine $instance = null;

	/**
	 * Regex patterns already proven to compile, keyed by raw pattern.
	 *
	 * @var array<string,bool>
	 */
	private array $regex_cache = array();

	/**
	 * Shared instance.
	 */
	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Register WordPress hooks.
	 *
	 * Priority 10 is load bearing: core's ownership mapping hooks the same
	 * action at 20 and reads environment and criticality, so classification
	 * has to have finished by then.
	 */
	public function hooks(): void {
		add_action( 'vulnhub_sync_complete', array( $this, 'after_sync' ), 10, 3 );
	}

	/* -----------------------------------------------------------------
	 * Vocabulary
	 * --------------------------------------------------------------- */

	/**
	 * Fields a condition can match on.
	 *
	 * @return array<string,string>
	 */
	public static function match_fields(): array {
		return array(
			'hostname'         => __( 'Hostname', 'vulnhub' ),
			'fqdn'             => __( 'FQDN', 'vulnhub' ),
			'ipv4'             => __( 'IPv4 address', 'vulnhub' ),
			'operating_system' => __( 'Operating system', 'vulnhub' ),
			'os_version'       => __( 'OS version', 'vulnhub' ),
			'asset_type'       => __( 'Asset type', 'vulnhub' ),
			'tag'              => __( 'Tenable tag value', 'vulnhub' ),
			'tag_category'     => __( 'Tenable tag category', 'vulnhub' ),
			'business_service' => __( 'CMDB business service', 'vulnhub' ),
			'lifecycle_status' => __( 'Lifecycle status', 'vulnhub' ),
			'primary_source'   => __( 'Discovered by', 'vulnhub' ),
			'environment'      => __( 'Environment (current value)', 'vulnhub' ),
			'criticality'      => __( 'Business criticality (current value)', 'vulnhub' ),
		);
	}

	/**
	 * Comparison operators.
	 *
	 * @return array<string,string>
	 */
	public static function operators(): array {
		return array(
			'contains'     => __( 'contains', 'vulnhub' ),
			'not_contains' => __( 'does not contain', 'vulnhub' ),
			'equals'       => __( 'is exactly', 'vulnhub' ),
			'not_equals'   => __( 'is not', 'vulnhub' ),
			'starts_with'  => __( 'starts with', 'vulnhub' ),
			'ends_with'    => __( 'ends with', 'vulnhub' ),
			'regex'        => __( 'matches regex', 'vulnhub' ),
			'in_list'      => __( 'is one of (comma separated)', 'vulnhub' ),
			'in_cidr'      => __( 'is in CIDR range', 'vulnhub' ),
			'empty'        => __( 'is empty', 'vulnhub' ),
			'exists'       => __( 'is present', 'vulnhub' ),
		);
	}

	/**
	 * Operators that take no comparison value.
	 *
	 * @return string[]
	 */
	public static function valueless_operators(): array {
		return array( 'empty', 'exists' );
	}

	/**
	 * Environment vocabulary a rule can assign.
	 *
	 * @return array<string,string>
	 */
	public static function environments(): array {
		return array(
			'production'  => __( 'Production', 'vulnhub' ),
			'staging'     => __( 'Staging', 'vulnhub' ),
			'test'        => __( 'Test', 'vulnhub' ),
			'development' => __( 'Development', 'vulnhub' ),
			'dr'          => __( 'Disaster recovery', 'vulnhub' ),
		);
	}

	/**
	 * Business criticality vocabulary a rule can assign.
	 *
	 * @return array<string,string>
	 */
	public static function criticalities(): array {
		return array(
			'critical' => __( 'Critical', 'vulnhub' ),
			'high'     => __( 'High', 'vulnhub' ),
			'medium'   => __( 'Medium', 'vulnhub' ),
			'low'      => __( 'Low', 'vulnhub' ),
		);
	}

	/**
	 * Asset columns this engine is allowed to write.
	 *
	 * @return array<string,string>
	 */
	public static function assignable_columns(): array {
		return array(
			'environment'      => __( 'Environment', 'vulnhub' ),
			'criticality'      => __( 'Business criticality', 'vulnhub' ),
			'asset_type'       => __( 'Asset type', 'vulnhub' ),
			'business_service' => __( 'Business service', 'vulnhub' ),
		);
	}

	/* -----------------------------------------------------------------
	 * Scheduling
	 * --------------------------------------------------------------- */

	/**
	 * Re-classify after any sync that changes asset data.
	 *
	 * @param string              $connector Connector id.
	 * @param string              $status    Run status.
	 * @param array<string,mixed> $stats     Run counters (unused).
	 */
	public function after_sync( string $connector, string $status, array $stats = array() ): void {
		unset( $stats );

		if ( 'success' !== $status ) {
			return;
		}
		if ( ! in_array( $connector, array( 'tenable', 'intune', 'cmdb' ), true ) ) {
			return;
		}

		$this->run( array( 'trigger' => 'sync:' . $connector ) );
	}

	/* -----------------------------------------------------------------
	 * Running
	 * --------------------------------------------------------------- */

	/**
	 * Apply every enabled rule to the estate and write the results.
	 *
	 * @param array<string,mixed> $args Optional 'asset_id' to classify one asset,
	 *                                  and 'trigger' for the run record.
	 * @return array{processed:int,matched:int,changed:int,rules:int}
	 */
	public function run( array $args = array() ): array {
		$rules = VulnHub_Rules_Repo::rules( true );

		$processed = 0;
		$matched   = 0;
		$changed   = 0;
		$counts    = array();

		if ( $rules ) {
			foreach ( $this->assets( $args ) as $asset ) {
				++$processed;

				$verdict = $this->evaluate( $asset, $rules );
				if ( ! $verdict['rules'] ) {
					continue;
				}

				++$matched;

				foreach ( array_keys( $verdict['rules'] ) as $rule_id ) {
					$counts[ $rule_id ] = ( $counts[ $rule_id ] ?? 0 ) + 1;
				}

				if ( $this->apply( $asset, $verdict ) ) {
					++$changed;
				}
			}
		}

		if ( $counts ) {
			VulnHub_Rules_Repo::bump_match_counts( $counts );
		}

		update_option(
			'vulnhub_rules_last_run',
			array(
				'at'        => vh_now(),
				'trigger'   => (string) ( $args['trigger'] ?? 'manual' ),
				'processed' => $processed,
				'matched'   => $matched,
				'changed'   => $changed,
				'rules'     => count( $rules ),
			),
			false
		);

		return array(
			'processed' => $processed,
			'matched'   => $matched,
			'changed'   => $changed,
			'rules'     => count( $rules ),
		);
	}

	/**
	 * Evaluate rules against assets and report what WOULD change.
	 *
	 * Writes nothing at all — no asset row, no match counter, no option.
	 *
	 * @param array<int,array<string,mixed>> $rules Rules to evaluate.
	 * @param int                            $limit Maximum example rows to return.
	 * @return array{matched:int,scanned:int,changes:int,rows:array<int,array<string,mixed>>}
	 */
	public function preview( array $rules, int $limit = 25 ): array {
		$scanned = 0;
		$matched = 0;
		$changes = 0;
		$rows    = array();

		if ( ! $rules ) {
			return array(
				'matched' => 0,
				'scanned' => 0,
				'changes' => 0,
				'rows'    => array(),
			);
		}

		foreach ( $this->assets( array() ) as $asset ) {
			++$scanned;

			$verdict = $this->evaluate( $asset, $rules );
			if ( ! $verdict['rules'] ) {
				continue;
			}

			++$matched;

			$diff = $this->diff( $asset, $verdict );
			if ( $diff ) {
				++$changes;
			}

			if ( count( $rows ) < $limit ) {
				$rows[] = array(
					'asset'      => $asset,
					'diff'       => $diff,
					'weight'     => $verdict['weight'],
					'old_weight' => VulnHub_Rules_Repo::priority_weight( (int) $asset['id'] ),
					'rules'      => $verdict['rules'],
				);
			}
		}

		return array(
			'matched' => $matched,
			'scanned' => $scanned,
			'changes' => $changes,
			'rows'    => $rows,
		);
	}

	/**
	 * Stream assets in batches.
	 *
	 * @param array<string,mixed> $args Optional 'asset_id'.
	 * @return Generator<array<string,mixed>>
	 */
	private function assets( array $args ): Generator {
		global $wpdb;

		$table = vh_table( 'assets' );

		if ( ! empty( $args['asset_id'] ) ) {
			$row = $wpdb->get_row(
				$wpdb->prepare( 'SELECT * FROM ' . $table . ' WHERE id = %d', (int) $args['asset_id'] ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				ARRAY_A
			);
			if ( $row ) {
				yield (array) $row;
			}
			return;
		}

		$batch  = 500;
		$offset = 0;

		do {
			$rows = (array) $wpdb->get_results(
				$wpdb->prepare( 'SELECT * FROM ' . $table . ' ORDER BY id ASC LIMIT %d OFFSET %d', $batch, $offset ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				ARRAY_A
			);

			foreach ( $rows as $row ) {
				yield (array) $row;
			}

			$offset += $batch;
		} while ( count( $rows ) === $batch );
	}

	/**
	 * Decide what the rule set says about one asset.
	 *
	 * @param array<string,mixed>            $asset Asset row.
	 * @param array<int,array<string,mixed>> $rules Ordered rules with conditions.
	 * @return array{sets:array<string,string>,weight:?int,rules:array<int,string>}
	 */
	public function evaluate( array $asset, array $rules ): array {
		$tags   = $this->tags( $asset );
		$sets   = array();
		$weight = null;
		$hits   = array();

		foreach ( $rules as $rule ) {
			if ( ! $this->rule_matches( $rule, $asset, $tags ) ) {
				continue;
			}

			$hits[ (int) $rule['id'] ] = (string) $rule['name'];

			foreach ( self::assignable_columns() as $column => $unused_label ) {
				$value = (string) ( $rule[ 'set_' . $column ] ?? '' );
				if ( '' !== $value ) {
					$sets[ $column ] = $value;
				}
			}

			if ( null !== ( $rule['set_priority_weight'] ?? null ) && '' !== (string) $rule['set_priority_weight'] ) {
				$weight = (int) $rule['set_priority_weight'];
			}

			if ( ! empty( $rule['stop_processing'] ) ) {
				break;
			}
		}

		return array(
			'sets'   => $sets,
			'weight' => $weight,
			'rules'  => $hits,
		);
	}

	/**
	 * Columns that would actually change for this asset.
	 *
	 * @param array<string,mixed>                                            $asset   Asset row.
	 * @param array{sets:array<string,string>,weight:?int,rules:array<int,string>} $verdict Evaluation result.
	 * @return array<string,array{from:string,to:string}>
	 */
	public function diff( array $asset, array $verdict ): array {
		$diff = array();

		foreach ( $verdict['sets'] as $column => $value ) {
			$current = (string) ( $asset[ $column ] ?? '' );
			if ( $current !== $value ) {
				$diff[ $column ] = array(
					'from' => $current,
					'to'   => $value,
				);
			}
		}

		if ( null !== $verdict['weight'] ) {
			$current = VulnHub_Rules_Repo::priority_weight( (int) $asset['id'] );
			if ( $current !== (int) $verdict['weight'] ) {
				$diff['priority_weight'] = array(
					'from' => (string) $current,
					'to'   => (string) (int) $verdict['weight'],
				);
			}
		}

		return $diff;
	}

	/**
	 * Write an evaluation result to the database.
	 *
	 * @param array<string,mixed>                                            $asset   Asset row.
	 * @param array{sets:array<string,string>,weight:?int,rules:array<int,string>} $verdict Evaluation result.
	 * @return bool True when something was written.
	 */
	private function apply( array $asset, array $verdict ): bool {
		global $wpdb;

		$diff    = $this->diff( $asset, $verdict );
		$applied = vh_trim( implode( ' -> ', $verdict['rules'] ), 250 );

		VulnHub_Rules_Repo::save_asset_state(
			(int) $asset['id'],
			null === $verdict['weight'] ? VulnHub_Rules_Repo::priority_weight( (int) $asset['id'] ) : (int) $verdict['weight'],
			$applied
		);

		if ( ! $diff ) {
			return false;
		}

		$update = array();
		foreach ( $diff as $column => $change ) {
			if ( 'priority_weight' === $column ) {
				continue;
			}
			$update[ $column ] = $change['to'];
		}

		if ( $update ) {
			$update['updated_at'] = vh_now();
			$wpdb->update( vh_table( 'assets' ), $update, array( 'id' => (int) $asset['id'] ) );
		}

		return true;
	}

	/* -----------------------------------------------------------------
	 * Matching
	 * --------------------------------------------------------------- */

	/**
	 * Does a rule match this asset?
	 *
	 * @param array<string,mixed>  $rule  Rule row with 'conditions'.
	 * @param array<string,mixed>  $asset Asset row.
	 * @param array<int,array{category:string,value:string}> $tags Decoded tags.
	 */
	private function rule_matches( array $rule, array $asset, array $tags ): bool {
		$conditions = (array) ( $rule['conditions'] ?? array() );

		if ( ! $conditions ) {
			return false;
		}

		$all = 'any' !== (string) ( $rule['match_type'] ?? 'all' );

		foreach ( $conditions as $condition ) {
			$hit = $this->condition_matches( (array) $condition, $asset, $tags );

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
	 * Evaluate one condition.
	 *
	 * @param array<string,mixed>  $condition Condition row.
	 * @param array<string,mixed>  $asset     Asset row.
	 * @param array<int,array{category:string,value:string}> $tags Decoded tags.
	 */
	private function condition_matches( array $condition, array $asset, array $tags ): bool {
		$field    = (string) ( $condition['match_field'] ?? '' );
		$key      = (string) ( $condition['field_key'] ?? '' );
		$operator = (string) ( $condition['match_operator'] ?? '' );
		$want     = (string) ( $condition['match_value'] ?? '' );

		$subjects = $this->subjects( $field, $key, $asset, $tags );

		if ( 'empty' === $operator ) {
			return array() === $subjects;
		}
		if ( 'exists' === $operator ) {
			return array() !== $subjects;
		}

		if ( '' === trim( $want ) ) {
			return false;
		}

		// Negative operators must hold for every candidate value, not just one:
		// an asset with three tags "does not contain X" only when none of them does.
		$negative = in_array( $operator, array( 'not_contains', 'not_equals' ), true );
		$pool     = $subjects ?: array( '' );

		foreach ( $pool as $subject ) {
			$hit = $this->compare( $operator, $subject, $want );

			if ( $negative && ! $hit ) {
				return false;
			}
			if ( ! $negative && $hit ) {
				return true;
			}
		}

		return $negative;
	}

	/**
	 * Apply one operator to one subject value.
	 *
	 * @param string $operator Operator slug.
	 * @param string $subject  Value taken from the asset.
	 * @param string $want     Value configured on the condition.
	 */
	private function compare( string $operator, string $subject, string $want ): bool {
		switch ( $operator ) {
			case 'contains':
				return false !== stripos( $subject, $want );

			case 'not_contains':
				return false === stripos( $subject, $want );

			case 'equals':
				return 0 === strcasecmp( $subject, $want );

			case 'not_equals':
				return 0 !== strcasecmp( $subject, $want );

			case 'starts_with':
				return str_starts_with( strtolower( $subject ), strtolower( $want ) );

			case 'ends_with':
				return str_ends_with( strtolower( $subject ), strtolower( $want ) );

			case 'regex':
				return $this->regex_matches( $want, $subject );

			case 'in_list':
				foreach ( self::split_list( $want ) as $candidate ) {
					if ( 0 === strcasecmp( $subject, $candidate ) ) {
						return true;
					}
				}
				return false;

			case 'in_cidr':
				foreach ( self::split_list( $want ) as $cidr ) {
					if ( self::ip_in_cidr( $subject, $cidr ) ) {
						return true;
					}
				}
				return false;
		}

		return false;
	}

	/**
	 * Candidate values for a field. Several fields are legitimately multi-valued
	 * (a second IP address, three Tenable tags), so matching is OR across them.
	 *
	 * @param string               $field Field slug.
	 * @param string               $key   Tag category, when the field is 'tag'.
	 * @param array<string,mixed>  $asset Asset row.
	 * @param array<int,array{category:string,value:string}> $tags Decoded tags.
	 * @return string[] Non-empty candidate values.
	 */
	private function subjects( string $field, string $key, array $asset, array $tags ): array {
		$out = array();

		switch ( $field ) {
			case 'tag':
				foreach ( $tags as $tag ) {
					if ( '' !== $key && 0 !== strcasecmp( $tag['category'], $key ) ) {
						continue;
					}
					$out[] = $tag['value'];
				}
				break;

			case 'tag_category':
				foreach ( $tags as $tag ) {
					$out[] = $tag['category'];
				}
				break;

			case 'ipv4':
				$out[] = (string) ( $asset['ipv4'] ?? '' );
				foreach ( explode( ',', (string) ( $asset['ipv4s'] ?? '' ) ) as $ip ) {
					$out[] = $ip;
				}
				break;

			default:
				if ( array_key_exists( $field, self::match_fields() ) ) {
					$out[] = (string) ( $asset[ $field ] ?? '' );
				}
				break;
		}

		$out = array_map( 'trim', $out );

		return array_values(
			array_filter(
				$out,
				static fn( string $value ): bool => '' !== $value
			)
		);
	}

	/**
	 * Decode an asset's Tenable tags.
	 *
	 * Tenable calls the left-hand side "category" in both its export CSV and
	 * its API; simpler feeds use "key". Accept either — reading only "key"
	 * matches nothing against real Tenable data.
	 *
	 * @param array<string,mixed> $asset Asset row.
	 * @return array<int,array{category:string,value:string}>
	 */
	private function tags( array $asset ): array {
		$raw = vh_json( $asset['tags_json'] ?? null );
		$out = array();

		foreach ( $raw as $tag ) {
			if ( is_array( $tag ) ) {
				$category = (string) ( $tag['category'] ?? $tag['category_name'] ?? $tag['key'] ?? '' );
				$value    = (string) ( $tag['value'] ?? '' );
			} elseif ( is_string( $tag ) && str_contains( $tag, ':' ) ) {
				[ $category, $value ] = array_map( 'trim', explode( ':', $tag, 2 ) );
			} else {
				continue;
			}

			if ( '' === $category && '' === $value ) {
				continue;
			}

			$out[] = array(
				'category' => $category,
				'value'    => $value,
			);
		}

		return $out;
	}

	/* -----------------------------------------------------------------
	 * Safe regex and CIDR
	 * --------------------------------------------------------------- */

	/**
	 * Split a comma separated list into trimmed, non-empty parts.
	 *
	 * @param string $value Raw list.
	 * @return string[]
	 */
	public static function split_list( string $value ): array {
		$parts = array_map( 'trim', explode( ',', $value ) );

		return array_values(
			array_filter(
				$parts,
				static fn( string $part ): bool => '' !== $part
			)
		);
	}

	/**
	 * Wrap a user pattern in delimiters, escaping any unescaped delimiter.
	 *
	 * @param string $pattern Raw pattern as typed by an administrator.
	 */
	public static function delimit_regex( string $pattern ): string {
		$escaped = (string) preg_replace( '/(?<!\\\\)~/', '\\~', $pattern );

		return '~' . $escaped . '~i';
	}

	/**
	 * Validate a pattern, returning the compiler's complaint or ''.
	 *
	 * The error handler is swapped out so a bad pattern can never emit a PHP
	 * warning into debug.log — it becomes a message on the form instead.
	 *
	 * @param string $pattern Raw pattern.
	 * @return string Empty when the pattern is usable.
	 */
	public static function regex_error( string $pattern ): string {
		if ( '' === trim( $pattern ) ) {
			return __( 'Enter a regular expression to match on.', 'vulnhub' );
		}

		$message = '';

		set_error_handler( // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			static function ( int $errno, string $errstr ) use ( &$message ): bool {
				unset( $errno );
				$message = $errstr;
				return true;
			}
		);

		$result = preg_match( self::delimit_regex( $pattern ), '' );

		restore_error_handler();

		if ( false === $result ) {
			$detail = (string) preg_replace( '/^preg_match\(\):\s*/', '', $message );

			return $detail ? $detail : __( 'That regular expression could not be compiled.', 'vulnhub' );
		}

		return '';
	}

	/**
	 * Match a subject against a user pattern, silently ignoring a broken one.
	 *
	 * @param string $pattern Raw pattern.
	 * @param string $subject Value under test.
	 */
	private function regex_matches( string $pattern, string $subject ): bool {
		if ( ! array_key_exists( $pattern, $this->regex_cache ) ) {
			$this->regex_cache[ $pattern ] = '' === self::regex_error( $pattern );
		}

		if ( ! $this->regex_cache[ $pattern ] ) {
			return false;
		}

		return 1 === preg_match( self::delimit_regex( $pattern ), $subject );
	}

	/**
	 * Is an IPv4 address inside a CIDR block?
	 *
	 * Accepts "10.31.40.0/24" and a bare address (treated as /32). Anything
	 * that is not a real IPv4 value on either side is a non-match, never a
	 * warning — CMDB exports are full of "DHCP" in the IP column.
	 *
	 * @param string $ip   Candidate address.
	 * @param string $cidr Network in CIDR notation.
	 */
	public static function ip_in_cidr( string $ip, string $cidr ): bool {
		$ip   = trim( $ip );
		$cidr = trim( $cidr );

		if ( '' === $ip || '' === $cidr ) {
			return false;
		}
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return false;
		}

		$bits = 32;
		if ( str_contains( $cidr, '/' ) ) {
			[ $cidr, $suffix ] = explode( '/', $cidr, 2 );
			$cidr              = trim( $cidr );
			$suffix            = trim( $suffix );

			if ( '' === $suffix || ! ctype_digit( $suffix ) ) {
				return false;
			}
			$bits = (int) $suffix;
		}

		if ( $bits < 0 || $bits > 32 ) {
			return false;
		}
		if ( ! filter_var( $cidr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return false;
		}

		$ip_long  = (int) sprintf( '%u', ip2long( $ip ) );
		$net_long = (int) sprintf( '%u', ip2long( $cidr ) );

		if ( 0 === $bits ) {
			return true;
		}

		$mask = ( 0xFFFFFFFF << ( 32 - $bits ) ) & 0xFFFFFFFF;

		return ( $ip_long & $mask ) === ( $net_long & $mask );
	}

	/**
	 * Human-readable summary of a rule's conditions.
	 *
	 * @param array<string,mixed> $rule Rule row with 'conditions'.
	 */
	public static function describe_conditions( array $rule ): string {
		$fields    = self::match_fields();
		$operators = self::operators();
		$parts     = array();

		foreach ( (array) ( $rule['conditions'] ?? array() ) as $condition ) {
			$field = (string) $condition['match_field'];
			$label = (string) ( $fields[ $field ] ?? $field );

			if ( 'tag' === $field && '' !== (string) $condition['field_key'] ) {
				/* translators: %s: Tenable tag category. */
				$label = sprintf( __( 'Tenable tag "%s"', 'vulnhub' ), (string) $condition['field_key'] );
			}

			$operator = (string) ( $operators[ (string) $condition['match_operator'] ] ?? (string) $condition['match_operator'] );
			$value    = (string) $condition['match_value'];

			$parts[] = in_array( (string) $condition['match_operator'], self::valueless_operators(), true )
				? $label . ' ' . $operator
				: $label . ' ' . $operator . ' "' . $value . '"';
		}

		if ( ! $parts ) {
			return __( 'no conditions', 'vulnhub' );
		}

		$joiner = 'any' === (string) ( $rule['match_type'] ?? 'all' )
			? __( ' OR ', 'vulnhub' )
			: __( ' AND ', 'vulnhub' );

		return implode( $joiner, $parts );
	}

	/**
	 * Human-readable summary of what a rule sets.
	 *
	 * @param array<string,mixed> $rule Rule row.
	 */
	public static function describe_assignments( array $rule ): string {
		$parts = array();

		foreach ( self::assignable_columns() as $column => $label ) {
			$value = (string) ( $rule[ 'set_' . $column ] ?? '' );
			if ( '' !== $value ) {
				$parts[] = $label . ' = ' . $value;
			}
		}

		if ( null !== ( $rule['set_priority_weight'] ?? null ) && '' !== (string) $rule['set_priority_weight'] ) {
			$parts[] = __( 'Priority weight', 'vulnhub' ) . ' = ' . (int) $rule['set_priority_weight'];
		}

		return $parts ? implode( ', ', $parts ) : __( 'nothing', 'vulnhub' );
	}
}

