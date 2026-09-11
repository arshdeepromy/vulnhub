<?php
/**
 * Asset ↔ owner ↔ team ↔ location mapping engine.
 *
 * The business rule this implements:
 *   - a workstation (or mobile) MUST resolve to an individual person;
 *     that person comes from Intune's primary user, and their team and
 *     location come from Entra ID (department / office) or the CMDB;
 *   - everything else resolves to a team, via Tenable tags, CMDB records,
 *     or an administrator-defined rule.
 *
 * Rules are evaluated in priority order and each one can stop processing.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Mapping {

	public function hooks(): void {
		add_action( 'vulnhub_sync_complete', array( $this, 'after_sync' ), 20, 3 );
	}

	/**
	 * Re-map after any connector that changes asset or people data.
	 */
	public function after_sync( string $connector, string $status ): void {
		if ( 'success' !== $status ) {
			return;
		}
		if ( ! in_array( $connector, array( 'tenable', 'intune', 'cmdb' ), true ) ) {
			return;
		}
		$this->run();
	}

	/**
	 * Match field vocabulary offered in the rule builder.
	 *
	 * @return array<string,string>
	 */
	public static function match_fields(): array {
		$fields = array(
			'asset_type'       => __( 'Asset type', 'vulnhub' ),
			'hostname'         => __( 'Hostname', 'vulnhub' ),
			'fqdn'             => __( 'FQDN', 'vulnhub' ),
			'ipv4'             => __( 'IPv4 address', 'vulnhub' ),
			'operating_system' => __( 'Operating system', 'vulnhub' ),
			'primary_source'   => __( 'Discovered by', 'vulnhub' ),
			'environment'      => __( 'Environment', 'vulnhub' ),
			'business_service' => __( 'Business service', 'vulnhub' ),
			'patch_group'      => __( 'Patch group', 'vulnhub' ),
			'cloud_account_id' => __( 'Cloud account ID', 'vulnhub' ),
			'cloud_region'     => __( 'Cloud region', 'vulnhub' ),
			'tag'              => __( 'Tag (any value)', 'vulnhub' ),
		);

		/*
		 * The engine matches any `tag:<key>`, so the only reason to list
		 * keys here is so a person can pick one. A fixed list of four
		 * guesses is no use against a real estate: this customer's AWS
		 * resource tags carry `Patch Group`, `owner`, `technical`, `env`,
		 * `costgroup` and `server_role`, and none of them were offered.
		 * Ask the data instead.
		 */
		foreach ( self::tag_keys() as $key ) {
			/* translators: %s: a tag key found in the imported data. */
			$fields[ 'tag:' . $key ] = sprintf( __( 'Tag: %s', 'vulnhub' ), $key );
		}

		return $fields;
	}

	/**
	 * Distinct tag keys present on assets, newest data first.
	 *
	 * Cached for five minutes: the rule builder asks on every render and the
	 * answer only changes when an import lands.
	 *
	 * @return array<int,string>
	 */
	public static function tag_keys(): array {
		$cached = get_transient( 'vulnhub_tag_keys' );

		if ( is_array( $cached ) ) {
			return $cached;
		}

		global $wpdb;

		$rows = (array) $wpdb->get_col(
			'SELECT tags_json FROM ' . vh_table( 'assets' ) . " WHERE tags_json <> '' AND tags_json <> '[]' ORDER BY updated_at DESC LIMIT 2000"
		);

		$keys = array();

		foreach ( $rows as $json ) {
			$tags = json_decode( (string) $json, true );

			if ( ! is_array( $tags ) ) {
				continue;
			}

			foreach ( $tags as $tag ) {
				$key = is_array( $tag ) ? trim( (string) ( $tag['category'] ?? $tag['key'] ?? '' ) ) : '';

				if ( '' !== $key && ! isset( $keys[ $key ] ) ) {
					$keys[ $key ] = true;
				}
			}
		}

		$keys = array_keys( $keys );
		sort( $keys, SORT_NATURAL | SORT_FLAG_CASE );
		$keys = array_slice( $keys, 0, 40 );

		set_transient( 'vulnhub_tag_keys', $keys, 5 * MINUTE_IN_SECONDS );

		return $keys;
	}

	/**
	 * @return array<string,string>
	 */
	public static function operators(): array {
		return array(
			'equals'      => __( 'is exactly', 'vulnhub' ),
			'not_equals'  => __( 'is not', 'vulnhub' ),
			'contains'    => __( 'contains', 'vulnhub' ),
			'starts_with' => __( 'starts with', 'vulnhub' ),
			'ends_with'   => __( 'ends with', 'vulnhub' ),
			'regex'       => __( 'matches regex', 'vulnhub' ),
			'exists'      => __( 'is present', 'vulnhub' ),
			'empty'       => __( 'is empty', 'vulnhub' ),
		);
	}

	/**
	 * @return array<string,string>
	 */
	public static function assign_types(): array {
		return array(
			'person_from_intune'    => __( 'Owner = the device\'s Intune primary user', 'vulnhub' ),
			'person_from_tag'       => __( 'Owner = person named in a Tenable tag', 'vulnhub' ),
			'person'                => __( 'Owner = a specific person (UPN)', 'vulnhub' ),
			'team_from_tag'         => __( 'Team = the value of a Tenable tag', 'vulnhub' ),
			'team_from_owner'       => __( 'Team = the owner\'s department', 'vulnhub' ),
			'team'                  => __( 'Team = a specific team', 'vulnhub' ),
			'team_default'          => __( 'Team = a specific team, only if none is known', 'vulnhub' ),
			'location_from_owner'   => __( 'Location = the owner\'s office', 'vulnhub' ),
			'location_from_tag'     => __( 'Location = the value of a Tenable tag', 'vulnhub' ),
			'location'              => __( 'Location = a specific location', 'vulnhub' ),
			'criticality'           => __( 'Set business criticality', 'vulnhub' ),
			'asset_type'            => __( 'Set asset type', 'vulnhub' ),
		);
	}

	/**
	 * Run the mapping engine over assets.
	 *
	 * @param array<string,mixed> $args Optional: asset_id to map one asset only.
	 * @return array{processed:int,changed:int,unresolved:int}
	 */
	public function run( array $args = array() ): array {
		global $wpdb;

		$rules = (array) $wpdb->get_results(
			'SELECT * FROM ' . vh_table( 'mapping_rules' ) . ' WHERE enabled = 1 ORDER BY priority ASC, id ASC',
			ARRAY_A
		);

		$where  = '1=1';
		$params = array();
		if ( ! empty( $args['asset_id'] ) ) {
			$where    = 'id = %d';
			$params[] = (int) $args['asset_id'];
		}

		$batch      = 500;
		$offset     = 0;
		$processed  = 0;
		$changed    = 0;
		$unresolved = 0;

		do {
			$sql  = 'SELECT * FROM ' . vh_table( 'assets' ) . " WHERE {$where} ORDER BY id ASC LIMIT %d OFFSET %d";
			$qp   = $params;
			$qp[] = $batch;
			$qp[] = $offset;

			$assets = (array) $wpdb->get_results( $wpdb->prepare( $sql, ...$qp ), ARRAY_A ); // phpcs:ignore

			foreach ( $assets as $asset ) {
				++$processed;
				if ( $this->map_asset( $asset, $rules ) ) {
					++$changed;
				}
				if ( in_array( (string) $asset['asset_type'], vh_user_bound_asset_types(), true ) ) {
					$refreshed = Repo::asset( (int) $asset['id'] );
					if ( $refreshed && ! (int) $refreshed['owner_person_id'] ) {
						++$unresolved;
					}
				}
			}

			$offset += $batch;
		} while ( count( $assets ) === $batch );

		update_option(
			'vulnhub_last_mapping',
			array(
				'at'         => vh_now(),
				'processed'  => $processed,
				'changed'    => $changed,
				'unresolved' => $unresolved,
			),
			false
		);

		return compact( 'processed', 'changed', 'unresolved' );
	}

	/**
	 * Apply all rules to one asset. Returns true when something changed.
	 *
	 * @param array<string,mixed>            $asset Asset row.
	 * @param array<int,array<string,mixed>> $rules Rule rows.
	 */
	private function map_asset( array $asset, array $rules ): bool {
		global $wpdb;

		$updates = array();
		$applied = array();
		$tags    = $this->tag_map( $asset );

		foreach ( $rules as $rule ) {
			if ( ! $this->rule_matches( $rule, $asset, $tags ) ) {
				continue;
			}

			$result = $this->apply_assignment( $rule, $asset, $tags );
			if ( $result ) {
				$updates   = array_merge( $updates, $result );
				$applied[] = (string) $rule['name'];
				$wpdb->query( $wpdb->prepare( 'UPDATE ' . vh_table( 'mapping_rules' ) . ' SET match_count = match_count + 1 WHERE id = %d', (int) $rule['id'] ) );
			}

			if ( ! empty( $rule['stop_processing'] ) && $result ) {
				break;
			}
		}

		// Derive team/location from the resolved owner when still unset.
		$owner_id = (int) ( $updates['owner_person_id'] ?? $asset['owner_person_id'] );
		if ( $owner_id ) {
			$person = Repo::person( $owner_id );
			if ( $person ) {
				$team_id = (int) ( $updates['team_id'] ?? $asset['team_id'] );
				if ( ! $team_id ) {
					$derived = (int) $person['team_id'];
					if ( ! $derived && ! empty( $person['department'] ) ) {
						$derived = Repo::ensure_team( (string) $person['department'], 'intune' );
					}
					if ( $derived ) {
						$updates['team_id'] = $derived;
						$applied[]          = 'derived: owner department';
					}
				}
				$loc_id = (int) ( $updates['location_id'] ?? $asset['location_id'] );
				if ( ! $loc_id ) {
					$derived = (int) $person['location_id'];
					if ( ! $derived && ! empty( $person['office_location'] ) ) {
						$derived = Repo::ensure_location( (string) $person['office_location'], (string) $person['city'], (string) $person['country'] );
					}
					if ( $derived ) {
						$updates['location_id'] = $derived;
						$applied[]              = 'derived: owner office';
					}
				}
			}
		}

		if ( ! $updates ) {
			return false;
		}

		// Skip the write when nothing actually differs.
		$diff = array();
		foreach ( $updates as $key => $value ) {
			if ( (string) ( $asset[ $key ] ?? '' ) !== (string) $value ) {
				$diff[ $key ] = $value;
			}
		}
		if ( ! $diff ) {
			return false;
		}

		$diff['owner_rule'] = vh_trim( implode( ' → ', array_unique( $applied ) ), 190 );
		$diff['updated_at'] = vh_now();

		$wpdb->update( vh_table( 'assets' ), $diff, array( 'id' => (int) $asset['id'] ) );

		return true;
	}

	/**
	 * Decode an asset's Tenable tags into key => value.
	 *
	 * @param array<string,mixed> $asset Asset row.
	 * @return array<string,string>
	 */
	private function tag_map( array $asset ): array {
		$tags = vh_json( $asset['tags_json'] ?? null );
		$out  = array();

		foreach ( $tags as $tag ) {
			if ( is_array( $tag ) ) {
				// Tenable names the tag's left-hand side "category" in both its
				// export CSV and its API; older/simpler feeds use "key". We
				// accept either, because reading only "key" silently matched
				// nothing at all against real Tenable data.
				$key = (string) ( $tag['category'] ?? $tag['category_name'] ?? $tag['key'] ?? '' );
				if ( '' !== $key ) {
					$out[ $key ] = (string) ( $tag['value'] ?? '' );
				}
			} elseif ( is_string( $tag ) && str_contains( $tag, ':' ) ) {
				[ $k, $v ] = array_map( 'trim', explode( ':', $tag, 2 ) );
				$out[ $k ] = $v;
			}
		}

		return $out;
	}

	/**
	 * @param array<string,mixed>  $rule  Rule row.
	 * @param array<string,mixed>  $asset Asset row.
	 * @param array<string,string> $tags  Decoded tags.
	 */
	private function rule_matches( array $rule, array $asset, array $tags ): bool {
		$field = (string) $rule['match_field'];
		$op    = (string) $rule['match_operator'];
		$want  = (string) $rule['match_value'];

		if ( str_starts_with( $field, 'tag:' ) ) {
			$subject = $tags[ substr( $field, 4 ) ] ?? '';
		} elseif ( 'tag' === $field ) {
			$subject = implode( ' ', array_map( static fn( $k, $v ): string => "{$k}:{$v}", array_keys( $tags ), $tags ) );
		} else {
			$subject = (string) ( $asset[ $field ] ?? '' );
		}

		return match ( $op ) {
			'equals'      => 0 === strcasecmp( $subject, $want ),
			'not_equals'  => 0 !== strcasecmp( $subject, $want ),
			'contains'    => '' !== $want && false !== stripos( $subject, $want ),
			'starts_with' => '' !== $want && str_starts_with( strtolower( $subject ), strtolower( $want ) ),
			'ends_with'   => '' !== $want && str_ends_with( strtolower( $subject ), strtolower( $want ) ),
			'regex'       => '' !== $want && 1 === @preg_match( '~' . str_replace( '~', '\~', $want ) . '~i', $subject ),
			'exists'      => '' !== trim( $subject ),
			'empty'       => '' === trim( $subject ),
			default       => false,
		};
	}

	/**
	 * Compute the column updates for a matched rule.
	 *
	 * @param array<string,mixed>  $rule  Rule row.
	 * @param array<string,mixed>  $asset Asset row.
	 * @param array<string,string> $tags  Decoded tags.
	 * @return array<string,mixed>
	 */
	private function apply_assignment( array $rule, array $asset, array $tags ): array {
		$type  = (string) $rule['assign_type'];
		$value = (string) $rule['assign_value'];

		switch ( $type ) {
			case 'person_from_intune':
				// The Intune connector writes the primary user's UPN into raw_json.
				$raw = vh_json( $asset['raw_json'] ?? null );
				$upn = (string) ( $raw['intune']['userPrincipalName'] ?? $raw['userPrincipalName'] ?? '' );
				if ( '' === $upn ) {
					return array();
				}
				$person = Repo::person_by_upn( $upn );
				if ( ! $person ) {
					return array();
				}
				return array(
					'owner_person_id'  => (int) $person['id'],
					'owner_source'     => 'intune',
					'owner_confidence' => 'high',
				);

			case 'person_from_tag':
				$upn = $tags[ $value ?: 'Owner' ] ?? '';
				if ( '' === $upn ) {
					return array();
				}
				$person = Repo::person_by_upn( $upn );
				if ( ! $person ) {
					return array();
				}
				return array(
					'owner_person_id'  => (int) $person['id'],
					'owner_source'     => 'tenable-tag',
					'owner_confidence' => 'medium',
				);

			case 'person':
				$person = Repo::person_by_upn( $value );
				if ( ! $person ) {
					return array();
				}
				return array(
					'owner_person_id'  => (int) $person['id'],
					'owner_source'     => 'rule',
					'owner_confidence' => 'high',
				);

			case 'team_from_tag':
				$name = $tags[ $value ?: 'Team' ] ?? '';
				if ( '' === $name ) {
					return array();
				}
				$id = Repo::ensure_team( $name, 'tenable-tag' );
				return $id ? array( 'team_id' => $id ) : array();

			case 'team_from_owner':
				$person = Repo::person( (int) $asset['owner_person_id'] );
				if ( ! $person || '' === (string) $person['department'] ) {
					return array();
				}
				$id = Repo::ensure_team( (string) $person['department'], 'intune' );
				return $id ? array( 'team_id' => $id ) : array();

			case 'team':
				$id = Repo::team_id_by_slug( $value ) ?: Repo::team_id_by_name( $value );
				return $id ? array( 'team_id' => $id ) : array();

			/*
			 * A floor, not an override.
			 *
			 * "Servers default to Infrastructure" is seeded unconditionally, and
			 * because the engine runs after every import it re-won the argument
			 * on every pass: a CMDB that named a Unix team as the support
			 * group for 221 servers had that answer overwritten each time, and
			 * all 406 servers sat on Infrastructure. A rule whose name says
			 * "default" has no business beating a system that actually knows.
			 */
			case 'team_default':
				if ( (int) ( $asset['team_id'] ?? 0 ) > 0 ) {
					return array();
				}
				$id = Repo::team_id_by_slug( $value ) ?: Repo::team_id_by_name( $value );
				return $id ? array( 'team_id' => $id ) : array();

			case 'location_from_owner':
				$person = Repo::person( (int) $asset['owner_person_id'] );
				if ( ! $person ) {
					return array();
				}
				$id = Repo::ensure_location(
					(string) $person['office_location'],
					(string) $person['city'],
					(string) $person['country']
				);
				return $id ? array( 'location_id' => $id ) : array();

			case 'location_from_tag':
				$name = $tags[ $value ?: 'Location' ] ?? '';
				if ( '' === $name ) {
					return array();
				}
				$id = Repo::ensure_location( $name );
				return $id ? array( 'location_id' => $id ) : array();

			case 'location':
				global $wpdb;
				$id = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT id FROM ' . vh_table( 'locations' ) . ' WHERE slug = %s OR name = %s LIMIT 1', sanitize_title( $value ), $value ) );
				return $id ? array( 'location_id' => $id ) : array();

			case 'criticality':
				return in_array( $value, array( 'critical', 'high', 'medium', 'low' ), true )
					? array( 'criticality' => $value )
					: array();

			case 'asset_type':
				return array_key_exists( $value, vh_asset_types() )
					? array( 'asset_type' => $value )
					: array();
		}

		return array();
	}

	/**
	 * Assets that break the "a workstation must have a user" rule.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function unresolved_user_assets( int $limit = 100 ): array {
		global $wpdb;

		$types = "'" . implode( "','", array_map( 'esc_sql', vh_user_bound_asset_types() ) ) . "'";
		$live  = vh_in_service_sql();

		return (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT * FROM ' . vh_table( 'assets' ) . " WHERE asset_type IN ({$types}) AND owner_person_id = 0 AND lifecycle_status IN ({$live}) ORDER BY (open_critical + open_high) DESC, hostname ASC LIMIT %d", // phpcs:ignore
				$limit
			),
			ARRAY_A
		);
	}
}

