<?php
/**
 * Domain names, and what they actually point at.
 *
 * Every other page in this plugin names a resource by its id or its private
 * address, which is not how anybody refers to it. The name people use lives
 * in DNS, and until now nothing read DNS at all -- so a Lambda behind an API
 * Gateway was only ever "y4wk3ovwd4.execute-api.ap-southeast-2.amazonaws.com"
 * here, even where the estate reaches it at a real hostname.
 *
 * Two readers fill that in, both read-only control-plane calls:
 *
 *   1. **API Gateway custom domain names** and their base-path mappings, per
 *      account and region. This is what says an API is also served at a real
 *      hostname, and -- through `distributionDomainName` -- whether a
 *      CloudFront distribution is genuinely in front of it.
 *   2. **Route 53** hosted zones and their record sets, per account. Every A,
 *      AAAA and CNAME is matched against what this plugin already knows: the
 *      public addresses on `net_nodes` (Elastic IPs, interfaces, instances),
 *      load balancer DNS names, `execute-api` hostnames and CloudFront.
 *
 * Three things this class is careful about, because each one is a way to be
 * confidently wrong:
 *
 * - **An account we could not read is not an account with no domains.** Every
 *   account and region records its own run row with a status, so "denied"
 *   and "none found" can never be confused. A page that shows a blank where
 *   a permission error belongs is worse than one that shows nothing at all.
 * - **Route 53 is not the estate's DNS.** It holds the zones hosted in the
 *   accounts this login can read, and nothing else. A name served from
 *   on-prem DNS, a registrar or a CDN will not appear here, so every name
 *   carries the source it came from and the page says what the source covers.
 *   Anything genuinely fronted by the corporate firewall is the likeliest
 *   thing to be missing.
 * - **A match is a fact, not a guess.** A name is only tied to a resource
 *   when the address or hostname it resolves to is one we hold. Where it is
 *   not, the row is kept unmatched rather than attached to the nearest
 *   plausible thing.
 *
 * See docs/AWS-NETWORK.md, "Domain names".
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_AWS_Domains {

	private const DB_VERSION = '1';
	private const OPT_DB     = 'vulnhub_aws_domains_db';

	/** Route 53's XML namespace. SimpleXML will not see a child without it. */
	private const NS = 'https://route53.amazonaws.com/doc/2013-04-01/';

	/** Hosted zones read per account before the reader stops and says so. */
	private const MAX_ZONES = 80;

	/** Record sets kept per account. A zone with a generated record per host
	 *  can run to tens of thousands, and this table is an index, not a copy
	 *  of DNS. */
	private const MAX_RECORDS = 4000;

	/** Custom domain names read per account and region. */
	private const MAX_DOMAINS = 200;

	/** @var array<string,array<string,string>>|null Public address -> resource. */
	private static ?array $by_ip = null;

	/** @var array<string,array<string,string>>|null Load balancer DNS name -> resource. */
	private static ?array $by_dns = null;

	public static function table(): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_aws_domains';
	}

	public static function runs_table(): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_aws_domain_runs';
	}

	public static function install(): void {
		if ( self::DB_VERSION === (string) get_option( self::OPT_DB, '' ) ) {
			return;
		}

		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$t       = self::table();
		$r       = self::runs_table();

		/*
		 * Same reasoning as the serverless table: the natural key (account,
		 * source, zone, name, type, target) is far past the index length a
		 * utf8mb4 table allows, so one hash keys the row.
		 */
		dbDelta(
			"CREATE TABLE {$t} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				fingerprint char(40) NOT NULL DEFAULT '',
				account_id varchar(24) NOT NULL DEFAULT '',
				region varchar(32) NOT NULL DEFAULT '',
				source varchar(16) NOT NULL DEFAULT '',
				zone varchar(255) NOT NULL DEFAULT '',
				name varchar(255) NOT NULL DEFAULT '',
				record_type varchar(16) NOT NULL DEFAULT '',
				target varchar(512) NOT NULL DEFAULT '',
				private tinyint(1) NOT NULL DEFAULT 0,
				matched_kind varchar(24) NOT NULL DEFAULT '',
				matched_ref varchar(128) NOT NULL DEFAULT '',
				matched_name varchar(255) NOT NULL DEFAULT '',
				detail text NULL,
				last_seen datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				UNIQUE KEY fp (fingerprint),
				KEY acct (account_id,region),
				KEY nm (name),
				KEY matched (matched_kind,matched_ref)
			) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$r} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				account_id varchar(24) NOT NULL DEFAULT '',
				region varchar(32) NOT NULL DEFAULT '',
				source varchar(16) NOT NULL DEFAULT '',
				status varchar(16) NOT NULL DEFAULT '',
				note varchar(255) NOT NULL DEFAULT '',
				zones int(10) unsigned NOT NULL DEFAULT 0,
				names int(10) unsigned NOT NULL DEFAULT 0,
				matched int(10) unsigned NOT NULL DEFAULT 0,
				last_run datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				UNIQUE KEY scope (account_id,region,source)
			) {$charset};"
		);

		update_option( self::OPT_DB, self::DB_VERSION, false );
	}

	/* =================================================================
	 * Capture -- API Gateway custom domains (per account and region)
	 * ============================================================== */

	/**
	 * Custom domain names in one account and region, with what they map to.
	 *
	 * @param VulnHub_AWS_Client $client  Signed client for this account.
	 * @param string             $account Account id.
	 * @param string             $region  Region.
	 * @param string             $now     UTC stamp for the whole run.
	 * @return int Rows written.
	 */
	public static function capture_apigw( VulnHub_AWS_Client $client, string $account, string $region, string $now ): int {
		/*
		 * Both API Gateways, because AWS has two and they are different
		 * services behind one console page.
		 *
		 * `/domainnames` is REST (v1). `/v2/domainnames` is HTTP and WebSocket
		 * APIs (v2). A v1 call against an account whose APIs are all v2
		 * returns HTTP 200 with an empty list -- not an error, not a
		 * permission problem, just nothing -- so this reader reported "ok, no
		 * custom domains" for 57 accounts while DNS held 148 ALIAS records
		 * pointing straight at `d-….execute-api` endpoints, which only exist
		 * where a custom domain does. The estate's own serverless reader has
		 * been calling `/v2/apis` all along; only this one was asking the
		 * older service.
		 *
		 * The two are merged into one set of rows under one source, because
		 * nothing downstream should have to care which flavour of API Gateway
		 * a hostname was served by.
		 */
		$rows   = array();
		$seen   = 0;
		$notes  = array();
		$errors = array();

		$rest = $client->get( 'apigateway', $region, '/domainnames', array( 'limit' => '500' ) );

		if ( ! empty( $rest['ok'] ) ) {
			$seen += self::apigw_rest_rows( $client, $region, (array) ( $rest['data']['items'] ?? array() ), $rows, $notes );
		} else {
			$errors[] = array( 'error' => (string) $rest['error'], 'status' => (int) $rest['status'] );
		}

		$http = $client->get( 'apigateway', $region, '/v2/domainnames', array( 'maxResults' => '500' ) );

		if ( ! empty( $http['ok'] ) ) {
			$seen += self::apigw_http_rows( $client, $region, (array) ( $http['data']['items'] ?? $http['data']['Items'] ?? array() ), $rows, $notes );
		} else {
			$errors[] = array( 'error' => (string) $http['error'], 'status' => (int) $http['status'] );
		}

		// Neither answered: that is a failed read, not an empty estate, and
		// it keeps whatever was stored last time.
		if ( 2 === count( $errors ) ) {
			self::record_run(
				$account,
				$region,
				'apigw',
				self::status_for( (string) $errors[0]['error'], (int) $errors[0]['status'] ),
				(string) $errors[0]['error'],
				0,
				0,
				0,
				$now
			);

			return 0;
		}

		// One of the two failed: the rows that did come back are stored, and
		// the run says what was missed rather than passing for complete.
		foreach ( $errors as $err ) {
			$notes[] = (string) $err['error'];
		}

		return self::store( $account, $region, 'apigw', $rows, implode( '; ', array_filter( $notes ) ), $seen, $now );
	}

	/**
	 * REST (v1) custom domains and their base-path mappings.
	 *
	 * @param array<int,mixed>              $items Items from /domainnames.
	 * @param array<int,array<string,mixed>> $rows  Rows, appended to.
	 * @param array<int,string>             $notes Notes, appended to.
	 * @return int Domains seen.
	 */
	private static function apigw_rest_rows( VulnHub_AWS_Client $client, string $region, array $items, array &$rows, array &$notes ): int {
		$seen = count( $items );

		if ( $seen > self::MAX_DOMAINS ) {
			$notes[] = sprintf(
				/* translators: %d: the cap on custom domain names read per account and region. */
				__( 'more than %d REST custom domain names; the rest were not read', 'vulnhub' ),
				self::MAX_DOMAINS
			);
			$items = array_slice( $items, 0, self::MAX_DOMAINS );
		}

		foreach ( $items as $item ) {
			$item = (array) $item;
			$name = strtolower( trim( (string) ( $item['domainName'] ?? '' ) ) );

			if ( '' === $name ) {
				continue;
			}

			$dist   = (string) ( $item['distributionDomainName'] ?? '' );
			$shared = array(
				'api'          => 'rest',
				'endpoint'     => (array) ( $item['endpointConfiguration']['types'] ?? array() ),
				'regional'     => (string) ( $item['regionalDomainName'] ?? '' ),
				'distribution' => $dist,
				'security'     => (string) ( $item['securityPolicy'] ?? '' ),
			);

			$maps = $client->get( 'apigateway', $region, '/domainnames/' . rawurlencode( $name ) . '/basepathmappings', array( 'limit' => '500' ) );
			$made = false;

			if ( ! empty( $maps['ok'] ) ) {
				foreach ( (array) ( $maps['data']['items'] ?? array() ) as $map ) {
					$map = (array) $map;
					$api = (string) ( $map['restApiId'] ?? '' );

					if ( '' === $api ) {
						continue;
					}

					$base   = (string) ( $map['basePath'] ?? '' );
					$stage  = (string) ( $map['stage'] ?? '' );
					$made   = true;
					$rows[] = self::apigw_row( $name, $api, $stage, $base, $shared );
				}
			} elseif ( '' !== (string) $maps['error'] ) {
				$notes[] = 'base path mappings: ' . (string) $maps['error'];
			}

			if ( ! $made ) {
				$rows[] = self::apigw_bare_row( $name, $dist, $shared );
			}
		}

		return $seen;
	}

	/**
	 * HTTP and WebSocket (v2) custom domains and their API mappings.
	 *
	 * The v2 API spells everything differently -- `apiMappings` not
	 * `basepathmappings`, `apiId` not `restApiId`, the endpoint hostname
	 * inside `domainNameConfigurations` -- and has been seen returning
	 * both `items` and `Items`. Read through pick() so a spelling change
	 * costs a missed field rather than a missed domain.
	 *
	 * @param array<int,mixed>              $items Items from /v2/domainnames.
	 * @param array<int,array<string,mixed>> $rows  Rows, appended to.
	 * @param array<int,string>             $notes Notes, appended to.
	 * @return int Domains seen.
	 */
	private static function apigw_http_rows( VulnHub_AWS_Client $client, string $region, array $items, array &$rows, array &$notes ): int {
		$seen = count( $items );

		if ( $seen > self::MAX_DOMAINS ) {
			$notes[] = sprintf(
				/* translators: %d: the cap on custom domain names read per account and region. */
				__( 'more than %d HTTP API custom domain names; the rest were not read', 'vulnhub' ),
				self::MAX_DOMAINS
			);
			$items = array_slice( $items, 0, self::MAX_DOMAINS );
		}

		$pick = static function ( array $from, array $keys, string $fallback = '' ): string {
			foreach ( $keys as $key ) {
				if ( isset( $from[ $key ] ) && '' !== (string) $from[ $key ] ) {
					return (string) $from[ $key ];
				}
			}

			return $fallback;
		};

		foreach ( $items as $item ) {
			$item = (array) $item;
			$name = strtolower( trim( $pick( $item, array( 'domainName', 'DomainName' ) ) ) );

			if ( '' === $name ) {
				continue;
			}

			$config = (array) ( $item['domainNameConfigurations'] ?? $item['DomainNameConfigurations'] ?? array() );
			$first  = (array) ( $config[0] ?? array() );
			$host   = $pick( $first, array( 'apiGatewayDomainName', 'ApiGatewayDomainName' ) );
			$type   = $pick( $first, array( 'endpointType', 'EndpointType' ) );

			$shared = array(
				'api'          => 'http',
				'endpoint'     => '' !== $type ? array( $type ) : array(),
				'regional'     => 'EDGE' === strtoupper( $type ) ? '' : $host,
				'distribution' => 'EDGE' === strtoupper( $type ) ? $host : '',
				'security'     => $pick( $first, array( 'securityPolicy', 'SecurityPolicy' ) ),
			);

			$maps = $client->get( 'apigateway', $region, '/v2/domainnames/' . rawurlencode( $name ) . '/apimappings', array( 'maxResults' => '500' ) );
			$made = false;

			if ( ! empty( $maps['ok'] ) ) {
				foreach ( (array) ( $maps['data']['items'] ?? $maps['data']['Items'] ?? array() ) as $map ) {
					$map = (array) $map;
					$api = $pick( $map, array( 'apiId', 'ApiId' ) );

					if ( '' === $api ) {
						continue;
					}

					$made   = true;
					$rows[] = self::apigw_row(
						$name,
						$api,
						$pick( $map, array( 'stage', 'Stage' ) ),
						$pick( $map, array( 'apiMappingKey', 'ApiMappingKey' ) ),
						$shared
					);
				}
			} elseif ( '' !== (string) $maps['error'] ) {
				$notes[] = 'API mappings: ' . (string) $maps['error'];
			}

			if ( ! $made ) {
				$rows[] = self::apigw_bare_row( $name, (string) $shared['distribution'], $shared );
			}
		}

		return $seen;
	}

	/**
	 * One custom domain mapped to one API.
	 *
	 * @param array<string,mixed> $shared Fields shared by every row of this domain.
	 * @return array<string,mixed>
	 */
	private static function apigw_row( string $name, string $api, string $stage, string $base, array $shared ): array {
		return array(
			'source'       => 'apigw',
			'zone'         => '',
			'name'         => $name,
			'record_type'  => 'BASEPATH',
			'target'       => $api . ( '' !== $stage ? '/' . $stage : '' ),
			'private'      => 0,
			'matched_kind' => 'apigw',
			'matched_ref'  => $api,
			'matched_name' => '' !== $base && '(none)' !== $base ? '/' . ltrim( $base, '/' ) : '/',
			'detail'       => $shared + array(
				'basePath' => $base,
				'stage'    => $stage,
			),
		);
	}

	/**
	 * A custom domain with no mapping: still a name that exists and
	 * resolves, and saying nothing about it would hide it.
	 *
	 * @param array<string,mixed> $shared Fields shared by every row of this domain.
	 * @return array<string,mixed>
	 */
	private static function apigw_bare_row( string $name, string $dist, array $shared ): array {
		return array(
			'source'       => 'apigw',
			'zone'         => '',
			'name'         => $name,
			'record_type'  => 'DOMAIN',
			'target'       => '' !== $dist ? $dist : (string) $shared['regional'],
			'private'      => 0,
			'matched_kind' => '' !== $dist ? 'cloudfront' : '',
			'matched_ref'  => '',
			'matched_name' => '',
			'detail'       => $shared,
		);
	}

	/* =================================================================
	 * Capture -- Route 53 (per account; the service is global)	/* =================================================================
	 * Capture -- Route 53 (per account; the service is global)
	 * ============================================================== */

	/**
	 * Every hosted zone in one account, and the records that name something.
	 *
	 * @param VulnHub_AWS_Client $client  Signed client for this account.
	 * @param string             $account Account id.
	 * @param string             $now     UTC stamp for the whole run.
	 * @return int Rows written.
	 */
	public static function capture_dns( VulnHub_AWS_Client $client, string $account, string $now ): int {
		$zones  = array();
		$marker = '';
		$note   = '';

		do {
			$query = array( 'maxitems' => '100' );

			if ( '' !== $marker ) {
				$query['marker'] = $marker;
			}

			$res = $client->get_xml( 'route53', 'us-east-1', '/2013-04-01/hostedzone', $query, 'route53.amazonaws.com' );

			if ( empty( $res['ok'] ) || ! $res['xml'] instanceof SimpleXMLElement ) {
				self::record_run( $account, '', 'route53', self::status_for( (string) $res['error'], (int) $res['status'] ), (string) $res['error'], 0, 0, 0, $now );

				return 0;
			}

			$xml = $res['xml'];

			foreach ( self::nodes( $xml, 'HostedZone' ) as $zone ) {
				$id = self::val( $zone, 'Id' );
				$id = (string) preg_replace( '#^/hostedzone/#', '', $id );

				if ( '' === $id ) {
					continue;
				}

				$config  = $zone->children( self::NS )->Config ?? null; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
				$zones[] = array(
					'id'      => $id,
					'name'    => rtrim( strtolower( self::val( $zone, 'Name' ) ), '.' ),
					'private' => $config instanceof SimpleXMLElement && 'true' === self::val( $config, 'PrivateZone' ),
				);
			}

			$marker = 'true' === self::val( $xml, 'IsTruncated' ) ? self::val( $xml, 'NextMarker' ) : '';
		} while ( '' !== $marker && count( $zones ) < self::MAX_ZONES );

		if ( count( $zones ) > self::MAX_ZONES ) {
			$note  = sprintf(
				/* translators: %d: the cap on hosted zones read per account. */
				__( 'more than %d hosted zones; the rest were not read', 'vulnhub' ),
				self::MAX_ZONES
			);
			$zones = array_slice( $zones, 0, self::MAX_ZONES );
		}

		$rows = array();

		foreach ( $zones as $zone ) {
			if ( count( $rows ) >= self::MAX_RECORDS ) {
				$note = '' !== $note ? $note : sprintf(
					/* translators: %d: the cap on records kept per account. */
					__( 'more than %d records; the rest were not read', 'vulnhub' ),
					self::MAX_RECORDS
				);
				break;
			}

			$err = self::read_zone( $client, $zone, $rows );

			if ( '' !== $err && '' === $note ) {
				$note = $err;
			}
		}

		return self::store( $account, '', 'route53', $rows, $note, count( $zones ), $now );
	}

	/**
	 * The record sets of one zone, appended to $rows.
	 *
	 * @param array{id:string,name:string,private:bool} $zone One hosted zone.
	 * @param array<int,array<string,mixed>>            $rows Collected rows, by reference.
	 * @return string Error, or '' when the zone read cleanly.
	 */
	private static function read_zone( VulnHub_AWS_Client $client, array $zone, array &$rows ): string {
		$next_name = '';
		$next_type = '';
		$guard     = 0;

		do {
			$query = array( 'maxitems' => '300' );

			if ( '' !== $next_name ) {
				$query['name'] = $next_name;
				$query['type'] = $next_type;
			}

			$res = $client->get_xml(
				'route53',
				'us-east-1',
				'/2013-04-01/hostedzone/' . rawurlencode( $zone['id'] ) . '/rrset',
				$query,
				'route53.amazonaws.com'
			);

			if ( empty( $res['ok'] ) || ! $res['xml'] instanceof SimpleXMLElement ) {
				return 'zone ' . $zone['id'] . ': ' . (string) $res['error'];
			}

			$xml = $res['xml'];

			foreach ( self::nodes( $xml, 'ResourceRecordSet' ) as $set ) {
				$type = self::val( $set, 'Type' );

				// An index of names that point at something, not a copy of the
				// zone: NS, SOA, TXT, MX and the rest name no resource here.
				if ( ! in_array( $type, array( 'A', 'AAAA', 'CNAME' ), true ) ) {
					continue;
				}

				$name   = rtrim( strtolower( self::val( $set, 'Name' ) ), '.' );
				$name   = (string) str_replace( '\\052', '*', $name );
				$alias  = $set->children( self::NS )->AliasTarget ?? null; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
				$values = array();

				if ( $alias instanceof SimpleXMLElement ) {
					$values[] = rtrim( strtolower( self::val( $alias, 'DNSName' ) ), '.' );
				} else {
					foreach ( self::nodes( $set, 'ResourceRecord' ) as $rr ) {
						$values[] = trim( self::val( $rr, 'Value' ) );
					}
				}

				foreach ( $values as $value ) {
					if ( '' === $name || '' === $value ) {
						continue;
					}

					$match  = self::match_target( $value );
					$rows[] = array(
						'source'       => 'route53',
						'zone'         => $zone['name'],
						'name'         => $name,
						'record_type'  => $alias instanceof SimpleXMLElement ? 'ALIAS' : $type,
						'target'       => $value,
						'private'      => $zone['private'] ? 1 : 0,
						'matched_kind' => (string) $match['kind'],
						'matched_ref'  => (string) $match['ref'],
						'matched_name' => (string) $match['name'],
						'detail'       => array( 'zone_id' => $zone['id'] ),
					);

					if ( count( $rows ) >= self::MAX_RECORDS ) {
						return '';
					}
				}
			}

			$next_name = 'true' === self::val( $xml, 'IsTruncated' ) ? self::val( $xml, 'NextRecordName' ) : '';
			$next_type = '' !== $next_name ? self::val( $xml, 'NextRecordType' ) : '';
			++$guard;
		} while ( '' !== $next_name && $guard < 40 );

		return '';
	}

	/* =================================================================
	 * Matching -- a name is only tied to something we hold
	 * ============================================================== */

	/**
	 * Public face of the matcher, for readers outside this class -- the zone
	 * file and WAF imports run every name through the same rules, so a name
	 * from DNS and a name from AWS resolve to a resource the same way.
	 *
	 * @return array{kind:string,ref:string,name:string}
	 */
	public static function classify( string $value ): array {
		return self::match_target( $value );
	}

	/**
	 * What one record's value points at, where we already know the thing.
	 *
	 * @return array{kind:string,ref:string,name:string}
	 */
	private static function match_target( string $value ): array {
		$none = array(
			'kind' => '',
			'ref'  => '',
			'name' => '',
		);

		$value = strtolower( rtrim( trim( $value ), '.' ) );

		if ( '' === $value ) {
			return $none;
		}

		// A literal address: the commonest case, and the one the network map
		// can answer outright.
		if ( filter_var( $value, FILTER_VALIDATE_IP ) ) {
			return self::by_address( $value ) ?? $none;
		}

		// AWS's own public name for an instance carries the address in it.
		if ( preg_match( '/^ec2-(\d+)-(\d+)-(\d+)-(\d+)\./', $value, $m ) ) {
			$hit = self::by_address( $m[1] . '.' . $m[2] . '.' . $m[3] . '.' . $m[4] );

			if ( null !== $hit ) {
				return $hit;
			}
		}

		if ( preg_match( '/^([a-z0-9]+)\.execute-api\.[a-z0-9-]+\.amazonaws\.com$/', $value, $m ) ) {
			return array(
				'kind' => 'apigw',
				'ref'  => $m[1],
				'name' => '',
			);
		}

		if ( preg_match( '/\.cloudfront\.net$/', $value ) ) {
			return array(
				'kind' => 'cloudfront',
				'ref'  => $value,
				'name' => '',
			);
		}

		if ( preg_match( '/\.elb\.([a-z0-9-]+\.)?amazonaws\.com$/', $value ) ) {
			$hit = self::dns_index()[ $value ] ?? null;

			if ( null !== $hit ) {
				return $hit;
			}

			return array(
				'kind' => 'elb',
				'ref'  => '',
				'name' => '',
			);
		}

		if ( preg_match( '/\.s3[.-][a-z0-9.-]*amazonaws\.com$/', $value ) ) {
			return array(
				'kind' => 's3',
				'ref'  => $value,
				'name' => '',
			);
		}

		$hit = self::dns_index()[ $value ] ?? null;

		return null !== $hit ? $hit : $none;
	}

	/**
	 * @return array{kind:string,ref:string,name:string}|null
	 */
	private static function by_address( string $ip ): ?array {
		return self::ip_index()[ $ip ] ?? null;
	}

	/**
	 * Public address -> the resource holding it, across every account read.
	 *
	 * Cross-account on purpose: a zone in the DNS account routinely names an
	 * address that lives in an application account, and refusing to join
	 * those would drop most of the useful answers.
	 *
	 * @return array<string,array{kind:string,ref:string,name:string}>
	 */
	private static function ip_index(): array {
		if ( null !== self::$by_ip ) {
			return self::$by_ip;
		}

		global $wpdb;

		self::$by_ip = array();

		if ( ! class_exists( 'VulnHub_AWS_Network' ) ) {
			return self::$by_ip;
		}

		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB
			'SELECT node_type, resource_id, name, public_ip FROM ' . VulnHub_AWS_Network::nodes_table() . " WHERE public_ip <> '' ORDER BY FIELD(node_type,'instance','eni','eip') DESC",
			ARRAY_A
		);

		foreach ( (array) $rows as $row ) {
			$ip = (string) $row['public_ip'];

			// An instance beats the interface or address that carries it:
			// "this name is that server" is the answer somebody wants.
			if ( isset( self::$by_ip[ $ip ] ) && 'instance' !== (string) $row['node_type'] ) {
				continue;
			}

			self::$by_ip[ $ip ] = array(
				'kind' => (string) $row['node_type'],
				'ref'  => (string) $row['resource_id'],
				'name' => (string) $row['name'],
			);
		}

		return self::$by_ip;
	}

	/**
	 * Load balancer DNS name -> the balancer.
	 *
	 * @return array<string,array{kind:string,ref:string,name:string}>
	 */
	private static function dns_index(): array {
		if ( null !== self::$by_dns ) {
			return self::$by_dns;
		}

		global $wpdb;

		self::$by_dns = array();

		if ( ! class_exists( 'VulnHub_AWS_Network' ) ) {
			return self::$by_dns;
		}

		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB
			'SELECT resource_id, name, detail FROM ' . VulnHub_AWS_Network::nodes_table() . " WHERE node_type = 'elb'",
			ARRAY_A
		);

		foreach ( (array) $rows as $row ) {
			$detail = json_decode( (string) $row['detail'], true );
			$dns    = is_array( $detail ) ? strtolower( trim( (string) ( $detail['dns'] ?? '' ) ) ) : '';

			if ( '' === $dns ) {
				continue;
			}

			self::$by_dns[ $dns ] = array(
				'kind' => 'elb',
				'ref'  => (string) $row['resource_id'],
				'name' => (string) $row['name'],
			);
		}

		return self::$by_dns;
	}

	/** Drop the cached indexes, so a long sync picks up what it just stored. */
	public static function forget_indexes(): void {
		self::$by_ip  = null;
		self::$by_dns = null;
	}

	/* =================================================================
	 * Storage
	 * ============================================================== */

	/**
	 * Replace a whole non-AWS source (a zone file drop, say) in one go.
	 *
	 * @param array<int,array<string,mixed>> $rows Rows for this source.
	 */
	public static function replace_source( string $source, array $rows, string $note, int $zones, string $now ): int {
		return self::store( '', '', $source, $rows, $note, $zones, $now );
	}

	/**
	 * Replace one scope's rows, then record how the read went.
	 *
	 * @param array<int,array<string,mixed>> $rows Rows for this scope.
	 * @return int Rows written.
	 */
	private static function store( string $account, string $region, string $source, array $rows, string $note, int $zones, string $now ): int {
		global $wpdb;

		// Delete only once the reader has returned, so a refused account
		// keeps its last good answer instead of silently emptying.
		$wpdb->query( // phpcs:ignore WordPress.DB
			$wpdb->prepare(
				'DELETE FROM ' . self::table() . ' WHERE account_id = %s AND region = %s AND source = %s',
				$account,
				$region,
				$source
			)
		);

		$written = 0;
		$matched = 0;

		foreach ( $rows as $row ) {
			$written += self::write( $row, $account, $region, $now );
			$matched += '' !== (string) $row['matched_kind'] ? 1 : 0;
		}

		self::record_run( $account, $region, $source, '' !== $note ? 'partial' : 'ok', $note, $zones, $written, $matched, $now );

		return $written;
	}

	/**
	 * @param array<string,mixed> $row One record.
	 */
	private static function write( array $row, string $account, string $region, string $now ): int {
		global $wpdb;

		$fp = sha1(
			implode(
				'|',
				array(
					$account,
					$region,
					(string) $row['source'],
					(string) $row['zone'],
					(string) $row['name'],
					(string) $row['record_type'],
					(string) $row['target'],
				)
			)
		);

		$ok = $wpdb->query( // phpcs:ignore WordPress.DB
			$wpdb->prepare(
				'INSERT INTO ' . self::table() . ' (fingerprint,account_id,region,source,zone,name,record_type,target,private,matched_kind,matched_ref,matched_name,detail,last_seen)
				 VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%d,%s,%s,%s,%s,%s)
				 ON DUPLICATE KEY UPDATE private=VALUES(private), matched_kind=VALUES(matched_kind), matched_ref=VALUES(matched_ref),
				   matched_name=VALUES(matched_name), detail=VALUES(detail), last_seen=VALUES(last_seen)',
				$fp,
				$account,
				$region,
				(string) $row['source'],
				vh_trim( (string) $row['zone'], 250 ),
				vh_trim( (string) $row['name'], 250 ),
				(string) $row['record_type'],
				vh_trim( (string) $row['target'], 500 ),
				(int) $row['private'],
				(string) $row['matched_kind'],
				vh_trim( (string) $row['matched_ref'], 120 ),
				vh_trim( (string) $row['matched_name'], 250 ),
				(string) wp_json_encode( (array) $row['detail'] ),
				$now
			)
		);

		return $ok ? 1 : 0;
	}

	private static function record_run( string $account, string $region, string $source, string $status, string $note, int $zones, int $names, int $matched, string $now ): void {
		global $wpdb;

		$wpdb->query( // phpcs:ignore WordPress.DB
			$wpdb->prepare(
				'INSERT INTO ' . self::runs_table() . ' (account_id,region,source,status,note,zones,names,matched,last_run)
				 VALUES (%s,%s,%s,%s,%s,%d,%d,%d,%s)
				 ON DUPLICATE KEY UPDATE status=VALUES(status), note=VALUES(note), zones=VALUES(zones),
				   names=VALUES(names), matched=VALUES(matched), last_run=VALUES(last_run)',
				$account,
				$region,
				$source,
				$status,
				vh_trim( $note, 250 ),
				$zones,
				$names,
				$matched,
				$now
			)
		);
	}

	/**
	 * Tell a refusal apart from a failure, because they mean different things
	 * to somebody reading the page: one is a grant to add, the other a fault.
	 */
	private static function status_for( string $error, int $status ): string {
		if ( 403 === $status || false !== stripos( $error, 'AccessDenied' ) || false !== stripos( $error, 'not authorized' ) || false !== stripos( $error, 'UnauthorizedOperation' ) ) {
			return 'denied';
		}

		return 'failed';
	}

	/* =================================================================
	 * Reading
	 * ============================================================== */

	/**
	 * Every name that points at one API Gateway REST API.
	 *
	 * Both readers can produce these: a custom domain's base-path mapping
	 * names the API directly, and a Route 53 alias to its `execute-api`
	 * hostname resolves to the same id.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function for_api( string $api_id ): array {
		global $wpdb;

		if ( '' === $api_id ) {
			return array();
		}

		return (array) $wpdb->get_results( // phpcs:ignore WordPress.DB
			$wpdb->prepare(
				'SELECT name, record_type, target, source, private, matched_name, detail FROM ' . self::table() . '
				 WHERE matched_kind = %s AND matched_ref = %s ORDER BY name LIMIT 25',
				'apigw',
				$api_id
			),
			ARRAY_A
		);
	}

	/**
	 * How much of the estate the domain readers could actually see.
	 *
	 * @return array{names:int,matched:int,accounts:int,denied:int,failed:int,zones:int,captured_at:string}
	 */
	public static function coverage(): array {
		global $wpdb;

		$t = self::table();
		$r = self::runs_table();

		$row = $wpdb->get_row( // phpcs:ignore WordPress.DB
			"SELECT COUNT(*) AS names, SUM(matched_kind <> '') AS matched FROM {$t}",
			ARRAY_A
		);

		$runs = $wpdb->get_row( // phpcs:ignore WordPress.DB
			"SELECT COUNT(DISTINCT account_id) AS accounts, SUM(status = 'denied') AS denied,
			        SUM(status = 'failed') AS failed, SUM(zones) AS zones, MAX(last_run) AS captured_at FROM {$r}",
			ARRAY_A
		);

		return array(
			'names'       => (int) ( $row['names'] ?? 0 ),
			'matched'     => (int) ( $row['matched'] ?? 0 ),
			'accounts'    => (int) ( $runs['accounts'] ?? 0 ),
			'denied'      => (int) ( $runs['denied'] ?? 0 ),
			'failed'      => (int) ( $runs['failed'] ?? 0 ),
			'zones'       => (int) ( $runs['zones'] ?? 0 ),
			'captured_at' => (string) ( $runs['captured_at'] ?? '' ),
		);
	}

	/* =================================================================
	 * XML helpers -- Route 53 puts everything in its own namespace
	 * ============================================================== */

	/**
	 * One namespaced leaf, as a string.
	 */
	private static function val( SimpleXMLElement $el, string $name ): string {
		$kids = $el->children( self::NS );

		return isset( $kids->$name ) ? trim( (string) $kids->$name ) : '';
	}

	/**
	 * Every descendant of one name, wherever it sits in the document.
	 *
	 * @return array<int,SimpleXMLElement>
	 */
	private static function nodes( SimpleXMLElement $el, string $name ): array {
		$el->registerXPathNamespace( 'r', self::NS );

		$found = $el->xpath( './/r:' . $name );

		return false === $found ? array() : $found;
	}
}

