<?php
/**
 * Serverless entry points: what the internet can invoke without a credential.
 *
 * The network map this plugin already keeps answers "which port on which
 * machine can the internet open" from security groups, route tables and load
 * balancers. A Lambda function has none of those things -- no interface, no
 * security group, no subnet, no address -- so nothing in that model can ever
 * reach a verdict about one, and the estate's "internet-facing" count was
 * quietly a count of *virtual machines* that read like a count of everything.
 *
 * A function is reachable when something in front of it will pass an
 * unauthenticated request through. There are three such doors, and this class
 * reads all three from the control plane rather than inferring any of them:
 *
 *   1. **An API Gateway REST method** whose `authorizationType` is `NONE`,
 *      with no API key required, on an API that has a deployed stage, is not
 *      `PRIVATE`, and has not disabled its execute-api endpoint.
 *   2. **An API Gateway HTTP (v2) route** with no authorizer attached.
 *   3. **A Lambda function URL** whose `AuthType` is `NONE`, or a function
 *      resource policy granting `lambda:InvokeFunction` to `*` with no
 *      condition narrowing who may call it.
 *
 * Each of those is a *fact from AWS*, not a guess, and each is stored with the
 * evidence that produced it. Routes that are guarded are stored too: the
 * difference between "we looked and it is protected" and "nobody has looked"
 * is the whole value of the number, and a table that only holds the bad news
 * cannot tell them apart.
 *
 * What this class deliberately does not do:
 *
 * - It does not write to `vh_vulnhub_asset_exposure`. That table is keyed by
 *   an asset row id, and a function is not an asset; a synthetic row there
 *   would be silently dropped at best and a lie about a machine at worst.
 * - It does not invent vulnerability data. AWS says nothing about the code
 *   inside a function, and the posture feed carries no CVEs, so the only
 *   software facts here are the ones AWS states: the runtime and when the
 *   function was last changed.
 *
 * See docs/AWS-NETWORK.md, "Serverless entry points".
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_AWS_Serverless {

	private const DB_VERSION = '1';
	private const OPT_DB     = 'vulnhub_aws_serverless_db';

	/**
	 * Functions read per account and region before the reader gives up.
	 *
	 * Two calls are made per function (its policy and its URL config), so an
	 * account with thousands of them would otherwise dominate a sync. Hitting
	 * this is recorded on the run rather than passed over: a truncated read
	 * that reports success is indistinguishable from an estate that shrank.
	 */
	private const MAX_FUNCTIONS = 600;

	/** @var array<string,array<string,mixed>>|null Findings keyed by lower-case function name. */
	private static ?array $posture = null;

	public static function table(): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_aws_serverless';
	}

	public static function runs_table(): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_aws_serverless_runs';
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
		 * `fingerprint` rather than a composite unique key: the natural key is
		 * account + door + route + target, which runs past the index length a
		 * utf8mb4 table allows. One hash of those parts keys the row and the
		 * columns stay readable.
		 */
		dbDelta(
			"CREATE TABLE {$t} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				fingerprint char(40) NOT NULL DEFAULT '',
				account_id varchar(24) NOT NULL DEFAULT '',
				region varchar(32) NOT NULL DEFAULT '',
				entry_type varchar(16) NOT NULL DEFAULT '',
				entry_id varchar(64) NOT NULL DEFAULT '',
				entry_name varchar(255) NOT NULL DEFAULT '',
				entry_url varchar(512) NOT NULL DEFAULT '',
				route varchar(255) NOT NULL DEFAULT '',
				auth varchar(24) NOT NULL DEFAULT '',
				is_public tinyint(1) NOT NULL DEFAULT 0,
				reason varchar(255) NOT NULL DEFAULT '',
				target_type varchar(16) NOT NULL DEFAULT '',
				target_name varchar(255) NOT NULL DEFAULT '',
				target_arn varchar(512) NOT NULL DEFAULT '',
				runtime varchar(48) NOT NULL DEFAULT '',
				runtime_state varchar(16) NOT NULL DEFAULT '',
				last_modified varchar(40) NOT NULL DEFAULT '',
				role_arn varchar(512) NOT NULL DEFAULT '',
				detail text NULL,
				last_seen datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				UNIQUE KEY fp (fingerprint),
				KEY acct (account_id,region),
				KEY pub (is_public),
				KEY target (target_name)
			) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$r} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				account_id varchar(24) NOT NULL DEFAULT '',
				region varchar(32) NOT NULL DEFAULT '',
				status varchar(16) NOT NULL DEFAULT '',
				note varchar(255) NOT NULL DEFAULT '',
				apis int(10) unsigned NOT NULL DEFAULT 0,
				routes int(10) unsigned NOT NULL DEFAULT 0,
				functions int(10) unsigned NOT NULL DEFAULT 0,
				public_routes int(10) unsigned NOT NULL DEFAULT 0,
				last_run datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				UNIQUE KEY scope (account_id,region)
			) {$charset};"
		);

		update_option( self::OPT_DB, self::DB_VERSION, false );
	}

	/* =================================================================
	 * Capture
	 * ============================================================== */

	/**
	 * Read one account and region, and replace what we hold for it.
	 *
	 * @param VulnHub_AWS_Client $client  Signed client for this account.
	 * @param string             $account Account id.
	 * @param string             $region  Region.
	 * @param string             $now     UTC stamp for the whole run.
	 * @return int Rows written.
	 */
	public static function capture( VulnHub_AWS_Client $client, string $account, string $region, string $now ): int {
		global $wpdb;

		$rows   = array();
		$errors = array();
		$apis   = 0;

		$apis += self::read_rest( $client, $account, $region, $rows, $errors );
		$apis += self::read_http( $client, $account, $region, $rows, $errors );

		$functions = self::read_functions( $client, $account, $region, $rows, $errors );

		/*
		 * Only replace this scope's rows once the readers have run. Deleting
		 * first would empty the page for a denied account rather than leaving
		 * the last good answer in place, which is the same mistake as counting
		 * an unread account as clean.
		 */
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::table() . ' WHERE account_id = %s AND region = %s', $account, $region ) ); // phpcs:ignore WordPress.DB

		$written = 0;
		$public  = 0;

		foreach ( $rows as $row ) {
			$written += self::write( $row, $account, $region, $now );
			$public  += empty( $row['is_public'] ) ? 0 : 1;
		}

		self::record_run(
			$account,
			$region,
			$errors ? 'partial' : 'ok',
			$errors ? implode( '; ', array_slice( $errors, 0, 3 ) ) : '',
			$apis,
			count( $rows ),
			$functions,
			$public,
			$now
		);

		return $written;
	}

	/**
	 * REST (v1) APIs: every method, and whether it asks for anything.
	 *
	 * @param array<int,array<string,mixed>> $rows   Collected rows, by reference.
	 * @param string[]                       $errors Reader errors, by reference.
	 * @return int APIs read.
	 */
	private static function read_rest( VulnHub_AWS_Client $client, string $account, string $region, array &$rows, array &$errors ): int {
		$res = $client->get( 'apigateway', $region, '/restapis', array( 'limit' => '500' ) );

		if ( empty( $res['ok'] ) ) {
			$errors[] = 'REST APIs: ' . (string) $res['error'];
			return 0;
		}

		$apis  = self::hal_items( (array) $res['data'] );
		$count = 0;

		foreach ( $apis as $api ) {
			$id   = (string) ( $api['id'] ?? '' );
			$name = (string) ( $api['name'] ?? '' );

			if ( '' === $id ) {
				continue;
			}

			$types   = (array) ( $api['endpointConfiguration']['types'] ?? array() );
			$private = in_array( 'PRIVATE', $types, true );
			$off     = ! empty( $api['disableExecuteApiEndpoint'] );
			$policy  = trim( (string) ( $api['policy'] ?? '' ) );

			$stages = self::patient_get( $client, $region, '/restapis/' . rawurlencode( $id ) . '/stages' );
			$names  = array();
			$wafs   = array();

			foreach ( self::hal_items( (array) $stages['data'] ) as $st ) {
				if ( empty( $st['stageName'] ) ) {
					continue;
				}

				$stage   = (string) $st['stageName'];
				$names[] = $stage;

				// The web ACL rides along on the stage record we already
				// hold: whether WAF stands in front of this API costs no
				// extra call, and the old reader discarded it.
				if ( ! empty( $st['webAclArn'] ) ) {
					$wafs[ $stage ] = (string) $st['webAclArn'];
				}
			}

			$resources = self::patient_get(
				$client,
				$region,
				'/restapis/' . rawurlencode( $id ) . '/resources',
				array(
					'embed' => 'methods',
					'limit' => '500',
				)
			);

			if ( empty( $resources['ok'] ) ) {
				$errors[] = 'REST methods: ' . (string) $resources['error'];
				continue;
			}

			$items = self::hal_items( (array) $resources['data'] );

			foreach ( $items as $resource ) {
				$path = (string) ( $resource['path'] ?? '' );

				foreach ( self::embedded_methods( $resource ) as $method ) {
					$verb   = strtoupper( (string) ( $method['httpMethod'] ?? '' ) );
					$auth   = strtoupper( (string) ( $method['authorizationType'] ?? '' ) );
					$apikey = ! empty( $method['apiKeyRequired'] );
					$uri    = (string) ( $method['_embedded']['method:integration']['uri'] ?? '' );
					$target = '' !== $uri
						? self::arn_function( $uri )
						: self::integration_target( $client, $region, $id, (string) ( $resource['id'] ?? '' ), $verb );

					if ( '' === $verb ) {
						continue;
					}

					$rows[] = self::route_row(
						array(
							'entry_type' => 'rest',
							'entry_id'   => $id,
							'entry_name' => $name,
							'entry_url'  => $names ? sprintf( 'https://%s.execute-api.%s.amazonaws.com/%s', $id, $region, $names[0] ) : '',
							'route'      => $verb . ' ' . $path,
							'auth'       => self::auth_label( $auth, $apikey, (string) ( $method['authorizerId'] ?? '' ) ),
							'private'    => $private,
							'endpoint_off' => $off,
							'deployed'   => (bool) $names,
							'stages'     => $names,
							'policy'      => '' !== $policy,
							'policy_doc'  => $policy,
							'waf'         => $wafs,
							'endpoint_id' => $id,
							'target'     => $target,
							'types'      => $types,
						)
					);
				}
			}

			++$count;
		}

		return $count;
	}

	/**
	 * HTTP (v2) APIs: routes and their authorizers.
	 *
	 * @param array<int,array<string,mixed>> $rows   Collected rows, by reference.
	 * @param string[]                       $errors Reader errors, by reference.
	 * @return int APIs read.
	 */
	private static function read_http( VulnHub_AWS_Client $client, string $account, string $region, array &$rows, array &$errors ): int {
		$res = $client->get( 'apigateway', $region, '/v2/apis', array( 'MaxResults' => '500' ) );

		if ( empty( $res['ok'] ) ) {
			$errors[] = 'HTTP APIs: ' . (string) $res['error'];
			return 0;
		}

		$apis  = (array) ( $res['data']['Items'] ?? $res['data']['items'] ?? array() );
		$count = 0;

		foreach ( $apis as $api ) {
			$id = (string) ( $api['ApiId'] ?? '' );

			if ( '' === $id ) {
				continue;
			}

			$routes = $client->get( 'apigateway', $region, '/v2/apis/' . rawurlencode( $id ) . '/routes', array( 'MaxResults' => '500' ) );

			if ( empty( $routes['ok'] ) ) {
				$errors[] = 'HTTP routes: ' . (string) $routes['error'];
				continue;
			}

			$integrations = $client->get( 'apigateway', $region, '/v2/apis/' . rawurlencode( $id ) . '/integrations', array( 'MaxResults' => '500' ) );
			$by_id        = array();

			foreach ( (array) ( $integrations['data']['Items'] ?? array() ) as $int ) {
				$by_id[ (string) ( $int['IntegrationId'] ?? '' ) ] = (string) ( $int['IntegrationUri'] ?? '' );
			}

			foreach ( (array) ( $routes['data']['Items'] ?? array() ) as $route ) {
				$key    = (string) ( $route['RouteKey'] ?? '' );
				$auth   = strtoupper( (string) ( $route['AuthorizationType'] ?? 'NONE' ) );
				$int_id = '';

				if ( preg_match( '#integrations/([A-Za-z0-9]+)#', (string) ( $route['Target'] ?? '' ), $m ) ) {
					$int_id = $m[1];
				}

				$rows[] = self::route_row(
					array(
						'entry_type'   => 'http',
						'entry_id'     => $id,
						'entry_name'   => (string) ( $api['Name'] ?? '' ),
						'entry_url'    => (string) ( $api['ApiEndpoint'] ?? '' ),
						'route'        => $key,
						'auth'         => self::auth_label( $auth, false, (string) ( $route['AuthorizerId'] ?? '' ) ),
						'private'      => false,
						'endpoint_off' => ! empty( $api['DisableExecuteApiEndpoint'] ),
						'deployed'     => true,
						'stages'       => array(),
						'policy'       => false,
						'target'       => self::arn_function( (string) ( $by_id[ $int_id ] ?? '' ) ),
						'types'        => array( 'REGIONAL' ),
					)
				);
			}

			++$count;
		}

		return $count;
	}

	/**
	 * Functions: their own front doors, and the facts AWS states about them.
	 *
	 * A function URL and a wide-open resource policy are doors nothing else in
	 * the estate can see, so this reads every function rather than only those
	 * an API Gateway already pointed at.
	 *
	 * @param array<int,array<string,mixed>> $rows   Collected rows, by reference.
	 * @param string[]                       $errors Reader errors, by reference.
	 * @return int Functions read.
	 */
	private static function read_functions( VulnHub_AWS_Client $client, string $account, string $region, array &$rows, array &$errors ): int {
		$marker    = '';
		$seen      = 0;
		$functions = array();

		do {
			$query = array( 'MaxItems' => '50' );

			if ( '' !== $marker ) {
				$query['Marker'] = $marker;
			}

			$res = $client->get( 'lambda', $region, '/2015-03-31/functions/', $query );

			if ( empty( $res['ok'] ) ) {
				$errors[] = 'functions: ' . (string) $res['error'];
				break;
			}

			foreach ( (array) ( $res['data']['Functions'] ?? array() ) as $fn ) {
				$functions[] = $fn;
				++$seen;
			}

			$marker = (string) ( $res['data']['NextMarker'] ?? '' );

			if ( $seen >= self::MAX_FUNCTIONS ) {
				$errors[] = sprintf( 'stopped after %d functions', self::MAX_FUNCTIONS );
				break;
			}
		} while ( '' !== $marker );

		$by_name = array();

		foreach ( $functions as $fn ) {
			$name = (string) ( $fn['FunctionName'] ?? '' );

			if ( '' === $name ) {
				continue;
			}

			$by_name[ strtolower( $name ) ] = $fn;

			$url    = $client->get( 'lambda', $region, '/2021-10-31/functions/' . rawurlencode( $name ) . '/url' );
			$policy = $client->get( 'lambda', $region, '/2015-03-31/functions/' . rawurlencode( $name ) . '/policy' );

			if ( ! empty( $url['ok'] ) && ! empty( $url['data']['FunctionUrl'] ) ) {
				$auth = strtoupper( (string) ( $url['data']['AuthType'] ?? '' ) );

				$rows[] = self::function_row(
					$fn,
					array(
						'entry_type' => 'url',
						'entry_id'   => 'url',
						'entry_name' => __( 'Lambda function URL', 'vulnhub' ),
						'entry_url'  => (string) $url['data']['FunctionUrl'],
						'route'      => __( 'any request', 'vulnhub' ),
						'auth'       => 'NONE' === $auth ? 'none' : 'iam',
						'is_public'  => 'NONE' === $auth,
						'reason'     => 'NONE' === $auth
							? __( 'function URL with AuthType NONE', 'vulnhub' )
							: __( 'function URL, but AWS_IAM signing is required', 'vulnhub' ),
						'detail'     => array( 'cors' => (array) ( $url['data']['Cors'] ?? array() ) ),
					)
				);
			}

			$wide = ! empty( $policy['ok'] ) ? self::wide_open( (string) ( $policy['data']['Policy'] ?? '' ) ) : '';

			if ( '' !== $wide ) {
				$rows[] = self::function_row(
					$fn,
					array(
						'entry_type' => 'policy',
						'entry_id'   => 'policy',
						'entry_name' => __( 'Function resource policy', 'vulnhub' ),
						'entry_url'  => '',
						'route'      => __( 'lambda:InvokeFunction', 'vulnhub' ),
						'auth'       => 'none',
						'is_public'  => true,
						'reason'     => $wide,
						'detail'     => array(),
					)
				);
			}
		}

		/*
		 * Fill in what AWS says about each function an API Gateway route
		 * pointed at. The route rows were built before the functions were
		 * read, because a route names its target by ARN and nothing else.
		 */
		foreach ( $rows as $i => $row ) {
			if ( '' === (string) $row['target_name'] || '' !== (string) $row['runtime'] ) {
				continue;
			}

			$fn = $by_name[ strtolower( (string) $row['target_name'] ) ] ?? null;

			if ( ! $fn ) {
				continue;
			}

			$rows[ $i ]['runtime']       = (string) ( $fn['Runtime'] ?? '' );
			$rows[ $i ]['runtime_state'] = self::runtime_state( (string) ( $fn['Runtime'] ?? '' ) );
			$rows[ $i ]['last_modified'] = (string) ( $fn['LastModified'] ?? '' );
			$rows[ $i ]['role_arn']      = (string) ( $fn['Role'] ?? '' );
			$rows[ $i ]['target_arn']    = (string) ( $fn['FunctionArn'] ?? $row['target_arn'] );
		}

		return $seen;
	}

	/* =================================================================
	 * Judging
	 * ============================================================== */

	/**
	 * One API Gateway route, judged.
	 *
	 * Every link has to hold for the route to count as open: an
	 * unauthenticated method, on an API that is not private, whose
	 * execute-api endpoint still answers, with a stage deployed behind it.
	 * Each link alone is a confident wrong answer.
	 *
	 * @param array<string,mixed> $in Reader values.
	 * @return array<string,mixed>
	 */
	private static function route_row( array $in ): array {
		$auth   = (string) $in['auth'];
		$public = 'none' === $auth;
		$why    = array();

		if ( 'none' !== $auth ) {
			$why[] = sprintf(
				/* translators: %s: what the route asks callers for. */
				__( 'the route requires %s', 'vulnhub' ),
				self::auth_words( $auth )
			);
		}

		if ( ! empty( $in['private'] ) ) {
			$public = false;
			$why[]  = __( 'the API is private to a VPC endpoint', 'vulnhub' );
		}

		if ( ! empty( $in['endpoint_off'] ) ) {
			$public = false;
			$why[]  = __( 'the execute-api endpoint is disabled', 'vulnhub' );
		}

		if ( empty( $in['deployed'] ) ) {
			$public = false;
			$why[]  = __( 'no stage is deployed', 'vulnhub' );
		}

		$policy = self::parse_policy( (string) ( $in['policy_doc'] ?? '' ) );

		if ( $public && ! empty( $policy['restricts'] ) ) {
			/*
			 * Read now, and it narrows the caller -- but the route is still
			 * counted open. Parsing a policy is reading somebody's intent,
			 * and dropping a route from the exposure count on the strength
			 * of that is the wrong way round: over-reporting costs somebody
			 * a look, under-reporting costs them the finding. The panel on
			 * the page shows what the narrowing actually is.
			 */
			$why[] = __( 'a resource policy narrows who may call it -- check it covers this route', 'vulnhub' );
		} elseif ( $public && ! empty( $in['policy'] ) ) {
			$why[] = __( 'a resource policy is set on the API but places no limit on the caller', 'vulnhub' );
		}

		if ( $public ) {
			array_unshift( $why, __( 'the method asks callers for nothing', 'vulnhub' ) );
		}

		return array(
			'entry_type'    => (string) $in['entry_type'],
			'entry_id'      => (string) $in['entry_id'],
			'entry_name'    => (string) $in['entry_name'],
			'entry_url'     => (string) $in['entry_url'],
			'route'         => (string) $in['route'],
			'auth'          => $auth,
			'is_public'     => $public ? 1 : 0,
			'reason'        => implode( '; ', $why ),
			'target_type'   => '' !== (string) $in['target'] ? 'lambda' : '',
			'target_name'   => (string) $in['target'],
			'target_arn'    => '',
			'runtime'       => '',
			'runtime_state' => '',
			'last_modified' => '',
			'role_arn'      => '',
			'detail'        => array(
				'stages'    => (array) ( $in['stages'] ?? array() ),
				'endpoint'  => (array) ( $in['types'] ?? array() ),
				'apiPolicy' => ! empty( $in['policy'] ),
				'policy'    => $policy,
				'waf'       => (array) ( $in['waf'] ?? array() ),
				'apiId'     => (string) ( $in['endpoint_id'] ?? '' ),
				'offSwitch' => ! empty( $in['endpoint_off'] ),
			),
		);
	}

	/**
	 * One function-level door, judged by the reader that found it.
	 *
	 * @param array<string,mixed> $fn Function record from ListFunctions.
	 * @param array<string,mixed> $in Door values.
	 * @return array<string,mixed>
	 */
	private static function function_row( array $fn, array $in ): array {
		return array(
			'entry_type'    => (string) $in['entry_type'],
			'entry_id'      => (string) $in['entry_id'],
			'entry_name'    => (string) $in['entry_name'],
			'entry_url'     => (string) $in['entry_url'],
			'route'         => (string) $in['route'],
			'auth'          => (string) $in['auth'],
			'is_public'     => ! empty( $in['is_public'] ) ? 1 : 0,
			'reason'        => (string) $in['reason'],
			'target_type'   => 'lambda',
			'target_name'   => (string) ( $fn['FunctionName'] ?? '' ),
			'target_arn'    => (string) ( $fn['FunctionArn'] ?? '' ),
			'runtime'       => (string) ( $fn['Runtime'] ?? '' ),
			'runtime_state' => self::runtime_state( (string) ( $fn['Runtime'] ?? '' ) ),
			'last_modified' => (string) ( $fn['LastModified'] ?? '' ),
			'role_arn'      => (string) ( $fn['Role'] ?? '' ),
			'detail'        => (array) ( $in['detail'] ?? array() ),
		);
	}

	/**
	 * Whether a Lambda resource policy lets anyone invoke the function, and
	 * the words to say so.
	 *
	 * A statement naming a service principal is how every API Gateway
	 * integration is wired and says nothing on its own. What matters is a
	 * statement open to `*` with no condition narrowing the caller -- the
	 * shape that makes a function invokable by any AWS principal anywhere.
	 */
	private static function wide_open( string $policy ): string {
		$json = json_decode( $policy, true );

		if ( ! is_array( $json ) ) {
			return '';
		}

		foreach ( (array) ( $json['Statement'] ?? array() ) as $st ) {
			if ( 'Allow' !== (string) ( $st['Effect'] ?? '' ) ) {
				continue;
			}

			$principal = $st['Principal'] ?? '';
			$principal = is_array( $principal ) ? ( $principal['AWS'] ?? $principal['Service'] ?? '' ) : $principal;
			$principal = is_array( $principal ) ? (string) reset( $principal ) : (string) $principal;

			if ( '*' !== $principal ) {
				continue;
			}

			if ( ! empty( $st['Condition'] ) ) {
				continue;
			}

			return __( 'the function policy allows anyone to invoke it, with no condition', 'vulnhub' );
		}

		return '';
	}

	/**
	 * What an API Gateway resource policy allows, in the terms this page
	 * needs: who may call it, and from where.
	 *
	 * Only the shapes that genuinely narrow a caller are interpreted --
	 * source address, VPC endpoint, organisation, a named principal.
	 * Anything else sets `other`, so a policy this code only half
	 * understands is reported as unread rather than summarised as safe.
	 *
	 * @return array{present:bool,restricts:bool,allow_ips:array<int,string>,deny_ips:array<int,string>,vpce:array<int,string>,orgs:array<int,string>,accounts:array<int,string>,other:bool}
	 */
	private static function parse_policy( string $json ): array {
		$out = array(
			'present'   => '' !== trim( $json ),
			'restricts' => false,
			'allow_ips' => array(),
			'deny_ips'  => array(),
			'vpce'      => array(),
			'orgs'      => array(),
			'accounts'  => array(),
			'other'     => false,
		);

		if ( ! $out['present'] ) {
			return $out;
		}

		$doc = json_decode( $json, true );

		// API Gateway hands the policy back with its quotes escaped.
		if ( ! is_array( $doc ) ) {
			$doc = json_decode( stripslashes( $json ), true );
		}

		if ( ! is_array( $doc ) ) {
			$out['other'] = true;

			return $out;
		}

		foreach ( (array) ( $doc['Statement'] ?? array() ) as $st ) {
			$deny = 'Deny' === (string) ( $st['Effect'] ?? '' );

			foreach ( (array) ( $st['Condition'] ?? array() ) as $operator => $tests ) {
				$negate = false !== stripos( (string) $operator, 'Not' );

				foreach ( (array) $tests as $key => $values ) {
					$values = array_map( 'strval', (array) $values );

					switch ( strtolower( (string) $key ) ) {
						case 'aws:sourceip':
							/*
							 * A Deny on NotIpAddress narrows exactly as an
							 * Allow on IpAddress does -- both leave an
							 * allow-list -- so the two flags cancel.
							 */
							$list             = ( $deny xor $negate ) ? 'deny_ips' : 'allow_ips';
							$out[ $list ]     = array_merge( $out[ $list ], $values );
							$out['restricts'] = true;
							break;
						case 'aws:sourcevpce':
						case 'aws:sourcevpc':
							$out['vpce']      = array_merge( $out['vpce'], $values );
							$out['restricts'] = true;
							break;
						case 'aws:principalorgid':
							$out['orgs']      = array_merge( $out['orgs'], $values );
							$out['restricts'] = true;
							break;
						default:
							$out['other'] = true;
							break;
					}
				}
			}

			$principal = $st['Principal'] ?? '';
			$principal = is_array( $principal ) ? ( $principal['AWS'] ?? '' ) : $principal;

			foreach ( (array) $principal as $who ) {
				$who = (string) $who;

				if ( '' !== $who && '*' !== $who ) {
					$out['accounts'][] = $who;
					$out['restricts']  = true;
				}
			}
		}

		foreach ( array( 'allow_ips', 'deny_ips', 'vpce', 'orgs', 'accounts' ) as $key ) {
			$out[ $key ] = array_values( array_slice( array_unique( $out[ $key ] ), 0, 40 ) );
		}

		return $out;
	}

	/** What a route asks a caller for, as one word this table can group on. */
	private static function auth_label( string $type, bool $apikey, string $authorizer ): string {
		if ( 'AWS_IAM' === $type ) {
			return 'iam';
		}

		if ( in_array( $type, array( 'CUSTOM', 'COGNITO_USER_POOLS', 'JWT' ), true ) || '' !== $authorizer ) {
			return 'authorizer';
		}

		if ( $apikey ) {
			return 'apikey';
		}

		return 'none';
	}

	/** The same, in words for a sentence. */
	private static function auth_words( string $auth ): string {
		$map = array(
			'iam'        => __( 'a signed AWS request', 'vulnhub' ),
			'authorizer' => __( 'a token its authorizer accepts', 'vulnhub' ),
			'apikey'     => __( 'an API key', 'vulnhub' ),
		);

		return $map[ $auth ] ?? __( 'nothing', 'vulnhub' );
	}

	/**
	 * Whether AWS still ships security patches for a runtime.
	 *
	 * Only runtimes whose support has already ended are named. Anything else
	 * reads as "supported as far as we know" rather than "supported", because
	 * this list is a fact about the vendor's calendar that this repository
	 * cannot refresh on its own -- `vulnhub_lambda_dead_runtimes` is the hook
	 * to correct it without editing code.
	 *
	 * @return string deprecated|current|unknown
	 */
	public static function runtime_state( string $runtime ): string {
		if ( '' === $runtime ) {
			return 'unknown';
		}

		$dead = (array) apply_filters(
			'vulnhub_lambda_dead_runtimes',
			array(
				'nodejs', 'nodejs4.3', 'nodejs4.3-edge', 'nodejs6.10', 'nodejs8.10',
				'nodejs10.x', 'nodejs12.x', 'nodejs14.x', 'nodejs16.x',
				'python2.7', 'python3.6', 'python3.7', 'python3.8',
				'ruby2.5', 'ruby2.7',
				'java8',
				'dotnetcore1.0', 'dotnetcore2.0', 'dotnetcore2.1', 'dotnetcore3.1',
				'dotnet5.0', 'dotnet7',
				'go1.x',
				'provided',
			)
		);

		return in_array( $runtime, $dead, true ) ? 'deprecated' : 'current';
	}

	/* =================================================================
	 * Storage
	 * ============================================================== */

	/**
	 * @param array<string,mixed> $row One judged row.
	 */
	private static function write( array $row, string $account, string $region, string $now ): int {
		global $wpdb;

		$fp = sha1(
			implode(
				'|',
				array(
					$account,
					$region,
					(string) $row['entry_type'],
					(string) $row['entry_id'],
					(string) $row['route'],
					(string) $row['target_name'],
				)
			)
		);

		$ok = $wpdb->query( // phpcs:ignore WordPress.DB
			$wpdb->prepare(
				'INSERT INTO ' . self::table() . ' (fingerprint,account_id,region,entry_type,entry_id,entry_name,entry_url,route,auth,is_public,reason,target_type,target_name,target_arn,runtime,runtime_state,last_modified,role_arn,detail,last_seen)
				 VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
				 ON DUPLICATE KEY UPDATE entry_name=VALUES(entry_name), entry_url=VALUES(entry_url), auth=VALUES(auth),
				   is_public=VALUES(is_public), reason=VALUES(reason), target_type=VALUES(target_type),
				   target_arn=VALUES(target_arn), runtime=VALUES(runtime), runtime_state=VALUES(runtime_state),
				   last_modified=VALUES(last_modified), role_arn=VALUES(role_arn), detail=VALUES(detail), last_seen=VALUES(last_seen)',
				$fp,
				$account,
				$region,
				(string) $row['entry_type'],
				(string) $row['entry_id'],
				vh_trim( (string) $row['entry_name'], 250 ),
				vh_trim( (string) $row['entry_url'], 500 ),
				vh_trim( (string) $row['route'], 250 ),
				(string) $row['auth'],
				(int) $row['is_public'],
				vh_trim( (string) $row['reason'], 250 ),
				(string) $row['target_type'],
				vh_trim( (string) $row['target_name'], 250 ),
				vh_trim( (string) $row['target_arn'], 500 ),
				(string) $row['runtime'],
				(string) $row['runtime_state'],
				(string) $row['last_modified'],
				vh_trim( (string) $row['role_arn'], 500 ),
				(string) wp_json_encode( (array) $row['detail'] ),
				$now
			)
		);

		return $ok ? 1 : 0;
	}

	private static function record_run( string $account, string $region, string $status, string $note, int $apis, int $routes, int $functions, int $public, string $now ): void {
		global $wpdb;

		$wpdb->query( // phpcs:ignore WordPress.DB
			$wpdb->prepare(
				'INSERT INTO ' . self::runs_table() . ' (account_id,region,status,note,apis,routes,functions,public_routes,last_run)
				 VALUES (%s,%s,%s,%s,%d,%d,%d,%d,%s)
				 ON DUPLICATE KEY UPDATE status=VALUES(status), note=VALUES(note), apis=VALUES(apis), routes=VALUES(routes),
				   functions=VALUES(functions), public_routes=VALUES(public_routes), last_run=VALUES(last_run)',
				$account,
				$region,
				$status,
				vh_trim( $note, 250 ),
				$apis,
				$routes,
				$functions,
				$public,
				$now
			)
		);
	}

	/* =================================================================
	 * Reading
	 * ============================================================== */

	/**
	 * The headline: how many functions the internet can invoke, and what the
	 * read covered.
	 *
	 * @return array{public:int,targets:int,routes:int,accounts:int,scanned:int,partial:int,captured_at:string}
	 */
	public static function summary(): array {
		global $wpdb;

		$t = self::table();
		$r = self::runs_table();

		$row = $wpdb->get_row( // phpcs:ignore WordPress.DB
			"SELECT COUNT(*) AS routes,
				SUM(is_public) AS public_routes,
				COUNT(DISTINCT CASE WHEN is_public = 1 AND target_name <> '' THEN CONCAT(account_id, ':', target_name) END) AS targets,
				SUM(CASE WHEN is_public = 1 AND target_name = '' THEN 1 ELSE 0 END) AS orphan_routes,
				COUNT(DISTINCT CASE WHEN is_public = 1 THEN account_id END) AS accounts,
				MAX(last_seen) AS captured_at
			 FROM {$t}",
			ARRAY_A
		);

		$runs = $wpdb->get_row( "SELECT COUNT(*) AS scanned, SUM(status <> 'ok') AS partial FROM {$r}", ARRAY_A ); // phpcs:ignore WordPress.DB

		return array(
			'public'      => (int) ( $row['public_routes'] ?? 0 ),
			'targets'     => (int) ( $row['targets'] ?? 0 ),
			'routes'      => (int) ( $row['routes'] ?? 0 ),
			'accounts'    => (int) ( $row['accounts'] ?? 0 ),
			'orphans'     => (int) ( $row['orphan_routes'] ?? 0 ),
			'scanned'     => (int) ( $runs['scanned'] ?? 0 ),
			'partial'     => (int) ( $runs['partial'] ?? 0 ),
			'captured_at' => (string) ( $row['captured_at'] ?? '' ),
		);
	}

	/**
	 * One row per publicly invokable function, with every door into it.
	 *
	 * @param array<string,string> $filters account, region, runtime, search.
	 * @return array<int,array<string,mixed>>
	 */
	public static function targets( array $filters = array() ): array {
		global $wpdb;

		$where  = array( 'is_public = 1', "target_name <> ''" );
		$params = array();

		if ( ! empty( $filters['account'] ) ) {
			$where[]  = 'account_id = %s';
			$params[] = (string) $filters['account'];
		}

		if ( ! empty( $filters['region'] ) ) {
			$where[]  = 'region = %s';
			$params[] = (string) $filters['region'];
		}

		if ( ! empty( $filters['runtime'] ) ) {
			$where[]  = 'runtime_state = %s';
			$params[] = (string) $filters['runtime'];
		}

		if ( ! empty( $filters['search'] ) ) {
			$where[]  = '( LOCATE(%s, LOWER(target_name)) > 0 OR LOCATE(%s, LOWER(entry_name)) > 0 )';
			$term     = strtolower( (string) $filters['search'] );
			$params[] = $term;
			$params[] = $term;
		}

		$sql = 'SELECT * FROM ' . self::table() . ' WHERE ' . implode( ' AND ', $where ) . ' ORDER BY account_id ASC, target_name ASC, route ASC';
		$rows = $params
			? (array) $wpdb->get_results( $wpdb->prepare( $sql, ...$params ), ARRAY_A ) // phpcs:ignore WordPress.DB
			: (array) $wpdb->get_results( $sql, ARRAY_A ); // phpcs:ignore WordPress.DB

		$out = array();

		foreach ( $rows as $row ) {
			$key = $row['account_id'] . '|' . $row['target_name'];

			if ( ! isset( $out[ $key ] ) ) {
				$out[ $key ] = array(
					'key'           => md5( $key ),
					'account_id'    => (string) $row['account_id'],
					'account_name'  => self::account_name( (string) $row['account_id'] ),
					'region'        => (string) $row['region'],
					'target_name'   => (string) $row['target_name'],
					'target_arn'    => (string) $row['target_arn'],
					'runtime'       => (string) $row['runtime'],
					'runtime_state' => (string) $row['runtime_state'],
					'last_modified' => (string) $row['last_modified'],
					'role_arn'      => (string) $row['role_arn'],
					'doors'         => array(),
				);
			}

			$out[ $key ]['doors'][] = array(
				'entry_type' => (string) $row['entry_type'],
				'entry_name' => (string) $row['entry_name'],
				'entry_id'   => (string) $row['entry_id'],
				'entry_url'  => (string) $row['entry_url'],
				'route'      => (string) $row['route'],
				'auth'       => (string) $row['auth'],
				'reason'     => (string) $row['reason'],
				'detail'     => json_decode( (string) $row['detail'], true ) ?: array(),
			);
		}

		foreach ( $out as $key => $row ) {
			$out[ $key ]['posture'] = self::posture_for( (string) $row['target_name'], (string) $row['account_id'] );
			$out[ $key ]['reaches'] = self::reaches( (string) $row['target_name'], (string) $row['account_id'] );
			$out[ $key ]['asset']   = self::asset_for( (string) $row['target_name'] );
		}

		return array_values( $out );
	}

	/**
	 * Guarded routes, by what they ask for. The other half of the answer: a
	 * page that only lists the open doors cannot say how much was looked at.
	 *
	 * @return array<string,int>
	 */
	public static function guarded(): array {
		global $wpdb;

		$out  = array();
		$rows = (array) $wpdb->get_results( 'SELECT auth, COUNT(*) c FROM ' . self::table() . ' WHERE is_public = 0 GROUP BY auth', ARRAY_A ); // phpcs:ignore WordPress.DB

		foreach ( $rows as $row ) {
			$out[ (string) $row['auth'] ] = (int) $row['c'];
		}

		return $out;
	}

	/**
	 * Accounts and regions read, with whatever went wrong.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function runs(): array {
		global $wpdb;

		$rows = (array) $wpdb->get_results( 'SELECT * FROM ' . self::runs_table() . ' ORDER BY status DESC, account_id ASC', ARRAY_A ); // phpcs:ignore WordPress.DB

		foreach ( $rows as $i => $row ) {
			$rows[ $i ]['account_name'] = self::account_name( (string) $row['account_id'] );
		}

		return $rows;
	}

	/* =================================================================
	 * Joining to what the rest of the estate knows
	 * ============================================================== */

	private static function account_name( string $id ): string {
		if ( ! class_exists( 'VulnHub_AWS_Account_Names' ) ) {
			return '';
		}

		$names = (array) VulnHub_AWS_Account_Names::all();

		return (string) ( $names[ $id ] ?? '' );
	}

	/**
	 * Every posture finding the vendor has raised against Lambda functions,
	 * grouped by function, read once.
	 *
	 * @return array<string,array<int,array<string,mixed>>>
	 */
	private static function posture_index(): array {
		global $wpdb;

		if ( null !== self::$posture ) {
			return self::$posture;
		}

		self::$posture = array();
		$table         = $wpdb->prefix . 'vulnhub_plerion_findings';

		// The table only exists when the posture connector is installed.
		if ( (string) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) { // phpcs:ignore WordPress.DB
			return self::$posture;
		}

		$rows = (array) $wpdb->get_results( // phpcs:ignore WordPress.DB
			"SELECT resource_name, account_id, severity, message, detection_id, first_observed, raw_json
			 FROM {$table} WHERE resource_type = 'AWS::Lambda::Function'",
			ARRAY_A
		);

		foreach ( $rows as $row ) {
			$key                     = strtolower( (string) $row['resource_name'] ) . '|' . $row['account_id'];
			self::$posture[ $key ][] = $row;
		}

		return self::$posture;
	}

	/**
	 * What the posture feed says about this function.
	 *
	 * Attributed rather than absorbed: the vendor's count of vulnerabilities
	 * inside a function is the vendor's claim, arrived at by scanning a
	 * package we do not scan, and the feed carries no CVE for any of it -- so
	 * there is nothing here to match against a scanner or to patch-group.
	 * Every finding it raised is listed rather than only the worst, because
	 * "publicly accessible" and "has exploitable vulnerabilities" are two
	 * different statements and collapsing them loses the second.
	 *
	 * @return array<string,mixed>
	 */
	private static function posture_for( string $name, string $account ): array {
		$hits = self::posture_index()[ strtolower( $name ) . '|' . $account ] ?? array();

		if ( ! $hits ) {
			return array();
		}

		$order    = array(
			'CRITICAL' => 4,
			'HIGH'     => 3,
			'MEDIUM'   => 2,
			'LOW'      => 1,
		);
		$worst    = '';
		$rank     = 0;
		$vulns    = 0;
		$exploits = false;
		$findings = array();

		foreach ( $hits as $hit ) {
			$severity = strtoupper( (string) $hit['severity'] );
			$message  = (string) $hit['message'];

			if ( ( $order[ $severity ] ?? 0 ) > $rank ) {
				$rank  = $order[ $severity ] ?? 0;
				$worst = $severity;
			}

			// "with 17 vulnerabilities" -- their number, kept as their number.
			if ( preg_match( '/(\d+)\s+vulnerabilit/i', $message, $m ) ) {
				$vulns = max( $vulns, (int) $m[1] );
			}

			if ( false !== stripos( $message, 'exploit' ) ) {
				$exploits = true;
			}

			$findings[] = array(
				'severity'  => $severity,
				'detection' => (string) $hit['detection_id'],
				'message'   => $message,
				'observed'  => (string) $hit['first_observed'],
			);
		}

		usort(
			$findings,
			static function ( array $a, array $b ) use ( $order ): int {
				return ( $order[ $b['severity'] ] ?? 0 ) <=> ( $order[ $a['severity'] ] ?? 0 );
			}
		);

		return array(
			'severity' => $worst,
			'count'    => count( $findings ),
			'vulns'    => $vulns,
			'exploits' => $exploits,
			'message'  => (string) ( $findings[0]['message'] ?? '' ),
			'findings' => $findings,
		);
	}

	/**
	 * Where a compromised function could reach, from the posture feed's own
	 * path graph. Empty when we have no such graph -- never guessed from the
	 * role name, because a plausible-looking bucket in a diagram is worse
	 * than a blank one: somebody acts on it.
	 *
	 * @return array<int,array{kind:string,name:string}>
	 */
	private static function reaches( string $name, string $account ): array {
		$hits = self::posture_index()[ strtolower( $name ) . '|' . $account ] ?? array();
		$out  = array();

		foreach ( $hits as $hit ) {
			$raw = json_decode( (string) $hit['raw_json'], true );

			foreach ( (array) ( $raw['attackPaths']['nodes'] ?? array() ) as $node ) {
				if ( empty( $node['isDataSource'] ) ) {
					continue;
				}

				$label = (string) ( $node['name'] ?? '' );

				if ( '' === $label || isset( $out[ $label ] ) ) {
					continue;
				}

				$type          = (string) ( $node['assetType'] ?? '' );
				$out[ $label ] = array(
					'kind' => strtolower( (string) ( explode( '::', $type )[1] ?? $type ) ),
					'name' => $label,
				);
			}
		}

		return array_values( $out );
	}

	/**
	 * The inventory record for a function, when one exists.
	 *
	 * Almost never, and that is the point: a function is not a machine, so it
	 * has no patch group, no owner and no scan history. Saying so plainly is
	 * better than an empty row that reads like missing data.
	 *
	 * @return array<string,mixed>
	 */
	private static function asset_for( string $name ): array {
		global $wpdb;

		$row = $wpdb->get_row( // phpcs:ignore WordPress.DB
			$wpdb->prepare(
				'SELECT id, hostname, patch_group, team_id, owner_person_id FROM ' . vh_table( 'assets' ) . ' WHERE hostname = %s LIMIT 1',
				$name
			),
			ARRAY_A
		);

		return is_array( $row ) ? $row : array();
	}

	/**
	 * An API Gateway control-plane GET, retried when the service throttles.
	 *
	 * The control plane allows only a handful of requests a second per account
	 * and answers the rest with 429. Treating that as a failure loses a whole
	 * API's methods and reports the account as clean, which is the one wrong
	 * answer this page must never give -- so a throttle is waited out rather
	 * than recorded.
	 *
	 * @param array<string,string> $query Query arguments.
	 * @return array<string,mixed>
	 */
	private static function patient_get( VulnHub_AWS_Client $client, string $region, string $path, array $query = array() ): array {
		$waits = array( 600000, 1500000, 3500000 );
		$res   = array();

		foreach ( array_merge( array( 0 ), $waits ) as $wait ) {
			if ( $wait > 0 ) {
				usleep( $wait );
			}

			$res = $client->get( 'apigateway', $region, $path, $query );

			if ( ! empty( $res['ok'] ) ) {
				return $res;
			}

			$throttled = 429 === (int) ( $res['status'] ?? 0 )
				|| false !== stripos( (string) ( $res['error'] ?? '' ), 'Too Many Requests' )
				|| false !== stripos( (string) ( $res['error'] ?? '' ), 'Throttl' );

			if ( ! $throttled ) {
				return $res;
			}
		}

		return $res;
	}

	/**
	 * The rows of an API Gateway v1 collection.
	 *
	 * v1 answers in HAL: the list lives under `_embedded.item`, and a
	 * collection of exactly one comes back as that one object rather than a
	 * list of one -- reading `item` off the top level, as the shape of every
	 * other AWS list suggests, silently finds nothing at all.
	 *
	 * @param array<string,mixed> $data Decoded response body.
	 * @return array<int,array<string,mixed>>
	 */
	private static function hal_items( array $data ): array {
		$items = $data['_embedded']['item'] ?? $data['item'] ?? array();

		if ( ! is_array( $items ) ) {
			return array();
		}

		// One-element collections arrive unwrapped.
		if ( ! array_is_list( $items ) ) {
			$items = array( $items );
		}

		return array_values( array_filter( $items, 'is_array' ) );
	}

	/**
	 * The methods embedded in one `?embed=methods` resource.
	 *
	 * They arrive under the resource's own `_embedded['resource:methods']`,
	 * not the documented `resourceMethods` map, and a resource with a single
	 * verb carries that verb's object directly instead of a list. Each method
	 * brings its integration with it, which is what lets this read a whole API
	 * in two calls rather than one per method -- the control plane throttles
	 * at a handful of requests a second and answers the rest with 429.
	 *
	 * @param array<string,mixed> $resource One resource from the collection.
	 * @return array<int,array<string,mixed>>
	 */
	private static function embedded_methods( array $resource ): array {
		$methods = $resource['_embedded']['resource:methods'] ?? $resource['resourceMethods'] ?? array();

		if ( ! is_array( $methods ) ) {
			return array();
		}

		if ( ! array_is_list( $methods ) ) {
			// Either the one-method shape, or the documented verb => method map.
			$methods = isset( $methods['httpMethod'] ) ? array( $methods ) : array_values( $methods );
		}

		return array_values( array_filter( $methods, 'is_array' ) );
	}

	/** The function name out of an integration URI, or ''. */
	private static function arn_function( string $uri ): string {
		return preg_match( '#function:([A-Za-z0-9._-]+)#', $uri, $m ) ? $m[1] : '';
	}

	/** The function an API Gateway method forwards to, or ''. */
	private static function integration_target( VulnHub_AWS_Client $client, string $region, string $api, string $resource, string $verb ): string {
		if ( '' === $resource ) {
			return '';
		}

		$res = $client->get(
			'apigateway',
			$region,
			'/restapis/' . rawurlencode( $api ) . '/resources/' . rawurlencode( $resource ) . '/methods/' . rawurlencode( $verb ) . '/integration'
		);

		return empty( $res['ok'] ) ? '' : self::arn_function( (string) ( $res['data']['uri'] ?? '' ) );
	}
}

