<?php
/**
 * Jira Service Management Assets (Insight) object client — read only.
 *
 * One endpoint does everything this connector needs, the AQL object search:
 *
 *   POST https://api.atlassian.com/ex/jira/{cloudId}
 *          /jsm/assets/workspace/{workspaceId}/v1/object/aql
 *        ?startAt={n}&maxResults=50&includeAttributes=true
 *   Authorization: Basic base64(email:api-token)
 *   Body: {"qlQuery": "objectSchemaId = 6 AND objectType IN (\"Servers\", …)"}
 *
 * The response carries `values[]` (the objects), `total`, `startAt`,
 * `maxResults` and `isLast`. **`maxResults` is capped server-side at 50**, so
 * the ~1,200 objects in a real workspace always arrive over ~24 pages and
 * pagination is not optional.
 *
 * Two deliberate choices, both about honesty:
 *
 * 1. `includeAttributes=true` is never dropped. A token missing
 *    `read:cmdb-attribute:jira` makes the very same call fail 401 even though
 *    the object scopes are present, and the tempting "fix" — retry without
 *    attributes — would succeed and import ~1,200 objects with nothing on them
 *    but a label. An empty CMDB that reports success is worse than a failure,
 *    so the 401 is surfaced with the scope list instead.
 *
 * 2. Nothing here writes. There is no PUT, PATCH or DELETE, and the only POST
 *    is this search — Assets exposes object search as a POST because AQL is a
 *    body, not because it mutates anything. The operator's token is scoped to
 *    the five `read:cmdb-*` scopes, so a write would fail anyway; not having
 *    the code path is the stronger guarantee.
 *
 * The API token is only ever placed in the Authorization header. It is never
 * put in a URL, never logged, and never returned to a caller.
 *
 * @package VulnHub\Cmdb
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Thin, read-only wrapper over the Assets AQL object search.
 */
final class VulnHub_Cmdb_Assets_Client {

	/** Atlassian's gateway host for cloud-id addressed product APIs. */
	private const API_HOST = 'https://api.atlassian.com';

	/**
	 * Page size. The API silently clamps anything larger to 50, and asking for
	 * more would make the runaway guard below compute the wrong page count.
	 */
	public const PAGE_SIZE = 50;

	/**
	 * Absolute ceiling on pages, whatever `total` claims. 400 pages is 20,000
	 * objects — an order of magnitude more than the workspace holds — so this
	 * only ever fires when the API stops advancing.
	 */
	private const HARD_MAX_PAGES = 400;

	/** Seconds allowed per request. Assets pages are small; 30s is generous. */
	private const TIMEOUT = 30;

	/**
	 * Atlassian account email, the Basic auth user name.
	 */
	private string $email;

	/**
	 * Scoped API token, the Basic auth password. Never logged.
	 */
	private string $token;

	/**
	 * Atlassian cloud id for the site.
	 */
	private string $cloud_id;

	/**
	 * Assets workspace id.
	 */
	private string $workspace_id;

	/**
	 * Shared HTTP client — it already retries 429 and 5xx with exponential
	 * backoff and honours Retry-After, which is exactly what §5 of the brief
	 * asks for, so this client does not reimplement it.
	 */
	private \VulnHub\Core\Http $http;

	/**
	 * Run logger.
	 *
	 * @var callable
	 */
	private $log;

	/**
	 * @param string             $email        Atlassian account email.
	 * @param string             $token        Scoped API token.
	 * @param string             $cloud_id     Site cloud id.
	 * @param string             $workspace_id Assets workspace id.
	 * @param \VulnHub\Core\Http $http         Shared HTTP client.
	 * @param callable|null      $log          Logger callback.
	 */
	public function __construct(
		string $email,
		string $token,
		string $cloud_id,
		string $workspace_id,
		\VulnHub\Core\Http $http,
		?callable $log = null
	) {
		$this->email        = trim( $email );
		$this->token        = trim( $token );
		$this->cloud_id     = self::clean_id( $cloud_id );
		$this->workspace_id = self::clean_id( $workspace_id );
		$this->http         = $http;
		$this->log          = $log ?? static function ( string $message ): void {};
	}

	/**
	 * Strip anything that is not valid in an Atlassian identifier.
	 *
	 * These two ids are interpolated into a URL path, so they are constrained
	 * rather than escaped: a cloud id is a UUID and a workspace id is a UUID,
	 * and nothing outside that alphabet can be legitimate.
	 */
	private static function clean_id( string $id ): string {
		return (string) preg_replace( '/[^A-Za-z0-9-]/', '', trim( $id ) );
	}

	/**
	 * Do we have enough to make the call at all?
	 */
	public function has_credentials(): bool {
		return '' !== $this->email
			&& '' !== $this->token
			&& '' !== $this->cloud_id
			&& '' !== $this->workspace_id;
	}

	/**
	 * Which of the four required settings are missing, for the error message.
	 *
	 * @return array<int,string>
	 */
	public function missing(): array {
		$missing = array();

		if ( '' === $this->email ) {
			$missing[] = __( 'Atlassian account email', 'vulnhub' );
		}
		if ( '' === $this->token ) {
			$missing[] = __( 'API token', 'vulnhub' );
		}
		if ( '' === $this->cloud_id ) {
			$missing[] = __( 'cloud id', 'vulnhub' );
		}
		if ( '' === $this->workspace_id ) {
			$missing[] = __( 'workspace id', 'vulnhub' );
		}

		return $missing;
	}

	/**
	 * Build the AQL query for one schema and a set of object types.
	 *
	 * Type names are quoted and any embedded quote or backslash escaped, so a
	 * type genuinely called `Servers "DR"` cannot break out of the string.
	 *
	 * @param int               $schema_id    Object schema id.
	 * @param array<int,string> $object_types Object type names.
	 */
	public static function build_aql( int $schema_id, array $object_types ): string {
		$aql = sprintf( 'objectSchemaId = %d', max( 1, $schema_id ) );

		$quoted = array();
		foreach ( $object_types as $type ) {
			$type = trim( (string) $type );

			if ( '' === $type ) {
				continue;
			}

			$quoted[] = '"' . str_replace( array( '\\', '"' ), array( '\\\\', '\\"' ), $type ) . '"';
		}

		if ( $quoted ) {
			$aql .= ' AND objectType IN (' . implode( ', ', $quoted ) . ')';
		}

		return $aql;
	}

	/**
	 * Parse a comma separated list of object types from a settings field.
	 *
	 * Commas are the separator, so a type containing one has to be quoted —
	 * the same rule a spreadsheet uses, and the same one an operator expects.
	 *
	 * @return array<int,string>
	 */
	public static function parse_types( string $raw ): array {
		$types = array();

		foreach ( (array) str_getcsv( trim( $raw ) ) as $type ) {
			$type = trim( (string) $type );

			if ( '' !== $type ) {
				$types[] = $type;
			}
		}

		return array_values( array_unique( $types ) );
	}

	/**
	 * The AQL search endpoint for this workspace.
	 */
	public function endpoint(): string {
		return sprintf(
			'%s/ex/jira/%s/jsm/assets/workspace/%s/v1/object/aql',
			self::API_HOST,
			rawurlencode( $this->cloud_id ),
			rawurlencode( $this->workspace_id )
		);
	}

	/**
	 * Basic auth header. Never logged, never returned.
	 *
	 * @return array<string,string>
	 */
	private function headers(): array {
		return array(
			'Authorization' => 'Basic ' . base64_encode( $this->email . ':' . $this->token ),
			'Accept'        => 'application/json',
			'Content-Type'  => 'application/json',
		);
	}

	/**
	 * Fetch one page of AQL results.
	 *
	 * @param string $aql      AQL query.
	 * @param int    $start_at Offset.
	 * @param int    $limit    Page size (clamped to PAGE_SIZE).
	 * @return array{ok:bool,status:int,message:string,values:array<int,array<string,mixed>>,total:int,is_last:bool,attribute_names:array<string,string>}
	 */
	public function page( string $aql, int $start_at = 0, int $limit = self::PAGE_SIZE ): array {
		$limit = max( 1, min( self::PAGE_SIZE, $limit ) );

		$url = add_query_arg(
			array(
				'startAt'           => max( 0, $start_at ),
				'maxResults'        => $limit,
				'includeAttributes' => 'true',
			),
			$this->endpoint()
		);

		$response = $this->http->post(
			$url,
			array( 'qlQuery' => $aql ),
			$this->headers(),
			array( 'timeout' => self::TIMEOUT )
		);

		if ( ! $response->ok() ) {
			return array(
				'ok'              => false,
				'status'          => $response->status,
				'message'         => $this->explain( $response ),
				'values'          => array(),
				'total'           => 0,
				'is_last'         => true,
				'attribute_names' => array(),
			);
		}

		$data   = $response->data();
		$values = array();

		foreach ( (array) ( $data['values'] ?? array() ) as $object ) {
			if ( is_array( $object ) ) {
				$values[] = $object;
			}
		}

		return array(
			'ok'              => true,
			'status'          => $response->status,
			'message'         => '',
			'values'          => $values,
			'total'           => (int) ( $data['total'] ?? count( $values ) ),
			'is_last'         => ! empty( $data['isLast'] ),
			'attribute_names' => self::attribute_names( $data ),
		);
	}

	/**
	 * Turn a failed response into something an operator can act on.
	 *
	 * The 401 case is the one that matters. Atlassian returns 401 both for a
	 * wrong token and for a valid token whose scopes do not cover every part
	 * of the request — and because this call always asks for attributes, a
	 * token missing `read:cmdb-attribute:jira` fails here while working
	 * perfectly in a browser session. Saying so is the difference between a
	 * two-minute fix and an afternoon of re-pasting the same token.
	 */
	private function explain( \VulnHub\Core\Http_Response $response ): string {
		$detail = vh_trim( $response->error_message(), 200 );

		return match ( $response->status ) {
			401 => __( 'Atlassian rejected the credentials (401). Check the account email and token, and make sure the token carries all five Assets read scopes — read:cmdb-object:jira, read:cmdb-attribute:jira, read:cmdb-schema:jira, read:cmdb-type:jira and read:cmdb-icon:jira. A token without read:cmdb-attribute:jira fails this call even when it can read objects, because the call always asks for attributes.', 'vulnhub' ),
			403 => __( 'The token is valid but has no access to this object schema (403). Ask an Assets administrator to grant the account read access to the schema.', 'vulnhub' ),
			404 => sprintf(
				/* translators: %s: error detail from Atlassian. */
				__( 'No Assets workspace was found at that address (404). Check the cloud id and workspace id. %s', 'vulnhub' ),
				$detail
			),
			400 => sprintf(
				/* translators: %s: error detail from Atlassian. */
				__( 'Atlassian rejected the AQL query (400): %s', 'vulnhub' ),
				$detail
			),
			429 => __( 'Atlassian is rate limiting this workspace (429) and the request did not succeed after several backed-off retries. Try again in a few minutes.', 'vulnhub' ),
			0   => sprintf(
				/* translators: %s: transport error. */
				__( 'Could not reach api.atlassian.com: %s', 'vulnhub' ),
				$detail
			),
			default => sprintf(
				/* translators: 1: HTTP status, 2: error detail. */
				__( 'Assets returned %1$d: %2$s', 'vulnhub' ),
				$response->status,
				$detail
			),
		};
	}

	/**
	 * Attribute id → attribute name, from a page's definition block.
	 *
	 * The AQL response describes the columns once per page, in
	 * `objectTypeAttributes`, rather than repeating the name on every value.
	 * Older responses inline `objectTypeAttribute` on each attribute instead,
	 * so the flattener below reads both; this covers the page-level form.
	 *
	 * @param array<string,mixed> $data Decoded page body.
	 * @return array<string,string>
	 */
	public static function attribute_names( array $data ): array {
		$names = array();

		foreach ( (array) ( $data['objectTypeAttributes'] ?? array() ) as $definition ) {
			if ( ! is_array( $definition ) ) {
				continue;
			}

			$id   = (string) ( $definition['id'] ?? '' );
			$name = (string) ( $definition['name'] ?? '' );

			if ( '' !== $id && '' !== $name ) {
				$names[ $id ] = $name;
			}
		}

		return $names;
	}

	/**
	 * A single cheap call, for the connection test.
	 *
	 * @param string $aql AQL query to count against.
	 * @return array{ok:bool,message:string,detail:array<string,mixed>}
	 */
	public function test_connection( string $aql ): array {
		if ( ! $this->has_credentials() ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: %s: comma separated list of missing settings. */
					__( 'Not configured yet — still missing: %s.', 'vulnhub' ),
					implode( ', ', $this->missing() )
				),
				'detail'  => array( 'missing' => $this->missing() ),
			);
		}

		$page = $this->page( $aql, 0, 1 );

		if ( ! $page['ok'] ) {
			return array(
				'ok'      => false,
				'message' => $page['message'],
				'detail'  => array(
					'status' => $page['status'],
					'aql'    => $aql,
				),
			);
		}

		return array(
			'ok'      => true,
			'message' => sprintf(
				/* translators: %s: number of objects matching the query. */
				__( 'Connected. %s object(s) match.', 'vulnhub' ),
				number_format_i18n( $page['total'] )
			),
			'detail'  => array(
				'status' => $page['status'],
				'total'  => $page['total'],
				'aql'    => $aql,
			),
		);
	}

	/**
	 * Page through every object matching the query.
	 *
	 * Stops on `isLast`, on a short page, on reaching `total`, or on the
	 * runaway guard — whichever comes first. A failed page aborts the whole
	 * fetch rather than returning a partial set, because a partial set handed
	 * to the importer looks exactly like a shrinking CMDB.
	 *
	 * @param string        $aql      AQL query.
	 * @param callable|null $progress Called as f(fetched, total) after each page.
	 * @return array{ok:bool,message:string,objects:array<int,array<string,mixed>>,pages:int,total:int,attribute_names:array<string,string>}
	 */
	public function fetch_all( string $aql, ?callable $progress = null ): array {
		$objects   = array();
		$names     = array();
		$start_at  = 0;
		$pages     = 0;
		$total     = 0;
		$max_pages = self::HARD_MAX_PAGES;

		do {
			$page = $this->page( $aql, $start_at, self::PAGE_SIZE );
			++$pages;

			if ( ! $page['ok'] ) {
				return array(
					'ok'              => false,
					'message'         => $page['message'],
					'objects'         => array(),
					'pages'           => $pages,
					'total'           => $total,
					'attribute_names' => $names,
				);
			}

			$total = $page['total'];
			$names = $names + $page['attribute_names'];

			foreach ( $page['values'] as $object ) {
				$objects[] = $object;
			}

			call_user_func(
				$this->log,
				sprintf(
					'Assets: page %d (startAt %d) returned %d of %d object(s).',
					$pages,
					$start_at,
					count( $page['values'] ),
					$total
				)
			);

			if ( $progress ) {
				call_user_func( $progress, count( $objects ), $total );
			}

			/*
			 * Tighten the guard once `total` is known: the brief's
			 * total/PAGE_SIZE + 5. Until then HARD_MAX_PAGES applies.
			 */
			if ( $total > 0 ) {
				$max_pages = min( self::HARD_MAX_PAGES, (int) ceil( $total / self::PAGE_SIZE ) + 5 );
			}

			$exhausted = $page['is_last']
				|| count( $page['values'] ) < self::PAGE_SIZE
				|| ( $total > 0 && count( $objects ) >= $total );

			$start_at += self::PAGE_SIZE;
		} while ( ! $exhausted && $pages < $max_pages );

		/*
		 * The guard has five pages of headroom over what `total` implies, so a
		 * healthy workspace never reaches it. Reaching it means the API stopped
		 * advancing — and a set that stopped early is indistinguishable, once
		 * it is imported, from a CMDB that has shrunk. Fail instead.
		 */
		if ( ! $exhausted ) {
			call_user_func(
				$this->log,
				sprintf( 'Assets: stopped at the %d page guard with %d object(s) read.', $max_pages, count( $objects ) )
			);

			return array(
				'ok'              => false,
				'message'         => sprintf(
					/* translators: 1: number of pages, 2: objects read, 3: objects expected. */
					__( 'Assets kept returning full pages after %1$d requests (%2$d of a reported %3$d objects) without ever signalling the last page. Nothing was imported, because a partial read looks exactly like a CMDB that has shrunk.', 'vulnhub' ),
					$pages,
					count( $objects ),
					$total
				),
				'objects'         => array(),
				'pages'           => $pages,
				'total'           => $total,
				'attribute_names' => $names,
			);
		}

		return array(
			'ok'              => true,
			'message'         => '',
			'objects'         => $objects,
			'pages'           => $pages,
			'total'           => $total,
			'attribute_names' => $names,
		);
	}

	/**
	 * Flatten one Assets object into a row keyed by attribute name.
	 *
	 * This is the step that lets the rest of the connector treat Assets
	 * exactly like a spreadsheet. An Assets object carries its values in a
	 * list of attributes, each holding a list of values, each of which may be
	 * a plain string, a reference to another object, a user, a status or a
	 * date. Flattened to `{"Serial Number": "5CG1234ABC"}` it is a CSV row,
	 * and the CSV path's detection, mapping and normalisation all apply
	 * unchanged — which is the point: one set of rules, not two.
	 *
	 * Five synthetic columns are added for the fields that live on the object
	 * itself rather than in its attributes. They are prefixed so they cannot
	 * collide with a workspace attribute genuinely called "Label" or "Key",
	 * and the connector applies them only as a last resort — a workspace that
	 * has a real Name or Serial Number attribute always maps to that instead.
	 *
	 * @param array<string,mixed>  $object Raw object from `values[]`.
	 * @param array<string,string> $names  Attribute id → name, from the page.
	 * @return array<string,string>
	 */
	public static function flatten( array $object, array $names = array() ): array {
		$row = array(
			'Assets Object Id'   => (string) ( $object['id'] ?? '' ),
			'Assets Object Key'  => (string) ( $object['objectKey'] ?? '' ),
			'Assets Label'       => (string) ( $object['label'] ?? '' ),
			'Assets Object Type' => (string) ( $object['objectType']['name'] ?? '' ),
			'Assets Updated'     => (string) ( $object['updated'] ?? '' ),
		);

		foreach ( (array) ( $object['attributes'] ?? array() ) as $attribute ) {
			if ( ! is_array( $attribute ) ) {
				continue;
			}

			$name = (string) ( $attribute['objectTypeAttribute']['name'] ?? '' );

			if ( '' === $name ) {
				$name = (string) ( $names[ (string) ( $attribute['objectTypeAttributeId'] ?? '' ) ] ?? '' );
			}
			if ( '' === $name ) {
				continue;
			}

			$value = self::attribute_value( $attribute );

			// An attribute present but empty still tells the mapper the column
			// exists, so it is recorded rather than skipped.
			if ( ! isset( $row[ $name ] ) || '' === $row[ $name ] ) {
				$row[ $name ] = $value;
			}
		}

		return $row;
	}

	/**
	 * Read one attribute's value list down to a single string.
	 *
	 * Assets values are polymorphic. `displayValue` is what a human sees in
	 * the UI and is right for almost everything, but a user attribute's
	 * display value is a person's name, and a name cannot be looked up in the
	 * people table — so a user is rendered as "Name - email", which is the
	 * shape `vh_split_person()` already understands and the same shape the
	 * live CMDB export uses.
	 *
	 * @param array<string,mixed> $attribute One entry from `attributes[]`.
	 */
	private static function attribute_value( array $attribute ): string {
		$parts = array();

		foreach ( (array) ( $attribute['objectAttributeValues'] ?? array() ) as $value ) {
			if ( ! is_array( $value ) ) {
				continue;
			}

			$email = (string) ( $value['user']['emailAddress'] ?? '' );
			$who   = (string) ( $value['user']['displayName'] ?? '' );

			if ( '' !== $email || '' !== $who ) {
				$parts[] = trim( implode( ' - ', array_filter( array( $who, $email ) ) ) );
				continue;
			}

			$text = (string) (
				$value['displayValue']
				?? $value['value']
				?? $value['referencedObject']['label']
				?? $value['status']['name']
				?? ''
			);

			// `displayValue` can be present but null for an empty reference.
			if ( '' === $text ) {
				$text = (string) ( $value['referencedObject']['label'] ?? $value['status']['name'] ?? '' );
			}
			if ( '' !== $text ) {
				$parts[] = $text;
			}
		}

		return implode( ', ', array_unique( array_filter( $parts ) ) );
	}
}
