<?php
/**
 * A read-only client for the Check Point Management API (Web API).
 *
 * Works the same against a Smart-1 Cloud tenant
 * (`https://<tenant>.maas.checkpoint.com/<context>/web_api`) and an on-prem
 * Security Management or Multi-Domain server (`https://<server>/web_api`).
 *
 * Read-only is enforced three times over, and this class owns two of them:
 *
 *   1. On the Check Point side, the API key belongs to an administrator
 *      whose permission profile is Read Only. That is the operator's part.
 *   2. Every session is opened with `read-only: true`, so even a key with
 *      write rights gets a session that cannot change anything and takes no
 *      locks.
 *   3. call() refuses any command that is not `login`, `logout`,
 *      `keepalive` or a `show-*` command, before a byte leaves the box.
 *      There is no publish, discard, set, add, delete, install or run here,
 *      and no way to send one.
 *
 * Every Web API command is a POST, so the HTTP verb says nothing about
 * whether a call writes; the command name does, which is why the allowlist
 * is on the name.
 *
 * Paging follows CLAUDE.md: a truncated read is indistinguishable from a
 * shrunken policy, so each() walks to the server's `total` and throws if a
 * page comes back short or the total moves, rather than returning a partial
 * set that would read as rules having been removed.
 *
 * @package VulnHub\CheckPoint
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_CheckPoint_Client {

	/** Commands that are not `show-*` but are still allowed. None writes. */
	private const SESSION_COMMANDS = array( 'login', 'logout', 'keepalive' );

	private \VulnHub\Core\Http $http;
	private string $base;
	private string $key;
	private string $domain;
	private string $sid = '';
	private int $requests = 0;

	/**
	 * Check Point Portal (Infinity Portal) credentials, when management is
	 * reached through the portal gateway rather than directly: the portal
	 * hands out a bearer token for a Client ID and Secret Key, and every
	 * management call carries it. The management login (api-key) is still
	 * required on top -- the token gets you to the server, the key says who
	 * you are on it.
	 *
	 * @var array{auth_url:string,client_id:string,secret:string}|null
	 */
	private ?array $portal = null;
	private string $bearer = '';

	/** @var callable|null */
	private $mock;

	/**
	 * @param string        $base   Web API base URL, ending in /web_api.
	 * @param string        $key    API key of a read-only administrator.
	 * @param string        $domain Domain name on a Multi-Domain server, else ''.
	 * @param callable|null $log    Run logger.
	 * @param callable|null $mock   When set, answers commands instead of the network: fn( string $command, array $payload ): array.
	 */
	public function __construct( string $base, string $key, string $domain = '', ?callable $log = null, ?callable $mock = null ) {
		$this->base   = rtrim( trim( $base ), '/' );

		// The portal shows a management URL without the /web_api suffix
		// (…/environments/<id>); the commands live under it either way.
		if ( '' !== $this->base && ! str_ends_with( $this->base, '/web_api' ) ) {
			$this->base .= '/web_api';
		}
		$this->key    = $key;
		$this->domain = trim( $domain );
		$this->mock   = $mock;
		$this->http   = new \VulnHub\Core\Http( 'VulnHub-CheckPoint/' . VULNHUB_CHECKPOINT_VERSION, $log );
	}

	public function requests(): int {
		return $this->requests;
	}

	/**
	 * Reach management through the Check Point Portal gateway.
	 *
	 * @param string $auth_url  The Authentication URL shown with the portal API key.
	 * @param string $client_id Client ID.
	 * @param string $secret    Secret Key.
	 */
	public function via_portal( string $auth_url, string $client_id, string $secret ): void {
		$this->portal = array( 'auth_url' => trim( $auth_url ), 'client_id' => trim( $client_id ), 'secret' => $secret );
		$this->bearer = '';
	}

	/**
	 * Exchange the portal Client ID and Secret Key for a bearer token. This
	 * is the one request that is not a management command: it goes only to
	 * the configured Authentication URL and reads a token back.
	 */
	private function portal_token(): string {
		if ( '' !== $this->bearer || null === $this->portal ) {
			return $this->bearer;
		}

		if ( ! preg_match( '#^https://#i', $this->portal['auth_url'] ) ) {
			throw new RuntimeException( esc_html__( 'The Check Point Portal Authentication URL must start with https://.', 'vulnhub' ) );
		}

		++$this->requests;

		$res = $this->http->post(
			$this->portal['auth_url'],
			(string) wp_json_encode( array( 'clientId' => $this->portal['client_id'], 'accessKey' => $this->portal['secret'] ) ),
			array( 'Content-Type' => 'application/json', 'Accept' => 'application/json' ),
			array( 'timeout' => 60 )
		);

		$j     = (array) $res->data();
		$token = (string) ( $j['data']['token'] ?? $j['token'] ?? '' );

		if ( ! $res->ok() || '' === $token ) {
			throw new RuntimeException(
				sprintf(
					/* translators: 1: HTTP status, 2: error. */
					esc_html__( 'The Check Point Portal refused the Client ID and Secret Key (HTTP %1$d): %2$s', 'vulnhub' ),
					(int) $res->status,
					esc_html( (string) ( $j['message'] ?? $res->error_message() ) )
				)
			);
		}

		return $this->bearer = $token;
	}

	/**
	 * Read one thing from the Smart-1 Cloud service API with the portal
	 * token: the service details (`mgmt-service`) or the registered gateways
	 * (`gateways`). GET only, and only these two: that API can also register
	 * and delete gateways, and this client has no way to ask it to.
	 *
	 * The service API lives on the same host as the Authentication URL,
	 * under /app/maas/api/v1 (cloudinfra-gw.portal.checkpoint.com,
	 * cloudinfra-gw-us…, cloudinfra-gw.ap…).
	 *
	 * @return array<string,mixed> The response's `data`.
	 */
	public function portal_get( string $what ): array {
		if ( ! in_array( $what, array( 'mgmt-service', 'gateways' ), true ) ) {
			throw new RuntimeException( esc_html__( 'Refusing that Smart-1 Cloud service call: this integration only reads the service details and the gateway list.', 'vulnhub' ) );
		}
		if ( null === $this->portal ) {
			throw new RuntimeException( esc_html__( 'The Check Point Portal key is not configured.', 'vulnhub' ) );
		}

		$parts = wp_parse_url( $this->portal['auth_url'] );
		$url   = 'https://' . (string) ( $parts['host'] ?? '' ) . '/app/maas/api/v1/' . $what;

		++$this->requests;

		$send = fn() => $this->http->get( $url, array(), array( 'Authorization' => 'Bearer ' . $this->portal_token(), 'Accept' => 'application/json' ) );
		$res  = $send();

		if ( 401 === (int) $res->status ) {
			$this->bearer = '';
			$res          = $send();
		}

		$j = (array) $res->data();

		if ( ! $res->ok() || empty( $j['success'] ) ) {
			throw new RuntimeException(
				sprintf(
					/* translators: 1: what, 2: HTTP status, 3: error. */
					esc_html__( 'Smart-1 Cloud %1$s failed (HTTP %2$d): %3$s', 'vulnhub' ),
					esc_html( $what ),
					(int) $res->status,
					esc_html( (string) ( $j['message'] ?? $res->error_message() ) )
				)
			);
		}

		return (array) ( $j['data'] ?? array() );
	}

	public function set_base( string $base ): void {
		$this->base = rtrim( trim( $base ), '/' );

		if ( '' !== $this->base && ! str_ends_with( $this->base, '/web_api' ) ) {
			$this->base .= '/web_api';
		}
	}

	public function base(): string {
		return $this->base;
	}

	private string $user = '';
	private string $password = '';

	/** A management administrator's user name and password (instead of an API key). */
	public function with_user( string $user, string $password ): void {
		$this->user     = trim( $user );
		$this->password = $password;
	}

	/** True when the client holds a management login of its own. */
	public function has_key(): bool {
		return '' !== $this->key || ( '' !== $this->user && '' !== $this->password );
	}

	/** True for a command this client will send. */
	public static function allowed( string $command ): bool {
		return in_array( $command, self::SESSION_COMMANDS, true )
			|| 1 === preg_match( '/^show-[a-z0-9-]+$/', $command );
	}

	/**
	 * Open a read-only session.
	 *
	 * @return array<string,mixed> The login reply (api-server-version, etc.).
	 */
	public function login(): array {
		if ( '' === $this->base ) {
			throw new RuntimeException( esc_html__( 'No Management API URL is known yet.', 'vulnhub' ) );
		}

		// Without a management API key the login is attempted on the portal
		// token alone (sent as the bearer on every call). Check Point does
		// not document that for policy reads; Test connection reports
		// plainly whether the server accepted it.
		if ( ! $this->has_key() && null === $this->portal ) {
			throw new RuntimeException( esc_html__( 'No credentials to log in with.', 'vulnhub' ) );
		}

		// Smart-1 Cloud refuses session-name / session-description /
		// session-comments on a read-only login (HTTP 400, "unexpected, when
		// login is done in the readonly mode"): a read-only session has no
		// changes to label, so only the flag and the timeout are sent.
		$payload = array(
			'read-only'       => true,
			'session-timeout' => 900,
		);

		if ( '' !== $this->key ) {
			$payload = array( 'api-key' => $this->key ) + $payload;
		} elseif ( '' !== $this->user && '' !== $this->password ) {
			$payload = array( 'user' => $this->user, 'password' => $this->password ) + $payload;
		}

		if ( '' !== $this->domain ) {
			$payload['domain'] = $this->domain;
		}

		$reply = $this->call( 'login', $payload );
		$sid   = (string) ( $reply['sid'] ?? '' );

		if ( '' === $sid ) {
			throw new RuntimeException( esc_html__( 'Check Point accepted the login but returned no session id.', 'vulnhub' ) );
		}

		// A key with write rights still gets a read-only session (we asked
		// for one); say so loudly if the server ever reports otherwise.
		if ( isset( $reply['read-only'] ) && ! $reply['read-only'] ) {
			$this->sid = $sid;
			$this->logout();
			throw new RuntimeException( esc_html__( 'Check Point opened a session that is not read-only. Refusing to continue.', 'vulnhub' ) );
		}

		$this->sid = $sid;

		return $reply;
	}

	/** Close the session. Never throws: it runs in finally blocks. */
	public function logout(): void {
		if ( '' === $this->sid ) {
			return;
		}

		try {
			$this->call( 'logout', array() );
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			// The session times out on its own.
		}

		$this->sid = '';
	}

	/**
	 * Send one allowed command and return the decoded reply.
	 *
	 * @param array<string,mixed> $payload Command arguments.
	 * @return array<string,mixed>
	 */
	public function call( string $command, array $payload = array() ): array {
		if ( ! self::allowed( $command ) ) {
			throw new RuntimeException(
				sprintf(
					/* translators: %s: command name. */
					esc_html__( 'Refusing to send Check Point command "%s": this integration only reads.', 'vulnhub' ),
					esc_html( $command )
				)
			);
		}

		++$this->requests;

		if ( $this->mock ) {
			if ( 'login' === $command ) {
				return array( 'sid' => 'mock-session', 'read-only' => true, 'api-server-version' => '1.9' );
			}

			return (array) call_user_func( $this->mock, $command, $payload );
		}

		$headers = array( 'Content-Type' => 'application/json', 'Accept' => 'application/json' );

		if ( null !== $this->portal ) {
			$headers['Authorization'] = 'Bearer ' . $this->portal_token();
		}

		if ( 'login' !== $command ) {
			if ( '' === $this->sid ) {
				throw new RuntimeException( esc_html__( 'No Check Point session is open.', 'vulnhub' ) );
			}
			$headers['X-chkp-sid'] = $this->sid;
		}

		$res = $this->http->post(
			$this->base . '/' . $command,
			$payload ? (string) wp_json_encode( $payload ) : '{}',
			$headers,
			array( 'timeout' => 120 )
		);

		// A portal token can expire mid-run: fetch a new one once and retry.
		if ( null !== $this->portal && 401 === (int) $res->status ) {
			$this->bearer             = '';
			$headers['Authorization'] = 'Bearer ' . $this->portal_token();
			$res                      = $this->http->post( $this->base . '/' . $command, $payload ? (string) wp_json_encode( $payload ) : '{}', $headers, array( 'timeout' => 120 ) );
		}

		if ( ! $res->ok() ) {
			$j   = (array) $res->data();
			$msg = trim( (string) ( $j['code'] ?? '' ) . ' ' . (string) ( $j['message'] ?? '' ) );

			throw new RuntimeException(
				sprintf(
					/* translators: 1: command, 2: HTTP status, 3: error. */
					esc_html__( 'Check Point %1$s failed (HTTP %2$d): %3$s', 'vulnhub' ),
					esc_html( $command ),
					(int) $res->status,
					esc_html( '' !== $msg ? $msg : $res->error_message() )
				)
			);
		}

		return (array) $res->data();
	}

	/**
	 * Walk a paged `show-*` list to its total, handing each object to $cb.
	 *
	 * @param string              $command A show-* command returning `objects` (or $key).
	 * @param array<string,mixed> $payload Extra arguments.
	 * @param callable            $cb      Called with each object.
	 * @param string              $key     The array key holding the page.
	 * @param int                 $limit   Page size (the API caps most lists at 500).
	 * @return int Objects seen.
	 */
	public function each( string $command, array $payload, callable $cb, string $key = 'objects', int $limit = 500 ): int {
		$offset = 0;
		$total  = null;
		$seen   = 0;

		do {
			$page  = $this->call( $command, array_merge( $payload, array( 'limit' => $limit, 'offset' => $offset ) ) );
			$rows  = (array) ( $page[ $key ] ?? array() );
			$t     = (int) ( $page['total'] ?? count( $rows ) );

			if ( null === $total ) {
				$total = $t;
			} elseif ( $t !== $total ) {
				throw new RuntimeException(
					sprintf(
						/* translators: 1: command, 2: first total, 3: later total. */
						esc_html__( 'Check Point %1$s changed size while it was being read (%2$d, then %3$d). Nothing was imported; the next run will try again.', 'vulnhub' ),
						esc_html( $command ),
						(int) $total,
						(int) $t
					)
				);
			}

			foreach ( $rows as $row ) {
				$cb( (array) $row );
				++$seen;
			}

			if ( ! $rows && $seen < $total ) {
				throw new RuntimeException(
					sprintf(
						/* translators: 1: command, 2: read, 3: total. */
						esc_html__( 'Check Point %1$s stopped at %2$d of %3$d. Nothing was imported; the next run will try again.', 'vulnhub' ),
						esc_html( $command ),
						$seen,
						(int) $total
					)
				);
			}

			$offset += $limit;
		} while ( $seen < $total && $offset < 1000000 );

		return $seen;
	}

	/**
	 * Read a whole rulebase (access or NAT), sections flattened in order,
	 * with the object dictionary merged across pages.
	 *
	 * The rulebase commands page by rule, not by section, and every page
	 * carries only the dictionary entries its own rules use, so the
	 * dictionary is accumulated by uid.
	 *
	 * @param string              $command show-access-rulebase or show-nat-rulebase.
	 * @param array<string,mixed> $payload name/uid of the layer, or package.
	 * @return array{rules:array<int,array<string,mixed>>,dictionary:array<string,array<string,mixed>>}
	 */
	public function rulebase( string $command, array $payload ): array {
		$rules  = array();
		$dict   = array();
		$offset = 0;
		$limit  = 100;
		$total  = null;

		do {
			$page = $this->call(
				$command,
				array_merge(
					$payload,
					array(
						'limit'                 => $limit,
						'offset'                => $offset,
						'details-level'         => 'standard',
						'use-object-dictionary' => true,
					)
				)
			);

			$t = (int) ( $page['total'] ?? 0 );

			if ( null === $total ) {
				$total = $t;
			} elseif ( $t !== $total ) {
				throw new RuntimeException(
					sprintf(
						/* translators: %s: command */
						esc_html__( 'Check Point %s changed while it was being read. Nothing was imported; the next run will try again.', 'vulnhub' ),
						esc_html( $command )
					)
				);
			}

			foreach ( (array) ( $page['objects-dictionary'] ?? array() ) as $o ) {
				$o = (array) $o;

				if ( isset( $o['uid'] ) ) {
					$dict[ (string) $o['uid'] ] = $o;
				}
			}

			$before = count( $rules );
			self::flatten( (array) ( $page['rulebase'] ?? array() ), '', $rules );
			$got = count( $rules ) - $before;

			if ( 0 === $got && count( $rules ) < $total ) {
				throw new RuntimeException(
					sprintf(
						/* translators: 1: command, 2: read, 3: total. */
						esc_html__( 'Check Point %1$s stopped at %2$d of %3$d rules. Nothing was imported; the next run will try again.', 'vulnhub' ),
						esc_html( $command ),
						count( $rules ),
						(int) $total
					)
				);
			}

			$offset += $limit;
		} while ( count( $rules ) < $total && $offset < 200000 );

		return array( 'rules' => $rules, 'dictionary' => $dict );
	}

	/**
	 * Sections hold rules; rules are kept in order with the section name.
	 *
	 * @param array<int,mixed>              $items   Rulebase items.
	 * @param string                        $section Enclosing section name.
	 * @param array<int,array<string,mixed>> $out    Collected rules.
	 */
	private static function flatten( array $items, string $section, array &$out ): void {
		foreach ( $items as $item ) {
			$item = (array) $item;
			$type = (string) ( $item['type'] ?? '' );

			if ( str_ends_with( $type, '-section' ) ) {
				self::flatten( (array) ( $item['rulebase'] ?? array() ), (string) ( $item['name'] ?? '' ), $out );
				continue;
			}

			if ( str_ends_with( $type, '-rule' ) ) {
				$item['_section'] = $section;
				$out[]            = $item;
			}
		}
	}
}

