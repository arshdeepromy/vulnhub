<?php
/**
 * Jira Cloud connector.
 *
 * Owns the credentials, the settings, the connection test, and the scheduled
 * job that keeps every open ticket's status in step with Jira. Ticket creation
 * lives in VulnHub_Jira_Ticketer and the rule engine in
 * VulnHub_Jira_Automation, both of which borrow this connector's client.
 *
 * The status sync deliberately does NOT fetch one issue per HTTP call. It
 * batches the keys it cares about into `key in (…)` JQL and pages the enhanced
 * search endpoint with its `nextPageToken` cursor, so a thousand open tickets
 * cost about twenty requests rather than a thousand.
 *
 * @package VulnHub\Jira
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The `jira` connector.
 */
final class VulnHub_Jira_Connector extends \VulnHub\Core\Connector {

	/**
	 * Issue keys per JQL batch. Jira's enhanced search caps a page at 5000, but
	 * a `key in (…)` clause of a few hundred keys keeps the URL and the parse
	 * cost sane, and 100 comfortably fits inside one page of results.
	 */
	private const KEYS_PER_BATCH = 100;

	/**
	 * Maximum tickets examined in a single scheduled sync.
	 */
	private const SYNC_CEILING = 2000;

	/**
	 * Fields requested from Jira. Asking for a narrow set is what keeps the
	 * enhanced search fast and its pages full.
	 *
	 * @var string[]
	 */
	private const SYNC_FIELDS = array(
		'summary',
		'status',
		'resolution',
		'assignee',
		'priority',
		'issuetype',
		'project',
		'duedate',
		'labels',
		'updated',
		'resolutiondate',
	);

	/**
	 * Lazily-built REST client.
	 */
	private ?VulnHub_Jira_Client $client = null;

	/**
	 * Simulated site, built once per request in mock mode.
	 */
	private ?VulnHub_Jira_Mock $mock_site = null;

	/**
	 * Per-run tallies surfaced on the Jira admin screen.
	 *
	 * @var array<string,int>
	 */
	private array $counts = array();

	/* =================================================================
	 * Identity
	 * ============================================================== */

	/**
	 * Machine id.
	 */
	public function id(): string {
		return 'jira';
	}

	/**
	 * Human label.
	 */
	public function label(): string {
		return __( 'Jira Cloud', 'vulnhub' );
	}

	/**
	 * One-line description for the Integrations card.
	 */
	public function description(): string {
		return __( 'Raises remediation tickets in Jira Cloud from vulnerability findings, keeps their status in sync, and reopens issues the scanner still detects.', 'vulnhub' );
	}

	/**
	 * Dashicon slug.
	 */
	public function icon(): string {
		return 'dashicons-tickets-alt';
	}

	/**
	 * Connector category.
	 */
	public function category(): string {
		return 'itsm';
	}

	/**
	 * Default schedule. Ticket status changes matter quickly — a closure is
	 * what starts the verification clock — but not minute to minute.
	 */
	public function default_interval(): string {
		return 'vh_30min';
	}

	/* =================================================================
	 * Settings
	 * ============================================================== */

	/**
	 * Settings field definitions.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public function fields(): array {
		$oauth_only = array( 'auth_method' => array( 'oauth' ) );
		$basic_only = array( 'auth_method' => array( 'basic' ) );

		return array(
			array(
				'key'     => 'auth_method',
				'label'   => __( 'Sign in with', 'vulnhub' ),
				'type'    => 'select',
				'default' => 'basic',
				'options' => array(
					'basic' => __( 'API token (email + token)', 'vulnhub' ),
					'oauth' => __( 'OAuth — connect as yourself', 'vulnhub' ),
				),
				'help'    => __( 'OAuth acts as whoever clicks Allow on the Atlassian consent screen, and appears under that person’s Atlassian account → Connected apps. An API token acts as the account it belongs to. Either way, Jira only ever sees what that account is permitted to do.', 'vulnhub' ),
			),
			array(
				'key'       => 'oauth_connection',
				'type'      => 'note',
				'show_when' => $oauth_only,
				'help'      => $this->oauth_note(),
			),
			array(
				'key'         => 'oauth_client_id',
				'label'       => __( 'OAuth client ID', 'vulnhub' ),
				'type'        => 'text',
				'show_when'   => $oauth_only,
				'placeholder' => 'aBcD1234…',
				'help'        => __( 'From developer.atlassian.com → Console → your OAuth 2.0 integration → Settings. Add the Jira API and Jira Service Management API permissions to that app first.', 'vulnhub' ),
			),
			array(
				'key'       => 'oauth_client_secret',
				'label'     => __( 'OAuth client secret', 'vulnhub' ),
				'type'      => 'text',
				'secret'    => true,
				'show_when' => $oauth_only,
				'help'      => __( 'Stored encrypted. Leave blank when editing to keep the existing secret.', 'vulnhub' ),
			),
			array(
				'key'         => 'oauth_redirect_uri',
				'label'       => __( 'Callback URL', 'vulnhub' ),
				'type'        => 'url',
				'show_when'   => $oauth_only,
				'placeholder' => VulnHub_Jira_OAuth::default_redirect_uri(),
				'help'        => sprintf(
					/* translators: %s: the default callback URL. */
					__( 'Register exactly this in the Atlassian console under Authorization → OAuth 2.0 (3LO). Leave blank to use %s. Set it when the browser you connect from reaches this server by a different address — http://localhost:… is allowed; any other host must be https.', 'vulnhub' ),
					VulnHub_Jira_OAuth::default_redirect_uri()
				),
			),
			array(
				'key'         => 'oauth_scopes',
				'label'       => __( 'Scopes', 'vulnhub' ),
				'type'        => 'text',
				'show_when'   => $oauth_only,
				'placeholder' => VulnHub_Jira_OAuth::DEFAULT_SCOPES,
				'help'        => __( 'Leave blank for the defaults, which cover raising, reading, commenting and attaching on Jira and Jira Service Management. offline_access is always added: without it the connection ends an hour after you connect. Every scope must also be enabled on the app in the console.', 'vulnhub' ),
			),
			array(
				'key'         => 'base_url',
				'label'       => __( 'Jira site URL', 'vulnhub' ),
				'type'        => 'url',
				'required'    => true,
				'default'     => 'https://yoursite.atlassian.net',
				'placeholder' => 'https://yoursite.atlassian.net',
				'help'        => __( 'Your Atlassian Cloud site, without a path — the *.atlassian.net address, not a custom domain in front of it. Jira Data Center is not supported — this connector speaks the Cloud REST API v3. Under OAuth this picks which site the grant is used for when it reaches more than one.', 'vulnhub' ),
			),
			array(
				'key'         => 'email',
				'label'       => __( 'Account email', 'vulnhub' ),
				'type'        => 'email',
				'required'    => true,
				'show_when'   => $basic_only,
				'placeholder' => 'automation@yourcompany.com',
				'help'        => __( 'The Atlassian account the API token belongs to. Basic auth sends email:token, so both halves must match the same account. Use a dedicated service account so the audit trail in Jira is honest.', 'vulnhub' ),
			),
			array(
				'key'       => 'api_token',
				'label'     => __( 'API token', 'vulnhub' ),
				'type'      => 'text',
				'secret'    => true,
				'required'  => true,
				'show_when' => $basic_only,
				'help'     => __( 'Created at id.atlassian.com → Security → API tokens. Stored encrypted. Leave blank when editing to keep the existing token.', 'vulnhub' ),
			),
			array(
				'key'         => 'project_key',
				'label'       => __( 'Default project key', 'vulnhub' ),
				'type'        => 'text',
				'required'    => true,
				'default'     => 'SEC',
				'placeholder' => 'SEC',
				'help'        => __( 'Used whenever the owning team has no Jira project key of its own. A wrong project key is the most common misconfiguration, so the connection test checks it exists.', 'vulnhub' ),
			),
			array(
				'key'         => 'allowed_projects',
				'label'       => __( 'Only write to projects', 'vulnhub' ),
				'type'        => 'text',
				'default'     => '',
				'placeholder' => 'SEC, OPS',
				'help'        => __( 'Comma-separated project keys. When set, VulnHub refuses to create, comment on, transition, edit or attach to anything outside them — whoever asks, including automation rules and team routing. Reading is not restricted. Leave blank for no restriction. Recommended under OAuth, whose scopes reach every project the person who connected can see.', 'vulnhub' ),
			),
			array(
				'key'         => 'issue_type',
				'label'       => __( 'Default issue type', 'vulnhub' ),
				'type'        => 'text',
				'default'     => 'Task',
				'placeholder' => 'Task',
				'help'        => __( 'Overridden per team by the team\'s Jira issue type. Must exist in the target project\'s issue type scheme.', 'vulnhub' ),
			),
			array(
				'key'         => 'default_service_desk',
				'label'       => __( 'Default JSM service desk', 'vulnhub' ),
				'type'        => 'text',
				'default'     => '',
				'placeholder' => '1',
				'help'        => __( 'Numeric Jira Service Management service desk id. Used when the owning team has no Jira project key of its own. Pick it from the list on VulnHub → Jira routing rather than typing it — that screen reads the desks straight from GET /rest/servicedeskapi/servicedesk. Leave blank on a site without Jira Service Management.', 'vulnhub' ),
			),
			array(
				'key'         => 'default_request_type',
				'label'       => __( 'Default JSM request type', 'vulnhub' ),
				'type'        => 'text',
				'default'     => '',
				'placeholder' => '25',
				'help'        => __( 'Request type id inside the default service desk. Its issue type (the request type\'s issueTypeId) is what the created issue is raised as, so the ticket lands in the right queue instead of the desk\'s catch-all.', 'vulnhub' ),
			),
			array(
				'key'         => 'default_team',
				'label'       => __( 'Default team', 'vulnhub' ),
				'type'        => 'text',
				'default'     => '',
				'placeholder' => 'Security Operations',
				'help'        => __( 'Written to the Team custom field on every issue VulnHub raises that has no team-specific value. This is what stops support tickets silently piling up on whichever team the service desk defaults to.', 'vulnhub' ),
			),
			array(
				'key'         => 'team_field',
				'label'       => __( 'Team field id', 'vulnhub' ),
				'type'        => 'text',
				'default'     => '',
				'placeholder' => 'customfield_10001',
				'help'        => __( 'Leave blank to auto-detect from GET /rest/api/3/field: the Atlassian Teams field (com.atlassian.teams:rm-teams-custom-field-team) is preferred, then any custom field named Team. Set it only when your site has more than one.', 'vulnhub' ),
			),
			array(
				'key'     => 'priority_critical',
				'label'   => __( 'Jira priority for Critical', 'vulnhub' ),
				'type'    => 'text',
				'default' => 'Highest',
				'help'    => __( 'Jira priority names are case sensitive and site specific. The default scheme is Highest / High / Medium / Low / Lowest.', 'vulnhub' ),
			),
			array(
				'key'     => 'priority_high',
				'label'   => __( 'Jira priority for High', 'vulnhub' ),
				'type'    => 'text',
				'default' => 'High',
			),
			array(
				'key'     => 'priority_medium',
				'label'   => __( 'Jira priority for Medium', 'vulnhub' ),
				'type'    => 'text',
				'default' => 'Medium',
			),
			array(
				'key'     => 'priority_low',
				'label'   => __( 'Jira priority for Low', 'vulnhub' ),
				'type'    => 'text',
				'default' => 'Low',
			),
			array(
				'key'     => 'grouping',
				'label'   => __( 'Group findings into one ticket by', 'vulnhub' ),
				'type'    => 'select',
				'default' => 'per_asset_and_severity',
				'options' => self::grouping_options(),
				'help'    => __( 'One ticket per finding is precise but noisy on a fleet of any size. Grouping by asset and severity is usually what a remediation team actually wants to work.', 'vulnhub' ),
			),
			array(
				'key'            => 'reopen_on_recurrence',
				'label'          => __( 'Reopen tickets', 'vulnhub' ),
				'type'           => 'checkbox',
				'default'        => 1,
				'checkbox_label' => __( 'Reopen the Jira issue if the vulnerability comes back', 'vulnhub' ),
				'help'           => __( 'When closure verification finds the scanner still detects a vulnerability, comment on the issue explaining that and transition it back to an open status if the workflow allows it.', 'vulnhub' ),
			),
			array(
				'key'            => 'comment_on_verify',
				'label'          => __( 'Verification comments', 'vulnhub' ),
				'type'           => 'checkbox',
				'default'        => 1,
				'checkbox_label' => __( 'Post a comment when we verify a closure', 'vulnhub' ),
				'help'           => __( 'Writes the verification verdict back to Jira so the person who closed the ticket sees the evidence without leaving their tool.', 'vulnhub' ),
			),
			array(
				'key'     => 'sync_batch',
				'label'   => __( 'Issue keys per JQL batch', 'vulnhub' ),
				'type'    => 'number',
				'default' => self::KEYS_PER_BATCH,
				'help'    => __( 'How many issue keys go into a single "key in (…)" search. Lower it only if your site is unusually slow.', 'vulnhub' ),
			),
			array(
				'key'            => 'verbose_log',
				'label'          => __( 'Verbose logging', 'vulnhub' ),
				'type'           => 'checkbox',
				'default'        => 0,
				'checkbox_label' => __( 'Mirror the run log to the PHP error log', 'vulnhub' ),
				'help'           => __( 'Noisy. Useful while commissioning the integration. The API token is never written to any log.', 'vulnhub' ),
			),
		);
	}

	/**
	 * The four supported grouping strategies.
	 *
	 * @return array<string,string>
	 */
	public static function grouping_options(): array {
		return array(
			'per_finding'            => __( 'One ticket per finding', 'vulnhub' ),
			'per_asset'              => __( 'One ticket per asset', 'vulnhub' ),
			'per_vulnerability'      => __( 'One ticket per vulnerability (across assets)', 'vulnhub' ),
			'per_asset_and_severity' => __( 'One ticket per asset and severity', 'vulnhub' ),
		);
	}

	/**
	 * Project keys writes are confined to; empty means unrestricted.
	 *
	 * @return string[]
	 */
	public function allowed_projects(): array {
		$raw = (string) $this->get( 'allowed_projects', '' );

		return array_values( array_unique( array_filter( array_map( static fn( string $k ): string => strtoupper( trim( $k ) ), preg_split( '/[\s,;]+/', $raw ) ?: array() ) ) ) );
	}

	/**
	 * Configured means "can authenticate", which depends on the sign-in method.
	 *
	 * Core's check walks every field marked required, and the email and API
	 * token are required for API-token sign-in. Under OAuth they are hidden and
	 * empty by design, so the core check reported a working OAuth connection
	 * as "Not configured -- required credentials are missing".
	 */
	public function is_configured(): bool {
		if ( 'oauth' !== $this->auth_method() || $this->is_mock() ) {
			return parent::is_configured();
		}

		return $this->oauth()->has_app() && $this->oauth()->is_connected() && '' !== $this->default_project();
	}

	public function auth_method(): string {
		return 'oauth' === (string) $this->get( 'auth_method', 'basic' ) ? 'oauth' : 'basic';
	}

	private ?VulnHub_Jira_OAuth $oauth = null;

	public function oauth(): VulnHub_Jira_OAuth {
		if ( null === $this->oauth ) {
			$this->oauth = new VulnHub_Jira_OAuth( $this );
		}

		return $this->oauth;
	}

	/**
	 * The connection block on the settings screen: who is connected, and the
	 * Connect / Disconnect control.
	 *
	 * Links rather than buttons because the note sits inside the settings form,
	 * and a form cannot hold another. Both carry a nonce.
	 */
	private function oauth_note(): string {
		if ( ! function_exists( 'vulnhub' ) || ! did_action( 'init' ) ) {
			return '';
		}

		$oauth  = $this->oauth();
		$status = $oauth->status();
		$out    = '<strong>' . esc_html__( 'OAuth connection', 'vulnhub' ) . '</strong><br>';

		if ( $status['connected'] ) {
			$out .= esc_html(
				sprintf(
					/* translators: 1: person, 2: site, 3: date. */
					__( 'Connected as %1$s to %2$s since %3$s.', 'vulnhub' ),
					'' !== $status['account'] ? $status['account'] : __( 'an unknown account', 'vulnhub' ),
					$status['site'],
					vh_date( $status['connected_at'] )
				)
			);
			$out .= ' <a class="button vh-btn vh-btn--ghost vh-btn--sm" href="' . esc_url( VulnHub_Jira_OAuth::disconnect_url() ) . '">' . esc_html__( 'Disconnect', 'vulnhub' ) . '</a>';
		} elseif ( $oauth->has_app() ) {
			$out .= esc_html__( 'Not connected. Save any changes first, then connect: you will be sent to Atlassian to click Allow, and brought back here.', 'vulnhub' );
			$out .= ' <a class="button button-primary vh-btn vh-btn--primary vh-btn--sm" href="' . esc_url( VulnHub_Jira_OAuth::start_url() ) . '">' . esc_html__( 'Connect to Jira', 'vulnhub' ) . '</a>';
		} else {
			$out .= esc_html__( 'Not connected. Enter the client ID and secret from your Atlassian OAuth app below and save; a Connect button appears here.', 'vulnhub' );
		}

		if ( '' !== $status['last_message'] ) {
			$out .= '<br><em class="' . ( 'error' === $status['last_type'] ? 'vh-bad' : 'vh-muted' ) . '">'
				. esc_html( vh_date( $status['last_at'] ) . ' — ' . $status['last_message'] ) . '</em>';
		}

		return $out;
	}

	/**
	 * Configured grouping strategy.
	 */
	public function grouping(): string {
		$value = (string) $this->get( 'grouping', 'per_asset_and_severity' );

		return isset( self::grouping_options()[ $value ] ) ? $value : 'per_asset_and_severity';
	}

	/**
	 * Default project key.
	 */
	public function default_project(): string {
		return strtoupper( trim( (string) $this->get( 'project_key', 'SEC' ) ) );
	}

	/**
	 * Default issue type name.
	 */
	public function default_issue_type(): string {
		return trim( (string) $this->get( 'issue_type', 'Task' ) ) ?: 'Task';
	}

	/**
	 * Default JSM service desk id, or '' when none is configured.
	 */
	public function default_service_desk(): string {
		return trim( (string) $this->get( 'default_service_desk', '' ) );
	}

	/**
	 * Default JSM request type id, or '' when none is configured.
	 */
	public function default_request_type(): string {
		return trim( (string) $this->get( 'default_request_type', '' ) );
	}

	/**
	 * Default value written to the Team custom field.
	 */
	public function default_team(): string {
		return trim( (string) $this->get( 'default_team', '' ) );
	}

	/**
	 * Explicit Team custom field id, or '' to auto-detect.
	 */
	public function team_field_id(): string {
		return trim( (string) $this->get( 'team_field', '' ) );
	}

	/**
	 * Per-team routing overrides, keyed by VulnHub team id.
	 *
	 * The teams table already owns `jira_project_key`, `jira_issue_type` and
	 * `jira_default_assignee`, and those keep winning. It has no column for a
	 * JSM request type or a Team field value, and inventing one would mean
	 * editing core's schema, so those two live here in the connector's own
	 * settings blob instead.
	 *
	 * @return array<int,array<string,string>>
	 */
	public function team_routing(): array {
		$stored = $this->get( 'team_routing', array() );
		$out    = array();

		foreach ( (array) ( is_array( $stored ) ? $stored : array() ) as $team_id => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}

			$out[ (int) $team_id ] = array(
				'service_desk' => trim( (string) ( $row['service_desk'] ?? '' ) ),
				'request_type' => trim( (string) ( $row['request_type'] ?? '' ) ),
				'team_value'   => trim( (string) ( $row['team_value'] ?? '' ) ),
			);
		}

		return $out;
	}

	/**
	 * The routing override for one team, or an empty triple.
	 *
	 * @param int $team_id VulnHub team id.
	 * @return array<string,string>
	 */
	public function team_routing_for( int $team_id ): array {
		$all = $this->team_routing();

		return $all[ $team_id ] ?? array(
			'service_desk' => '',
			'request_type' => '',
			'team_value'   => '',
		);
	}

	/**
	 * Replace the whole per-team routing map.
	 *
	 * @param array<int,array<string,string>> $map Team id => override.
	 */
	public function save_team_routing( array $map ): void {
		$clean = array();

		foreach ( $map as $team_id => $row ) {
			$team_id = (int) $team_id;

			if ( $team_id <= 0 || ! is_array( $row ) ) {
				continue;
			}

			$entry = array(
				'service_desk' => trim( (string) ( $row['service_desk'] ?? '' ) ),
				'request_type' => trim( (string) ( $row['request_type'] ?? '' ) ),
				'team_value'   => trim( (string) ( $row['team_value'] ?? '' ) ),
			);

			// An entry that says nothing is not stored at all.
			if ( '' === $entry['service_desk'] && '' === $entry['request_type'] && '' === $entry['team_value'] ) {
				continue;
			}

			$clean[ $team_id ] = $entry;
		}

		$this->settings->set( $this->id(), 'team_routing', $clean );
	}

	/**
	 * The Jira priority name configured for one of our severities.
	 */
	public function priority_for( string $severity ): string {
		$defaults = array(
			'critical' => 'Highest',
			'high'     => 'High',
			'medium'   => 'Medium',
			'low'      => 'Low',
			'info'     => 'Lowest',
		);

		$severity = array_key_exists( $severity, $defaults ) ? $severity : 'medium';

		if ( 'info' === $severity ) {
			return (string) $this->get( 'priority_low', $defaults['low'] );
		}

		return trim( (string) $this->get( 'priority_' . $severity, $defaults[ $severity ] ) ) ?: $defaults[ $severity ];
	}

	/**
	 * Should we reopen issues whose vulnerability came back?
	 */
	public function reopens(): bool {
		return $this->settings->get_bool( $this->id(), 'reopen_on_recurrence', true );
	}

	/**
	 * Should we comment on verified closures?
	 */
	public function comments_on_verify(): bool {
		return $this->settings->get_bool( $this->id(), 'comment_on_verify', true );
	}

	/* =================================================================
	 * Client
	 * ============================================================== */

	/**
	 * The simulated Jira site (mock mode only).
	 */
	public function mock_site(): ?VulnHub_Jira_Mock {
		if ( ! $this->is_mock() ) {
			return null;
		}
		if ( null === $this->mock_site ) {
			$this->mock_site = new VulnHub_Jira_Mock( (string) $this->get( 'base_url', '' ) );
		}

		return $this->mock_site;
	}

	/**
	 * REST client, wired to the live site or the simulated one.
	 */
	public function client(): VulnHub_Jira_Client {
		if ( null === $this->client ) {
			$this->client = new VulnHub_Jira_Client(
				(string) $this->get( 'base_url', '' ),
				(string) $this->get( 'email', '' ),
				$this->secret( 'api_token' ),
				$this->http,
				$this->mock_site(),
				array( $this, 'log' )
			);

			if ( 'oauth' === $this->auth_method() && ! $this->is_mock() ) {
				$oauth = $this->oauth();

				$this->client->use_oauth(
					$oauth->cloud_id(),
					static fn( bool $force ): string => $oauth->access_token( $force ),
					$oauth->status()['site']
				);
			}

			$this->client->restrict_projects( $this->allowed_projects() );
		}

		return $this->client;
	}

	/* =================================================================
	 * Connection test
	 * ============================================================== */

	/**
	 * Verify credentials and the default project.
	 *
	 * Two calls, because two things go wrong: the credential, and the project
	 * key. A wrong project key authenticates perfectly and then fails at the
	 * first ticket, so it is worth checking here.
	 *
	 * @return array{ok:bool,message:string,detail:array<string,mixed>}
	 */
	public function test_connection(): array {
		$client  = $this->client();
		$project = $this->default_project();

		if ( $this->is_mock() ) {
			$site = $this->mock_site();

			return array(
				'ok'      => true,
				'message' => sprintf(
					/* translators: 1: simulated site URL, 2: project key, 3: issue count. */
					__( 'Mock mode: simulating the Jira Cloud site %1$s. Tickets are raised into project %2$s with keys like %2$s-1001, move To Do → In Progress → Done over time, and are assigned to the shared mock people. The simulated site currently holds %3$d issue(s). No credentials are used and nothing leaves this server.', 'vulnhub' ),
					$site ? $site->site_url() : 'https://vulnhub-demo.atlassian.net',
					$project ?: 'SEC',
					$site ? $site->issue_count() : 0
				),
				'detail'  => array(
					'mode'    => 'mock',
					'site'    => $site ? $site->site_url() : '',
					'project' => $project,
					'issues'  => $site ? $site->issue_count() : 0,
				),
			);
		}

		if ( ! $client->has_credentials() ) {
			return array(
				'ok'      => false,
				'message' => 'oauth' === $this->auth_method()
					? __( 'Jira is set to OAuth but is not connected. Enter the app’s client ID and secret, save, and click Connect to Jira.', 'vulnhub' )
					: __( 'Set the Jira site URL, the account email and an API token first.', 'vulnhub' ),
				'detail'  => array( 'mode' => 'live', 'auth' => $this->auth_method() ),
			);
		}

		$allowed = $this->allowed_projects();

		if ( $allowed && '' !== $project && ! in_array( $project, $allowed, true ) ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: 1: default project, 2: allowed projects. */
					__( 'The default project %1$s is not in the allowed projects (%2$s), so every ticket would be refused. Change one or the other.', 'vulnhub' ),
					$project,
					implode( ', ', $allowed )
				),
				'detail'  => array( 'project_key' => $project, 'allowed' => $allowed ),
			);
		}

		$me = $client->myself();

		if ( ! $me->ok() ) {
			return array(
				'ok'      => false,
				'message' => 401 === $me->status || 403 === $me->status
					? sprintf(
						/* translators: 1: HTTP status, 2: error message. */
						__( 'Jira rejected the credentials (HTTP %1$d): %2$s. Check that the email matches the account the API token was created on — Basic auth sends both.', 'vulnhub' ),
						$me->status,
						vh_trim( $me->error_message(), 160 )
					)
					: sprintf(
						/* translators: 1: HTTP status, 2: error message. */
						__( 'Could not reach GET /rest/api/3/myself (HTTP %1$d): %2$s', 'vulnhub' ),
						$me->status,
						vh_trim( $me->error_message(), 160 )
					),
				'detail'  => array(
					'endpoint' => 'GET /rest/api/3/myself',
					'status'   => $me->status,
				),
			);
		}

		$who     = $me->data();
		$name    = (string) ( $who['displayName'] ?? __( 'unknown user', 'vulnhub' ) );
		$account = (string) ( $who['accountId'] ?? '' );

		if ( '' === $project ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: 1: display name, 2: account id. */
					__( 'Authenticated to Jira as %1$s (account %2$s), but no default project key is set — VulnHub would have nowhere to raise a ticket.', 'vulnhub' ),
					$name,
					$account
				),
				'detail'  => array(
					'account_id'   => $account,
					'display_name' => $name,
				),
			);
		}

		$proj = $client->project( $project );

		if ( ! $proj->ok() ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: 1: display name, 2: account id, 3: project key, 4: HTTP status. */
					__( 'Authenticated to Jira as %1$s (account %2$s), but project "%3$s" could not be read (HTTP %4$d). Check the project key and that this account has Browse projects and Create issues permission on it.', 'vulnhub' ),
					$name,
					$account,
					$project,
					$proj->status
				),
				'detail'  => array(
					'account_id'   => $account,
					'display_name' => $name,
					'project_key'  => $project,
					'status'       => $proj->status,
				),
			);
		}

		$project_data = $proj->data();

		return array(
			'ok'      => true,
			'message' => sprintf(
				/* translators: 1: display name, 2: account id, 3: project name, 4: project key. */
				__( 'Authenticated to Jira as %1$s (account %2$s). Default project "%3$s" (%4$s) exists and is readable.', 'vulnhub' ),
				$name,
				$account,
				(string) ( $project_data['name'] ?? $project ),
				$project
			) . ( 'oauth' === $this->auth_method() ? ' ' . __( 'Signed in over OAuth.', 'vulnhub' ) : '' )
				. ( $allowed
					/* translators: %s: allowed project keys. */
					? ' ' . sprintf( __( 'Writes are limited to %s.', 'vulnhub' ), implode( ', ', $allowed ) )
					: '' ),
			'detail'  => array(
				'endpoint'     => 'GET /rest/api/3/myself + GET /rest/api/3/project/{key}',
				'auth'         => $this->auth_method(),
				'allowed'      => $allowed,
				'account_id'   => $account,
				'display_name' => $name,
				'email'        => (string) ( $who['emailAddress'] ?? '' ),
				'timezone'     => (string) ( $who['timeZone'] ?? '' ),
				'project_key'  => $project,
				'project_name' => (string) ( $project_data['name'] ?? '' ),
				'project_id'   => (string) ( $project_data['id'] ?? '' ),
			),
		);
	}

	/* =================================================================
	 * Sync — poll Jira for the tickets we know about
	 * ============================================================== */

	/**
	 * Refresh the status of every ticket that is not already closed.
	 *
	 * @param array<string,mixed> $args Options.
	 * @return array{ok:bool,message:string}
	 */
	protected function do_sync( array $args = array() ): array {
		$this->counts = array(
			'checked'   => 0,
			'changed'   => 0,
			'closed'    => 0,
			'missing'   => 0,
			'batches'   => 0,
			'requests'  => 0,
		);

		$include_done = ! empty( $args['full'] );
		$rows         = $this->tickets_to_poll( $include_done );

		if ( ! $rows ) {
			$this->log( 'No Jira tickets to poll — nothing has been raised yet, or everything is already closed.' );

			return array(
				'ok'      => true,
				'message' => __( 'No open Jira tickets to poll.', 'vulnhub' ),
			);
		}

		$by_key = array();
		foreach ( $rows as $row ) {
			$by_key[ strtoupper( (string) $row['external_key'] ) ] = $row;
		}

		$batch_size = max( 10, min( 500, $this->settings->get_int( $this->id(), 'sync_batch', self::KEYS_PER_BATCH ) ) );
		$batches    = array_chunk( array_keys( $by_key ), $batch_size );

		$this->log(
			sprintf(
				'Polling %d ticket(s) in %d batched JQL search(es) of up to %d keys each.',
				count( $by_key ),
				count( $batches ),
				$batch_size
			)
		);

		$seen = array();

		foreach ( $batches as $batch ) {
			++$this->counts['batches'];

			foreach ( $this->search_keys( $batch ) as $issue ) {
				$key = strtoupper( (string) ( $issue['key'] ?? '' ) );

				if ( '' === $key || ! isset( $by_key[ $key ] ) ) {
					continue;
				}

				$seen[ $key ] = true;
				$this->apply_issue( $by_key[ $key ], $issue );
			}
		}

		foreach ( $by_key as $key => $row ) {
			if ( isset( $seen[ $key ] ) ) {
				continue;
			}

			++$this->counts['missing'];
			$this->log( sprintf( 'WARNING: %s is recorded in VulnHub but Jira did not return it — it may have been deleted or moved out of view.', $key ) );
		}

		$this->settings->update(
			$this->id(),
			array(
				'last_poll'      => $this->counts,
				'last_poll_at'   => vh_now(),
				'last_poll_mode' => $this->is_mock() ? 'mock' : 'live',
			)
		);

		$message = sprintf(
			/* translators: 1: tickets checked, 2: tickets changed, 3: tickets closed, 4: batches. */
			__( 'Checked %1$d ticket(s) in %4$d batch(es): %2$d changed, %3$d newly closed in Jira.', 'vulnhub' ),
			$this->counts['checked'],
			$this->counts['changed'],
			$this->counts['closed'],
			$this->counts['batches']
		);

		return array(
			'ok'      => true,
			'message' => $message,
		);
	}

	/**
	 * Tickets worth polling: ours, with a key, and not already done.
	 *
	 * @param bool $include_done Also refresh closed tickets.
	 * @return array<int,array<string,mixed>>
	 */
	private function tickets_to_poll( bool $include_done = false ): array {
		global $wpdb;

		$sql = 'SELECT id, external_key, status, status_category, resolution, assignee, priority
			FROM ' . vh_table( 'tickets' ) . "
			WHERE provider = %s AND external_key <> ''";

		if ( ! $include_done ) {
			$sql .= " AND status_category <> 'done'";
		}

		$sql .= ' ORDER BY updated_at ASC LIMIT %d';

		return (array) $wpdb->get_results(
			$wpdb->prepare( $sql, 'jira', self::SYNC_CEILING ), // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			ARRAY_A
		);
	}

	/**
	 * Run one `key in (…)` search, following the nextPageToken cursor.
	 *
	 * @param string[] $keys Issue keys.
	 * @return array<int,array<string,mixed>> Raw Jira issue objects.
	 */
	private function search_keys( array $keys ): array {
		if ( ! $keys ) {
			return array();
		}

		$quoted = array_map(
			static fn( string $k ): string => '"' . str_replace( '"', '', $k ) . '"',
			$keys
		);

		$jql   = 'key in (' . implode( ',', $quoted ) . ') ORDER BY key ASC';
		$out   = array();
		$token = '';
		$guard = 0;

		do {
			++$guard;
			++$this->counts['requests'];

			$response = $this->client()->search_jql( $jql, self::SYNC_FIELDS, count( $keys ), $token );

			if ( ! $response->ok() ) {
				$this->log(
					sprintf(
						'JQL search failed (HTTP %d): %s',
						$response->status,
						vh_trim( $response->error_message(), 180 )
					)
				);
				$this->bump( 'failed' );
				break;
			}

			$data = $response->data();

			foreach ( (array) ( $data['issues'] ?? array() ) as $issue ) {
				if ( is_array( $issue ) ) {
					$out[] = $issue;
				}
			}

			$token = (string) ( $data['nextPageToken'] ?? '' );
			$last  = ! empty( $data['isLast'] ) || '' === $token;
		} while ( ! $last && $guard < 50 );

		return $out;
	}

	/**
	 * Persist one Jira issue onto the ticket row it belongs to.
	 *
	 * @param array<string,mixed> $row   Existing ticket row.
	 * @param array<string,mixed> $issue Raw Jira issue.
	 */
	private function apply_issue( array $row, array $issue ): void {
		$normalised = $this->normalise_issue( $issue );

		++$this->counts['checked'];
		$this->bump( 'processed' );

		$was_done = 'done' === (string) $row['status_category'];
		$is_done  = 'done' === $normalised['status_category'];

		$changed = (string) $row['status'] !== $normalised['status']
			|| (string) $row['status_category'] !== $normalised['status_category']
			|| (string) $row['resolution'] !== $normalised['resolution']
			|| (string) $row['assignee'] !== $normalised['assignee']
			|| (string) $row['priority'] !== $normalised['priority'];

		\VulnHub\Core\Tickets::upsert( $normalised );

		if ( $changed ) {
			++$this->counts['changed'];
			$this->bump( 'updated' );

			$this->log(
				sprintf(
					'%s: %s → %s (%s)%s',
					$normalised['external_key'],
					(string) $row['status'] ?: '—',
					$normalised['status'],
					$normalised['status_category'],
					'' !== $normalised['assignee'] ? ', assigned to ' . $normalised['assignee'] : ''
				)
			);
		}

		if ( $is_done && ! $was_done ) {
			++$this->counts['closed'];

			// This is what queues the Tenable closure verification: "done" is a
			// claim, and core parks the ticket until the scanner agrees.
			\VulnHub\Core\Tickets::mark_closed( (int) $row['id'], $normalised['resolution'] );

			$this->log(
				sprintf(
					'%s closed in Jira as "%s" — queued for closure verification.',
					$normalised['external_key'],
					$normalised['resolution'] ?: $normalised['status']
				)
			);

			vulnhub()->logger->audit(
				'ticket.closed',
				sprintf(
					/* translators: 1: ticket key, 2: resolution. */
					__( '%1$s was closed in Jira (%2$s) and is awaiting closure verification.', 'vulnhub' ),
					$normalised['external_key'],
					$normalised['resolution'] ?: $normalised['status']
				),
				'ticket',
				(int) $row['id'],
				array(
					'status'     => $normalised['status'],
					'resolution' => $normalised['resolution'],
					'assignee'   => $normalised['assignee'],
				)
			);
		}
	}

	/* =================================================================
	 * Normalisation — one code path for live and mock
	 * ============================================================== */

	/**
	 * Turn a raw Jira issue into the shape `Tickets::upsert()` wants.
	 *
	 * @param array<string,mixed> $issue Raw Jira issue object.
	 * @return array<string,mixed>
	 */
	public function normalise_issue( array $issue ): array {
		$fields   = (array) ( $issue['fields'] ?? array() );
		$key      = (string) ( $issue['key'] ?? '' );
		$status   = (array) ( $fields['status'] ?? array() );
		$category = (array) ( $status['statusCategory'] ?? array() );
		$assignee = is_array( $fields['assignee'] ?? null ) ? (array) $fields['assignee'] : array();

		return array(
			'provider'        => 'jira',
			'external_id'     => (string) ( $issue['id'] ?? '' ),
			'external_key'    => $key,
			'url'             => $this->client()->browse_url( $key ),
			'project_key'     => strtoupper( (string) ( $fields['project']['key'] ?? '' ) ),
			'issue_type'      => (string) ( $fields['issuetype']['name'] ?? '' ),
			'summary'         => vh_trim( (string) ( $fields['summary'] ?? '' ), 250 ),
			'status'          => (string) ( $status['name'] ?? '' ),
			'status_category' => self::status_category( (string) ( $category['key'] ?? '' ) ),
			'resolution'      => (string) ( $fields['resolution']['name'] ?? '' ),
			'priority'        => (string) ( $fields['priority']['name'] ?? '' ),
			'assignee'        => (string) ( $assignee['displayName'] ?? '' ),
			'assignee_id'     => (string) ( $assignee['accountId'] ?? '' ),
			'reporter'        => (string) ( $fields['reporter']['displayName'] ?? '' ),
			'payload'         => array(
				'labels'         => array_values( (array) ( $fields['labels'] ?? array() ) ),
				'duedate'        => (string) ( $fields['duedate'] ?? '' ),
				'updated'        => (string) ( $fields['updated'] ?? '' ),
				'resolutiondate' => (string) ( $fields['resolutiondate'] ?? '' ),
				'status_colour'  => (string) ( $category['colorName'] ?? '' ),
			),
		);
	}

	/**
	 * Normalise a Jira status category key.
	 *
	 * Jira defines exactly four: `undefined`, `new`, `indeterminate` and
	 * `done`. Some payloads (and a few older serialisations) use the internal
	 * display names instead, so those are folded in rather than trusted blindly.
	 */
	public static function status_category( string $key ): string {
		$key = strtolower( trim( $key ) );

		return match ( $key ) {
			'', 'new', 'to-do', 'todo', 'undefined' => 'new',
			'done', 'complete', 'completed'         => 'done',
			default                                 => 'indeterminate',
		};
	}

	/* =================================================================
	 * Single-ticket refresh (the button on the Tickets screen)
	 * ============================================================== */

	/**
	 * Answer the `vulnhub_refresh_ticket` filter.
	 *
	 * @param array<string,mixed>|null $result Result so far.
	 * @param array<string,mixed>      $ticket Ticket row.
	 * @return array<string,mixed>|null
	 */
	public function refresh_ticket( ?array $result, array $ticket ): ?array {
		if ( null !== $result ) {
			return $result;
		}
		if ( 'jira' !== (string) ( $ticket['provider'] ?? '' ) ) {
			return null;
		}
		if ( ! $this->is_enabled() ) {
			return null;
		}

		$key = (string) ( $ticket['external_key'] ?? '' );

		if ( '' === $key ) {
			return array(
				'ok'      => false,
				'message' => __( 'That ticket has no Jira issue key to refresh.', 'vulnhub' ),
			);
		}

		$response = $this->client()->get_issue( $key, self::SYNC_FIELDS );

		if ( ! $response->ok() ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: 1: issue key, 2: HTTP status, 3: error message. */
					__( 'Could not read %1$s from Jira (HTTP %2$d): %3$s', 'vulnhub' ),
					$key,
					$response->status,
					vh_trim( $response->error_message(), 160 )
				),
			);
		}

		$normalised = $this->normalise_issue( $response->data() );
		$was_done   = 'done' === (string) ( $ticket['status_category'] ?? '' );

		\VulnHub\Core\Tickets::upsert( $normalised );

		if ( 'done' === $normalised['status_category'] && ! $was_done ) {
			\VulnHub\Core\Tickets::mark_closed( (int) $ticket['id'], $normalised['resolution'] );
		}

		return array(
			'ok'      => true,
			'message' => sprintf(
				/* translators: 1: issue key, 2: status name, 3: assignee. */
				__( '%1$s is now "%2$s"%3$s.', 'vulnhub' ),
				$key,
				$normalised['status'],
				'' !== $normalised['assignee'] ? sprintf( __( ', assigned to %s', 'vulnhub' ), $normalised['assignee'] ) : ''
			),
			'ticket'  => \VulnHub\Core\Tickets::by_key( $key ),
		);
	}
}

