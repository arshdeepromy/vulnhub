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

	/** Longest comment accepted, in characters (Jira's comment body holds 32,767). */
	private const COMMENT_MAX = 30000;

	/**
	 * Transient prefix and lifetime for a cached issue conversation.
	 *
	 * Five minutes: long enough that walking a list of tickets pays the Jira
	 * round trip once per ticket rather than once per click, short enough that
	 * a comment somebody left in Jira shows up while they are still thinking
	 * about it. Anything written from here -- a posted comment, a Refresh --
	 * clears the entry, so the only staleness possible is somebody else's.
	 */
	private const COMMENTS_CACHE = 'vh_jira_comments_';
	private const COMMENTS_TTL   = 300;

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
	 * Routing directory, built on demand.
	 */
	private ?VulnHub_Jira_Directory $directory = null;

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
	 * Fields to request, plus the Team field when this site has one.
	 *
	 * Not part of SYNC_FIELDS because the field's id is site specific and only
	 * known once the directory has looked. Asked for by id rather than through
	 * `*navigable`, which would return every navigable field on every issue of
	 * a two-thousand-ticket sync -- the opposite of why the list is narrow.
	 *
	 * @return string[]
	 */
	private function sync_fields(): array {
		$id = (string) ( $this->directory()->team_field()['id'] ?? '' );

		return '' === $id ? self::SYNC_FIELDS : array_merge( self::SYNC_FIELDS, array( $id ) );
	}

	/**
	 * The routing directory for this connector, built once per request.
	 */
	private function directory(): VulnHub_Jira_Directory {
		return $this->directory ??= new VulnHub_Jira_Directory( $this );
	}

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
				'key'            => 'send_priority',
				'label'          => __( 'Priority', 'vulnhub' ),
				'type'           => 'checkbox',
				'default'        => 1,
				'checkbox_label' => __( 'Send a priority by default', 'vulnhub' ),
				'help'           => __( 'On: tickets carry the Jira priority mapped from their severity below. Off: no priority is sent and Jira applies the project default. Either way the review offers the priorities the project actually allows, read from Jira, so one can be chosen per ticket. Priority names are site specific -- a service desk may use P1-P4 rather than Highest-Lowest.', 'vulnhub' ),
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
				'key'            => 'link_back',
				'label'          => __( 'Links to VulnHub', 'vulnhub' ),
				'type'           => 'checkbox',
				'default'        => 1,
				'checkbox_label' => __( 'Link tickets back to VulnHub', 'vulnhub' ),
				'help'           => __( 'Adds an "Open the asset in VulnHub" link to the description and a web link on the issue. The address comes from the host VulnHub was opened on when the ticket was raised, so turn this off if the people working tickets cannot reach VulnHub -- a link to localhost opens nothing for them.', 'vulnhub' ),
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
	public function sends_priority(): bool {
		return $this->settings->get_bool( $this->id(), 'send_priority', true );
	}

	public function links_back(): bool {
		return $this->settings->get_bool( $this->id(), 'link_back', true );
	}

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

		$this->read_moved_conversations();

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

		$sql = 'SELECT id, external_key, status, status_category, resolution, assignee, priority, payload_json
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

			$response = $this->client()->search_jql( $jql, $this->sync_fields(), count( $keys ), $token );

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

		/*
		 * A comment moves Jira's `updated` and nothing else this poll reads,
		 * so that is the signal to read the conversation again -- once, for
		 * the tickets that moved, rather than every ticket every poll. A
		 * ticket never read before is read once to start it off.
		 */
		$kept = json_decode( (string) ( $row['payload_json'] ?? '' ), true );
		$kept = is_array( $kept ) ? $kept : array();

		if ( ! $is_done && (
			! is_array( $kept['conversation'] ?? null )
			|| (string) ( $kept['updated'] ?? '' ) !== (string) $normalised['payload']['updated']
		) ) {
			$this->moved[ (int) $row['id'] ] = (string) $normalised['external_key'];
		}

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

		// Whoever is actually carrying it. A desk that routes by team assigns
		// the team, not a person, and "unassigned" on a ticket somebody is
		// working is worse than saying nothing.
		$team_field = $this->directory()->team_field();
		$team_id    = (string) ( $team_field['id'] ?? '' );
		$team_raw   = '' !== $team_id ? ( $fields[ $team_id ] ?? null ) : null;
		$team_name  = '';

		if ( is_array( $team_raw ) ) {
			$team_name = (string) ( $team_raw['name'] ?? ( $team_raw['value'] ?? '' ) );
		} elseif ( is_string( $team_raw ) ) {
			$team_name = $team_raw;
		}

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
				'team_name'      => $team_name,
			),
		);
	}

	/**
	 * Who a ticket is with: the assignee, or the team carrying it.
	 *
	 * @param array<string,mixed> $ticket Ticket row.
	 * @return array{name:string,is_team:bool}
	 */
	public static function assigned_to( array $ticket ): array {
		$person = trim( (string) ( $ticket['assignee'] ?? '' ) );

		if ( '' !== $person ) {
			return array( 'name' => $person, 'is_team' => false );
		}

		$payload = json_decode( (string) ( $ticket['payload_json'] ?? '' ), true );
		$team    = is_array( $payload ) ? trim( (string) ( $payload['team_name'] ?? '' ) ) : '';

		return array( 'name' => $team, 'is_team' => '' !== $team );
	}

	/* =================================================================
	 * Comments
	 * ============================================================== */

	/**
	 * Every comment on an issue, newest first.
	 *
	 * @return array{ok:bool,message:string,comments:array<int,array<string,mixed>>}
	 */
	public function comments( string $key, int $max = 50, bool $fresh = false ): array {
		if ( ! $this->is_enabled() ) {
			return array( 'ok' => false, 'message' => __( 'Jira is not enabled.', 'vulnhub' ), 'comments' => array() );
		}
		if ( '' === trim( $key ) ) {
			return array( 'ok' => false, 'message' => __( 'That ticket has no Jira issue key.', 'vulnhub' ), 'comments' => array() );
		}

		/*
		 * Opening a ticket used to wait the better part of a second on this
		 * round trip, every time, including the back-and-forth of reading two
		 * tickets in a row. A conversation on a remediation ticket moves in
		 * hours, so a minute of cache costs nobody anything -- and posting a
		 * comment, or asking for a refresh, clears it rather than leaving the
		 * writer looking at their own missing reply.
		 */
		$cache = self::COMMENTS_CACHE . md5( $key . '|' . $max );

		if ( ! $fresh ) {
			$hit = get_transient( $cache );

			if ( is_array( $hit ) ) {
				return $hit;
			}
		}

		$response = $this->client()->issue_comments( $key, $max );

		if ( ! $response->ok() ) {
			return array(
				'ok'       => false,
				'message'  => sprintf(
					/* translators: 1: issue key, 2: HTTP status, 3: error message. */
					__( 'Could not read the comments on %1$s (HTTP %2$d): %3$s', 'vulnhub' ),
					$key,
					$response->status,
					vh_trim( $response->error_message(), 160 )
				),
				'comments' => array(),
			);
		}

		$out = array();

		foreach ( (array) ( $response->data()['comments'] ?? array() ) as $raw ) {
			$out[] = $this->normalise_comment( (array) $raw );
		}

		$read = array( 'ok' => true, 'message' => '', 'comments' => $out );

		// Only a good read is cached: a failure should be retried, not held.
		set_transient( $cache, $read, self::COMMENTS_TTL );

		return $read;
	}

	/**
	 * Forget the cached conversation on an issue.
	 *
	 * Called after writing a comment, and whenever somebody asks for the
	 * ticket to be refreshed: those are the two moments where a cached answer
	 * would be visibly wrong.
	 */
	public function forget_comments( string $key ): void {
		foreach ( array( 1, 50 ) as $max ) {
			delete_transient( self::COMMENTS_CACHE . md5( $key . '|' . $max ) );
		}
	}

	/**
	 * The status moves Jira will accept on an issue right now, normalised.
	 *
	 * Transition ids are workflow specific and the set depends on the issue's
	 * current status and on what the connecting account is permitted to do, so
	 * this is always asked live rather than guessed from a status name.
	 *
	 * Each transition carries the fields its screen makes **required**.
	 * Optional ones are dropped: a form that asks for everything a Jira screen
	 * could hold is a worse version of Jira. Anything required that cannot be
	 * rendered honestly -- a cascading select, an array of components -- is
	 * reported in `unsupported`, and the caller refuses the move and sends the
	 * person to Jira rather than posting a guess.
	 *
	 * @return array{ok:bool,message:string,transitions:array<int,array<string,mixed>>}
	 */
	public function transitions_for( string $key ): array {
		if ( ! $this->is_enabled() ) {
			return array( 'ok' => false, 'message' => __( 'Jira is not enabled.', 'vulnhub' ), 'transitions' => array() );
		}
		if ( '' === trim( $key ) ) {
			return array( 'ok' => false, 'message' => __( 'That ticket has no Jira issue key.', 'vulnhub' ), 'transitions' => array() );
		}

		$response = $this->client()->transitions( $key, true );

		if ( ! $response->ok() ) {
			return array(
				'ok'          => false,
				'message'     => sprintf(
					/* translators: 1: issue key, 2: HTTP status, 3: error message. */
					__( 'Could not read the available statuses for %1$s (HTTP %2$d): %3$s', 'vulnhub' ),
					$key,
					$response->status,
					vh_trim( $response->error_message(), 160 )
				),
				'transitions' => array(),
			);
		}

		$out = array();

		foreach ( (array) ( $response->data()['transitions'] ?? array() ) as $raw ) {
			if ( ! is_array( $raw ) || empty( $raw['id'] ) ) {
				continue;
			}
			// `isAvailable` is only present when Jira evaluated the conditions;
			// absent means unconditional, not unavailable.
			if ( array_key_exists( 'isAvailable', $raw ) && ! $raw['isAvailable'] ) {
				continue;
			}

			$fields      = array();
			$unsupported = array();

			foreach ( (array) ( $raw['fields'] ?? array() ) as $id => $field ) {
				if ( empty( $field['required'] ) ) {
					continue;
				}
				// Jira fills these itself on a transition; asking is noise.
				if ( in_array( (string) $id, array( 'summary', 'issuetype', 'project', 'reporter' ), true ) ) {
					continue;
				}

				$shape = $this->transition_field( (string) $id, (array) $field );

				if ( null === $shape ) {
					$unsupported[] = (string) ( $field['name'] ?? $id );
					continue;
				}

				$fields[] = $shape;
			}

			$out[] = array(
				'id'           => (string) $raw['id'],
				'name'         => (string) ( $raw['name'] ?? '' ),
				'to'           => (string) ( $raw['to']['name'] ?? '' ),
				'category'     => self::status_category( (string) ( $raw['to']['statusCategory']['key'] ?? '' ) ),
				'fields'       => $fields,
				'unsupported'  => $unsupported,
			);
		}

		return array( 'ok' => true, 'message' => '', 'transitions' => $out );
	}

	/**
	 * One required transition field, as something a form can actually render,
	 * or null when it cannot be rendered honestly.
	 *
	 * @param array<string,mixed> $field Jira's field definition.
	 * @return array<string,mixed>|null
	 */
	private function transition_field( string $id, array $field ): ?array {
		$type  = (string) ( $field['schema']['type'] ?? '' );
		$items = (string) ( $field['schema']['items'] ?? '' );
		$name  = (string) ( $field['name'] ?? $id );

		// A field with a fixed set of answers -- resolution is the one that
		// actually shows up on a close screen -- becomes a select.
		if ( isset( $field['allowedValues'] ) && is_array( $field['allowedValues'] ) ) {
			$options = array();

			foreach ( $field['allowedValues'] as $value ) {
				$value = (array) $value;
				$vid   = (string) ( $value['id'] ?? '' );
				$label = (string) ( $value['name'] ?? $value['value'] ?? $vid );

				if ( '' === $vid || '' === $label ) {
					continue;
				}

				$options[] = array( 'id' => $vid, 'label' => $label );
			}

			if ( ! $options ) {
				return null;
			}

			// An array-valued select (components, labels, fix versions) would
			// need multi-select and a different wire shape. Not guessed.
			if ( 'array' === $type ) {
				return null;
			}

			return array( 'id' => $id, 'name' => $name, 'kind' => 'select', 'options' => $options );
		}

		if ( in_array( $type, array( 'string', 'number' ), true ) && '' === $items ) {
			return array( 'id' => $id, 'name' => $name, 'kind' => 'string' );
		}

		return null;
	}

	/**
	 * Move an issue to another status.
	 *
	 * @param string               $key    Issue key.
	 * @param string               $id     Transition id from transitions_for().
	 * @param array<string,string> $values Field id => the chosen value's id, or free text.
	 * @param string               $note   Optional comment posted with the move.
	 * @return array{ok:bool,message:string}
	 */
	public function apply_transition( string $key, string $id, array $values = array(), string $note = '' ): array {
		if ( ! $this->is_enabled() ) {
			return array( 'ok' => false, 'message' => __( 'Jira is not enabled.', 'vulnhub' ) );
		}
		if ( '' === trim( $key ) || '' === trim( $id ) ) {
			return array( 'ok' => false, 'message' => __( 'That move is missing its ticket or its target status.', 'vulnhub' ) );
		}

		/*
		 * The offered set is read again here rather than trusted from the
		 * browser: it is the only way to know the transition is still valid,
		 * what its screen requires, and how to shape each value. A workflow
		 * can move under a form that has been open for a while.
		 */
		$offered = $this->transitions_for( $key );

		if ( empty( $offered['ok'] ) ) {
			return array( 'ok' => false, 'message' => (string) $offered['message'] );
		}

		$chosen = null;

		foreach ( $offered['transitions'] as $transition ) {
			if ( (string) $transition['id'] === trim( $id ) ) {
				$chosen = $transition;
				break;
			}
		}

		if ( null === $chosen ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: %s: issue key. */
					__( 'That status is no longer available on %s. Reload the ticket to see what the workflow offers now.', 'vulnhub' ),
					$key
				),
			);
		}

		if ( ! empty( $chosen['unsupported'] ) ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: 1: status name, 2: list of field names. */
					__( 'Moving to %1$s needs %2$s, which VulnHub cannot fill in correctly. Make this move in Jira.', 'vulnhub' ),
					(string) $chosen['to'],
					implode( ', ', array_map( 'strval', (array) $chosen['unsupported'] ) )
				),
			);
		}

		$fields = array();

		foreach ( (array) $chosen['fields'] as $field ) {
			$value = trim( (string) ( $values[ (string) $field['id'] ] ?? '' ) );

			if ( '' === $value ) {
				return array(
					'ok'      => false,
					'message' => sprintf(
						/* translators: 1: field name, 2: status name. */
						__( '%1$s is required to move this ticket to %2$s.', 'vulnhub' ),
						(string) $field['name'],
						(string) $chosen['to']
					),
				);
			}

			if ( 'select' === (string) $field['kind'] ) {
				$ids = array_column( (array) $field['options'], 'id' );

				if ( ! in_array( $value, $ids, true ) ) {
					return array(
						'ok'      => false,
						/* translators: %s: field name. */
						'message' => sprintf( __( 'That is not one of the values Jira offers for %s.', 'vulnhub' ), (string) $field['name'] ),
					);
				}

				$fields[ (string) $field['id'] ] = array( 'id' => $value );
				continue;
			}

			$fields[ (string) $field['id'] ] = $value;
		}

		$note     = trim( $note );
		$response = $this->client()->transition(
			$key,
			(string) $chosen['id'],
			'' !== $note ? VulnHub_Jira_Adf::doc()->paragraph( $note )->to_array() : null,
			$fields
		);

		if ( ! $response->ok() ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: 1: issue key, 2: status name, 3: HTTP status, 4: error message. */
					__( 'Jira refused to move %1$s to %2$s (HTTP %3$d): %4$s', 'vulnhub' ),
					$key,
					(string) $chosen['to'],
					$response->status,
					vh_trim( $response->error_message(), 200 )
				),
			);
		}

		// The conversation and the status both just changed at the far end.
		$this->forget_comments( $key );

		$this->log( sprintf( 'Moved %s to "%s" (transition %s).', $key, (string) $chosen['to'], (string) $chosen['id'] ) );

		return array(
			'ok'      => true,
			'message' => sprintf(
				/* translators: 1: issue key, 2: status name. */
				__( '%1$s moved to %2$s.', 'vulnhub' ),
				$key,
				(string) $chosen['to']
			),
			'status'  => (string) $chosen['to'],
		);
	}

	/**
	 * Tickets whose conversation this poll should read, id => key.
	 *
	 * @var array<int,string>
	 */
	private array $moved = array();

	/**
	 * How many conversations one poll reads at most. Each is one call; a
	 * first poll over a large backlog finishes the rest on the next one.
	 */
	private const CONVERSATIONS_PER_POLL = 40;

	/**
	 * Read the conversations of the tickets that moved during this poll.
	 */
	private function read_moved_conversations(): void {
		$read = 0;

		foreach ( $this->moved as $id => $key ) {
			if ( $read >= self::CONVERSATIONS_PER_POLL ) {
				$this->log( sprintf( 'Read %d conversations; the other %d wait for the next poll.', $read, count( $this->moved ) - $read ) );
				break;
			}

			$this->forget_comments( $key );
			$this->read_conversation( $id, $key );
			++$read;
		}

		$this->moved = array();
	}

	/**
	 * Read an issue's comments and keep what the Tickets list needs from
	 * them: the newest comment, and the conversation summary that answers
	 * "is anyone waiting on me" (see conversation()).
	 *
	 * The same 50-comment read the comments dialog makes, so the two share a
	 * cache entry. A failed read keeps what was stored: a refresh must not
	 * lose a mention because Jira hiccupped.
	 *
	 * @return array<string,mixed>|null The newest comment.
	 */
	public function read_conversation( int $ticket_id, string $key ): ?array {
		$read = $this->comments( $key );

		if ( empty( $read['ok'] ) ) {
			return null;
		}

		\VulnHub\Core\Tickets::set_last_comment( $ticket_id, $read['comments'][0] ?? null );
		\VulnHub\Core\Tickets::set_conversation( $ticket_id, self::conversation( $read['comments'] ) );

		return $read['comments'][0] ?? null;
	}

	/**
	 * What a ticket's conversation says about who owes whom a reply.
	 *
	 * Stored rather than worked out on every page view, because it needs the
	 * whole conversation and the list only ever has the newest comment. Kept
	 * free of anyone's identity, so each viewer's own answer is read off it
	 * at display time:
	 *
	 * - `last_by`: each author's most recent comment, so "has this person
	 *   replied since" is one comparison.
	 * - `mentions`: every @mention, by account id.
	 * - `said`: the newest comments that are a person talking -- not an
	 *   automation, not a relayed field change (see is_noise()) -- with the
	 *   start of their text, so a viewer's name written in plain words can be
	 *   found as well as a proper @mention. A relayed comment is credited to
	 *   the person it relays.
	 *
	 * All three are lists of records rather than maps keyed by account id: a
	 * numeric-looking key comes back from JSON as an int.
	 *
	 * @param array<int,array<string,mixed>> $comments Normalised, newest first.
	 * @return array<string,mixed>
	 */
	public static function conversation( array $comments ): array {
		$last_by  = array();
		$seen     = array();
		$mentions = array();
		$said     = array();

		foreach ( $comments as $c ) {
			$author = (string) ( $c['author_id'] ?? '' );
			$at     = (string) ( $c['created'] ?? '' );
			$body   = (string) ( $c['body'] ?? '' );

			if ( '' !== $author && ! isset( $seen[ $author ] ) ) {
				$seen[ $author ] = true;
				$last_by[]       = array( 'id' => $author, 'at' => $at );
			}

			foreach ( (array) ( $c['mentions'] ?? array() ) as $who ) {
				if ( count( $mentions ) < 30 ) {
					$mentions[] = array(
						'id'     => (string) $who,
						'by'     => (string) ( $c['author'] ?? '' ),
						'by_id'  => $author,
						'at'     => $at,
						'public' => ! empty( $c['public'] ),
					);
				}
			}

			if ( count( $said ) < 10 && 'app' !== (string) ( $c['author_type'] ?? '' ) && ! self::is_noise( $body ) ) {
				$said[] = array(
					'by'    => self::relayed_by( $body ) ?? (string) ( $c['author'] ?? '' ),
					'by_id' => $author,
					'at'    => $at,
					'text'  => mb_substr( $body, 0, 400 ),
				);
			}
		}

		return array(
			'read'     => count( $comments ),
			'last_by'  => $last_by,
			'mentions' => $mentions,
			'said'     => $said,
			'seen_at'  => vh_now(),
		);
	}

	/**
	 * Whether a comment is a record of a field changing rather than somebody
	 * saying something: "Status changed to: …", "<Field> changed in <other
	 * system> to: …" -- the lines a desk integration posts when it mirrors
	 * another tool. Nobody is waiting on an answer to one.
	 *
	 * Filter `vulnhub_ticket_comment_is_noise` for other shapes.
	 */
	public static function is_noise( string $body ): bool {
		$first = strtok( trim( $body ), "\n" );
		$noise = false !== $first && (bool) preg_match( '/^[^\n]{1,80}?\bchanged (?:in [^\n]{1,60}? )?to:/iu', $first );

		return (bool) apply_filters( 'vulnhub_ticket_comment_is_noise', $noise, $body );
	}

	/**
	 * The person a relayed comment speaks for: "<Name> in <other system>
	 * commented:" opens the relay's own post. Null when it is not one.
	 */
	public static function relayed_by( string $body ): ?string {
		return preg_match( '/^\s*([^\n]{2,60}?) in [^\n]{1,40}? commented:/u', $body, $m ) ? trim( $m[1] ) : null;
	}

	/**
	 * The Jira account a portal user is: ['id' => '', 'name' => ''] when it
	 * cannot be told.
	 *
	 * Only a portal admin (`vulnhub_admin`) is ever matched, and never an
	 * account that is also a WordPress administrator: those are the site's
	 * own logins, not people working tickets. The match needs both halves --
	 * Jira's search by the user's email has to return an account, and that
	 * account's display name has to be the user's own. An email alone can
	 * belong to a shared mailbox; a name alone can belong to two people.
	 *
	 * Remembered in user meta against the name and email it was made with,
	 * so changing either asks again; a miss is asked again a day later.
	 *
	 * @return array{id:string,name:string}
	 */
	public function jira_identity( int $user_id ): array {
		$none = array( 'id' => '', 'name' => '' );
		$user = $user_id > 0 ? get_userdata( $user_id ) : false;

		if ( ! $user || ! in_array( 'vulnhub_admin', (array) $user->roles, true ) || in_array( 'administrator', (array) $user->roles, true ) ) {
			return $none;
		}

		$email = strtolower( trim( (string) $user->user_email ) );
		$name  = self::same_name( (string) $user->display_name );

		if ( '' === $email || '' === $name || ! $this->is_enabled() ) {
			return $none;
		}

		$asked  = md5( $email . '|' . $name );
		$cached = get_user_meta( $user_id, 'vulnhub_jira_identity', true );

		if ( is_array( $cached ) && $asked === ( $cached['asked'] ?? '' )
			&& ( '' !== (string) ( $cached['id'] ?? '' ) || time() - (int) ( $cached['at'] ?? 0 ) < DAY_IN_SECONDS ) ) {
			return array( 'id' => (string) $cached['id'], 'name' => (string) ( $cached['name'] ?? '' ) );
		}

		$found    = $none;
		$response = $this->client()->user_search( $email );

		foreach ( $response->ok() ? (array) $response->data() : array() as $u ) {
			$theirs = strtolower( (string) ( $u['emailAddress'] ?? '' ) );

			// Jira hides most addresses; an account the search returned for
			// this address, with the address hidden, still matched on it.
			if ( ( '' === $theirs || $theirs === $email )
				&& 'atlassian' === (string) ( $u['accountType'] ?? '' )
				&& self::same_name( (string) ( $u['displayName'] ?? '' ) ) === $name
			) {
				$found = array( 'id' => (string) ( $u['accountId'] ?? '' ), 'name' => (string) ( $u['displayName'] ?? '' ) );
				break;
			}
		}

		if ( $response->ok() || '' !== $found['id'] ) {
			update_user_meta( $user_id, 'vulnhub_jira_identity', $found + array( 'asked' => $asked, 'at' => time() ) );
		}

		return $found;
	}

	/**
	 * A name, compared the way people write it: case and spacing ignored.
	 */
	private static function same_name( string $name ): string {
		return mb_strtolower( trim( (string) preg_replace( '/\s+/u', ' ', $name ) ) );
	}

	/**
	 * The newest comment on an issue, or null when there are none and when the
	 * read fails -- a caller refreshing a status should not lose the status
	 * because the comments could not be read.
	 *
	 * @return array<string,mixed>|null
	 */
	public function latest_comment( string $key ): ?array {
		$read = $this->comments( $key, 1 );

		return empty( $read['ok'] ) || ! $read['comments'] ? null : $read['comments'][0];
	}

	/**
	 * Add a comment to an issue.
	 *
	 * On a service desk an issue comment and a request comment are not the
	 * same thing: only the request API can say whether the customer sees it,
	 * and a comment added through the issue API is public by default. So
	 * anything with a visibility goes through the service desk route, and the
	 * issue route is the fallback for a project that is not a desk -- where
	 * "internal" has no meaning and the caller is told so rather than being
	 * quietly given a public comment.
	 *
	 * @param bool $public True for a reply the customer sees.
	 * @return array{ok:bool,message:string,comment?:array<string,mixed>}
	 */
	public function post_comment( string $key, string $body, bool $public ): array {
		$body = trim( $body );

		if ( ! $this->is_enabled() ) {
			return array( 'ok' => false, 'message' => __( 'Jira is not enabled.', 'vulnhub' ) );
		}
		if ( '' === trim( $key ) ) {
			return array( 'ok' => false, 'message' => __( 'That ticket has no Jira issue key.', 'vulnhub' ) );
		}
		if ( '' === $body ) {
			return array( 'ok' => false, 'message' => __( 'Write something first.', 'vulnhub' ) );
		}
		if ( mb_strlen( $body ) > self::COMMENT_MAX ) {
			return array(
				'ok'      => false,
				/* translators: %s: character limit. */
				'message' => sprintf( __( 'That comment is longer than the %s characters Jira accepts.', 'vulnhub' ), number_format_i18n( self::COMMENT_MAX ) ),
			);
		}

		// Whatever happens below, the cached conversation is now suspect.
		$this->forget_comments( $key );

		$response = $this->client()->request_comment( $key, $body, $public );

		/*
		 * 404 from the service desk API means this issue is not a request --
		 * an ordinary project, or a desk the token cannot see. An internal
		 * note cannot be honoured there, so it is refused rather than posted
		 * where the customer would read it.
		 */
		if ( 404 === $response->status ) {
			if ( ! $public ) {
				return array(
					'ok'      => false,
					'message' => sprintf(
						/* translators: %s: issue key. */
						__( '%s is not a service desk request, so there is no internal note to post -- every comment on it is visible to anyone who can see the issue. Post it as a reply if you meant to.', 'vulnhub' ),
						$key
					),
				);
			}

			$response = $this->client()->comment( $key, VulnHub_Jira_Adf::doc()->paragraph( $body )->to_array() );
		}

		if ( ! $response->ok() ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: 1: issue key, 2: HTTP status, 3: error message. */
					__( 'Jira refused the comment on %1$s (HTTP %2$d): %3$s', 'vulnhub' ),
					$key,
					$response->status,
					vh_trim( $response->error_message(), 160 )
				),
			);
		}

		$this->log( sprintf( 'Commented on %s (%s)', $key, $public ? 'reply to customer' : 'internal note' ) );

		return array(
			'ok'      => true,
			'message' => $public
				? __( 'Posted as a reply the customer can see.', 'vulnhub' )
				: __( 'Posted as an internal note.', 'vulnhub' ),
			'comment' => $this->normalise_comment( (array) $response->data() ),
		);
	}

	/**
	 * One comment, flattened for the screen.
	 *
	 * `jsdPublic` is the service desk's own flag and is absent on an ordinary
	 * project, where every comment is as visible as the issue. Absent is read
	 * as public, because that is what it means -- never as internal, which
	 * would label a customer-visible comment as private.
	 *
	 * @param array<string,mixed> $raw Comment from Jira.
	 * @return array<string,mixed>
	 */
	private function normalise_comment( array $raw ): array {
		$author = (array) ( $raw['author'] ?? array() );
		$body   = (array) ( $raw['body'] ?? array() );

		return array(
			'id'          => (string) ( $raw['id'] ?? '' ),
			'author'      => (string) ( $author['displayName'] ?? __( 'Unknown', 'vulnhub' ) ),
			'author_id'   => (string) ( $author['accountId'] ?? '' ),
			// `app` is Automation for Jira and its kind: a comment nobody is
			// waiting on an answer to.
			'author_type' => (string) ( $author['accountType'] ?? '' ),
			'avatar'      => (string) ( $author['avatarUrls']['24x24'] ?? '' ),
			'mentions'    => VulnHub_Jira_Adf::mentions( $body ),
			'body'        => trim( VulnHub_Jira_Adf::to_text( $body ) ),
			'html'        => VulnHub_Jira_Adf::to_html( $body ),
			// Jira sends ISO8601 with the site's own offset. Storage is UTC,
			// always -- left alone, a comment from this morning reads "in 12
			// hours" on a New Zealand site.
			'created'     => (string) ( vh_to_mysql( $raw['created'] ?? '' ) ?? '' ),
			'updated'     => (string) ( vh_to_mysql( $raw['updated'] ?? '' ) ?? '' ),
			'public'      => ! array_key_exists( 'jsdPublic', $raw ) || (bool) $raw['jsdPublic'],
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

		// "Refresh" means live, so the cached conversation goes too.
		$this->forget_comments( $key );

		$response = $this->client()->get_issue( $key, $this->sync_fields() );

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

		/*
		 * What is actually happening on the ticket, not just what column it
		 * sits in. A status of "To Do" three weeks running says nothing; "the
		 * desk asked a question on Tuesday and nobody answered" says all of
		 * it. Refreshing it here means every Verify picks it up, because Verify
		 * refreshes first. A failure to read comments never fails the refresh
		 * -- the status is the point, the comment is the colour.
		 */
		$comment = $this->read_conversation( (int) $ticket['id'], $key );

		if ( 'done' === $normalised['status_category'] && ! $was_done ) {
			\VulnHub\Core\Tickets::mark_closed( (int) $ticket['id'], $normalised['resolution'] );
		}

		$said = '';

		if ( null !== $comment && '' !== (string) $comment['body'] ) {
			$said = sprintf(
				/* translators: 1: author, 2: how long ago, 3: what they said. */
				__( ' Last comment %2$s by %1$s: "%3$s"', 'vulnhub' ),
				(string) $comment['author'],
				vh_ago( (string) $comment['created'] ),
				vh_trim( (string) $comment['body'], 140 )
			);
		}

		return array(
			'ok'      => true,
			'message' => sprintf(
				/* translators: 1: issue key, 2: status name, 3: assignee, 4: the last comment. */
				__( '%1$s is now "%2$s"%3$s.%4$s', 'vulnhub' ),
				$key,
				$normalised['status'],
				'' !== $normalised['assignee'] ? sprintf( __( ', assigned to %s', 'vulnhub' ), $normalised['assignee'] ) : '',
				$said
			),
			'ticket'  => \VulnHub\Core\Tickets::by_key( $key ),
		);
	}
}

