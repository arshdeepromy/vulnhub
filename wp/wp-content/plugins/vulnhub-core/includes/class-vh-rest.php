<?php
/**
 * Internal REST API — powers the admin screens and the front-end dashboard.
 *
 * Every route declares a permission_callback; none are public.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

use WP_REST_Request;
use WP_REST_Response;
use WP_Error;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Rest {

	public const NS = 'vulnhub/v1';

	public function register_routes(): void {

		register_rest_route(
			self::NS,
			'/summary',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'summary' ),
				'permission_callback' => array( $this, 'can_view' ),
			)
		);

		register_rest_route(
			self::NS,
			'/trend',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'trend' ),
				'permission_callback' => array( $this, 'can_view' ),
				'args'                => array(
					'days' => array(
						'type'    => 'integer',
						'default' => 30,
					),
				),
			)
		);

		register_rest_route(
			self::NS,
			'/breakdown',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'breakdown' ),
				'permission_callback' => array( $this, 'can_view' ),
				'args'                => array(
					'dimension' => array(
						'type'    => 'string',
						'default' => 'team',
						'enum'    => array( 'team', 'location', 'owner', 'asset_type' ),
					),
					'limit'     => array(
						'type'    => 'integer',
						'default' => 10,
					),
				),
			)
		);

		register_rest_route(
			self::NS,
			'/findings',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'findings' ),
				'permission_callback' => array( $this, 'can_view' ),
			)
		);

		register_rest_route(
			self::NS,
			'/findings/(?P<id>\d+)',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'finding' ),
				'permission_callback' => array( $this, 'can_view' ),
			)
		);

		register_rest_route(
			self::NS,
			'/assets',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'assets' ),
				'permission_callback' => array( $this, 'can_view' ),
			)
		);

		register_rest_route(
			self::NS,
			'/assets/(?P<id>\d+)',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'asset' ),
				'permission_callback' => array( $this, 'can_view' ),
			)
		);

		register_rest_route(
			self::NS,
			'/assets/(?P<id>\d+)/owner',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'set_owner' ),
				'permission_callback' => array( $this, 'can_triage' ),
			)
		);

		register_rest_route(
			self::NS,
			'/tickets',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'tickets' ),
					'permission_callback' => array( $this, 'can_view' ),
				),
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'create_ticket' ),
					'permission_callback' => array( $this, 'can_raise' ),
				),
			)
		);

		register_rest_route(
			self::NS,
			'/tickets/draft',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'draft_ticket' ),
				'permission_callback' => array( $this, 'can_raise' ),
			)
		);

		register_rest_route(
			self::NS,
			'/tickets/(?P<id>\d+)/refresh',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'refresh_ticket' ),
				'permission_callback' => array( $this, 'can_raise' ),
			)
		);

		register_rest_route(
			self::NS,
			'/exceptions',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'exceptions' ),
					'permission_callback' => array( $this, 'can_view' ),
				),
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'create_exception' ),
					'permission_callback' => array( $this, 'can_request_exception' ),
				),
			)
		);

		register_rest_route(
			self::NS,
			'/exceptions/(?P<id>\d+)/decide',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'decide_exception' ),
				'permission_callback' => array( $this, 'can_approve' ),
			)
		);

		register_rest_route(
			self::NS,
			'/connectors',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'connectors' ),
				'permission_callback' => array( $this, 'can_manage' ),
			)
		);

		register_rest_route(
			self::NS,
			'/connectors/(?P<id>[a-z0-9_\-]+)/test',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'test_connector' ),
				'permission_callback' => array( $this, 'can_manage' ),
			)
		);

		register_rest_route(
			self::NS,
			'/connectors/(?P<id>[a-z0-9_\-]+)/sync',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'sync_connector' ),
				'permission_callback' => array( $this, 'can_sync' ),
			)
		);

		register_rest_route(
			self::NS,
			'/mapping/run',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'run_mapping' ),
				'permission_callback' => array( $this, 'can_manage' ),
			)
		);
	}

	/* -----------------------------------------------------------------
	 * Permission callbacks
	 * --------------------------------------------------------------- */

	public function can_view(): bool|WP_Error {
		return Caps::can( Caps::VIEW ) ? true : $this->denied();
	}

	public function can_triage(): bool|WP_Error {
		return Caps::can( Caps::TRIAGE ) ? true : $this->denied();
	}

	public function can_raise(): bool|WP_Error {
		return Caps::can( Caps::RAISE_TICKET ) ? true : $this->denied();
	}

	public function can_request_exception(): bool|WP_Error {
		return Caps::can( Caps::REQUEST_EXCEPTION ) ? true : $this->denied();
	}

	public function can_approve(): bool|WP_Error {
		return Caps::can( Caps::APPROVE_EXCEPTION ) ? true : $this->denied();
	}

	public function can_sync(): bool|WP_Error {
		return Caps::can( Caps::RUN_SYNC ) ? true : $this->denied();
	}

	public function can_manage(): bool|WP_Error {
		return Caps::can( Caps::MANAGE ) ? true : $this->denied();
	}

	private function denied(): WP_Error {
		return new WP_Error(
			'vulnhub_forbidden',
			__( 'You do not have permission to do that.', 'vulnhub' ),
			array( 'status' => is_user_logged_in() ? 403 : 401 )
		);
	}

	/* -----------------------------------------------------------------
	 * Handlers
	 * --------------------------------------------------------------- */

	public function summary(): WP_REST_Response {
		return new WP_REST_Response( Repo::summary() );
	}

	public function trend( WP_REST_Request $request ): WP_REST_Response {
		$days = max( 7, min( 365, (int) $request->get_param( 'days' ) ) );
		return new WP_REST_Response(
			Repo::trend(
				array( 'open_critical', 'open_high', 'open_medium', 'open_low', 'tickets_open', 'tickets_done', 'findings_overdue' ),
				$days
			)
		);
	}

	public function breakdown( WP_REST_Request $request ): WP_REST_Response {
		return new WP_REST_Response(
			Repo::breakdown(
				(string) $request->get_param( 'dimension' ),
				max( 1, min( 50, (int) $request->get_param( 'limit' ) ) )
			)
		);
	}

	public function findings( WP_REST_Request $request ): WP_REST_Response {
		$args = $this->list_args(
			$request,
			array( 'state', 'severity', 'asset_id', 'team_id', 'location_id', 'asset_type', 'owner_person_id', 'search', 'has_ticket', 'excepted', 'overdue', 'orderby', 'order' )
		);
		return new WP_REST_Response( Repo::findings( $args ) );
	}

	public function finding( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$id      = (int) $request['id'];
		$finding = Repo::finding( $id );
		if ( ! $finding ) {
			return new WP_Error( 'vulnhub_not_found', __( 'Finding not found.', 'vulnhub' ), array( 'status' => 404 ) );
		}

		$finding['asset'] = Repo::asset( (int) $finding['asset_id'] );
		$finding['vuln']  = Repo::vuln( (int) $finding['vuln_id'] );
		$finding['owner'] = Repo::person( (int) ( $finding['asset']['owner_person_id'] ?? 0 ) );
		$finding['team']  = Repo::team( (int) ( $finding['asset']['team_id'] ?? 0 ) );
		$finding['ticket'] = Tickets::get( (int) $finding['ticket_id'] );

		return new WP_REST_Response( $finding );
	}

	public function assets( WP_REST_Request $request ): WP_REST_Response {
		$args = $this->list_args(
			$request,
			array( 'search', 'asset_type', 'team_id', 'location_id', 'owner_person_id', 'criticality', 'unowned', 'needs_user', 'has_vulns', 'orderby', 'order' )
		);
		return new WP_REST_Response( Repo::assets( $args ) );
	}

	public function asset( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$asset = Repo::asset( (int) $request['id'] );
		if ( ! $asset ) {
			return new WP_Error( 'vulnhub_not_found', __( 'Asset not found.', 'vulnhub' ), array( 'status' => 404 ) );
		}

		$asset['owner']    = Repo::person( (int) $asset['owner_person_id'] );
		$asset['team']     = Repo::team( (int) $asset['team_id'] );
		$asset['location'] = Repo::location( (int) $asset['location_id'] );
		$asset['tags']     = vh_json( $asset['tags_json'] );
		$asset['findings'] = Repo::findings(
			array(
				'asset_id' => (int) $asset['id'],
				'state'    => 'open_any',
				'limit'    => 200,
			)
		);

		return new WP_REST_Response( $asset );
	}

	public function set_owner( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		global $wpdb;

		$asset = Repo::asset( (int) $request['id'] );
		if ( ! $asset ) {
			return new WP_Error( 'vulnhub_not_found', __( 'Asset not found.', 'vulnhub' ), array( 'status' => 404 ) );
		}

		$update = array(
			'owner_source'     => 'manual',
			'owner_confidence' => 'high',
			'owner_rule'       => __( 'Set manually', 'vulnhub' ),
			'updated_at'       => vh_now(),
		);

		$upn = trim( (string) $request->get_param( 'owner_upn' ) );
		if ( '' !== $upn ) {
			$person = Repo::person_by_upn( $upn );
			if ( ! $person ) {
				return new WP_Error(
					'vulnhub_no_person',
					__( 'No person with that UPN or email is known to the platform yet. Run an Intune sync first, or add them manually.', 'vulnhub' ),
					array( 'status' => 400 )
				);
			}
			$update['owner_person_id'] = (int) $person['id'];
		} elseif ( $request->has_param( 'owner_person_id' ) ) {
			$update['owner_person_id'] = (int) $request->get_param( 'owner_person_id' );
		}

		if ( $request->has_param( 'team_id' ) ) {
			$update['team_id'] = (int) $request->get_param( 'team_id' );
		}
		if ( $request->has_param( 'location_id' ) ) {
			$update['location_id'] = (int) $request->get_param( 'location_id' );
		}
		if ( $request->has_param( 'criticality' ) ) {
			$c = (string) $request->get_param( 'criticality' );
			if ( in_array( $c, array( 'critical', 'high', 'medium', 'low' ), true ) ) {
				$update['criticality'] = $c;
			}
		}
		if ( $request->has_param( 'asset_type' ) ) {
			$t = (string) $request->get_param( 'asset_type' );
			if ( array_key_exists( $t, vh_asset_types() ) ) {
				$update['asset_type'] = $t;
			}
		}

		$wpdb->update( vh_table( 'assets' ), $update, array( 'id' => (int) $asset['id'] ) );

		vulnhub()->logger->audit(
			'asset.owner_changed',
			sprintf(
				/* translators: %s: hostname. */
				__( 'Ownership updated for %s', 'vulnhub' ),
				$asset['hostname']
			),
			'asset',
			(int) $asset['id'],
			$update
		);

		return new WP_REST_Response( Repo::asset( (int) $asset['id'] ) );
	}

	public function tickets( WP_REST_Request $request ): WP_REST_Response {
		$args = $this->list_args( $request, array( 'status_category', 'verification_state', 'team_id', 'project_key', 'search', 'open', 'orderby', 'order' ) );
		return new WP_REST_Response( Tickets::query( $args ) );
	}

	/**
	 * Ticket creation is delegated to whichever ITSM connector is installed.
	 */
	public function create_ticket( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$finding_ids = array_filter( array_map( 'intval', (array) $request->get_param( 'finding_ids' ) ) );

		// A reviewed draft carries its own findings; anything else must name some.
		if ( ! $finding_ids && '' === (string) $request->get_param( 'draft' ) ) {
			return new WP_Error( 'vulnhub_no_findings', __( 'Select at least one finding.', 'vulnhub' ), array( 'status' => 400 ) );
		}

		/**
		 * Filters the outcome of a ticket creation request.
		 *
		 * The Jira plugin hooks this and returns
		 * array{ok:bool,message:string,ticket?:array<string,mixed>}.
		 *
		 * @param array<string,mixed>|null $result      Result, null when unhandled.
		 * @param int[]                    $finding_ids Findings to cover.
		 * @param WP_REST_Request          $request     The request.
		 */
		$result = apply_filters( 'vulnhub_create_ticket', null, $finding_ids, $request );

		if ( null === $result ) {
			return new WP_Error(
				'vulnhub_no_itsm',
				__( 'No ticketing integration is active. Enable and configure the Jira connector first.', 'vulnhub' ),
				array( 'status' => 409 )
			);
		}
		if ( empty( $result['ok'] ) ) {
			return new WP_Error( 'vulnhub_ticket_failed', (string) ( $result['message'] ?? __( 'Ticket creation failed.', 'vulnhub' ) ), array( 'status' => 502 ) );
		}

		return new WP_REST_Response( $result );
	}

	/**
	 * Build a ticket for review: everything that would be sent, nothing sent.
	 */
	public function draft_ticket( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$params = array(
			'finding_ids' => array_filter( array_map( 'intval', (array) $request->get_param( 'finding_ids' ) ) ),
			'all'         => (bool) $request->get_param( 'all' ),
			'filters'     => (array) $request->get_param( 'filters' ),
			'cols'        => array_map( 'sanitize_key', (array) $request->get_param( 'cols' ) ),
			// An asset-list ticket (Assets & owners): the list's filters, its
			// raw query, the request type and the operator's own words.
			'scope'       => sanitize_key( (string) $request->get_param( 'scope' ) ),
			'kind'        => sanitize_key( (string) $request->get_param( 'kind' ) ),
			'query'       => (array) $request->get_param( 'query' ),
			'summary'     => (string) $request->get_param( 'summary' ),
			'notes'       => (string) $request->get_param( 'notes' ),
			'due_date'    => (string) $request->get_param( 'due_date' ),
		);

		/**
		 * Filters a ticket draft: the exact fields, description and attachment
		 * a raise would send, kept under a token that sending must name.
		 * Nothing is created.
		 *
		 * @param array<string,mixed>|null $result Result, null when unhandled.
		 * @param array<string,mixed>      $params finding_ids | all + filters; cols.
		 */
		$result = apply_filters( 'vulnhub_draft_ticket', null, $params );

		if ( null === $result ) {
			return new WP_Error( 'vulnhub_no_itsm', __( 'No ticketing integration is active. Enable and configure the Jira connector first.', 'vulnhub' ), array( 'status' => 409 ) );
		}

		return new WP_REST_Response( $result );
	}

	public function refresh_ticket( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$ticket = Tickets::get( (int) $request['id'] );
		if ( ! $ticket ) {
			return new WP_Error( 'vulnhub_not_found', __( 'Ticket not found.', 'vulnhub' ), array( 'status' => 404 ) );
		}

		/**
		 * Filters a single-ticket refresh.
		 *
		 * @param array<string,mixed>|null $result Result.
		 * @param array<string,mixed>      $ticket Ticket row.
		 */
		$result = apply_filters( 'vulnhub_refresh_ticket', null, $ticket );

		if ( null === $result ) {
			return new WP_Error( 'vulnhub_no_itsm', __( 'No ticketing integration is active.', 'vulnhub' ), array( 'status' => 409 ) );
		}

		return new WP_REST_Response( $result );
	}

	public function exceptions( WP_REST_Request $request ): WP_REST_Response {
		$args = $this->list_args( $request, array( 'status', 'reason', 'team_id', 'requested_by', 'expiring_days', 'search' ) );
		return new WP_REST_Response( Exceptions::query( $args ) );
	}

	public function create_exception( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$result = Exceptions::create(
			array(
				'scope_type'            => (string) $request->get_param( 'scope_type' ),
				'scope_ref'             => (string) $request->get_param( 'scope_ref' ),
				'asset_id'              => (int) $request->get_param( 'asset_id' ),
				'vuln_id'               => (int) $request->get_param( 'vuln_id' ),
				'team_id'               => (int) $request->get_param( 'team_id' ),
				'severity'              => (string) $request->get_param( 'severity' ),
				'title'                 => (string) $request->get_param( 'title' ),
				'reason'                => (string) $request->get_param( 'reason' ),
				'justification'         => (string) $request->get_param( 'justification' ),
				'compensating_controls' => (string) $request->get_param( 'compensating_controls' ),
				'business_impact'       => (string) $request->get_param( 'business_impact' ),
				'expires_at'            => (string) $request->get_param( 'expires_at' ),
				'review_at'             => (string) $request->get_param( 'review_at' ),
				'submit'                => (bool) $request->get_param( 'submit' ),
			)
		);

		if ( empty( $result['ok'] ) ) {
			return new WP_Error( 'vulnhub_exception_failed', (string) $result['message'], array( 'status' => 400 ) );
		}

		return new WP_REST_Response( $result );
	}

	public function decide_exception( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$decision = (string) $request->get_param( 'decision' );
		$result   = 'revoked' === $decision
			? Exceptions::revoke( (int) $request['id'], (string) $request->get_param( 'note' ) )
			: Exceptions::decide( (int) $request['id'], $decision, (string) $request->get_param( 'note' ) );

		if ( empty( $result['ok'] ) ) {
			return new WP_Error( 'vulnhub_decision_failed', (string) $result['message'], array( 'status' => 400 ) );
		}

		return new WP_REST_Response( $result );
	}

	public function connectors(): WP_REST_Response {
		$out = array();
		foreach ( vulnhub()->connectors->all() as $id => $connector ) {
			$out[] = array(
				'id'          => $id,
				'label'       => $connector->label(),
				'description' => $connector->description(),
				'category'    => $connector->category(),
				'enabled'     => $connector->is_enabled(),
				'configured'  => $connector->is_configured(),
				'mock'        => $connector->is_mock(),
				'health'      => $connector->health(),
				'next_run'    => Scheduler::next_run( $id ),
			);
		}
		return new WP_REST_Response( $out );
	}

	public function test_connector( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$connector = vulnhub()->connectors->get( (string) $request['id'] );
		if ( ! $connector ) {
			return new WP_Error( 'vulnhub_not_found', __( 'Connector not found.', 'vulnhub' ), array( 'status' => 404 ) );
		}
		return new WP_REST_Response( $connector->test_connection() );
	}

	public function sync_connector( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$connector = vulnhub()->connectors->get( (string) $request['id'] );
		if ( ! $connector ) {
			return new WP_Error( 'vulnhub_not_found', __( 'Connector not found.', 'vulnhub' ), array( 'status' => 404 ) );
		}

		// A long connector runs in the background so the browser is not held
		// open for a multi-minute import (and the sync is not lost if the tab
		// is closed). The progress poller shows it running; a resume picks it
		// up if it is interrupted.
		//
		// A full resync goes the same way. It used to be the exception -- `full`
		// forced the sync inline -- which put the longest run the connector has
		// inside a web request, and the staged sync ignored the flag anyway.
		// Now the request is recorded on the connector and the run is queued.
		$full = (bool) $request->get_param( 'full' );

		if ( $connector->async_sync() ) {
			if ( $full && $connector->supports_full_sync() ) {
				$connector->request_full_sync();
			}

			\VulnHub\Core\Scheduler::queue_sync( (string) $connector->id() );

			return new WP_REST_Response(
				array(
					'ok'      => true,
					'queued'  => true,
					'full'    => $full && $connector->supports_full_sync(),
					'message' => $full && $connector->supports_full_sync()
						? __( 'Full resync queued in the background — you can watch its progress here. It downloads everything the source holds, so it takes longer than a normal sync.', 'vulnhub' )
						: __( 'Sync started in the background — you can watch its progress here.', 'vulnhub' ),
				)
			);
		}

		$result = $connector->sync(
			array(
				'mode'  => 'manual',
				'force' => (bool) $request->get_param( 'force' ),
				'full'  => $full,
			)
		);

		return new WP_REST_Response( $result );
	}

	public function run_mapping(): WP_REST_Response {
		$result = ( new Mapping() )->run();
		return new WP_REST_Response( $result );
	}

	/* -----------------------------------------------------------------
	 * Helpers
	 * --------------------------------------------------------------- */

	/**
	 * Collect whitelisted list params plus pagination.
	 *
	 * @param string[] $keys Allowed filter keys.
	 * @return array<string,mixed>
	 */
	private function list_args( WP_REST_Request $request, array $keys ): array {
		$args = array(
			'limit'  => max( 1, min( 300, (int) ( $request->get_param( 'limit' ) ?: 50 ) ) ),
			'offset' => max( 0, (int) $request->get_param( 'offset' ) ),
		);
		foreach ( $keys as $key ) {
			$value = $request->get_param( $key );
			if ( null !== $value && '' !== $value ) {
				$args[ $key ] = is_array( $value ) ? array_map( 'sanitize_text_field', $value ) : sanitize_text_field( (string) $value );
			}
		}
		return $args;
	}
}

