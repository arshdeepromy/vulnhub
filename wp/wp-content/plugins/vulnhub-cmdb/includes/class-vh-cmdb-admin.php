<?php
/**
 * Admin form handling for the CMDB screen.
 *
 * Three `admin_post` endpoints: upload-and-preview, re-map-and-preview, and
 * import. Every one of them checks a nonce and the manage capability before it
 * looks at a single byte of input.
 *
 * The uploaded file itself is never persisted. It is parsed straight out of
 * PHP's upload temporary directory — which is outside the web root and which
 * PHP clears at the end of the request — and only the parsed rows survive, in
 * a transient that expires in half an hour.
 *
 * @package VulnHub\Cmdb
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Form handlers for the CMDB screen.
 */
final class VulnHub_Cmdb_Admin {

	/** Transient prefix for a staged preview. */
	private const PREVIEW_PREFIX = 'vulnhub_cmdb_preview_';

	/** How long a staged preview survives. */
	private const PREVIEW_TTL = 1800;

	/** Transient prefix for a one-shot admin notice. */
	private const NOTICE_PREFIX = 'vulnhub_cmdb_notice_';

	/**
	 * Register the handlers.
	 */
	public function hooks(): void {
		add_action( 'admin_post_vulnhub_cmdb_upload', array( $this, 'handle_upload' ) );
		add_action( 'admin_post_vulnhub_cmdb_remap', array( $this, 'handle_remap' ) );
		add_action( 'admin_post_vulnhub_cmdb_import', array( $this, 'handle_import' ) );
		add_action( 'admin_post_vulnhub_cmdb_mapping', array( $this, 'handle_mapping' ) );
		add_action( 'admin_post_vulnhub_cmdb_discard', array( $this, 'handle_discard' ) );
		add_action( 'admin_post_vulnhub_cmdb_assets_preview', array( $this, 'handle_assets_preview' ) );
	}

	/* =================================================================
	 * Handlers
	 * ============================================================== */

	/**
	 * Validate an uploaded CSV, parse it, and stage a preview.
	 */
	public function handle_upload(): void {
		$this->guard( 'vulnhub_cmdb_upload' );

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- guard() verified the nonce.
		$file = isset( $_FILES['vh_cmdb_file'] ) && is_array( $_FILES['vh_cmdb_file'] ) ? wp_unslash( $_FILES['vh_cmdb_file'] ) : array();

		$checked = VulnHub_Cmdb_Csv::validate_upload( $file );

		if ( ! $checked['ok'] ) {
			$this->notice( 'error', $checked['message'] );
			$this->redirect( 'csv' );
		}

		$parsed = VulnHub_Cmdb_Csv::parse( $checked['path'] );

		if ( ! $parsed['headers'] ) {
			$message = $parsed['errors'][0]['message'] ?? __( 'The file could not be parsed.', 'vulnhub' );
			$this->notice( 'error', (string) $message );
			$this->redirect( 'csv' );
		}

		if ( ! $parsed['rows'] ) {
			$this->notice( 'error', __( 'The file has a header row but no data rows.', 'vulnhub' ) );
			$this->redirect( 'csv' );
		}

		$connector = $this->connector();
		$map       = $connector ? $connector->column_map() : array();
		$detected  = VulnHub_Cmdb_Schema::detect_mapping( $parsed['headers'], array_slice( (array) ( $parsed['rows'] ?? array() ), 0, 50 ) );

		// The stored mapping only applies if its columns exist in this file.
		$usable = array();
		foreach ( $map as $field => $header ) {
			if ( in_array( $header, $parsed['headers'], true ) ) {
				$usable[ $field ] = $header;
			}
		}

		$token = $this->stage(
			array(
				'source'    => 'csv',
				'tab'       => 'csv',
				'file'      => $checked['name'],
				'headers'   => $parsed['headers'],
				'rows'      => $parsed['rows'],
				'errors'    => $parsed['errors'],
				'delimiter' => $parsed['delimiter'],
				'truncated' => $parsed['truncated'],
				'map'       => $usable ?: $detected,
				'detected'  => $detected,
			)
		);

		$this->notice(
			'success',
			sprintf(
				/* translators: 1: number of rows, 2: file name. */
				__( 'Parsed %1$d row(s) from %2$s. Review the mapping and the preview below, then import.', 'vulnhub' ),
				count( $parsed['rows'] ),
				$checked['name']
			)
		);

		$this->redirect( 'csv', array( 'preview' => $token ) );
	}

	/**
	 * Fetch live Jira Assets objects and stage the same preview a CSV upload
	 * would stage.
	 *
	 * Deliberately the identical flow: fetch, flatten, detect the mapping,
	 * dry run, show the operator what would change, let them correct the
	 * mapping, and only then import. An API source is not a reason to skip the
	 * step where somebody looks at the data before it lands on the inventory.
	 */
	public function handle_assets_preview(): void {
		$this->guard( 'vulnhub_cmdb_assets_preview' );

		$connector = $this->connector();

		if ( ! $connector ) {
			$this->notice( 'error', __( 'The CMDB connector is not registered.', 'vulnhub' ) );
			$this->redirect( 'assets' );
		}

		if ( 'assets' !== $connector->source() ) {
			$this->notice( 'error', __( 'Set the source system to Jira Service Management Assets on the Integrations screen first.', 'vulnhub' ) );
			$this->redirect( 'assets' );
		}

		$fetched = $connector->fetch_assets_rows();

		if ( ! $fetched['ok'] ) {
			$this->notice( 'error', $fetched['message'] );
			$this->redirect( 'assets' );
		}

		$token = $this->stage(
			array(
				'source'    => 'assets',
				'tab'       => 'assets',
				'file'      => __( 'Jira Assets', 'vulnhub' ),
				'headers'   => $fetched['headers'],
				'rows'      => $fetched['rows'],
				'errors'    => array(),
				'delimiter' => '',
				'truncated' => false,
				'map'       => $fetched['map'],
				'detected'  => $fetched['map'],
			)
		);

		$this->notice(
			'success',
			sprintf(
				/* translators: 1: number of objects, 2: number of attribute names. */
				__( 'Read %1$d object(s) carrying %2$d distinct attribute name(s). Check the mapping and the preview below, then import.', 'vulnhub' ),
				count( $fetched['rows'] ),
				count( $fetched['headers'] )
			)
		);

		$this->redirect( 'assets', array( 'preview' => $token ) );
	}

	/**
	 * Re-apply an operator-corrected column mapping to a staged preview.
	 */
	public function handle_remap(): void {
		$this->guard( 'vulnhub_cmdb_remap' );

		$token   = $this->token_from_request();
		$staged  = $this->staged( $token );

		if ( ! $staged ) {
			$this->notice( 'error', __( 'That preview has expired. Fetch the source again.', 'vulnhub' ) );
			$this->redirect( 'csv' );
		}

		$tab           = $this->tab_for( $staged );
		$staged['map'] = $this->map_from_request( (array) $staged['headers'] );

		set_transient( self::PREVIEW_PREFIX . $token, $staged, self::PREVIEW_TTL );

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- guard() verified the nonce.
		if ( ! empty( $_POST['vh_cmdb_save_mapping'] ) ) {
			$this->save_mapping( $staged['map'], (string) ( $staged['source'] ?? 'csv' ) );
			$this->notice( 'success', __( 'Mapping updated and saved as the default for this source.', 'vulnhub' ) );
		} else {
			$this->notice( 'success', __( 'Mapping updated. The preview below reflects it.', 'vulnhub' ) );
		}

		$this->redirect( $tab, array( 'preview' => $token ) );
	}

	/**
	 * Import a staged preview for real.
	 */
	public function handle_import(): void {
		$this->guard( 'vulnhub_cmdb_import' );

		$token  = $this->token_from_request();
		$staged = $this->staged( $token );

		if ( ! $staged ) {
			$this->notice( 'error', __( 'That preview has expired. Fetch the source again.', 'vulnhub' ) );
			$this->redirect( 'csv' );
		}

		$tab       = $this->tab_for( $staged );
		$connector = $this->connector();

		if ( ! $connector ) {
			$this->notice( 'error', __( 'The CMDB connector is not registered.', 'vulnhub' ) );
			$this->redirect( $tab );
		}

		$records = $this->records_from( $staged );

		if ( ! $records ) {
			$this->notice( 'error', __( 'No usable rows in that preview.', 'vulnhub' ) );
			$this->redirect( $tab, array( 'preview' => $token ) );
		}

		/*
		 * A CSV has no source to go back to, so its rows are staged for replay
		 * on the next scheduled sync. Assets does have one: staging a copy
		 * there would mean a nightly sync replayed a week-old snapshot of the
		 * workspace instead of reading it, so it re-fetches instead.
		 */
		if ( 'assets' !== (string) ( $staged['source'] ?? 'csv' ) ) {
			// Stage the rows first so a scheduled sync can replay exactly what
			// was imported, then run the import through the connector's own
			// sync entry point — which gives it a run log, the 30-minute lock
			// and, on success, the ownership mapping pass.
			$connector->store_rows(
				$records,
				array(
					'file'   => (string) $staged['file'],
					'source' => 'upload',
				)
			);
		}

		$result = $connector->sync(
			array(
				'force'   => true,
				'mode'    => 'manual',
				'records' => $records,
			)
		);

		delete_transient( self::PREVIEW_PREFIX . $token );

		$this->notice(
			! empty( $result['ok'] ) ? 'success' : 'error',
			(string) ( $result['message'] ?? '' )
		);

		$this->redirect( $tab );
	}

	/**
	 * Save the default column mapping from the Column mapping tab.
	 */
	public function handle_mapping(): void {
		$this->guard( 'vulnhub_cmdb_mapping' );

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- guard() verified the nonce.
		$headers = isset( $_POST['vh_cmdb_headers'] ) ? (array) wp_unslash( $_POST['vh_cmdb_headers'] ) : array();
		$headers = array_map( 'sanitize_text_field', array_map( 'strval', $headers ) );

		$this->save_mapping( $this->map_from_request( $headers, true ) );

		$this->notice( 'success', __( 'Column mapping saved.', 'vulnhub' ) );
		$this->redirect( 'mapping' );
	}

	/**
	 * Discard the staged CSV rows.
	 */
	public function handle_discard(): void {
		$this->guard( 'vulnhub_cmdb_discard' );

		$connector = $this->connector();

		if ( $connector ) {
			$connector->store_rows( array(), array( 'file' => '' ) );
		}

		$this->notice( 'success', __( 'Staged CSV rows discarded.', 'vulnhub' ) );
		$this->redirect( 'csv' );
	}

	/* =================================================================
	 * Shared helpers
	 * ============================================================== */

	/**
	 * Turn a staged preview into canonical records.
	 *
	 * @param array<string,mixed> $staged Staged preview.
	 * @return array<int,array<string,string>>
	 */
	public function records_from( array $staged ): array {
		$map     = (array) ( $staged['map'] ?? array() );
		$rows    = (array) ( $staged['rows'] ?? array() );
		$file    = (string) ( $staged['file'] ?? '' );
		$records = array();

		/*
		 * Assets records go through the connector's own normaliser rather than
		 * bare `apply_mapping()`, because the object type has to survive as an
		 * explicit asset type and the provenance has to say Assets, not CSV.
		 */
		if ( 'assets' === (string) ( $staged['source'] ?? 'csv' ) ) {
			$connector = $this->connector();

			if ( ! $connector ) {
				return array();
			}

			return $connector->normalise_assets_rows( $rows, $map );
		}

		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}

			$record                = VulnHub_Cmdb_Schema::apply_mapping( $row, $map );
			$record['source_ref']  = $file;
			$record['source_kind'] = 'csv:' . $file;
			$record['source_line'] = (string) ( $row['__line'] ?? '' );

			$records[] = $record;
		}

		return $records;
	}

	/**
	 * A staged preview, or null.
	 *
	 * @return array<string,mixed>|null
	 */
	public function staged( string $token ): ?array {
		if ( '' === $token ) {
			return null;
		}

		$staged = get_transient( self::PREVIEW_PREFIX . $token );

		return is_array( $staged ) ? $staged : null;
	}

	/**
	 * Stash a preview and return its token.
	 *
	 * @param array<string,mixed> $staged Preview payload.
	 */
	private function stage( array $staged ): string {
		$token = wp_generate_password( 20, false, false );

		set_transient( self::PREVIEW_PREFIX . $token, $staged, self::PREVIEW_TTL );

		return $token;
	}

	/**
	 * The preview token from the current request, sanitised.
	 */
	private function token_from_request(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- guard() verified the nonce.
		$token = isset( $_POST['vh_cmdb_token'] ) ? sanitize_key( wp_unslash( $_POST['vh_cmdb_token'] ) ) : '';

		return $token;
	}

	/**
	 * Read a submitted column mapping.
	 *
	 * @param array<int,string> $headers Headers the mapping may refer to.
	 * @param bool              $free    Allow headers that are not in the list.
	 * @return array<string,string>
	 */
	private function map_from_request( array $headers, bool $free = false ): array {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- guard() verified the nonce.
		$submitted = isset( $_POST['vh_cmdb_map'] ) ? (array) wp_unslash( $_POST['vh_cmdb_map'] ) : array();
		$fields    = VulnHub_Cmdb_Schema::fields();
		$map       = array();

		foreach ( $submitted as $field => $header ) {
			$field  = sanitize_key( (string) $field );
			$header = sanitize_text_field( (string) $header );

			if ( ! isset( $fields[ $field ] ) || '' === $header ) {
				continue;
			}
			if ( ! $free && ! in_array( $header, $headers, true ) ) {
				continue;
			}

			$map[ $field ] = $header;
		}

		return $map;
	}

	/**
	 * Persist a column mapping on the connector's settings.
	 *
	 * @param array<string,string> $map    Column mapping.
	 * @param string               $source Which source the mapping belongs to.
	 */
	private function save_mapping( array $map, string $source = 'csv' ): void {
		$key = 'assets' === $source
			? VulnHub_Cmdb_Connector::OPT_ASSETS_MAP
			: VulnHub_Cmdb_Connector::OPT_COLUMN_MAP;

		vulnhub()->settings->update(
			VulnHub_Cmdb_Connector::SOURCE,
			array( $key => $map )
		);
	}

	/**
	 * Which tab a staged preview belongs to.
	 *
	 * @param array<string,mixed> $staged Staged preview.
	 */
	private function tab_for( array $staged ): string {
		$tab = sanitize_key( (string) ( $staged['tab'] ?? 'csv' ) );

		return in_array( $tab, array( 'csv', 'assets' ), true ) ? $tab : 'csv';
	}

	/**
	 * Capability and nonce check, shared by every handler.
	 */
	private function guard( string $action ): void {
		if ( ! current_user_can( 'vulnhub_manage' ) ) {
			wp_die( esc_html__( 'You do not have permission to change the CMDB integration.', 'vulnhub' ), 403 );
		}

		check_admin_referer( $action );
	}

	/**
	 * The registered connector instance, if core has one.
	 */
	private function connector(): ?VulnHub_Cmdb_Connector {
		if ( ! function_exists( 'vulnhub' ) ) {
			return null;
		}

		$connector = vulnhub()->connectors->get( VulnHub_Cmdb_Connector::SOURCE );

		return $connector instanceof VulnHub_Cmdb_Connector ? $connector : null;
	}

	/**
	 * Queue a one-shot notice for the current user.
	 *
	 * @param string $type    success|error.
	 * @param string $message Message text.
	 */
	private function notice( string $type, string $message ): void {
		set_transient(
			self::NOTICE_PREFIX . get_current_user_id(),
			array(
				'type'    => 'error' === $type ? 'error' : 'success',
				'message' => $message,
			),
			60
		);
	}

	/**
	 * Read and clear the current user's notice.
	 *
	 * @return array{type:string,message:string}|null
	 */
	public static function take_notice(): ?array {
		$key    = self::NOTICE_PREFIX . get_current_user_id();
		$notice = get_transient( $key );

		if ( ! is_array( $notice ) || empty( $notice['message'] ) ) {
			return null;
		}

		delete_transient( $key );

		return array(
			'type'    => (string) ( $notice['type'] ?? 'success' ),
			'message' => (string) $notice['message'],
		);
	}

	/**
	 * Send the operator back to the screen and stop.
	 *
	 * @param string                   $tab  Tab to land on.
	 * @param array<string,string|int> $args Extra query arguments.
	 */
	private function redirect( string $tab, array $args = array() ): void {
		wp_safe_redirect( vh_admin_url( 'vulnhub-cmdb', array_merge( array( 'tab' => $tab ), $args ) ) );
		exit;
	}
}

