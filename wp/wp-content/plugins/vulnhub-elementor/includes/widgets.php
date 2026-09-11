<?php
/**
 * Every VulnHub Elementor widget.
 *
 * These are thin. The rendering, the SQL and the accessibility work all
 * already exist inside vulnhub-dashboard and vulnhub-core; a widget's job is
 * to expose the handful of choices worth making in the editor and then call
 * through. Anything that starts growing its own query belongs in the repo.
 *
 * @package VulnHub\Elementor
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Elementor\Controls_Manager;
use VulnHub\Core\Coverage;
use VulnHub\Core\Repo;

/* =====================================================================
 * The saved dashboard board
 * ================================================================== */

/**
 * The reader's own dashboard, exactly as they arranged it in the portal.
 */
final class VulnHub_El_Board extends VulnHub_El_Widget_Base {

	public function get_name(): string {
		return 'vulnhub-board';
	}

	public function get_title(): string {
		return esc_html__( 'VulnHub dashboard board', 'vulnhub' );
	}

	public function get_icon(): string {
		return 'eicon-gallery-grid';
	}

	protected function register_controls(): void {
		$this->start_controls_section(
			'vh_content',
			array( 'label' => esc_html__( 'Board', 'vulnhub' ) )
		);

		$this->add_heading_controls();

		$this->add_control(
			'vh_note',
			array(
				'type'            => Controls_Manager::RAW_HTML,
				'raw'             => esc_html__( 'Shows each person their own saved arrangement of widgets. They change it from the portal dashboard, not from here.', 'vulnhub' ),
				'content_classes' => 'elementor-descriptor',
			)
		);

		$this->end_controls_section();
	}

	protected function render(): void {
		if ( ! $this->may_view() ) {
			$this->render_denied();
			return;
		}

		$this->print_heading();

		$layout = VulnHub_Dash_Widgets::layout();

		if ( ! $layout ) {
			$this->render_empty( esc_html__( 'This board is empty.', 'vulnhub' ) );
			return;
		}

		echo '<div class="vh-board">';
		foreach ( $layout as $item ) {
			VulnHub_Dash_Widgets::render( (string) $item['id'], (int) $item['width'] );
		}
		echo '</div>';
	}
}

/* =====================================================================
 * One dashboard panel
 * ================================================================== */

/**
 * Any single one of the twenty-one dashboard widgets, on any page.
 */
final class VulnHub_El_Panel extends VulnHub_El_Widget_Base {

	public function get_name(): string {
		return 'vulnhub-panel';
	}

	public function get_title(): string {
		return esc_html__( 'VulnHub panel', 'vulnhub' );
	}

	public function get_icon(): string {
		return 'eicon-tabs';
	}

	protected function register_controls(): void {
		$this->start_controls_section(
			'vh_content',
			array( 'label' => esc_html__( 'Panel', 'vulnhub' ) )
		);

		$this->add_control(
			'vh_panel',
			array(
				'label'       => esc_html__( 'Which panel', 'vulnhub' ),
				'type'        => Controls_Manager::SELECT,
				'options'     => VulnHub_El_Widgets::panel_options(),
				'default'     => 'coverage_by_type',
				'label_block' => true,
			)
		);

		$this->add_control(
			'vh_width',
			array(
				'label'       => esc_html__( 'Grid width', 'vulnhub' ),
				'description' => esc_html__( 'Out of twelve. Only matters when several panels sit side by side in one container.', 'vulnhub' ),
				'type'        => Controls_Manager::SELECT,
				'options'     => array(
					'3'  => esc_html__( 'A quarter', 'vulnhub' ),
					'4'  => esc_html__( 'A third', 'vulnhub' ),
					'6'  => esc_html__( 'A half', 'vulnhub' ),
					'8'  => esc_html__( 'Two thirds', 'vulnhub' ),
					'12' => esc_html__( 'Full width', 'vulnhub' ),
				),
				'default'     => '12',
			)
		);

		$this->end_controls_section();
	}

	protected function render(): void {
		if ( ! $this->may_view() ) {
			$this->render_denied();
			return;
		}

		$s  = $this->get_settings_for_display();
		$id = (string) ( $s['vh_panel'] ?? '' );

		if ( ! isset( VulnHub_Dash_Widgets::all()[ $id ] ) ) {
			$this->render_empty( esc_html__( 'Choose a panel.', 'vulnhub' ) );
			return;
		}

		echo '<div class="vh-board">';
		VulnHub_Dash_Widgets::render( $id, (int) ( $s['vh_width'] ?? 12 ) );
		echo '</div>';
	}
}

/* =====================================================================
 * KPI tiles
 * ================================================================== */

/**
 * A row of headline numbers, chosen one at a time.
 */
final class VulnHub_El_Kpi extends VulnHub_El_Widget_Base {

	public function get_name(): string {
		return 'vulnhub-kpi';
	}

	public function get_title(): string {
		return esc_html__( 'VulnHub KPI tiles', 'vulnhub' );
	}

	public function get_icon(): string {
		return 'eicon-counter';
	}

	protected function register_controls(): void {
		$this->start_controls_section(
			'vh_content',
			array( 'label' => esc_html__( 'Tiles', 'vulnhub' ) )
		);

		$this->add_heading_controls();

		$repeater = new \Elementor\Repeater();

		$repeater->add_control(
			'metric',
			array(
				'label'       => esc_html__( 'Measure', 'vulnhub' ),
				'type'        => Controls_Manager::SELECT,
				'options'     => VulnHub_El_Widgets::metric_options(),
				'default'     => 'critical',
				'label_block' => true,
			)
		);

		$repeater->add_control(
			'label',
			array(
				'label'       => esc_html__( 'Label override', 'vulnhub' ),
				'type'        => Controls_Manager::TEXT,
				'placeholder' => esc_html__( 'Leave empty to use the standard wording', 'vulnhub' ),
				'label_block' => true,
			)
		);

		$this->add_control(
			'vh_tiles',
			array(
				'label'       => esc_html__( 'Tiles', 'vulnhub' ),
				'type'        => Controls_Manager::REPEATER,
				'fields'      => $repeater->get_controls(),
				'title_field' => '{{{ metric }}}',
				'default'     => array(
					array( 'metric' => 'critical' ),
					array( 'metric' => 'overdue' ),
					array( 'metric' => 'coverage_percent' ),
					array( 'metric' => 'assets_unowned' ),
				),
			)
		);

		$this->end_controls_section();
	}

	protected function render(): void {
		if ( ! $this->may_view() ) {
			$this->render_denied();
			return;
		}

		$tiles = (array) ( $this->get_settings_for_display( 'vh_tiles' ) ?? array() );

		if ( ! $tiles ) {
			$this->render_empty( esc_html__( 'Add at least one tile.', 'vulnhub' ) );
			return;
		}

		$this->print_heading();

		$labels = VulnHub_El_Widgets::metric_options();

		echo '<div class="vh-tiles">';
		foreach ( $tiles as $tile ) {
			$key = (string) ( $tile['metric'] ?? '' );

			if ( ! isset( $labels[ $key ] ) ) {
				continue;
			}

			$resolved = VulnHub_El_Widgets::metric_value( $key );
			$label    = trim( (string) ( $tile['label'] ?? '' ) );

			echo VulnHub_Dash_Charts::stat_tile( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside stat_tile().
				array(
					'label' => '' !== $label ? $label : $labels[ $key ],
					'value' => $resolved['value'],
					'tone'  => $resolved['tone'],
				)
			);
		}
		echo '</div>';
	}
}

/* =====================================================================
 * Tenable scanning coverage
 * ================================================================== */

/**
 * The coverage widget the brief asked for: by device type, by site, by team,
 * by anything, in whichever of four shapes suits the page.
 */
final class VulnHub_El_Coverage extends VulnHub_El_Widget_Base {

	public function get_name(): string {
		return 'vulnhub-coverage';
	}

	public function get_title(): string {
		return esc_html__( 'VulnHub Tenable coverage', 'vulnhub' );
	}

	public function get_icon(): string {
		return 'eicon-progress-tracker';
	}

	protected function register_controls(): void {
		$this->start_controls_section(
			'vh_content',
			array( 'label' => esc_html__( 'Coverage', 'vulnhub' ) )
		);

		$this->add_heading_controls( esc_html__( 'Tenable scanning coverage', 'vulnhub' ) );

		$this->add_control(
			'vh_dimension',
			array(
				'label'       => esc_html__( 'Break down by', 'vulnhub' ),
				'type'        => Controls_Manager::SELECT,
				'options'     => VulnHub_El_Widgets::dimension_options(),
				'default'     => 'asset_type',
				'label_block' => true,
			)
		);

		$this->add_control(
			'vh_view',
			array(
				'label'   => esc_html__( 'Shown as', 'vulnhub' ),
				'type'    => Controls_Manager::SELECT,
				'options' => array(
					'bars'  => esc_html__( 'Coverage bars', 'vulnhub' ),
					'donut' => esc_html__( 'Donut of coverage states', 'vulnhub' ),
					'meter' => esc_html__( 'One overall meter', 'vulnhub' ),
					'table' => esc_html__( 'Table only', 'vulnhub' ),
				),
				'default' => 'bars',
			)
		);

		$this->add_control(
			'vh_limit',
			array(
				'label'     => esc_html__( 'Rows', 'vulnhub' ),
				'type'      => Controls_Manager::NUMBER,
				'min'       => 1,
				'max'       => 40,
				'default'   => 12,
				'condition' => array( 'vh_view' => array( 'bars', 'table' ) ),
			)
		);

		$this->add_control(
			'vh_show_summary',
			array(
				'label'        => esc_html__( 'Show the headline line', 'vulnhub' ),
				'type'         => Controls_Manager::SWITCHER,
				'default'      => 'yes',
				'return_value' => 'yes',
			)
		);

		$this->end_controls_section();
	}

	protected function render(): void {
		if ( ! $this->may_view() ) {
			$this->render_denied();
			return;
		}

		$s       = $this->get_settings_for_display();
		$view    = (string) ( $s['vh_view'] ?? 'bars' );
		$dim     = (string) ( $s['vh_dimension'] ?? 'asset_type' );
		$limit   = max( 1, min( 40, (int) ( $s['vh_limit'] ?? 12 ) ) );
		$summary = Coverage::summary();

		echo '<div class="vh-card vh-el__cov">';
		$this->print_heading();

		if ( 'yes' === (string) ( $s['vh_show_summary'] ?? '' ) ) {
			printf(
				'<p class="vh-sub">%s</p>',
				esc_html(
					sprintf(
						/* translators: 1: covered assets, 2: assets in scope, 3: gap count, 4: freshness window in days. */
						__( '%1$s of %2$s in-scope assets have a Tenable scan inside %4$s days. %3$s do not.', 'vulnhub' ),
						number_format_i18n( (int) $summary['covered'] ),
						number_format_i18n( (int) $summary['in_scope'] ),
						number_format_i18n( (int) $summary['gaps'] ),
						number_format_i18n( (int) $summary['window_days'] )
					)
				)
			);
		}

		if ( 'meter' === $view ) {
			$pct = (float) $summary['percent'];
			echo VulnHub_Dash_Charts::meter( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside meter().
				(float) $summary['covered'],
				(float) max( 1, (int) $summary['in_scope'] ),
				__( 'Scanned recently', 'vulnhub' ),
				$pct >= 95 ? 'ok' : ( $pct >= 80 ? 'warn' : 'bad' )
			);
			echo '</div>';
			return;
		}

		if ( 'donut' === $view ) {
			/*
			 * Without a colour every slice fell back to series 1, so the donut
			 * and its legend came out in one flat blue and the states were only
			 * distinguishable by reading the numbers. Same mapping the portal's
			 * own coverage widget uses.
			 */
			$tone = array(
				Coverage::COVERED        => 'var(--vh-good)',
				Coverage::STALE          => 'var(--vh-sev-medium)',
				Coverage::NEVER_SCANNED  => 'var(--vh-sev-high)',
				Coverage::NOT_IN_TENABLE => 'var(--vh-sev-critical)',
				Coverage::OUT_OF_SCOPE   => 'var(--vh-muted)',
			);

			$rows = array();
			foreach ( Coverage::states() as $state => $def ) {
				$rows[] = array(
					'label' => Coverage::label( $state ),
					'value' => (float) ( $summary['states'][ $state ] ?? 0 ),
					'color' => $tone[ $state ] ?? 'var(--vh-muted)',
				);
			}
			echo VulnHub_Dash_Charts::donut( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside donut().
				$rows,
				array(
					'centre'       => number_format_i18n( (float) $summary['percent'], 1 ) . '%',
					'centre_label' => __( 'covered', 'vulnhub' ),
				)
			);
			echo '</div>';
			return;
		}

		$rows = Coverage::by_dimension( $dim, $limit );

		if ( ! $rows ) {
			$this->render_empty( esc_html__( 'No assets carry that attribute yet.', 'vulnhub' ) );
			echo '</div>';
			return;
		}

		if ( 'table' === $view ) {
			echo VulnHub_Dash_Charts::table_view( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside table_view().
				array(
					__( 'Group', 'vulnhub' ),
					__( 'Total', 'vulnhub' ),
					__( 'Covered', 'vulnhub' ),
					__( 'Gaps', 'vulnhub' ),
					__( 'Coverage %', 'vulnhub' ),
				),
				array_map(
					static fn( array $row ): array => array(
						(string) $row['label'],
						number_format_i18n( (int) $row['total'] ),
						number_format_i18n( (int) $row['covered'] ),
						number_format_i18n( (int) $row['gaps'] ),
						number_format_i18n( round( (float) $row['percent'], 1 ) ) . '%',
					),
					$rows
				)
			);
			echo '</div>';
			return;
		}

		echo VulnHub_Dash_Charts::coverage_bars( $rows ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside coverage_bars().
		echo '</div>';
	}
}

/* =====================================================================
 * The gap list
 * ================================================================== */

/**
 * Assets with no Tenable record, or a stale one. The chase list.
 */
final class VulnHub_El_Coverage_Gaps extends VulnHub_El_Widget_Base {

	public function get_name(): string {
		return 'vulnhub-coverage-gaps';
	}

	public function get_title(): string {
		return esc_html__( 'VulnHub coverage gaps', 'vulnhub' );
	}

	public function get_icon(): string {
		return 'eicon-warning';
	}

	protected function register_controls(): void {
		$this->start_controls_section(
			'vh_content',
			array( 'label' => esc_html__( 'Gaps', 'vulnhub' ) )
		);

		$this->add_heading_controls( esc_html__( 'Assets with no vulnerability cover', 'vulnhub' ) );

		$states = array( '' => esc_html__( 'Every kind of gap', 'vulnhub' ) );
		foreach ( Coverage::gap_states() as $state ) {
			$states[ $state ] = Coverage::label( $state );
		}

		$this->add_control(
			'vh_state',
			array(
				'label'       => esc_html__( 'Kind of gap', 'vulnhub' ),
				'type'        => Controls_Manager::SELECT,
				'options'     => $states,
				'default'     => '',
				'label_block' => true,
			)
		);

		$this->add_control(
			'vh_limit',
			array(
				'label'   => esc_html__( 'Rows', 'vulnhub' ),
				'type'    => Controls_Manager::NUMBER,
				'min'     => 1,
				'max'     => 100,
				'default' => 15,
			)
		);

		$this->end_controls_section();
	}

	protected function render(): void {
		if ( ! $this->may_view() ) {
			$this->render_denied();
			return;
		}

		$s    = $this->get_settings_for_display();
		$gaps = Coverage::gaps(
			array(
				'state' => (string) ( $s['vh_state'] ?? '' ),
				'limit' => max( 1, min( 100, (int) ( $s['vh_limit'] ?? 15 ) ) ),
			)
		);

		echo '<div class="vh-card">';
		$this->print_heading();

		if ( ! $gaps['rows'] ) {
			$this->render_empty( esc_html__( 'Every in-scope asset has a recent Tenable scan.', 'vulnhub' ) );
			echo '</div>';
			return;
		}

		printf(
			'<p class="vh-sub">%s</p>',
			esc_html(
				sprintf(
					/* translators: %s: number of assets. */
					_n( '%s asset needs a scanner on it.', '%s assets need a scanner on them.', (int) $gaps['total'], 'vulnhub' ),
					number_format_i18n( (int) $gaps['total'] )
				)
			)
		);

		echo '<div class="vh-tablewrap"><table class="vh-table"><thead><tr>';
		foreach (
			array(
				__( 'Asset', 'vulnhub' ),
				__( 'Type', 'vulnhub' ),
				__( 'Why', 'vulnhub' ),
				__( 'Owner', 'vulnhub' ),
				__( 'Team', 'vulnhub' ),
				__( 'Last scan', 'vulnhub' ),
			) as $header
		) {
			echo '<th scope="col">' . esc_html( $header ) . '</th>';
		}
		echo '</tr></thead><tbody>';

		foreach ( $gaps['rows'] as $row ) {
			echo '<tr>';
			echo '<td><strong>' . esc_html( (string) ( $row['hostname'] ?: $row['fqdn'] ?: $row['ipv4'] ) ) . '</strong></td>';
			echo '<td>' . esc_html( vh_asset_type_label( (string) $row['asset_type'] ) ) . '</td>';
			echo '<td><span class="vh-pill vh-pill--cov-' . esc_attr( Coverage::tone( (string) $row['coverage_state'] ) ) . '">'
				. esc_html( Coverage::label( (string) $row['coverage_state'] ) ) . '</span></td>';
			echo '<td>' . esc_html( (string) ( $row['owner_name'] ?: '—' ) ) . '</td>';
			echo '<td>' . esc_html( (string) ( $row['team_name'] ?: '—' ) ) . '</td>';
			echo '<td>' . esc_html( $row['tenable_last_scan'] ? vh_ago( (string) $row['tenable_last_scan'] ) : __( 'never', 'vulnhub' ) ) . '</td>';
			echo '</tr>';
		}

		echo '</tbody></table></div></div>';
	}
}

/* =====================================================================
 * Device information explorer
 * ================================================================== */

/**
 * The estate, filterable, with the identifiers each record carries.
 *
 * This is the "device information explorer" from the original brief. It is an
 * Elementor widget rather than a portal view because the same component is
 * useful on a team's own landing page filtered to that team.
 */
final class VulnHub_El_Devices extends VulnHub_El_Widget_Base {

	public function get_name(): string {
		return 'vulnhub-devices';
	}

	public function get_title(): string {
		return esc_html__( 'VulnHub device explorer', 'vulnhub' );
	}

	public function get_icon(): string {
		return 'eicon-device-desktop';
	}

	protected function register_controls(): void {
		$this->start_controls_section(
			'vh_content',
			array( 'label' => esc_html__( 'Devices', 'vulnhub' ) )
		);

		$this->add_heading_controls( esc_html__( 'Device information', 'vulnhub' ) );

		$types = array( '' => esc_html__( 'Every type', 'vulnhub' ) ) + vh_asset_types();

		$this->add_control(
			'vh_type',
			array(
				'label'       => esc_html__( 'Device type', 'vulnhub' ),
				'type'        => Controls_Manager::SELECT,
				'options'     => $types,
				'default'     => '',
				'label_block' => true,
			)
		);

		$teams = array( 0 => esc_html__( 'Every team', 'vulnhub' ) );
		foreach ( Repo::teams() as $team ) {
			$teams[ (int) $team['id'] ] = (string) $team['name'];
		}

		$this->add_control(
			'vh_team',
			array(
				'label'       => esc_html__( 'Owning team', 'vulnhub' ),
				'type'        => Controls_Manager::SELECT,
				'options'     => $teams,
				'default'     => 0,
				'label_block' => true,
			)
		);

		$this->add_control(
			'vh_coverage',
			array(
				'label'   => esc_html__( 'Tenable coverage', 'vulnhub' ),
				'type'    => Controls_Manager::SELECT,
				'options' => array(
					''    => esc_html__( 'Any', 'vulnhub' ),
					'gap' => esc_html__( 'Only gaps', 'vulnhub' ),
				) + array_map(
					static fn( array $def ): string => (string) $def['label'],
					Coverage::states()
				),
				'default' => '',
			)
		);

		$this->add_control(
			'vh_orderby',
			array(
				'label'   => esc_html__( 'Ordered by', 'vulnhub' ),
				'type'    => Controls_Manager::SELECT,
				'options' => array(
					'risk_score'    => esc_html__( 'Risk score', 'vulnhub' ),
					'open_critical' => esc_html__( 'Critical findings', 'vulnhub' ),
					'hostname'      => esc_html__( 'Name', 'vulnhub' ),
					'last_seen'     => esc_html__( 'Last seen', 'vulnhub' ),
				),
				'default' => 'risk_score',
			)
		);

		$this->add_control(
			'vh_limit',
			array(
				'label'   => esc_html__( 'Rows', 'vulnhub' ),
				'type'    => Controls_Manager::NUMBER,
				'min'     => 1,
				'max'     => 100,
				'default' => 15,
			)
		);

		$this->add_control(
			'vh_identifiers',
			array(
				'label'        => esc_html__( 'Show source identifiers', 'vulnhub' ),
				'description'  => esc_html__( 'CMDB, Intune and Tenable ids — how you prove a record is the same device in three systems.', 'vulnhub' ),
				'type'         => Controls_Manager::SWITCHER,
				'default'      => 'yes',
				'return_value' => 'yes',
			)
		);

		$this->end_controls_section();
	}

	protected function render(): void {
		if ( ! $this->may_view() ) {
			$this->render_denied();
			return;
		}

		$s   = $this->get_settings_for_display();
		$ids = 'yes' === (string) ( $s['vh_identifiers'] ?? '' );

		/*
		 * Scoped to what the platform reports on, like every other widget.
		 * Unscoped, this read the whole inventory -- "Showing 25 of 848
		 * devices" against a dashboard that said 804 and an assets page that
		 * said something else again.
		 */
		$result = Repo::assets(
			array(
				'asset_type'      => (string) ( $s['vh_type'] ?? '' ),
				'team_id'         => (int) ( $s['vh_team'] ?? 0 ),
				'coverage'        => (string) ( $s['vh_coverage'] ?? '' ),
				'orderby'         => (string) ( $s['vh_orderby'] ?? 'risk_score' ),
				'reportable_only' => '1',
				'limit'           => max( 1, min( 100, (int) ( $s['vh_limit'] ?? 15 ) ) ),
			)
		);

		echo '<div class="vh-card">';
		$this->print_heading();

		if ( ! $result['rows'] ) {
			$this->render_empty( esc_html__( 'No devices match that filter.', 'vulnhub' ) );
			echo '</div>';
			return;
		}

		printf(
			'<p class="vh-sub">%s</p>',
			esc_html(
				sprintf(
					/* translators: 1: rows shown, 2: total matching. */
					__( 'Showing %1$s of %2$s devices the platform reports on.', 'vulnhub' ),
					number_format_i18n( count( $result['rows'] ) ),
					number_format_i18n( (int) $result['total'] )
				)
			)
		);

		/*
		 * Label and column class together, so the two cannot drift apart.
		 *
		 * They had. Identifiers was spliced in at index 5, which put it after
		 * Coverage in the header while the body writes it before -- so every
		 * row showed CMDB/Intune/Tenable under "Coverage" and "Covered" under
		 * "Identifiers". Both columns were populated and both were labelled
		 * wrong, which is the kind of mistake nobody catches by glancing at
		 * the page: it looks like data, just filed under the wrong heading.
		 */
		$headers = array(
			array( __( 'Device', 'vulnhub' ), '' ),
			array( __( 'Type', 'vulnhub' ), 'vh-col-type' ),
			array( __( 'Operating system', 'vulnhub' ), 'vh-col-os' ),
			array( __( 'Owner', 'vulnhub' ), 'vh-col-owner' ),
			array( __( 'Coverage', 'vulnhub' ), 'vh-col-cov' ),
			array( __( 'Critical', 'vulnhub' ), 'vh-num' ),
			array( __( 'High', 'vulnhub' ), 'vh-num' ),
			array( __( 'Risk', 'vulnhub' ), 'vh-num' ),
		);

		if ( $ids ) {
			// 4, not 5: the body writes identifiers *before* coverage.
			array_splice( $headers, 4, 0, array( array( __( 'Identifiers', 'vulnhub' ), 'vh-col-ids' ) ) );
		}

		echo '<div class="vh-tablewrap"><table class="vh-table vh-table--estate"><thead><tr>';
		foreach ( $headers as $header ) {
			printf(
				'<th scope="col"%s>%s</th>',
				$header[1] ? ' class="' . esc_attr( $header[1] ) . '"' : '',
				esc_html( $header[0] )
			);
		}
		echo '</tr></thead><tbody>';

		foreach ( $result['rows'] as $row ) {
			$owner = (int) $row['owner_person_id'] ? Repo::person( (int) $row['owner_person_id'] ) : null;
			$team  = (int) $row['team_id'] ? Repo::team( (int) $row['team_id'] ) : null;

			echo '<tr>';
			echo '<td><strong>' . esc_html( (string) ( $row['hostname'] ?: $row['fqdn'] ?: $row['ipv4'] ) ) . '</strong>';

			if ( ! empty( $row['ipv4'] ) ) {
				echo '<br><span class="vh-muted">' . esc_html( (string) $row['ipv4'] ) . '</span>';
			}
			echo '</td>';

			echo '<td class="vh-col-type">' . esc_html( vh_asset_type_label( (string) $row['asset_type'] ) ) . '</td>';
			// Os::badge() escapes its own output; the raw string is only ever
			// used as a title attribute inside it.
			echo '<td class="vh-col-os">' . ( $row['operating_system']
				? \VulnHub\Core\Os::badge( (string) $row['operating_system'], true, (string) ( $row['os_version'] ?? '' ), (string) ( $row['asset_type'] ?? '' ) ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				: '—' ) . '</td>';
			echo '<td class="vh-col-owner">' . esc_html( $owner['display_name'] ?? ( $team['name'] ?? '—' ) ) . '</td>';

			if ( $ids ) {
				echo '<td class="vh-el__ids">';
				foreach (
					array(
						'CMDB'    => (string) $row['cmdb_id'],
						'Intune'  => (string) $row['intune_id'],
						'Tenable' => (string) $row['tenable_uuid'],
					) as $label => $value
				) {
					printf(
						'<span class="vh-pill vh-pill--%s" title="%s">%s</span>',
						esc_attr( $value ? 'cov-good' : 'cov-muted' ),
						esc_attr( $value ? $label . ': ' . $value : sprintf( /* translators: %s: source name. */ __( 'No %s record', 'vulnhub' ), $label ) ),
						esc_html( $label )
					);
				}
				echo '</td>';
			}

			echo '<td class="vh-col-cov"><span class="vh-pill vh-pill--cov-' . esc_attr( Coverage::tone( (string) $row['coverage_state'] ) ) . '">'
				. esc_html( Coverage::label( (string) $row['coverage_state'] ) ) . '</span></td>';
			echo '<td class="vh-num">' . esc_html( number_format_i18n( (int) $row['open_critical'] ) ) . '</td>';
			echo '<td class="vh-num">' . esc_html( number_format_i18n( (int) $row['open_high'] ) ) . '</td>';
			echo '<td class="vh-num">' . esc_html( number_format_i18n( (float) $row['risk_score'], 1 ) ) . '</td>';
			echo '</tr>';
		}

		echo '</tbody></table></div></div>';
	}
}

/* =====================================================================
 * Teams and owners
 * ================================================================== */

/**
 * Who owns what, drawn as a wall of teams rather than a table of ids.
 */
final class VulnHub_El_Teams extends VulnHub_El_Widget_Base {

	public function get_name(): string {
		return 'vulnhub-teams';
	}

	public function get_title(): string {
		return esc_html__( 'VulnHub teams and owners', 'vulnhub' );
	}

	public function get_icon(): string {
		return 'eicon-users';
	}

	protected function register_controls(): void {
		$this->start_controls_section(
			'vh_content',
			array( 'label' => esc_html__( 'Teams', 'vulnhub' ) )
		);

		$this->add_heading_controls( esc_html__( 'Who owns what', 'vulnhub' ) );

		$this->add_control(
			'vh_columns',
			array(
				'label'   => esc_html__( 'Columns', 'vulnhub' ),
				'type'    => Controls_Manager::SELECT,
				'options' => array(
					'2' => '2',
					'3' => '3',
					'4' => '4',
				),
				'default' => '3',
			)
		);

		$this->add_control(
			'vh_hide_empty',
			array(
				'label'        => esc_html__( 'Hide teams with no assets', 'vulnhub' ),
				'type'         => Controls_Manager::SWITCHER,
				'default'      => 'yes',
				'return_value' => 'yes',
			)
		);

		$this->end_controls_section();
	}

	protected function render(): void {
		if ( ! $this->may_view() ) {
			$this->render_denied();
			return;
		}

		$s     = $this->get_settings_for_display();
		$teams = Repo::teams();

		if ( ! $teams ) {
			$this->render_empty( esc_html__( 'No teams have been imported yet.', 'vulnhub' ) );
			return;
		}

		global $wpdb;

		/*
		 * One grouped query rather than a query per team. At twenty-five
		 * thousand assets the per-team version was the whole render.
		 */
		/*
		 * Both figures on the card carry the reporting scope. Neither used to:
		 * the card read 655 assets and 78 unowned for a team whose reported
		 * estate is 611 and 65, so every number on it was answering a question
		 * no other screen asked.
		 */
		$counts = (array) $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			'SELECT team_id, COUNT(*) AS assets,
				SUM(open_critical) AS crit, SUM(open_high) AS high,
				SUM(owner_person_id = 0) AS unowned
			 FROM ' . vh_table( 'assets' )
			. ' WHERE lifecycle_status IN (' . vh_reportable_sql() . ')'
			. ' GROUP BY team_id',
			ARRAY_A
		);

		$by_team = array();
		foreach ( $counts as $row ) {
			$by_team[ (int) $row['team_id'] ] = $row;
		}

		$this->print_heading();

		printf( '<div class="vh-teamwall vh-teamwall--%d">', (int) ( $s['vh_columns'] ?? 3 ) );

		foreach ( $teams as $team ) {
			$stat = $by_team[ (int) $team['id'] ] ?? array();
			$n    = (int) ( $stat['assets'] ?? 0 );

			if ( ! $n && 'yes' === (string) ( $s['vh_hide_empty'] ?? '' ) ) {
				continue;
			}

			$crit = (int) ( $stat['crit'] ?? 0 );
			$high = (int) ( $stat['high'] ?? 0 );

			echo '<article class="vh-teamcard">';
			printf(
				'<span class="vh-teamcard__avatar" aria-hidden="true">%s</span>',
				esc_html( mb_strtoupper( mb_substr( (string) $team['name'], 0, 2 ) ) )
			);
			echo '<h3 class="vh-teamcard__name">' . esc_html( (string) $team['name'] ) . '</h3>';

			if ( ! empty( $team['manager_email'] ) ) {
				printf(
					'<p class="vh-teamcard__lead"><a href="mailto:%1$s">%1$s</a></p>',
					esc_attr( (string) $team['manager_email'] )
				);
			}

			echo '<dl class="vh-teamcard__stats">';
			foreach (
				array(
					__( 'Assets', 'vulnhub' )   => number_format_i18n( $n ),
					__( 'Critical', 'vulnhub' ) => number_format_i18n( $crit ),
					__( 'High', 'vulnhub' )     => number_format_i18n( $high ),
					__( 'Unowned', 'vulnhub' )  => number_format_i18n( (int) ( $stat['unowned'] ?? 0 ) ),
				) as $label => $value
			) {
				echo '<div><dt>' . esc_html( $label ) . '</dt><dd>' . esc_html( $value ) . '</dd></div>';
			}
			echo '</dl>';
			echo '</article>';
		}

		echo '</div>';
	}
}

/* =====================================================================
 * Findings
 * ================================================================== */

/**
 * A short list of open findings, filtered to a severity if wanted.
 */
final class VulnHub_El_Findings extends VulnHub_El_Widget_Base {

	public function get_name(): string {
		return 'vulnhub-findings';
	}

	public function get_title(): string {
		return esc_html__( 'VulnHub findings list', 'vulnhub' );
	}

	public function get_icon(): string {
		return 'eicon-post-list';
	}

	protected function register_controls(): void {
		$this->start_controls_section(
			'vh_content',
			array( 'label' => esc_html__( 'Findings', 'vulnhub' ) )
		);

		$this->add_heading_controls( esc_html__( 'What needs attention', 'vulnhub' ) );

		$this->add_control(
			'vh_severity',
			array(
				'label'   => esc_html__( 'Severity', 'vulnhub' ),
				'type'    => Controls_Manager::SELECT,
				'options' => array(
					''         => esc_html__( 'Every severity', 'vulnhub' ),
					'critical' => esc_html__( 'Critical', 'vulnhub' ),
					'high'     => esc_html__( 'High', 'vulnhub' ),
					'medium'   => esc_html__( 'Medium', 'vulnhub' ),
					'low'      => esc_html__( 'Low', 'vulnhub' ),
				),
				'default' => 'critical',
			)
		);

		$this->add_control(
			'vh_overdue',
			array(
				'label'        => esc_html__( 'Only findings past their SLA', 'vulnhub' ),
				'type'         => Controls_Manager::SWITCHER,
				'return_value' => 'yes',
			)
		);

		$this->add_control(
			'vh_limit',
			array(
				'label'   => esc_html__( 'Rows', 'vulnhub' ),
				'type'    => Controls_Manager::NUMBER,
				'min'     => 1,
				'max'     => 50,
				'default' => 10,
			)
		);

		$this->end_controls_section();
	}

	protected function render(): void {
		if ( ! $this->may_view() ) {
			$this->render_denied();
			return;
		}

		$s    = $this->get_settings_for_display();
		$args = array(
			'state'    => 'open_any',
			'excepted' => '0',
			'orderby'  => 'risk_score',
			'limit'    => max( 1, min( 50, (int) ( $s['vh_limit'] ?? 10 ) ) ),
		);

		if ( ! empty( $s['vh_severity'] ) ) {
			$args['severity'] = (string) $s['vh_severity'];
		}
		if ( 'yes' === (string) ( $s['vh_overdue'] ?? '' ) ) {
			$args['overdue'] = 1;
		}

		$result = Repo::findings( $args );

		echo '<div class="vh-card">';
		$this->print_heading();

		if ( ! $result['rows'] ) {
			$this->render_empty( esc_html__( 'Nothing open matches that filter. Good.', 'vulnhub' ) );
			echo '</div>';
			return;
		}

		echo '<ul class="vh-list vh-el__findings">';
		foreach ( $result['rows'] as $row ) {
			echo '<li class="vh-list__row">';
			printf(
				'<span class="vh-pill vh-pill--%s">%s</span>',
				esc_attr( (string) $row['severity'] ),
				esc_html( ucfirst( (string) $row['severity'] ) )
			);
			echo '<span class="vh-list__main"><strong>' . esc_html( (string) ( $row['vuln_title'] ?? '' ) ) . '</strong>';
			echo '<span class="vh-muted"> — ' . esc_html( (string) ( $row['hostname'] ?? '' ) ) . '</span></span>';

			if ( ! empty( $row['due_at'] ) ) {
				echo '<span class="vh-list__meta">' . esc_html( vh_ago( (string) $row['due_at'] ) ) . '</span>';
			}
			echo '</li>';
		}
		echo '</ul>';

		printf(
			'<p class="vh-sub">%s</p>',
			esc_html(
				sprintf(
					/* translators: %s: total matching findings. */
					__( '%s findings match in total.', 'vulnhub' ),
					number_format_i18n( (int) $result['total'] )
				)
			)
		);

		echo '</div>';
	}
}

/* =====================================================================
 * Chrome: the pieces a Theme Builder header and footer are made of
 * ================================================================== */

/**
 * The portal's primary navigation, as a widget, so the header template can be
 * assembled in Elementor without hard-coding the view list anywhere.
 */
final class VulnHub_El_Nav extends VulnHub_El_Widget_Base {

	public function get_name(): string {
		return 'vulnhub-nav';
	}

	public function get_title(): string {
		return esc_html__( 'VulnHub navigation', 'vulnhub' );
	}

	public function get_icon(): string {
		return 'eicon-nav-menu';
	}

	protected function register_controls(): void {
		$this->start_controls_section(
			'vh_content',
			array( 'label' => esc_html__( 'Navigation', 'vulnhub' ) )
		);

		$this->add_control(
			'vh_icons',
			array(
				'label'        => esc_html__( 'Show icons', 'vulnhub' ),
				'type'         => Controls_Manager::SWITCHER,
				'default'      => 'yes',
				'return_value' => 'yes',
			)
		);

		$this->end_controls_section();
	}

	protected function render(): void {
		if ( ! $this->may_view() ) {
			$this->render_denied();
			return;
		}

		$icons   = 'yes' === (string) ( $this->get_settings_for_display( 'vh_icons' ) ?? '' );
		$current = VulnHub_Dash_App::current_view();

		echo '<nav class="vh-nav vh-nav--el" aria-label="' . esc_attr__( 'VulnHub sections', 'vulnhub' ) . '">';

		foreach ( vulnhub_dash_views() as $view => $def ) {
			if ( ! empty( $def['hidden'] ) ) {
				continue;
			}

			printf(
				'<a class="vh-nav__link%s" href="%s"%s>',
				$view === $current ? ' is-active' : '',
				esc_url( VulnHub_Dash_Portal::portal_url( $view ) ),
				$view === $current ? ' aria-current="page"' : ''
			);

			if ( $icons && ! empty( $def['icon'] ) ) {
				printf(
					'<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="%s" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
					esc_attr( (string) $def['icon'] )
				);
			}

			echo '<span>' . esc_html( (string) $def['menu'] ) . '</span></a>';
		}

		foreach ( VulnHub_Dash_App::extra_nav_links() as $link ) {
			printf(
				'<a class="vh-nav__link%s" href="%s">',
				! empty( $link['active'] ) ? ' is-active' : '',
				esc_url( (string) $link['url'] )
			);

			if ( $icons ) {
				printf(
					'<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="%s" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
					esc_attr( (string) $link['icon'] )
				);
			}

			echo '<span>' . esc_html( (string) $link['label'] ) . '</span></a>';
		}

		echo '</nav>';
	}
}

/**
 * Who is signed in, and the way out.
 */
final class VulnHub_El_Account extends VulnHub_El_Widget_Base {

	public function get_name(): string {
		return 'vulnhub-account';
	}

	public function get_title(): string {
		return esc_html__( 'VulnHub account menu', 'vulnhub' );
	}

	public function get_icon(): string {
		return 'eicon-user-circle-o';
	}

	protected function register_controls(): void {
		$this->start_controls_section(
			'vh_content',
			array( 'label' => esc_html__( 'Account', 'vulnhub' ) )
		);

		$this->add_control(
			'vh_admin_link',
			array(
				'label'        => esc_html__( 'Offer the administration link', 'vulnhub' ),
				'description'  => esc_html__( 'Only ever shown to people who hold the manage capability.', 'vulnhub' ),
				'type'         => Controls_Manager::SWITCHER,
				'default'      => 'yes',
				'return_value' => 'yes',
			)
		);

		$this->end_controls_section();
	}

	protected function render(): void {
		$user = wp_get_current_user();

		if ( ! $user || ! $user->ID ) {
			printf(
				'<a class="vh-btn vh-btn--primary" href="%s">%s</a>',
				esc_url( VulnHub_Dash_Portal::login_url() ),
				esc_html__( 'Sign in', 'vulnhub' )
			);
			return;
		}

		echo '<details class="vh-account"><summary>';
		printf(
			'<span class="vh-account__avatar" aria-hidden="true">%s</span><span class="vh-account__name">%s</span>',
			esc_html( mb_strtoupper( mb_substr( (string) $user->display_name, 0, 1 ) ) ),
			esc_html( (string) $user->display_name )
		);
		echo '</summary><div class="vh-account__menu">';
		echo '<p class="vh-account__email">' . esc_html( (string) $user->user_email ) . '</p>';

		if ( 'yes' === (string) ( $this->get_settings_for_display( 'vh_admin_link' ) ?? '' )
			&& current_user_can( \VulnHub\Core\Caps::MANAGE ) ) {
			printf(
				'<a href="%s">%s</a>',
				esc_url( VulnHub_Dash_Portal::portal_url( VulnHub_Dash_Portal::ADMIN_VIEW ) ),
				esc_html__( 'Administration', 'vulnhub' )
			);
		}

		printf(
			'<a href="%s">%s</a>',
			esc_url( wp_logout_url( VulnHub_Dash_Portal::login_url() ) ),
			esc_html__( 'Sign out', 'vulnhub' )
		);

		echo '</div></details>';
	}
}

/**
 * The wordmark. A widget rather than an image so it follows the organisation
 * name that is already configured in settings.
 */
final class VulnHub_El_Brand extends VulnHub_El_Widget_Base {

	public function get_name(): string {
		return 'vulnhub-brand';
	}

	public function get_title(): string {
		return esc_html__( 'VulnHub wordmark', 'vulnhub' );
	}

	public function get_icon(): string {
		return 'eicon-site-logo';
	}

	protected function register_controls(): void {
		$this->start_controls_section(
			'vh_content',
			array( 'label' => esc_html__( 'Wordmark', 'vulnhub' ) )
		);

		$this->add_control(
			'vh_show_org',
			array(
				'label'        => esc_html__( 'Show the organisation name', 'vulnhub' ),
				'type'         => Controls_Manager::SWITCHER,
				'default'      => 'yes',
				'return_value' => 'yes',
			)
		);

		$this->add_control(
			'vh_link',
			array(
				'label'        => esc_html__( 'Link to the dashboard', 'vulnhub' ),
				'type'         => Controls_Manager::SWITCHER,
				'default'      => 'yes',
				'return_value' => 'yes',
			)
		);

		$this->end_controls_section();
	}

	protected function render(): void {
		$s    = $this->get_settings_for_display();
		$link = 'yes' === (string) ( $s['vh_link'] ?? '' );
		$tag  = $link ? 'a' : 'span';

		printf(
			'<%s class="vh-brand"%s>',
			esc_html( $tag ),
			$link ? ' href="' . esc_url( VulnHub_Dash_Portal::portal_url() ) . '"' : ''
		);

		echo '<svg class="vh-brand__mark" viewBox="0 0 24 24" aria-hidden="true" focusable="false">'
			. '<path d="M12 2l8 3.5v6c0 5-3.4 8.8-8 10.5-4.6-1.7-8-5.5-8-10.5v-6z" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/>'
			. '<path d="M8.5 12.2l2.4 2.4 4.6-4.8" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>';

		echo '<span class="vh-brand__text">VulnHub</span>';

		if ( 'yes' === (string) ( $s['vh_show_org'] ?? '' ) ) {
			printf(
				'<span class="vh-brand__org">%s</span>',
				esc_html( (string) vulnhub()->settings->platform( 'org_name', get_bloginfo( 'name' ) ) )
			);
		}

		printf( '</%s>', esc_html( $tag ) );
	}
}

/**
 * How old the data is. Belongs in a footer; a security dashboard that does not
 * say when it last heard from the scanner is a dashboard you cannot trust.
 */
final class VulnHub_El_Freshness extends VulnHub_El_Widget_Base {

	public function get_name(): string {
		return 'vulnhub-freshness';
	}

	public function get_title(): string {
		return esc_html__( 'VulnHub data freshness', 'vulnhub' );
	}

	public function get_icon(): string {
		return 'eicon-clock-o';
	}

	protected function register_controls(): void {
		$this->start_controls_section(
			'vh_content',
			array( 'label' => esc_html__( 'Freshness', 'vulnhub' ) )
		);

		$this->add_control(
			'vh_sources',
			array(
				'label'       => esc_html__( 'Connectors', 'vulnhub' ),
				'type'        => Controls_Manager::SELECT2,
				'multiple'    => true,
				'options'     => array(
					'tenable'  => esc_html__( 'Tenable', 'vulnhub' ),
					'defender' => esc_html__( 'Defender', 'vulnhub' ),
					'cmdb'     => esc_html__( 'CMDB', 'vulnhub' ),
					'intune'   => esc_html__( 'Intune', 'vulnhub' ),
					'jira'     => esc_html__( 'Jira', 'vulnhub' ),
				),
				'default'     => array( 'tenable' ),
				'label_block' => true,
			)
		);

		$this->end_controls_section();
	}

	protected function render(): void {
		$sources = (array) ( $this->get_settings_for_display( 'vh_sources' ) ?? array() );

		if ( ! $sources ) {
			$sources = array( 'tenable' );
		}

		$labels = array(
			'tenable'  => __( 'Tenable', 'vulnhub' ),
			'defender' => __( 'Defender', 'vulnhub' ),
			'cmdb'     => __( 'CMDB', 'vulnhub' ),
			'intune'   => __( 'Intune', 'vulnhub' ),
			'jira'     => __( 'Jira', 'vulnhub' ),
		);

		echo '<ul class="vh-freshness">';
		foreach ( $sources as $source ) {
			$source = (string) $source;
			$last   = vulnhub()->logger->last_run( $source );

			echo '<li><span class="vh-freshness__source">' . esc_html( $labels[ $source ] ?? $source ) . '</span> ';
			echo '<span class="vh-freshness__when">'
				. esc_html(
					$last
						? vh_ago( (string) $last['finished_at'] )
						: __( 'never run', 'vulnhub' )
				)
				. '</span></li>';
		}
		echo '</ul>';
	}
}

/**
 * Light or dark, remembered per browser.
 *
 * The portal's own top bar carries this button. Once the chrome is an
 * Elementor template the button has to be a widget too, or moving to the Theme
 * Builder quietly takes the setting away from everybody.
 */
final class VulnHub_El_Theme_Toggle extends VulnHub_El_Widget_Base {

	public function get_name(): string {
		return 'vulnhub-theme-toggle';
	}

	public function get_title(): string {
		return esc_html__( 'VulnHub light/dark toggle', 'vulnhub' );
	}

	public function get_icon(): string {
		return 'eicon-theme-style';
	}

	protected function register_controls(): void {
		$this->start_controls_section(
			'vh_content',
			array( 'label' => esc_html__( 'Toggle', 'vulnhub' ) )
		);

		$this->add_control(
			'vh_label',
			array(
				'label'        => esc_html__( 'Show a text label', 'vulnhub' ),
				'type'         => Controls_Manager::SWITCHER,
				'return_value' => 'yes',
			)
		);

		$this->end_controls_section();
	}

	protected function render(): void {
		$label = 'yes' === (string) ( $this->get_settings_for_display( 'vh_label' ) ?? '' );

		printf(
			'<button type="button" class="vh-iconbtn" data-vh-theme aria-label="%s">',
			esc_attr__( 'Switch between light and dark', 'vulnhub' )
		);
		echo '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M21 13a9 9 0 11-10-10 7 7 0 0010 10z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>';

		if ( $label ) {
			echo '<span>' . esc_html__( 'Theme', 'vulnhub' ) . '</span>';
		}

		echo '</button>';
	}
}

/**
 * The "running on generated sample data" warning.
 *
 * Small, and load-bearing: somebody reading a number off a wallboard needs to
 * know whether it came from Tenable or from the seeder.
 */
final class VulnHub_El_Mode extends VulnHub_El_Widget_Base {

	public function get_name(): string {
		return 'vulnhub-mode';
	}

	public function get_title(): string {
		return esc_html__( 'VulnHub data-source badge', 'vulnhub' );
	}

	public function get_icon(): string {
		return 'eicon-info-circle-o';
	}

	protected function register_controls(): void {
		$this->start_controls_section(
			'vh_content',
			array( 'label' => esc_html__( 'Badge', 'vulnhub' ) )
		);

		$this->add_control(
			'vh_always',
			array(
				'label'        => esc_html__( 'Show even when the data is live', 'vulnhub' ),
				'type'         => Controls_Manager::SWITCHER,
				'return_value' => 'yes',
			)
		);

		$this->end_controls_section();
	}

	protected function render(): void {
		$mock   = (bool) vulnhub()->settings->mock_mode();
		$always = 'yes' === (string) ( $this->get_settings_for_display( 'vh_always' ) ?? '' );

		if ( ! $mock && ! $always && ! $this->in_editor() ) {
			return;
		}

		printf(
			'<span class="vh-chip vh-chip--%s" title="%s">%s</span>',
			esc_attr( $mock ? 'warn' : 'ok' ),
			esc_attr(
				$mock
					? __( 'Running on generated sample data. Add credentials in the portal to go live.', 'vulnhub' )
					: __( 'Every number on this page came from a connector.', 'vulnhub' )
			),
			esc_html( $mock ? __( 'Sample data', 'vulnhub' ) : __( 'Live data', 'vulnhub' ) )
		);
	}
}
