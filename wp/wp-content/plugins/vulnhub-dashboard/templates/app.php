<?php
/**
 * The VulnHub application shell.
 *
 * Rendered instead of the theme's template so the product looks identical
 * whatever theme is installed, while still calling wp_head()/wp_footer() so the
 * admin bar, enqueued assets and other plugins behave normally.
 *
 * @package VulnHub\Dashboard
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$vh_view = VulnHub_Dash_App::current_view();
$vh_defs = vulnhub_dash_views();
$vh_def  = $vh_defs[ $vh_view ] ?? reset( $vh_defs );

/*
 * Sign-in draws its own header and footer as part of the scene, so the shell's
 * chrome stays out of its way. A product nav offering Dashboard and Assets to
 * somebody who has not signed in yet was never much use anyway.
 */
$vh_bare = VulnHub_Dash_Portal::LOGIN_VIEW === $vh_view;
?>
<!doctype html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="robots" content="noindex, nofollow">
	<?php wp_head(); ?>
	<script>
		/* Apply the saved theme before first paint so there is no flash. */
		( function () {
			try {
				var t = localStorage.getItem( 'vh-theme' );
				if ( t === 'dark' || t === 'light' ) {
					document.documentElement.setAttribute( 'data-theme', t );
				}
			} catch ( e ) {}
		}() );
	</script>
</head>
<body <?php body_class( 'vh-app' ); ?>>
<?php wp_body_open(); ?>

<a class="vh-skip" href="#vh-main"><?php esc_html_e( 'Skip to content', 'vulnhub' ); ?></a>

<?php
/*
 * The chrome is replaceable, the application is not.
 *
 * If somebody has built a header in the Elementor Pro Theme Builder and
 * assigned it, it is used; otherwise the portal draws its own. Same for the
 * footer. This is the only seam Elementor gets in the app shell -- the view
 * itself is server-rendered on purpose and is not a canvas.
 */
if ( $vh_bare ) {
	// The scene draws its own header.
} elseif ( apply_filters( 'vulnhub_portal_has_custom_header', false ) ) {
	do_action( 'vulnhub_portal_header' );
} else {
	VulnHub_Dash_App::render_nav();
}

do_action( 'vulnhub_portal_notice' );
?>

<main id="vh-main" class="vh-main">
	<?php VulnHub_Dash_App::render_view( $vh_view ); ?>
</main>

<?php if ( $vh_bare ) : ?>
<?php elseif ( apply_filters( 'vulnhub_portal_has_custom_footer', false ) ) : ?>
	<?php do_action( 'vulnhub_portal_footer' ); ?>
<?php else : ?>
<footer class="vh-footer">
	<span>
		<?php
		printf(
			/* translators: %s: organisation name. */
			esc_html__( 'VulnHub — vulnerability and asset intelligence for %s', 'vulnhub' ),
			esc_html( (string) vulnhub()->settings->platform( 'org_name', get_bloginfo( 'name' ) ) )
		);
		?>
	</span>
	<span class="vh-footer__meta">
		<?php
		$vh_last = vulnhub()->logger->last_run( 'tenable' );
		echo $vh_last
			? esc_html( sprintf( /* translators: %s: relative time. */ __( 'Vulnerability data last refreshed %s', 'vulnhub' ), vh_ago( (string) $vh_last['finished_at'] ) ) )
			: esc_html__( 'No vulnerability sync has run yet', 'vulnhub' );
		?>
	</span>
</footer>
<?php endif; ?>

<div class="vh-tooltip" id="vh-tooltip" role="status" aria-live="polite" hidden></div>

<?php wp_footer(); ?>
</body>
</html>

