<?php
/**
 * The shell an Elementor page is drawn in when the active theme cannot do it.
 *
 * Twenty Twenty-Five is a block theme: it renders through `wp_template` parts
 * and never calls `elementor_theme_do_location()`, so a header built in the
 * Theme Builder is assigned, valid, and invisible. This template is the
 * missing half -- head, header location, the Elementor content, footer
 * location -- and nothing else, so the page is exactly what was built in the
 * editor.
 *
 * @package VulnHub\Elementor
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<!doctype html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<?php wp_head(); ?>
	<script>
		/* Same pre-paint theme restore as the portal, so the two match. */
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
<body <?php body_class( 'vh-app vh-app--elementor' ); ?>>
<?php wp_body_open(); ?>

<a class="vh-skip" href="#vh-main"><?php esc_html_e( 'Skip to content', 'vulnhub' ); ?></a>

<?php
if ( apply_filters( 'vulnhub_portal_has_custom_header', false ) ) {
	do_action( 'vulnhub_portal_header' );
} elseif ( class_exists( 'VulnHub_Dash_App' ) ) {
	VulnHub_Dash_App::render_nav();
}
?>

<main id="vh-main" class="vh-main">
	<?php
	while ( have_posts() ) {
		the_post();
		the_content();
	}
	?>
</main>

<?php
if ( apply_filters( 'vulnhub_portal_has_custom_footer', false ) ) {
	do_action( 'vulnhub_portal_footer' );
}

wp_footer();
?>
</body>
</html>

