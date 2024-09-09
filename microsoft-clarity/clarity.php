<?php
/**
 * Plugin Name:       Microsoft Clarity
 * Plugin URI:        https://clarity.microsoft.com/
 * Description:       With data and session replay from Clarity, you'll see how people are using your site — where they get stuck and what they love.
 * Version:           0.10.1
 * Author:            Microsoft
 * Author URI:        https://www.microsoft.com/en-us/
 * License:           MIT
 * License URI:       https://docs.opensource.microsoft.com/content/releasing/license.html
 */

require_once plugin_dir_path( __FILE__ ) . '/clarity-page.php';
require_once plugin_dir_path( __FILE__ ) . '/clarity-hooks.php';

/**
 * Runs when Clarity Plugin is activated.
 */
register_activation_hook( __FILE__, 'clarity_on_activation' );
function clarity_on_activation() {
	clrt_update_clarity_options( 'activate' );
}

/**
 * Runs when Clarity Plugin is deactivated.
 */
register_deactivation_hook( __FILE__, 'clarity_on_deactivation' );
function clarity_on_deactivation() {
	clrt_update_clarity_options( 'deactivate' );
}

/**
 * Runs when Clarity Plugin is uninstalled.
 */
register_uninstall_hook( __FILE__, 'clarity_on_uninstall' );
function clarity_on_uninstall() {
	clrt_update_clarity_options( 'uninstall' );
}

/**
 * Updates clarity options based on the plugin's action and WordPress installation type.
 *
 * @since 0.10.1
 *
 * @param string $action activate, deactivate or uninstall.
 */
function clrt_update_clarity_options( $action ) {
	if ( is_multisite() ) {
		$sites = get_sites();
		foreach ( $sites as $site ) {
			switch_to_blog( $site->blog_id );

			clrt_update_clarity_options_handler( $action );

			restore_current_blog();
		}
	} else {
		clrt_update_clarity_options_handler( $action );
	}
}

/**
 * @since 0.10.1
 */
function clrt_update_clarity_options_handler( $action ) {
	switch ( $action ) {
		case 'activate':
			update_option( 'clarity_wordpress_site_id', wp_generate_uuid4() );
			break;
		case 'deactivate':
			update_option( 'clarity_wordpress_site_id', '' );
			update_option( 'clarity_project_id', '' );
			break;
		case 'uninstall':
			delete_option( 'clarity_wordpress_site_id' );
			delete_option( 'clarity_project_id' );
			break;
	}
}

/**
 * Escapes the plugin id characters.
 */
function escape_value_for_script( $value ) {
	return htmlspecialchars( $value, ENT_QUOTES, 'UTF-8' );
}

/**
 * Adds the script to run clarity.
 */
add_action( 'wp_head', 'clarity_add_script_to_header' );
function clarity_add_script_to_header() {
	$p_id_option = get_option( 'clarity_project_id' );
	if ( ! empty( $p_id_option ) ) {
		?>
		<script type="text/javascript">
				(function(c,l,a,r,i,t,y){
					c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)};t=l.createElement(r);t.async=1;
					t.src="https://www.clarity.ms/tag/"+i+"?ref=wordpress";y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);
				})(window, document, "clarity", "script", "<?php echo escape_value_for_script( $p_id_option ); ?>");
		</script>
		<?php
	}
}

/**
 * Adds the page link to the Microsoft Clarity block on installed plugin page.
 */
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), 'clarity_page_link' );
function clarity_page_link( $links ) {
	$url          = get_admin_url() . 'admin.php?page=microsoft-clarity';
	$clarity_link = "<a href='$url'>" . __( 'Clarity Dashboard' ) . '</a>';
	array_unshift( $links, $clarity_link );
	return $links;
}
