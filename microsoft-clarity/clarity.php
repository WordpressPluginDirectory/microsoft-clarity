<?php
/**
 * Plugin Name:       Microsoft Clarity
 * Plugin URI:        https://clarity.microsoft.com/
 * Description:       With data and session replay from Clarity, you'll see how people are using your site — where they get stuck and what they love.
 * Version:           0.10.7
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
add_action( 'admin_init', 'clarity_activation_redirect' );

/**
 * Plugin activation callback. Registers option to redirect on next admin load.
 */
function clarity_on_activation( $network_wide) {
	// update activate option
	clrt_update_clarity_options( 'activate', $network_wide );

	// Don't do redirects when multiple plugins are bulk activated
	if (
		( isset( $_REQUEST['action'] ) && 'activate-selected' === $_REQUEST['action'] ) &&
		( isset( $_POST['checked'] ) && count( $_POST['checked'] ) > 1 ) ) {
			return;
	}
	add_option( 'clarity_activation_redirect', wp_get_current_user()->ID );
}

/**
 * Redirects the user after plugin activation
 */
function clarity_activation_redirect() {
	// Make sure it is the user that activated the plugin
	if ( is_user_logged_in() && intval( get_option( 'clarity_activation_redirect', false ) ) === wp_get_current_user()->ID ) {
		// Make sure we don't redirect again
		delete_option( 'clarity_activation_redirect' );
		wp_safe_redirect( admin_url( 'admin.php?page=microsoft-clarity' ) );
		exit;
	}
}

/**
 * Runs when Clarity Plugin is deactivated.
 */
register_deactivation_hook( __FILE__, 'clarity_on_deactivation' );
function clarity_on_deactivation( $network_wide ) {
	clrt_update_clarity_options( 'deactivate', $network_wide );
}

/**
 * Runs when Clarity Plugin is uninstalled.
 */
register_uninstall_hook( __FILE__, 'clarity_on_uninstall' );
function clarity_on_uninstall() {
	// Uninstall hook doesn't pass $network_wide flag.
	// Set it to true to delete options for all the sites in a multisite setup (in a single site setup, the flag is irrelevant).

	clrt_update_clarity_options( 'uninstall', true );
}

/**
 * Updates clarity options based on the plugin's action and WordPress installation type.
 *
 * @since 0.10.1
 *
 * @param string $action activate, deactivate or uninstall.
 * @param bool   $network_wide In case of a multisite installation, should the action be performed on all the sites or not.
 */
function clrt_update_clarity_options( $action, $network_wide ) {
	if ( is_multisite() && $network_wide ) {
		$sites = get_sites();
		foreach ( $sites as $site ) {
			switch_to_blog( $site->blog_id );

			clrt_update_clarity_options_handler( $action, $network_wide );

			restore_current_blog();
		}
	} else {
		clrt_update_clarity_options_handler( $action, $network_wide );
	}
}

/**
 * @since 0.10.1
 */
function clrt_update_clarity_options_handler( $action, $network_wide ) {
	switch ( $action ) {
		case 'activate':
			$id = get_option( 'clarity_wordpress_site_id' );

			if ( ! $id ) {
				update_option( 'clarity_wordpress_site_id', wp_generate_uuid4() );
			}
			break;
		case 'deactivate':
			// Plugin activation/deactivation is handled differently in the database for site-level and network-wide activation.
			// Ensure a complete deactivation if the plugin was activated per site before network-wide activation.

			$plugin_name = plugin_basename( __FILE__ );
			if ( $network_wide && in_array( $plugin_name, (array) get_option( 'active_plugins', array() ), true ) ) {
				deactivate_plugins( $plugin_name, true, false );
			}

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

/**
 * Send request info to Clarity BE.
 */
add_action( 'init', 'clarity_send_request_info' );
function clarity_send_request_info() {
	$p_id_option = get_option( 'clarity_project_id' );
	$clarity_wp_site = get_option('clarity_wordpress_site_id');
	try {
		if ( ! empty( $p_id_option ) && ! empty( $clarity_wp_site ) && ! is_admin() ) {

			$envelope = array(
			'projectId'     => $p_id_option,
			'sessionId'     => "",
			'integrationId' => $clarity_wp_site,
			'version'       => 'WordPress-0.10.7',
			);

			$analytics = array(
			'time'   => time(),
			'ip'     => get_ip_address(),
			'ua'     => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field($_SERVER['HTTP_USER_AGENT']) : 'Unkonwn',
			'url'    => home_url($_SERVER['REQUEST_URI']),
			'method' => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'Unkonwn',
			);

			$body = array(
				'envelope'  => $envelope,
				'analytics' => $analytics,
			);

			$args = array(
				'body'        => json_encode($body),
				'timeout'     => '1',
				'redirection' => '5',
				'httpversion' => '1.0',
				'blocking'    => false,
				'headers'     => array( 'Content-Type' => 'application/json' ),
				'cookies'     => array(),
			);

			$response = wp_remote_post('https://ai.clarity.ms/collect-request', $args );
		}
	} catch (Throwable $e) {
		// do nothing
	}
}

// ref: https://usersinsights.com/wordpress-get-user-ip/
function get_ip_address(){
    foreach (array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR') as $key){
        if (array_key_exists($key, $_SERVER) === true){
            foreach (explode(',', $_SERVER[$key]) as $ip){
                $ip = trim($ip);

                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false){
                    return $ip;
                }
            }
        }
    }
}
