<?php

/**
 * Plugin Name:       Microsoft Clarity
 * Plugin URI:        https://clarity.microsoft.com/
 * Description:       With data and session replay from Clarity, you'll see how people are using your site — where they get stuck and what they love.
 * Version:           0.10.22
 * Author:            Microsoft
 * Author URI:        https://www.microsoft.com/en-us/
 * License:           MIT
 * License URI:       https://docs.opensource.microsoft.com/content/releasing/license.html
 */

require_once plugin_dir_path(__FILE__) . '/includes/brandagent-config.php';
require_once plugin_dir_path(__FILE__) . '/includes/brandagent-webhooks.php';
require_once plugin_dir_path(__FILE__) . '/includes/brandagent-custom-webhooks.php';
require_once plugin_dir_path(__FILE__) . '/includes/brandagent-rest-api.php';
require_once plugin_dir_path(__FILE__) . '/clarity-page.php';
require_once plugin_dir_path(__FILE__) . '/clarity-hooks.php';
require_once plugin_dir_path(__FILE__) . '/clarity-server-analytics.php';

/**
 * Runs when Clarity Plugin is activated.
 */
register_activation_hook(__FILE__, 'clarity_on_activation');
add_action('admin_init', 'clarity_activation_redirect');

/**
 * Plugin activation callback. Registers option to redirect on next admin load.
 */
function clarity_on_activation($network_wide)
{
	// update activate option
	clrt_update_clarity_options('activate', $network_wide);

	// Register Brand Agent routes and flush rewrite rules
	brandagent_register_routes();
	flush_rewrite_rules();

	// Don't do redirects when multiple plugins are bulk activated
	if (
		(isset($_REQUEST['action']) && 'activate-selected' === $_REQUEST['action']) &&
		(isset($_POST['checked']) && count($_POST['checked']) > 1)
	) {
		return;
	}
	add_option('clarity_activation_redirect', wp_get_current_user()->ID);
}

/**
 * Redirects the user after plugin activation
 */
function clarity_activation_redirect()
{
	// Make sure it is the user that activated the plugin
	if (is_user_logged_in() && intval(get_option('clarity_activation_redirect', false)) === wp_get_current_user()->ID) {
		// Make sure we don't redirect again
		delete_option('clarity_activation_redirect');
		wp_safe_redirect(admin_url('admin.php?page=microsoft-clarity'));
		exit;
	}
}

/**
 * Runs when Clarity Plugin is deactivated.
 */
register_deactivation_hook(__FILE__, 'clarity_on_deactivation');
function clarity_on_deactivation($network_wide)
{
	clrt_update_clarity_options('deactivate', $network_wide);
	flush_rewrite_rules();
}

/**
 * Runs when Clarity Plugin is uninstalled.
 */
register_uninstall_hook(__FILE__, 'clarity_on_uninstall');
function clarity_on_uninstall()
{
	// Uninstall hook doesn't pass $network_wide flag.
	// Set it to true to delete options for all the sites in a multisite setup (in a single site setup, the flag is irrelevant).

	clrt_update_clarity_options('uninstall', true);
}

/**
 * Updates clarity options based on the plugin's action and WordPress installation type.
 *
 * @since 0.10.1
 *
 * @param string $action activate, deactivate or uninstall.
 * @param bool   $network_wide In case of a multisite installation, should the action be performed on all the sites or not.
 */
function clrt_update_clarity_options($action, $network_wide)
{
	if (is_multisite() && $network_wide) {
		$sites = get_sites();
		foreach ($sites as $site) {
			switch_to_blog($site->blog_id);

			clrt_update_clarity_options_handler($action, $network_wide);

			restore_current_blog();
		}
	} else {
		clrt_update_clarity_options_handler($action, $network_wide);
	}
}

/**
 * @since 0.10.1
 */
function clrt_update_clarity_options_handler($action, $network_wide)
{
	switch ($action) {
		case 'activate':
			$id = get_option('clarity_wordpress_site_id');

			if (! $id) {
				update_option('clarity_wordpress_site_id', wp_generate_uuid4());
			}

			// Initialize BAInjectFrontendScript with default value
			if ( get_option( 'BAInjectFrontendScript' ) === false ) {
				add_option( 'BAInjectFrontendScript', 'false' );
			}

			// Resume all BrandAgent webhooks
			if ( class_exists( 'BrandAgent_Webhooks' ) ) {
				BrandAgent_Webhooks::resume_all_brandagent_webhooks();
			}

			break;
		case 'deactivate':
			// Plugin activation/deactivation is handled differently in the database for site-level and network-wide activation.
			// Ensure a complete deactivation if the plugin was activated per site before network-wide activation.

			$plugin_name = plugin_basename(__FILE__);
			if ($network_wide && in_array($plugin_name, (array) get_option('active_plugins', array()), true)) {
				deactivate_plugins($plugin_name, true, false);
			}

			update_option('clarity_wordpress_site_id', '');
			update_option('clarity_project_id', '');
			clarity_flush_and_clear_collect_recurring();

			// Pause all BrandAgent webhooks
			if ( class_exists( 'BrandAgent_Webhooks' ) ) {
				BrandAgent_Webhooks::pause_all_brandagent_webhooks();
			}

			break;
		case 'uninstall':
			handle_brandagent_uninstall();

			delete_option('clarity_wordpress_site_id');
			delete_option('clarity_project_id');
			delete_option( 'BAOauthSuccess' );
            delete_option( 'BAInjectFrontendScript' );
			// Cleanup for the option used up to version 0.10.16. Should remove this after users migrate to 0.10.17+ where this option is no longer used.
			delete_option('clarity_collect_batch');
			clarity_flush_and_clear_collect_recurring();
			clarity_drop_collect_events_table();

			// Delete all BrandAgent webhooks
			if ( class_exists( 'BrandAgent_Webhooks' ) ) {
				BrandAgent_Webhooks::delete_all_brandagent_webhooks();
			}

			// Delete stored HMAC secret for this store
			if ( function_exists( 'brandagent_delete_hmac_secret' ) ) {
				brandagent_delete_hmac_secret();
			}

			break;
	}
}

/**
 * Escapes the plugin id characters.
 */
function escape_value_for_script($value)
{
	return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

/**
 * Adds the script to run clarity.
 */
add_action('wp_head', 'clarity_add_script_to_header');
function clarity_add_script_to_header()
{
	$clarity_project_id = get_option('clarity_project_id');
	if (! empty($clarity_project_id)) {
?>
		<script type="text/javascript">
			(function(c, l, a, r, i, t, y) {
				c[a] = c[a] || function() {
					(c[a].q = c[a].q || []).push(arguments)
				};
				t = l.createElement(r);
				t.async = 1;
				t.src = "https://www.clarity.ms/tag/" + i + "?ref=wordpress";
				y = l.getElementsByTagName(r)[0];
				y.parentNode.insertBefore(t, y);
			})(window, document, "clarity", "script", "<?php echo escape_value_for_script($clarity_project_id); ?>");
		</script>
	<?php
	}
}

/**
 * Adds the script to run clarity.
 */
add_action('wp_head', 'brand_agent_add_script_to_header');
function brand_agent_add_script_to_header()
{
	$ba_oauth_success = get_option( 'BAOauthSuccess' );
	$should_inject_on_woo_page = should_inject_brand_agents_script();

	// Inject if: oauth succeeded AND (WooCommerce page OR BAInjectFrontendScript=true)
	$should_inject = $ba_oauth_success == 1 && $should_inject_on_woo_page;

	if ( $should_inject ) {
		$frontend_injection_url = 'https://adsagentclientafd-b7hqhjdrf3fpeqh2.b01.azurefd.net/frontendInjection.js'
	?>
		<script>
			(function() {
				var script = document.createElement('script');
				script.src = '<?php echo esc_js($frontend_injection_url); ?>';
				script.type = 'module';
				document.head.appendChild(script);
			})();
		</script>
<?php
	}
}

/**
 * Adds the page link to the Microsoft Clarity block on installed plugin page.
 */
add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'clarity_page_link');
function clarity_page_link($links)
{
	$url          = get_admin_url() . 'admin.php?page=microsoft-clarity';
	$clarity_link = "<a href='$url'>" . __('Clarity Dashboard') . '</a>';
	array_unshift($links, $clarity_link);
	return $links;
}

/**
 * Retrieving the currently installed plugin version
 */
function get_installed_plugin_version()
{
	if (! function_exists('get_plugin_data')) {
		require_once(ABSPATH . 'wp-admin/includes/plugin.php');
	}

	$plugin_data = get_plugin_data(plugin_dir_path(__FILE__) . 'clarity.php');

	return $plugin_data['Version'];
}

/**
 * Retrieving the latest version from the WordPress.org repository.
 */
function get_latest_plugin_version_from_api()
{
	$api_url = 'http://api.wordpress.org/plugins/info/1.0/microsoft-clarity.json';
	$response = wp_remote_get($api_url);

	if (is_wp_error($response)) {
		return false;
	}

	$body = wp_remote_retrieve_body($response);
	$plugin_info = json_decode($body);

	if ($plugin_info && isset($plugin_info->version)) {
		return $plugin_info->version;
	}

	return false;
}

/**
 * Checking if the current plugin version is latest
 */
add_action('admin_init', 'check_if_installed_plugin_version_is_latest');
function check_if_installed_plugin_version_is_latest()
{
	// Skip for ajax requests.
	if (wp_doing_ajax()) {
		return;
	}

	$cached_is_latest_version = get_transient('clarity_is_latest_plugin_version');
	if ($cached_is_latest_version !== false) {
		return;
	}

	$installed_version = get_installed_plugin_version();
	$latest_version = get_latest_plugin_version_from_api();

	if ($installed_version && $latest_version) {
		$is_latest_version = version_compare($installed_version, $latest_version, '<') ? '0' : '1';
		set_transient('clarity_is_latest_plugin_version', $is_latest_version, 24 * 60 * 60); // 24 hours cache
	}
}

/**
 * Clear cached plugin-version status after this plugin is updated.
 * This is needed to avoid showing a banner after update due to stale cache.
 */
add_action('upgrader_process_complete', 'clarity_invalidate_latest_version_transient_on_update', 10, 2);
function clarity_invalidate_latest_version_transient_on_update($upgrader_object, $options)
{
	if (
		! is_array($options) ||
		($options['type'] ?? '') !== 'plugin' ||
		($options['action'] ?? '') !== 'update' ||
		! in_array(plugin_basename(__FILE__), (array) ($options['plugins'] ?? array()), true)
	) {
		return;
	}

	delete_transient('clarity_is_latest_plugin_version');
}

/**
 * Check if script should be injected on current page
 */
function should_inject_brand_agents_script() {
    if ( get_option( 'BAInjectFrontendScript', 'false' ) !== 'true' ) {
        return false;
    }
 
    // Don't inject on admin pages
    if ( is_admin() ) {
        return false;
    }
 
    // Don't inject on login/register pages
    if ( function_exists( 'is_login' ) && is_login() ) {
        return false;
    }
 
    // Don't inject on wp-login.php
    if ( $GLOBALS['pagenow'] === 'wp-login.php' ) {
        return false;
    }
 
    // Inject on all other pages
    return true;
}

/**
 * Brand Agent Proxy Endpoints
 * Rewrite rules and handlers for proxying requests from the frontend to the
 * BrandAgent backend server. HMAC helper functions are defined in
 * includes/brandagent-config.php (loaded first to be available during OAuth callback).
 */

/**
 * Register rewrite rules for Brand Agent proxy endpoints
 */
function brandagent_register_routes() {
    add_rewrite_rule(
        '^a/msba/(.*)',
        'index.php?brandagent_api=1&brandagent_path=$matches[1]',
        'top'
    );
}
add_action( 'init', 'brandagent_register_routes' );

/**
 * Register query vars for Brand Agent endpoints
 */
function brandagent_register_query_vars( $vars ) {
    $vars[] = 'brandagent_api';
    $vars[] = 'brandagent_path';
    return $vars;
}
add_filter( 'query_vars', 'brandagent_register_query_vars' );

/**
 * Handle Brand Agent custom endpoint requests
 */
function brandagent_handle_custom_endpoint() {
    if ( intval( get_query_var( 'brandagent_api' ) ) === 1 ) {
        require_once plugin_dir_path( __FILE__ ) . 'includes/brandagent-endpoint.php';
        exit;
    }
}
add_action( 'template_redirect', 'brandagent_handle_custom_endpoint' );

/**
 * Register Brand Agent REST API endpoints
 */
function brandagent_register_rest_api() {
	$rest_api = new BrandAgent_REST_API();
	$rest_api->register_routes();
}
add_action( 'rest_api_init', 'brandagent_register_rest_api' );

/**
 * Check for pending webhook deletion after WordPress is initialized
 * This handles the case where webhook deletion was requested but WooCommerce wasn't loaded yet
 * Uses 'init' hook with priority 20 to ensure WooCommerce is available
 */
add_action( 'init', 'brandagent_process_pending_webhook_deletion', 20 );
function brandagent_process_pending_webhook_deletion() {
    $pending = get_transient( 'brandagent_pending_webhook_deletion' );
    
    if ( ! $pending ) {
        return;
    }
    
    // Check if WooCommerce is available
    if ( ! class_exists( 'WooCommerce' ) || ! class_exists( 'WC_Webhook' ) ) {
        error_log( 'BrandAgent: WooCommerce not available yet for pending webhook deletion' );
        return;
    }
    
    // Delete the transient first to prevent multiple attempts
    delete_transient( 'brandagent_pending_webhook_deletion' );
    
    if ( class_exists( 'BrandAgent_Webhooks' ) ) {
        $deleted_count = BrandAgent_Webhooks::delete_all_brandagent_webhooks();
        error_log( 'BrandAgent: Deleted ' . $deleted_count . ' webhook(s) via pending deletion' );
    } else {
        error_log( 'BrandAgent: BrandAgent_Webhooks class not available for pending deletion' );
    }
}

/**
 * Call Clarity dashboard uninstall endpoint to clean up BA server data
 * This function can be called during plugin uninstall to notify the backend
 */
function handle_brandagent_uninstall() {
	if ( get_option( 'BAOauthSuccess' ) == 1 ) {
		$site_url = home_url();

		// HMAC-signed request through Clarity proxy
		$clarity_domain = BrandAgent_Config::get_clarity_server_url();
		$uninstall_endpoint = $clarity_domain . '/woocommerce/uninstall';
		$response = brandagent_sign_outbound_request( $uninstall_endpoint, wp_json_encode( array( 'storeUrl' => $site_url ) ), 'POST', 15 );

		// Log error if call fails, but continue with local cleanup
		if ( is_wp_error( $response ) ) {
			error_log( 'BrandAgent: Failed to call uninstall endpoint: ' . $response->get_error_message() );
		}
	}
}