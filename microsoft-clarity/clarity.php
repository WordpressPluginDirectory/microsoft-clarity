<?php

/**
 * Plugin Name:       Microsoft Clarity
 * Plugin URI:        https://clarity.microsoft.com/
 * Description:       With data and session replay from Clarity, you'll see how people are using your site — where they get stuck and what they love.
 * Version:           0.10.17
 * Author:            Microsoft
 * Author URI:        https://www.microsoft.com/en-us/
 * License:           MIT
 * License URI:       https://docs.opensource.microsoft.com/content/releasing/license.html
 */

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

			clarity_create_collect_events_table();
			clarity_schedule_collect_recurring();
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
			break;
		case 'uninstall':
			delete_option('clarity_wordpress_site_id');
			delete_option('clarity_project_id');
			delete_option('clarity_is_agent_enabled');
			// Cleanup for the option used up to version 0.10.16. Should remove this after users migrate to 0.10.17+ where this option is no longer used.
			delete_option('clarity_collect_batch');
			clarity_flush_and_clear_collect_recurring();
			clarity_drop_collect_events_table();
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
	$is_agent_enabled = get_option('clarity_is_agent_enabled');
	$should_inject_brand_agents_script = should_inject_brand_agents_script();
	if ($is_agent_enabled == 1 && $should_inject_brand_agents_script) {
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
	$installed_version = get_installed_plugin_version();
	$latest_version = get_latest_plugin_version_from_api();

	if ($installed_version && $latest_version) {
		if (version_compare($installed_version, $latest_version, '<')) {
			update_option('clarity_is_latest_plugin_version', '0');
		} else {
			update_option('clarity_is_latest_plugin_version', '1');
		}
	}
}

/**
 * Check if script should be injected on current page
 */
function should_inject_brand_agents_script()
{
	// Inject on WooCommerce pages
	if (function_exists('is_woocommerce') && is_woocommerce()) {
		return true;
	}

	// Inject on shop page
	if (function_exists('is_shop') && is_shop()) {
		return true;
	}

	// Inject on product pages
	if (function_exists('is_product') && is_product()) {
		return true;
	}

	// Inject on cart page
	if (function_exists('is_cart') && is_cart()) {
		return true;
	}

	// Inject on checkout page
	if (function_exists('is_checkout') && is_checkout()) {
		return true;
	}

	// Inject on account pages
	if (function_exists('is_account_page') && is_account_page()) {
		return true;
	}

	// Inject on homepage if it's the shop
	if (is_front_page() && get_option('show_on_front') === 'page' && function_exists('wc_get_page_id') && get_option('page_on_front') == wc_get_page_id('shop')) {
		return true;
	}

	return false;
}
