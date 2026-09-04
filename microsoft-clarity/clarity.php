<?php

/**
 * Plugin Name:       Microsoft Clarity
 * Plugin URI:        https://clarity.microsoft.com/
 * Description:       With data and session replay from Clarity, you'll see how people are using your site — where they get stuck and what they love.
 * Version:           0.10.29
 * Author:            Microsoft
 * Author URI:        https://www.microsoft.com/en-us/
 * License:           MIT
 * License URI:       https://docs.opensource.microsoft.com/content/releasing/license.html
 */

require_once plugin_dir_path(__FILE__) . '/includes/brandagent-config.php';
require_once plugin_dir_path(__FILE__) . '/includes/brandagent-webhooks.php';
require_once plugin_dir_path(__FILE__) . '/includes/brandagent-custom-webhooks.php';
require_once plugin_dir_path(__FILE__) . '/includes/brandagent-rest-api.php';
require_once plugin_dir_path(__FILE__) . '/includes/brandagent-wordpress.php';
require_once plugin_dir_path(__FILE__) . '/includes/brandagent-content-webhooks.php';
require_once plugin_dir_path(__FILE__) . '/clarity-page.php';
require_once plugin_dir_path(__FILE__) . '/clarity-hooks.php';
require_once plugin_dir_path(__FILE__) . '/clarity-server-analytics.php';

/**
 * Runs when Clarity Plugin is activated.
 */
register_activation_hook(__FILE__, 'clarity_on_activation');
add_action('admin_init', 'clarity_activation_redirect');

/**
 * Whether WooCommerce is active for the blog that is currently switched in.
 *
 * class_exists( 'WooCommerce' ) cannot answer this inside a switch_to_blog() loop: switching swaps
 * DB and global context but never loads or unloads plugin code, so the class is present or absent
 * for the whole request based on whichever blog bootstrapped it, and every iteration would get the
 * same answer. The active_plugins option is per-blog and is re-read after each switch, and
 * is_plugin_active() also covers a network-activated WooCommerce.
 *
 * @return bool True when WooCommerce is active for the current blog.
 */
function clarity_is_woocommerce_active_for_current_blog()
{
	if ( ! function_exists( 'is_plugin_active' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}

	return is_plugin_active( 'woocommerce/woocommerce.php' );
}

/**
 * Fire a non-blocking Brand Agent lifecycle notification, retrying once on transport failure.
 *
 * Even with blocking=false, wp_remote_post() can fail immediately (e.g. invalid URL, transport
 * error), so every lifecycle call shares the same single retry and the same log shape.
 *
 * @param string $endpoint     Absolute endpoint URL.
 * @param array  $request_args Arguments passed straight to wp_remote_post().
 * @param string $log_label    Endpoint name used in the log message.
 * @return array|WP_Error Response from the final attempt.
 */
function brandagent_notify_lifecycle_endpoint( $endpoint, $request_args, $log_label )
{
	$response = wp_remote_post( $endpoint, $request_args );
	if ( is_wp_error( $response ) ) {
		brandagent_log(
			'BrandAgent Lifecycle: ' . $log_label . ' call failed; retrying once',
			array(
				'endpoint' => $endpoint,
				'error'    => $response->get_error_message(),
			)
		);

		$response = wp_remote_post( $endpoint, $request_args );
		if ( is_wp_error( $response ) ) {
			brandagent_log(
				'BrandAgent Lifecycle: ' . $log_label . ' call failed after retry',
				array(
					'endpoint' => $endpoint,
					'error'    => $response->get_error_message(),
				)
			);
		}
	}

	return $response;
}

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

	// Notify the BA server that the plugin was installed and trigger upsell product ingest
	// (fire-and-forget, non-blocking). On multisite network activation, notify once per site
	// so backend state is consistent for each subsite's home_url().
	$clarity_server_url = BrandAgent_Config::get_clarity_server_url();
	if ( ! empty( $clarity_server_url ) ) {
		// WooCommerce activation is per-site on multisite, so the check has to happen inside the
		// switch_to_blog() loop rather than once globally - otherwise a network activation would
		// route every subsite down whichever branch the current blog happens to match. The check
		// reads the per-blog active-plugins option because class_exists() is not switch-aware.
		$store_urls = array();

		if ( is_multisite() && $network_wide ) {
			foreach ( get_sites() as $site ) {
				switch_to_blog( (int) $site->blog_id );
				$store_urls[] = array(
					'url'     => home_url(),
					'has_woo' => clarity_is_woocommerce_active_for_current_blog(),
				);
				restore_current_blog();
			}
		} else {
			$store_urls[] = array(
				'url'     => home_url(),
				'has_woo' => clarity_is_woocommerce_active_for_current_blog(),
			);
		}

		$base_url                            = trailingslashit( $clarity_server_url );
		$plugin_installed_endpoint           = $base_url . 'woocommerce/plugin-installed';
		$upsell_ingest_endpoint              = $base_url . 'woocommerce/upsell-ingest';
		$wordpress_plugin_installed_endpoint = $base_url . 'wordpress/plugin-installed';

		foreach ( $store_urls as $store ) {
			$store_url    = $store['url'];
			$request_args = array(
				'blocking' => false,
				'timeout'  => 3,
				'headers'  => array( 'Content-Type' => 'application/json' ),
				'body'     => wp_json_encode( array( 'storeUrl' => $store_url ) ),
			);

			if ( ! $store['has_woo'] ) {
				// Plain WordPress: create AdvertiserMetadata stamped platform=WordPress. There is no
				// companion upsell-ingest call because a content site has no catalogue to pre-index.
				brandagent_notify_lifecycle_endpoint( $wordpress_plugin_installed_endpoint, $request_args, 'wordpress plugin-installed' );

				continue;
			}

			// plugin-installed: BA server creates AdvertiserMetadata for this store.
			brandagent_notify_lifecycle_endpoint( $plugin_installed_endpoint, $request_args, 'plugin-installed' );

			// upsell-ingest: pre-index products so they are ready before the merchant reaches publish.
			brandagent_notify_lifecycle_endpoint( $upsell_ingest_endpoint, $request_args, 'upsell-ingest' );
		}
	}

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

			// Clear the cached version flag so a reinstall re-evaluates instead of inheriting a stale banner.
			delete_transient('clarity_is_latest_plugin_version');

			// Drop the cached BrandAgent backend URL (24h TTL). Content webhooks post to it on the hot path
			// and read it from this cache, so a plugin update/reactivate is the recovery lever when the
			// backend moves — without this the store keeps posting to the old host until the TTL lapses.
			BrandAgent_Config::clear_cache();

			// Initialize BAInjectFrontendScript with default value
			if ( get_option( 'BAInjectFrontendScript' ) === false ) {
				add_option( 'BAInjectFrontendScript', 'false' );
				brandagent_log( 'BrandAgent Lifecycle: Initialized BAInjectFrontendScript option', array( 'value' => 'false' ) );
			}

			// Resume all BrandAgent webhooks
			if ( class_exists( 'BrandAgent_Webhooks' ) ) {
				$resumed_count = BrandAgent_Webhooks::resume_all_brandagent_webhooks();
				brandagent_log( 'BrandAgent Lifecycle: Plugin activated; resumed webhooks', array( 'resumed_count' => $resumed_count ) );
			} else {
				brandagent_log( 'BrandAgent Lifecycle: Plugin activated; BrandAgent_Webhooks class not available for resume' );
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
				$paused_count = BrandAgent_Webhooks::pause_all_brandagent_webhooks();
				brandagent_log( 'BrandAgent Lifecycle: Plugin deactivated; paused webhooks', array( 'paused_count' => $paused_count ) );
			} else {
				brandagent_log( 'BrandAgent Lifecycle: Plugin deactivated; BrandAgent_Webhooks class not available for pause' );
			}

			break;
		case 'uninstall':
			brandagent_log( 'BrandAgent Lifecycle: Plugin uninstall started' );
			handle_brandagent_uninstall();

			delete_option('clarity_wordpress_site_id');
			delete_option('clarity_project_id');
			delete_option( 'BAOauthSuccess' );
            delete_option( 'BAInjectFrontendScript' );
			delete_option( 'BAOauthRepairDone' );
			delete_option( 'BAWebhooksCreated' );
			delete_option( 'BAWebhooksBackfillDone' );
			delete_option( 'clarity_ba_eligible_triggered' );
			// Plain-WordPress connect bookkeeping. Without this a reinstall still looks opted in, and
			// brandagent_wordpress_maybe_resume_connect() silently reconnects a site the merchant just
			// removed the plugin from.
			delete_option( 'brandagent_wp_connect_optin' );
			delete_option( 'brandagent_wp_connect_attempts' );
			delete_transient( 'brandagent_wp_connect_throttle' );
			delete_transient( 'brandagent_connect_nonce' );
			// Cleanup for the option used up to version 0.10.16. Should remove this after users migrate to 0.10.17+ where this option is no longer used.
			delete_option('clarity_collect_batch');
			// Remove the cached banner flag so it can't linger and resurface on reinstall.
			delete_transient('clarity_is_latest_plugin_version');
			delete_option('clarity_dismissed_update_version');
			clarity_flush_and_clear_collect_recurring();
			clarity_drop_collect_events_table();

			// Delete all BrandAgent webhooks
			if ( class_exists( 'BrandAgent_Webhooks' ) ) {
				$deleted_count = BrandAgent_Webhooks::delete_all_brandagent_webhooks();
				brandagent_log( 'BrandAgent Lifecycle: Plugin uninstall deleted webhooks', array( 'deleted_count' => $deleted_count ) );
			} else {
				brandagent_log( 'BrandAgent Lifecycle: Plugin uninstall; BrandAgent_Webhooks class not available for deletion' );
			}

			// Delete stored HMAC secret for this store
			if ( function_exists( 'brandagent_delete_hmac_secret' ) ) {
				brandagent_delete_hmac_secret();
			} else {
				brandagent_log( 'BrandAgent Lifecycle: Plugin uninstall; HMAC delete helper not available' );
			}

			brandagent_log( 'BrandAgent Lifecycle: Plugin uninstall completed' );
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
 * Determines whether the Brand Agent frontend loader should run on the current
 * request: OAuth must be connected and the current page must be an allowed
 * (non-admin / non-login) context with BAInjectFrontendScript enabled.
 */
function brand_agent_should_inject_frontend_script()
{
	// Inject if: oauth succeeded AND (WooCommerce page OR BAInjectFrontendScript=true)
	return get_option( 'BAOauthSuccess' ) == 1 && should_inject_brand_agents_script();
}

/**
 * Enqueue the Brand Agent loader through the WordPress Script Modules API
 * (WordPress 6.5+). Letting core emit the module tag guarantees it is printed
 * AFTER the import map (in <head> for block themes, in the footer for classic
 * themes), so the import map is always registered first. That keeps the
 * WooCommerce Interactivity API (mini-cart, add-to-cart, product collections,
 * checkout) working in browsers that reject import maps registered after a
 * module load has started (Firefox, Chrome < 133, Android WebView).
 */
add_action('wp_enqueue_scripts', 'brand_agent_enqueue_frontend_module');
function brand_agent_enqueue_frontend_module()
{
	// Only handled here on WordPress 6.5+; older versions use the inline fallback.
	if ( ! function_exists( 'wp_enqueue_script_module' ) ) {
		return;
	}

	if ( ! brand_agent_should_inject_frontend_script() ) {
		return;
	}

	wp_enqueue_script_module(
		'brand-agent-frontend',
		BrandAgent_Config::get_frontend_injection_url(),
		array(),
		null
	);
}

/**
 * Fallback loader for WordPress versions without the Script Modules API (< 6.5).
 * Those versions predate the block Interactivity API import map, so injecting the
 * module from an inline script is safe. Insertion is still deferred until the
 * document has parsed as a defensive measure.
 */
add_action('wp_head', 'brand_agent_add_script_to_header');
function brand_agent_add_script_to_header()
{
	// WordPress 6.5+ is handled by the Script Modules API path above.
	if ( function_exists( 'wp_enqueue_script_module' ) ) {
		return;
	}

	if ( ! brand_agent_should_inject_frontend_script() ) {
		return;
	}

	$frontend_injection_url = BrandAgent_Config::get_frontend_injection_url();
	?>
		<script>
			(function() {
				var injectBrandAgentLoader = function() {
					var script = document.createElement('script');
					script.src = '<?php echo esc_js($frontend_injection_url); ?>';
					script.type = 'module';
					document.head.appendChild(script);
				};
				if (document.readyState === 'loading') {
					document.addEventListener('DOMContentLoaded', injectBrandAgentLoader);
				} else {
					injectBrandAgentLoader();
				}
			})();
		</script>
	<?php
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
 * One-time migration: repair BAOauthSuccess if it was cleared by the
 * register_setting('general') bug (fixed in 0.10.23) while
 * BAInjectFrontendScript remained true and the HMAC secret is still present.
 */
add_action('admin_init', 'clarity_repair_oauth_status');
function clarity_repair_oauth_status() {
	if ( get_option('BAOauthRepairDone') ) {
		return;
	}

	if ( get_option('BAInjectFrontendScript') === 'true'
		 && brandagent_get_hmac_secret()
		 && get_option('BAOauthSuccess') != 1 ) {
		update_option('BAOauthSuccess', true);
		brandagent_log( 'BrandAgent OAuth Repair: Restored BAOauthSuccess from existing Brand Agent state' );
	}

	update_option('BAOauthRepairDone', true);
}

/**
 * One-time migration: backfill BAWebhooksCreated for stores that already have
 * BrandAgent webhooks set up before this flag existed. Without this, a future
 * config/update would unnecessarily re-trigger complete-onboarding +
 * create_webhooks() for healthy stores. Stores that completed OAuth but never
 * got webhooks (the bug we're fixing) are intentionally left without the flag,
 * so the next config/update will recover them.
 */
add_action('admin_init', 'clarity_backfill_webhooks_created');
function clarity_backfill_webhooks_created() {
	if ( get_option('BAWebhooksBackfillDone') ) {
		return;
	}

	// Defer if WooCommerce isn't ready yet — without WC_Webhook, has_any_brandagent_webhook()
	// would return false for healthy stores and we'd mark the backfill done with the flag
	// unset, causing one unnecessary complete-onboarding round-trip on the next config/update.
	if ( ! class_exists('BrandAgent_Webhooks') || ! class_exists('WC_Webhook') ) {
		return;
	}

	if ( get_option('BAOauthSuccess') == 1
		 && get_option('BAInjectFrontendScript') === 'true'
		 && BrandAgent_Webhooks::has_any_brandagent_webhook() ) {
		update_option('BAWebhooksCreated', true);
	}

	update_option('BAWebhooksBackfillDone', true);
}

/**
 * Refresh the cached "update available" flag used by the admin banner.
 * Gated on core's update_plugins->response (the same source the Update button
 * installs from), so the banner never offers an update that can't yet be installed.
 */
add_action('admin_init', 'check_if_installed_plugin_version_is_latest');
function check_if_installed_plugin_version_is_latest()
{
	// Skip for ajax requests.
	if (wp_doing_ajax()) {
		return;
	}

	// Throttle the check to every 5 minutes.
	if (get_transient('clarity_is_latest_plugin_version') !== false) {
		return;
	}

	// Refresh core's update data (self-throttled internally) and read its verdict.
	wp_update_plugins();

	$plugin_file = plugin_basename(__FILE__);
	$updates = get_site_transient('update_plugins');
	$update_available = isset($updates->response[$plugin_file]->new_version);

	set_transient('clarity_is_latest_plugin_version', $update_available ? '0' : '1', 5 * 60); // 5 minutes cache
}

/**
 * Clear cached plugin-version status after this plugin is installed or updated.
 * This is needed to avoid showing a banner after update due to stale cache.
 */
add_action('upgrader_process_complete', 'clarity_invalidate_latest_version_transient_on_update', 10, 2);
function clarity_invalidate_latest_version_transient_on_update($upgrader_object, $options)
{
	if (! is_array($options) || ($options['type'] ?? '') !== 'plugin') {
		return;
	}

	$action = $options['action'] ?? '';
	if ($action !== 'update' && $action !== 'install') {
		return;
	}

	// Bulk updates pass a 'plugins' array; single update/install passes a 'plugin' string.
	$affected_plugins = (array) ($options['plugins'] ?? array());
	if (! empty($options['plugin'])) {
		$affected_plugins[] = $options['plugin'];
	}

	// On overwrite-install the affected plugin isn't always reported; clear anyway to be safe.
	if (! empty($affected_plugins) && ! in_array(plugin_basename(__FILE__), $affected_plugins, true)) {
		return;
	}

	delete_transient('clarity_is_latest_plugin_version');

	// A plugin update is also the recovery lever for a moved BrandAgent backend: drop the cached backend
	// URL (24h TTL) that content webhooks post to, so the new version re-fetches instead of posting to a
	// stale host until the TTL lapses.
	BrandAgent_Config::clear_cache();
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
        brandagent_log( 'BrandAgent Webhooks: WooCommerce not available yet for pending webhook deletion' );
        return;
    }
    
    // Delete the transient first to prevent multiple attempts
    delete_transient( 'brandagent_pending_webhook_deletion' );
    
    if ( class_exists( 'BrandAgent_Webhooks' ) ) {
        $deleted_count = BrandAgent_Webhooks::delete_all_brandagent_webhooks();
        brandagent_log( 'BrandAgent Webhooks: Deleted webhooks via pending deletion', array( 'deleted_count' => $deleted_count ) );
    } else {
        brandagent_log( 'BrandAgent Webhooks: BrandAgent_Webhooks class not available for pending deletion' );
    }
}

/**
 * Call the Clarity dashboard uninstall endpoint so the backend drops this site's Brand Agent data.
 * Invoked during plugin uninstall, before the local HMAC secret is deleted.
 *
 * Which endpoint depends on how the site onboarded, and the two are not interchangeable. A
 * WooCommerce store is registered as Platform=WooCommerce with credentials and webhooks the
 * WooCommerce teardown unwinds, and its secret is filed in Key Vault under a woocommerce-* name.
 * A plain site is Platform=WordPress with a wordpress-* secret and a different signing scheme.
 * Sending either one down the other's path fails signature verification, and because uninstall is
 * fire-and-forget the merchant's data would be left behind with nothing to retry it.
 */
function handle_brandagent_uninstall() {
	if ( get_option( 'BAOauthSuccess' ) != 1 ) {
		brandagent_log( 'BrandAgent Uninstall: Skipping backend uninstall because OAuth is not marked successful' );
		return;
	}

	// Follows the credential this site actually holds, which is what "how it onboarded" means once
	// the secret is filed under a platform-specific Key Vault name. Live activation state is the
	// wrong signal here for the same reason it is wrong for signing: a store that deactivates
	// WooCommerce before deleting the plugin still holds a woocommerce-* secret, so the WordPress
	// teardown would fail verification and strand its data with nothing to retry the call.
	if ( brandagent_get_hmac_platform() !== 'woocommerce' ) {
		if ( function_exists( 'brandagent_wordpress_notify_uninstall' ) ) {
			brandagent_wordpress_notify_uninstall();
		} else {
			brandagent_log( 'BrandAgent Uninstall: WordPress uninstall helper not available' );
		}

		return;
	}

	$site_url = home_url();

	// HMAC-signed request through Clarity proxy
	$clarity_domain = BrandAgent_Config::get_clarity_server_url();
	$uninstall_endpoint = $clarity_domain . '/woocommerce/uninstall';
	brandagent_log( 'BrandAgent Uninstall: Calling backend uninstall endpoint', array( 'store_url' => $site_url, 'endpoint' => $uninstall_endpoint ) );
	$response = brandagent_sign_outbound_request( $uninstall_endpoint, wp_json_encode( array( 'storeUrl' => $site_url ) ), 'POST', 15 );

	// Log error if call fails, but continue with local cleanup
	if ( is_wp_error( $response ) ) {
		brandagent_log( 'BrandAgent Uninstall: Failed to call backend uninstall endpoint', array( 'error' => $response->get_error_message() ) );
		return;
	}

	$status_code = wp_remote_retrieve_response_code( $response );
	brandagent_log( 'BrandAgent Uninstall: Backend uninstall endpoint returned', array( 'status_code' => $status_code ) );
}
