<?php

/*******************************************************************************
 * File with Clarity page
 *******************************************************************************/

// Handle Brand Agent remove from waitlist success callback - use add_action to ensure WordPress is loaded
add_action( 'init', 'brandagent_handle_remove_from_waitlist_success_callback', 1 );
function brandagent_handle_remove_from_waitlist_success_callback() {
    if ( isset( $_GET['brandagent_remove_from_waitlist_success'] ) && $_GET['brandagent_remove_from_waitlist_success'] == '1' ) {
        brandagent_log( 'BrandAgent: Received remove from waitlist success callback' );

        // Verify HMAC signature from request headers
        $client_id = isset( $_SERVER['HTTP_X_WOOCOMMERCE_CLIENT_ID'] ) 
            ? sanitize_text_field( $_SERVER['HTTP_X_WOOCOMMERCE_CLIENT_ID'] ) 
            : '';
        $timestamp = isset( $_SERVER['HTTP_X_WOOCOMMERCE_TIMESTAMP'] ) 
            ? sanitize_text_field( $_SERVER['HTTP_X_WOOCOMMERCE_TIMESTAMP'] ) 
            : '';
        $signature = isset( $_SERVER['HTTP_X_WOOCOMMERCE_SIGNATURE'] ) 
            ? sanitize_text_field( $_SERVER['HTTP_X_WOOCOMMERCE_SIGNATURE'] ) 
            : '';

        // Validate required headers are present
        if ( empty( $client_id ) || empty( $timestamp ) || empty( $signature ) ) {
            brandagent_log( 'BrandAgent: Remove from waitlist callback missing required HMAC headers' );
            header( 'Content-Type: application/json' );
            http_response_code( 401 );
            echo json_encode( array( 'success' => false, 'error' => 'Missing authentication headers' ) );
            exit;
        }

        // Validate timestamp (5-minute window for replay attack prevention)
        $time_difference = abs( time() - intval( $timestamp ) );
        if ( $time_difference > 300 ) {
            brandagent_log( 'BrandAgent: Remove from waitlist callback timestamp too old: ' . $time_difference . ' seconds' );
            header( 'Content-Type: application/json' );
            http_response_code( 401 );
            echo json_encode( array( 'success' => false, 'error' => 'Request timestamp expired' ) );
            exit;
        }

        // Get the stored HMAC secret and verify signature
        $secret_key = brandagent_get_hmac_secret();
        if ( ! $secret_key ) {
            brandagent_log( 'BrandAgent: Remove from waitlist callback - no HMAC secret stored' );
            header( 'Content-Type: application/json' );
            http_response_code( 401 );
            echo json_encode( array( 'success' => false, 'error' => 'HMAC secret not found' ) );
            exit;
        }

        // Compute expected signature: message = clientId + timestamp
        $expected_signature = brandagent_generate_hmac_signature( $client_id, $timestamp, $secret_key );

        // Constant-time comparison to prevent timing attacks
        if ( ! hash_equals( $expected_signature, $signature ) ) {
            brandagent_log( 'BrandAgent: Remove from waitlist callback HMAC signature verification failed' );
            header( 'Content-Type: application/json' );
            http_response_code( 401 );
            echo json_encode( array( 'success' => false, 'error' => 'Invalid signature' ) );
            exit;
        }

        brandagent_log( 'BrandAgent: Remove from waitlist callback HMAC signature verified successfully' );

        delete_option( 'BAOauthSuccess' );
        delete_option( 'BAInjectFrontendScript' );
        brandagent_delete_hmac_secret();

        // Try to delete webhooks immediately if WooCommerce is available
        $deleted_immediately = false;
        if ( class_exists( 'WooCommerce' ) && class_exists( 'BrandAgent_Webhooks' ) ) {
            $deleted_count = BrandAgent_Webhooks::delete_all_brandagent_webhooks();
            brandagent_log( 'BrandAgent: Deleted ' . $deleted_count . ' webhook(s) immediately' );
            $deleted_immediately = true;
        }

        // If WooCommerce not loaded, set transient for later deletion
        if ( ! $deleted_immediately ) {
            set_transient( 'brandagent_pending_webhook_deletion', true, 3600 );
            brandagent_log( 'BrandAgent: Set pending webhook deletion transient (WooCommerce not loaded)' );
        }

        header( 'Content-Type: application/json' );
        echo json_encode( array( 'success' => true ) );
        exit;
    }
}

// Handle WooCommerce OAuth return URL (browser redirect after user authorizes).
// Deferred to 'init' so that wp_remote_post() and the HTTP API are fully loaded.
add_action( 'init', 'brandagent_handle_oauth_callback', 1 );
function brandagent_handle_oauth_callback() {
    if ( ! isset($_GET['brandagent_callback']) || $_GET['brandagent_callback'] != '1' ) {
        return;
    }

    $oauth_token = isset($_GET['oauth_token']) ? sanitize_text_field($_GET['oauth_token']) : '';

    // WooCommerce adds success=1 to the return URL when the callback was successful
    $wc_success = isset($_GET['success']) && $_GET['success'] == '1';
    $success = false;

    if ($wc_success && !empty($oauth_token)) {
        // Pull the HMAC secret from Clarity server (server-to-server, secret in response body)
        if ( ! class_exists( 'BrandAgent_Config' ) ) {
            $config_path = plugin_dir_path( __FILE__ ) . 'includes/brandagent-config.php';
            if ( file_exists( $config_path ) ) {
                require_once $config_path;
            } else {
                brandagent_log( 'BrandAgent OAuth: ERROR - Config file not found at ' . $config_path );
            }
        }

        $clarity_server_url = BrandAgent_Config::get_clarity_server_url();
        $fetch_url = $clarity_server_url . '/woocommerce/fetch-secret';

        $request_body = wp_json_encode( array( 'oauth_token' => $oauth_token ) );

        $response = wp_remote_post( $fetch_url, array(
            'timeout' => 15,
            'headers' => array( 'Content-Type' => 'application/json' ),
            'body'    => $request_body,
        ) );

        if ( is_wp_error( $response ) ) {
            brandagent_log( 'BrandAgent OAuth: ERROR - wp_remote_post failed: ' . $response->get_error_message() );
        } else {
            $status_code = wp_remote_retrieve_response_code( $response );
            $response_body = wp_remote_retrieve_body( $response );

            if ( $status_code === 200 ) {
                $body = json_decode( $response_body, true );
                if ( json_last_error() !== JSON_ERROR_NONE ) {
                    brandagent_log( 'BrandAgent OAuth: ERROR - JSON parse failed: ' . json_last_error_msg() );
                } elseif ( isset( $body['success'] ) && $body['success'] === true && ! empty( $body['hmac_secret'] ) ) {
                    brandagent_store_hmac_secret( $body['hmac_secret'] );
                    update_option( 'BAOauthSuccess', true );
                    $success = true;
                    brandagent_log( 'BrandAgent OAuth: SUCCESS - HMAC secret stored, BAOauthSuccess set.' );
                } else {
                    brandagent_log( 'BrandAgent OAuth: ERROR - Unexpected response from fetch-secret' );
                }
            } else {
                brandagent_log( 'BrandAgent OAuth: ERROR - fetch-secret returned status ' . $status_code );
            }
        }
    } else {
        brandagent_log( 'BrandAgent OAuth: SKIPPED - wc_success=' . ($wc_success ? 'true' : 'false') . ', oauth_token=' . (!empty($oauth_token) ? 'present' : 'MISSING') );
    }

    ?>
    <!DOCTYPE html>
    <html>
        <body>
            <script>
                if (window.opener) {
                    <?php if ($success): ?>
                        window.opener.postMessage({
                            type: 'WOOCOMMERCE_OAUTH_SUCCESS'
                        }, '*');
                    <?php else: ?>
                        window.opener.postMessage({
                            type: 'WOOCOMMERCE_OAUTH_FAILURE'
                        }, '*');
                    <?php endif; ?>

                    setTimeout(function() {
                        window.close();
                    }, 100);
                }
            </script>
        </body>
    </html>
    <?php
    exit;
}

// Handle Brand Agent refresh credentials callback
add_action( 'init', 'brandagent_handle_refresh_credentials_callback', 1 );
function brandagent_handle_refresh_credentials_callback() {
    if ( ! isset( $_GET['brandagent_refresh_credentials'] ) || $_GET['brandagent_refresh_credentials'] != '1' ) {
        return;
    }

    $oauth_token = isset( $_GET['oauth_token'] ) ? sanitize_text_field( $_GET['oauth_token'] ) : '';
    $success = false;

    if ( ! empty( $oauth_token ) ) {
        // Ensure BrandAgent_Config is loaded
        if ( ! class_exists( 'BrandAgent_Config' ) ) {
            $config_path = plugin_dir_path( __FILE__ ) . 'includes/brandagent-config.php';
            if ( file_exists( $config_path ) ) {
                require_once $config_path;
            } else {
                brandagent_log( 'BrandAgent Refresh: ERROR - Config file not found at ' . $config_path );
            }
        }

        // Fetch the new HMAC secret from Clarity server using the opaque token
        $clarity_server_url = BrandAgent_Config::get_clarity_server_url();
        $fetch_url = $clarity_server_url . '/woocommerce/fetch-secret';

        $request_body = wp_json_encode( array( 'oauth_token' => $oauth_token ) );

        $response = wp_remote_post( $fetch_url, array(
            'timeout' => 15,
            'headers' => array( 'Content-Type' => 'application/json' ),
            'body'    => $request_body,
        ) );

        if ( is_wp_error( $response ) ) {
            brandagent_log( 'BrandAgent Refresh: ERROR - wp_remote_post failed: ' . $response->get_error_message() );
        } else {
            $status_code = wp_remote_retrieve_response_code( $response );
            $response_body = wp_remote_retrieve_body( $response );

            if ( $status_code === 200 ) {
                $body = json_decode( $response_body, true );
                if ( json_last_error() !== JSON_ERROR_NONE ) {
                    brandagent_log( 'BrandAgent Refresh: ERROR - JSON parse failed: ' . json_last_error_msg() );
                } elseif ( isset( $body['success'] ) && $body['success'] === true && ! empty( $body['hmac_secret'] ) ) {
                    brandagent_store_hmac_secret( $body['hmac_secret'] );
                    $success = true;
                    brandagent_log( 'BrandAgent Refresh: SUCCESS - New HMAC secret stored.' );
                } else {
                    brandagent_log( 'BrandAgent Refresh: ERROR - Unexpected response from fetch-secret' );
                }
            } else {
                brandagent_log( 'BrandAgent Refresh: ERROR - fetch-secret returned status ' . $status_code );
            }
        }
    } else {
        brandagent_log( 'BrandAgent Refresh: ERROR - Missing oauth_token parameter' );
    }

    header( 'Content-Type: application/json' );
    if ( $success ) {
        echo json_encode( array( 'success' => true ) );
    } else {
        http_response_code( 500 );
        echo json_encode( array( 'success' => false, 'error' => 'Failed to refresh credentials' ) );
    }
    exit;
}

function generate_wordpress_id_option_if_empty()
{
    $clarity_wp_site = get_option('clarity_wordpress_site_id');
    if (empty($clarity_wp_site)) {
        update_option('clarity_wordpress_site_id', wp_generate_uuid4());
    };
}

/**
 * generate a guid identifier for this wordpress site
 * runs in the callback of register_activation_hook, rerunning here for existing plugin which updated 
 **/
function refresh_wordpress_id_option()
{
    update_option('clarity_wordpress_site_id', wp_generate_uuid4());
}

/**
 * Detects whether this site is hosted on WordPress.com.
 **/
function clarity_is_wordpress_com_hosted()
{
    return defined('IS_WPCOM') && IS_WPCOM;
}

/**
 * Displays the embedded iframe in Clarity settings
 **/
function clarity_section_iframe_callback()
{
    $nonce = wp_create_nonce('wp_ajax_edit_clarity_project_id');

    $clarity_project_id_option = get_option(
        'clarity_project_id', /* option */
        clarity_project_id_default_value() /* default */
    );
    $clarity_wp_site = get_option(
        'clarity_wordpress_site_id' /* option */
        /* default */
    );

    $site_url = home_url();
    $hosting_type = clarity_is_wordpress_com_hosted() ? 'wpcom' : 'selfhosted';

    $clarity_domain = "https://clarity.microsoft.com/embed";

    $query_params = "?nonce=$nonce&integration=Wordpress&wpsite=$clarity_wp_site&siteurl=$site_url&hostingtype=$hosting_type";

    // set a QP if user is admin
    if (current_user_can('manage_options')) {
        $query_params = $query_params . "&WPAdmin=1";
    }

    // set a QP if user is WooCommerce plugin is active
    if (class_exists('woocommerce')) {
        $query_params = $query_params . "&WooCommerce=1";
    }

    // set a QP if permalink structure is plain (required for Brand Agent rewrite rules)
    if (get_option('permalink_structure') === '') {
        $query_params = $query_params . "&PlainPermalink=1";
    }

    // Add flag to indicate Brand Agent integration is supported (0.10.21+)
    // If this flag is missing, iframe knows user is on an older version
    $query_params = $query_params . "&BrandAgentSupported=1";

    // initially set iframe src to the new users path
    $iframe_src = $clarity_domain . $query_params;

    // clarity project exist
    if (!empty($clarity_project_id_option)) {
        $iframe_src = $iframe_src . "&project=" . $clarity_project_id_option;
    }

    // Support deep-linking to specific pages in the embedded Clarity dashboard
    if (isset($_GET['iframeRedirect']) && !empty($_GET['iframeRedirect'])) {
        $iframe_redirect = sanitize_text_field($_GET['iframeRedirect']);
        $iframe_src = $iframe_src . "&iframeRedirect=" . rawurlencode($iframe_redirect);
    }

?>
    <div style="width:100%;height:100vh;padding-right:15px;margin-top:0px;box-sizing:border-box;">
        <iframe sandbox="allow-modals allow-forms allow-scripts allow-same-origin allow-popups allow-storage-access-by-user-activation" src="<?php echo $iframe_src ?>" width="100%" height="100%" title="Microsoft Clarity" />
    </div>
<?php
}

/**
 * clarity project id default value is empty string
 **/
function clarity_project_id_default_value()
{
    return '';
}

/**
 * Generates a menu page
 **/

add_action('admin_menu', 'clarity_page_generation');
function clarity_page_generation()
{
    add_menu_page(
        'microsoft-clarity', /* $page_title */
        'Clarity', /* menu_title */
        'edit_posts', /* capability */
        'microsoft-clarity', /* menu_slug */
        'clarity_section_iframe_callback', /* callback */
        'https://claritystatic.blob.core.windows.net/images/logo.svg', /* icon_url */
        99 /* position */
    );
}

/**
 * Register Plugin settings
 * clarity_project_id: option for currently integrated Clarity project id
 * clarity_wordpress_site_id: a guid generated by the Clarity plugin to uniquely identify this wordpress site
 * clarity_section_iframe_callback: part of the settings page in which the iframe is embedded
 * BAOauthSuccess: option for checking if brand agent oauth was successful
 **/
add_action('admin_init', 'clarity_register_settings');
function clarity_register_settings()
{
    register_setting(
        'clarity_settings_fields', /* $option_group */
        'clarity_project_id' /* option_name */
        /* args */
    );
    register_setting(
        'general', /* $option_group */
        'clarity_wordpress_site_id' /* option_name */
        /* args */
    );
    register_setting(
        'general', /* $option_group */
        'BAOauthSuccess' /* option_name */
        /* args */
    );
}

/** 
 * Notice for when wordpress admins did not finish intalling Clarity
 * did not integrate a project
 */
add_action('admin_notices', 'setup_clarity_notice__info');
function setup_clarity_notice__info()
{
    global $pagenow;
    $url = get_admin_url() . 'admin.php?page=microsoft-clarity';

    $learnMoreUrl = 'https://wordpress.org/plugins/microsoft-clarity/';

    $clarity_project_id_option = get_option(
        'clarity_project_id', /* option */
        clarity_project_id_default_value() /* default */
    );
    $pageQPExists = isset($_GET['page']);
    if ($pageQPExists) {
        $pageQP =  $_GET['page'];
    } else {
        $pageQP = "";
    }


    if (empty($clarity_project_id_option) && $pageQP !== "microsoft-clarity" && current_user_can("manage_options")) {
        echo
        '<div class="notice notice-info is-dismissible">
            <p style="font-weight:700">
                Unlock User Insights with Microsoft Clarity!
            </p>
            <p style="font-weight:500">
                Almost there! Start tracking user behavior on your site with Microsoft Clarity. See exactly where on your site users click, scroll, and get stuck. It takes just a few moments to set up.
            </p>
            <p>
                <a class="button-primary" href="' . $url . '">
                    Setup Clarity
                </a>
                <a class="button-primary" style="margin-left:10px" href="' . $learnMoreUrl . '">
                    Learn more
                </a>
            </p>
        </div>';
    }
}

/**
 * Add js function to listen to message on all admin pages
 * These message contain changes to integrated Clarity project
 * remove - change - add new
 */
add_action('admin_enqueue_scripts', 'add_event_listeners');
function add_event_listeners($hook)
{
    $pageQPExists = isset($_GET['page']);
    if ($pageQPExists) {
        $pageQP =  $_GET['page'];
    } else {
        $pageQP = "";
    }

    if ($pageQP !== "microsoft-clarity") {
        return;
    }

    if (!current_user_can("edit_posts")) {
        return;
    }

    wp_register_script(
        'window_listeners_js', /* handle */
        plugins_url('js\add_window_listeners.js', __FILE__), /* src */
        array(), /* deps  */
        false, /* ver  */
        false /* in_footer */
    );
    wp_enqueue_script(
        'window_listeners_js' /* handle */
        /* src */
        /* deps  */
        /* ver  */
        /* in_footer */
    );
}

/**
 * Add callback triggered when a new message is received
 * Edits the clarity project id option respectively
 */
add_action('wp_ajax_edit_clarity_project_id', "edit_clarity_project_id");
function edit_clarity_project_id()
{
    $new_value = $_POST['new_value'];
    $nonce = $_POST['nonce'];
    if (!wp_verify_nonce($nonce, "wp_ajax_edit_clarity_project_id")) {
        die(json_encode(
                array(
                    'success' => false,
                    'message' => 'Invalid nonce.',
                )
            ));
    }
    // only admins are allowed to edit the Clarity project id
    if (!current_user_can('manage_options')) {
        die(json_encode(
                array(
                    'success' => false,
                    'message' => 'User must be WordPress admin.'
                )
            ));
    } else {
        update_option(
            'clarity_project_id', /* option */
            $new_value /* value */
            /* autoload */
        );
        die(json_encode(
                array(
                    'success' => true,
                    'message' => 'Clarity project updated successfully.'
                )
            ));
    }
}

/**
 * Add callback triggered when a new message is received
 * Edits the agent enabled status option respectively
 */
add_action('wp_ajax_edit_agent_enabled_status', "edit_agent_enabled_status");
function edit_agent_enabled_status()
{
    $new_value = $_POST['new_value'];
    $nonce = $_POST['nonce'];
    if (!wp_verify_nonce($nonce, "wp_ajax_edit_clarity_project_id")) {
        die(json_encode(
                array(
                    'success' => false,
                    'message' => 'Invalid nonce.',
                )
            ));
    }
    // only admins are allowed to edit the Clarity project id
    if (!current_user_can('manage_options')) {
        die(json_encode(
                array(
                    'success' => false,
                    'message' => 'User must be WordPress admin.'
                )
            ));
    } else {
        update_option(
            'BAOauthSuccess', /* option */
            $new_value /* value */
            /* autoload */
        );
        die(json_encode(
                array(
                    'success' => true,
                    'message' => 'Agent enabled status updated successfully.'
                )
            ));
    }
}

/**
 * Displays an admin notice if the plugin version installed is not the latest
 */
add_action('admin_notices', 'plugin_update_notice');
function plugin_update_notice()
{
    // Only show the notice to users who can update plugins
    if (! current_user_can('update_plugins')) {
        return;
    }

    $is_latest_version = get_transient('clarity_is_latest_plugin_version');
    if ($is_latest_version !== '0') {
        return;
    }

    $plugin_slug = 'microsoft-clarity/clarity.php';
    $update_url = wp_nonce_url(
        add_query_arg(
            array(
                'action'       => 'trigger_plugin_update',
                'plugin'       => urlencode($plugin_slug),
            ),
            admin_url('admin.php')
        ),
        'plugin_update_nonce'
    );

?>
    <div class="notice notice-warning is-dismissible">
        <p style="font-weight:700">
            <?php _e('A new version of Microsoft Clarity is available.', 'text-domain'); ?>
        </p>
        <p>
            <a href="<?php echo esc_url($update_url); ?>" class="button button-primary">
                <?php _e('Update Now', 'text-domain'); ?>
            </a>
        </p>
    </div>
<?php
}

/**
 * Updates the plugin to the latest version programmatically
 * The upgrade function deactives the plugin by default before the upgrade, hence the need to reactivate it
 */
add_action('admin_action_trigger_plugin_update', 'plugin_perform_update');
function plugin_perform_update()
{
    if (! current_user_can('update_plugins')) {
        wp_die(__('You do not have sufficient permissions to update plugins.', 'text-domain'));
    }

    if (! isset($_GET['plugin']) || ! isset($_GET['_wpnonce'])) {
        return;
    }

    $plugin_slug = sanitize_text_field(urldecode($_GET['plugin']));

    if (! wp_verify_nonce($_GET['_wpnonce'], 'plugin_update_nonce')) {
        wp_die(__('Nonce verification failed.', 'text-domain'));
    }

    include_once(ABSPATH . 'wp-admin/includes/class-wp-upgrader.php');
    include_once(ABSPATH . 'wp-admin/includes/plugin.php');

    // Create a custom skin to handle output and redirection
    $upgrader_skin = new Automatic_Upgrader_Skin();
    $upgrader      = new Plugin_Upgrader($upgrader_skin);

    // Perform the update
    $updated = $upgrader->upgrade($plugin_slug);

    if (is_wp_error($updated) || ! $updated) {
        // Handle error: redirect back to admin page with an error notice 
        $redirect_url = add_query_arg('plugin_update_error', '1', admin_url('plugins.php'));
        wp_redirect(esc_url($redirect_url));
        exit;
    } else {
        // Success: redirect back to the plugin page with a success notice
        activate_plugin($plugin_slug);
        $redirect_url = add_query_arg('plugin_updated', '1', admin_url('admin.php?page=microsoft-clarity'));
        wp_redirect(esc_url($redirect_url));
        exit;
    }
}

/**
 * Display an admin notice with the status of the plugin update
 */
add_action('admin_notices', 'plugin_admin_notices');
function plugin_admin_notices()
{
    if (isset($_GET['plugin_updated']) && '1' === $_GET['plugin_updated']) {
        echo
        '<div class="notice notice-success is-dismissible">
            <p><strong>Microsoft Clarity plugin has been updated successfully.</strong></p>
        </div>';
    } else if (isset($_GET['plugin_update_error']) && '1' === $_GET['plugin_update_error']) {
        echo
        '<div class="notice notice-error is-dismissible">
            <p><strong>Microsoft Clarity plugin update failed.</strong></p>
        </div>';
    }
}
