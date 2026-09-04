<?php
/**
 * Brand Agent Endpoint Handler
 *
 * Handles proxying requests from the frontend to the BrandAgent backend server
 * with HMAC authentication.
 *
 * @package MicrosoftClarity
 * @since 0.10.21
 */

// Exit if accessed directly
defined( 'ABSPATH' ) || exit;

/**
 * Brand Agent Endpoint Handler Class
 */
class BrandAgent_Endpoint {

    /**
     * Handle incoming API requests
     */
    public static function handle_request() {
        $path = get_query_var( 'brandagent_path' );

        if ( $path === 'api/config/read' ) {
            self::handle_config_read();
        }

        if ( $path === 'api/v1/init' ) {
            self::handle_init();
        }

        if ( $path === 'api/config/update' ) {
            self::handle_config_update();
        }

        if ( $path === 'api/config/status' ) {
            self::handle_config_status();
        }

        if ( $path === 'api/content/fetch' ) {
            self::handle_content_fetch();
        }
    }

    /**
     * Build the outbound query suffix for a proxied backend call.
     *
     * clientInformation is handled separately because http_build_query() would double-escape the
     * JSON; it is unescaped once, re-encoded, then encoded exactly once. The suffix is built here
     * so the outbound URL and the signed backend path are always derived from the same string:
     * the plain-WordPress signature covers path + query exactly as the BA server receives it, so
     * the two must never drift.
     *
     * @param array $query_params Raw request query parameters (typically $_GET).
     * @return string Query suffix, already URL-encoded.
     */
    private static function build_query_suffix( array $query_params ) {
        // Handle clientInformation separately to avoid double escaping
        $client_info = null;
        if ( isset( $query_params['clientInformation'] ) ) {
            // Get the raw value and clean it up
            $raw_client_info = $query_params['clientInformation'];

            // Remove any existing escaping
            $clean_json = stripslashes( $raw_client_info );

            // Validate it's valid JSON
            $decoded = json_decode( $clean_json, true );
            if ( $decoded !== null ) {
                // Re-encode as clean JSON
                $clean_json = json_encode( $decoded, JSON_UNESCAPED_SLASHES );
            }

            // URL encode it properly
            $client_info = rawurlencode( $clean_json );
            unset( $query_params['clientInformation'] ); // Remove from main query
        }

        // Build the main query without clientInformation, then append it. The separator is derived
        // rather than hard-coded: both handlers reject a request without clientId, so the query is
        // never empty here today, but a hard-coded '&' would silently emit '/path&clientInformation='
        // if that ever changed, corrupting the URL and the signed path with it. null vs '' matters,
        // so a present-but-empty clientInformation still emits a bare 'clientInformation='.
        $query_suffix = '';
        if ( ! empty( $query_params ) ) {
            $query_suffix = '?' . http_build_query( $query_params );
        }
        if ( $client_info !== null ) {
            $query_suffix .= ( $query_suffix === '' ? '?' : '&' ) . 'clientInformation=' . $client_info;
        }

        return $query_suffix;
    }

    /**
     * Build the outbound backend URL and the auth headers for a proxied GET.
     *
     * A plain-WordPress site's per-site secret is filed in Key Vault under
     * wordpress-{site}-hmac-secret. The X-WooCommerce-* headers select the backend's
     * WooCommerceHmac scheme, which only ever resolves woocommerce-{site}-hmac-secret and so
     * fails closed on a site that never ran the wc-auth flow. WooCommerce stores must keep the
     * original scheme: their secret really is filed under the WooCommerce name.
     *
     * @param string $endpoint_path Backend path, e.g. '/api/config/read'.
     * @param array  $base_headers  Endpoint-specific headers (Accept, Content-Type, ...).
     * @param array  $query_params  Raw request query parameters (typically $_GET).
     * @param string $client_id     Client id, WooCommerce scheme only.
     * @param string $store_url     Store URL, WooCommerce scheme only.
     * @param string $signature     Signature, WooCommerce scheme only.
     * @param int    $timestamp     Timestamp, WooCommerce scheme only.
     * @return array|WP_Error Array with 'url' and 'headers', or WP_Error when signing fails.
     */
    private static function build_backend_request( $endpoint_path, array $base_headers, array $query_params, $client_id, $store_url, $signature, $timestamp ) {
        $query_suffix = self::build_query_suffix( $query_params );
        $headers      = $base_headers;

        // Scheme follows the stored credential, not the current WooCommerce load state, so that
        // deactivating WooCommerce on an onboarded store cannot start signing with the wrong scheme.
        if ( brandagent_get_hmac_platform() !== 'woocommerce' ) {
            $wp_headers = brandagent_wordpress_build_signed_headers( $endpoint_path . $query_suffix, '', 'GET' );
            if ( is_wp_error( $wp_headers ) ) {
                return $wp_headers;
            }
            $headers = array_merge( $headers, $wp_headers );
        } else {
            $headers['X-WooCommerce-Client-Id'] = $client_id;
            $headers['X-WooCommerce-Store-Url'] = $store_url;
            $headers['X-WooCommerce-Signature'] = $signature;
            $headers['X-WooCommerce-Timestamp'] = (string) $timestamp;
        }

        // Add any existing headers from the original request that might be needed
        if ( isset( $_SERVER['HTTP_ACCEPT'] ) ) {
            $headers['Accept'] = $_SERVER['HTTP_ACCEPT'];
        }
        if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
            $headers['User-Agent'] = $_SERVER['HTTP_USER_AGENT'];
        }

        return array(
            'url'     => BrandAgent_Config::get_backend_base_url() . $endpoint_path . $query_suffix,
            'headers' => $headers,
        );
    }

    /**
     * Handle api/config/read endpoint
     * Proxies config requests to the BrandAgent backend
     */
    private static function handle_config_read() {
        // Get HMAC secret for this specific store (decrypted from wp_options)
        $store_url = home_url();
        $secret_key = brandagent_get_hmac_secret();

        if ( ! $secret_key ) {
            brandagent_log( 'BrandAgent Config Read: HMAC secret missing' );
            wp_send_json_error( array( 'message' => 'HMAC secret not found. Please complete onboarding.' ), 401 );
        }

        // clientId presence is required; the widget always sends it.
        $client_id = brandagent_get_client_id();
        if ( ! $client_id ) {
            brandagent_log( 'BrandAgent Config Read: Missing clientId parameter' );
            wp_send_json_error( array( 'message' => 'No clientId provided' ), 400 );
        }

        $timestamp = time();
        $signature = brandagent_generate_hmac_signature( $client_id, $timestamp, $secret_key );

        // URL and auth headers come from the shared builder so this handler and handle_init()
        // cannot drift apart on the signing contract.
        $request = self::build_backend_request(
            '/api/config/read',
            array(
                'Content-Type'               => 'application/json',
                'Accept'                     => 'application/json',
                'User-Agent'                 => 'BrandAgent-WordPress-Plugin/1.0',
                'ngrok-skip-browser-warning' => 'true', // Bypass ngrok browser warning
            ),
            $_GET,
            $client_id,
            $store_url,
            $signature,
            $timestamp
        );

        if ( is_wp_error( $request ) ) {
            brandagent_log( 'BrandAgent Config Read: Unable to sign WordPress request', array( 'error' => $request->get_error_message() ) );
            wp_send_json_error( array( 'message' => 'HMAC secret not found. Please complete onboarding.' ), 401 );
        }

        $config_response = wp_remote_get(
            $request['url'],
            array(
                'timeout' => 30,
                'headers' => $request['headers'],
            )
        );

        if ( is_wp_error( $config_response ) ) {
            brandagent_log( 'BrandAgent Config Read: Failed to get client config', array( 'error' => $config_response->get_error_message() ) );
            wp_send_json_error( array( 'message' => 'Failed to get client configuration' ), 502 );
        }

        $config_status_code = wp_remote_retrieve_response_code( $config_response );
        $config_body = wp_remote_retrieve_body( $config_response );

        if ( $config_status_code === 200 ) {
            // Return the actual client configuration from ConfigController
            header( 'Content-Type: application/json' );
            echo $config_body;
            exit;
        } else {
            brandagent_log( 'BrandAgent Config Read: Backend returned non-success status', array( 'status_code' => $config_status_code ) );
            wp_send_json_error( array( 'message' => 'Failed to retrieve configuration' ), $config_status_code );
        }
    }

    /**
     * Handle api/v1/init endpoint
     * Proxies SSE stream requests to the BrandAgent backend
     */
    private static function handle_init() {
        // Get HMAC secret for this specific store (decrypted from wp_options)
        $store_url = home_url();
        $secret_key = brandagent_get_hmac_secret();

        if ( ! $secret_key ) {
            brandagent_log( 'BrandAgent Init: HMAC secret missing' );
            wp_send_json_error( array( 'message' => 'HMAC secret not found. Please complete onboarding.' ), 401 );
        }

        // clientId presence is required; the widget always sends it.
        $client_id = brandagent_get_client_id();
        if ( ! $client_id ) {
            brandagent_log( 'BrandAgent Init: Missing clientId parameter' );
            wp_send_json_error( array( 'message' => 'No clientId provided' ), 400 );
        }

        $timestamp = time();
        $signature = brandagent_generate_hmac_signature( $client_id, $timestamp, $secret_key );

        // Shared builder, as in handle_config_read(). For a plain-WordPress site the X-WordPress-*
        // scheme also routes the request to the document orchestration path, which is the correct
        // agent for a content site. WooCommerce stores are unchanged.
        $request = self::build_backend_request(
            '/api/v1/init',
            array(
                'Accept'                     => 'text/event-stream',
                'Cache-Control'              => 'no-cache',
                'User-Agent'                 => 'BrandAgent-WordPress-Plugin/1.0',
                'ngrok-skip-browser-warning' => 'true', // Bypass ngrok browser warning
            ),
            $_GET,
            $client_id,
            $store_url,
            $signature,
            $timestamp
        );

        if ( is_wp_error( $request ) ) {
            brandagent_log( 'BrandAgent Init: Unable to sign WordPress request', array( 'error' => $request->get_error_message() ) );
            wp_send_json_error( array( 'message' => 'HMAC secret not found. Please complete onboarding.' ), 401 );
        }

        $init_response = wp_remote_get(
            $request['url'],
            array(
                'timeout' => 30,
                'headers' => $request['headers'],
            )
        );

        if ( is_wp_error( $init_response ) ) {
            brandagent_log( 'BrandAgent Init: Failed to initialize chat', array( 'error' => $init_response->get_error_message() ) );
            wp_send_json_error( array( 'message' => 'Failed to initialize chat' ), 502 );
        }

        $init_status_code = wp_remote_retrieve_response_code( $init_response );
        $init_body = wp_remote_retrieve_body( $init_response );

        if ( $init_status_code === 200 ) {
            // Set SSE headers for the response
            header( 'Content-Type: text/event-stream' );
            header( 'Cache-Control: no-cache' );
            header( 'Connection: keep-alive' );

            echo $init_body;
            exit;
        } else {
            brandagent_log( 'BrandAgent Init: Backend returned non-success status', array( 'status_code' => $init_status_code ) );
            wp_send_json_error( array( 'message' => 'Failed to initialize chat' ), $init_status_code );
        }
    }

    /**
     * Handle api/config/update endpoint
     * Receives configuration updates from the backend server
     */
    private static function handle_config_update() {
        // Prevent caching of this state-changing endpoint
        header( 'Cache-Control: no-store' );

        // Get authentication headers
        $signature = isset( $_SERVER['HTTP_X_BA_SIGNATURE'] )
            ? sanitize_text_field( $_SERVER['HTTP_X_BA_SIGNATURE'] )
            : '';
        $timestamp = isset( $_SERVER['HTTP_X_BA_TIMESTAMP'] )
            ? sanitize_text_field( $_SERVER['HTTP_X_BA_TIMESTAMP'] )
            : '';
        $store_url_header = isset( $_SERVER['HTTP_X_BA_STORE_URL'] )
            ? sanitize_text_field( $_SERVER['HTTP_X_BA_STORE_URL'] )
            : '';

        // Validate required headers present
        if ( empty( $signature ) || empty( $timestamp ) || empty( $store_url_header ) ) {
            brandagent_log( 'BrandAgent Config Update: Missing required authentication headers' );
            wp_send_json_error( array( 'message' => 'Missing authentication headers' ), 401 );
        }

        // Verify store URL matches this site
        if ( $store_url_header !== home_url() ) {
            brandagent_log( 'BrandAgent Config Update: Store URL mismatch', array(
                'expected_store_url' => home_url(),
                'received_store_url' => $store_url_header,
            ) );
            wp_send_json_error( array( 'message' => 'Store URL mismatch' ), 403 );
        }

        // Read BAInjectFrontendScript from query parameter (GET) or JSON body (POST, legacy)
        $ba_value = null;
        $hmac_payload = '';
        if ( isset( $_GET['BAInjectFrontendScript'] ) ) {
            $ba_value = sanitize_text_field( $_GET['BAInjectFrontendScript'] );
            // HMAC signs the query string (same string the C# sender hashes)
            $hmac_payload = 'BAInjectFrontendScript=' . $ba_value;
        } elseif ( $_SERVER['REQUEST_METHOD'] === 'POST' ) {
            // Legacy POST support for backward compatibility during rollout
            $hmac_payload = file_get_contents( 'php://input' );
            $data = json_decode( $hmac_payload, true );
            if ( json_last_error() === JSON_ERROR_NONE && isset( $data['BAInjectFrontendScript'] ) ) {
                $ba_value = $data['BAInjectFrontendScript'] === true || $data['BAInjectFrontendScript'] === 'true' ? 'true' : 'false';
            }
        }

        if ( $ba_value === null ) {
            brandagent_log( 'BrandAgent Config Update: Missing BAInjectFrontendScript parameter', array( 'method' => $_SERVER['REQUEST_METHOD'] ?? '' ) );
            wp_send_json_error( array( 'message' => 'Missing BAInjectFrontendScript parameter' ), 400 );
        }

        // Verify HMAC signature
        if ( ! brandagent_verify_incoming_hmac_signature( $signature, $timestamp, $hmac_payload ) ) {
            brandagent_log( 'BrandAgent Config Update: HMAC signature verification failed' );
            wp_send_json_error( array( 'message' => 'Invalid signature' ), 401 );
        }

        // Handle BAInjectFrontendScript update
        $new_value = ( $ba_value === 'true' );
        update_option( 'BAInjectFrontendScript', $new_value ? 'true' : 'false' );

        brandagent_log( 'BrandAgent Config Update: BAInjectFrontendScript updated', array(
            'new_value' => $new_value ? 'true' : 'false',
        ) );

        // Create webhooks once when inject=true AND OAuth has succeeded.
        if ( $new_value
             && get_option( 'BAOauthSuccess' ) == 1
             && ! get_option( 'BAWebhooksCreated' ) ) {
            // BA server has already handled complete-onboarding via PublishAgent.
            // The plugin's only job here is to register WooCommerce webhooks.
            if ( class_exists( 'BrandAgent_Webhooks' ) ) {
                $results       = BrandAgent_Webhooks::create_webhooks();
                $webhook_count = is_array( $results ) ? count( $results ) : 0;
                $success_count = is_array( $results ) ? count( array_filter( $results ) ) : 0;
                $failure_count = $webhook_count - $success_count;
                $all_succeeded = ( 0 < $webhook_count && 0 === $failure_count );
                if ( $all_succeeded ) {
                    update_option( 'BAWebhooksCreated', true );
                    brandagent_log( 'BrandAgent Config Update: Webhooks created on store approval', array(
                        'webhook_count' => $webhook_count,
                        'success_count' => $success_count,
                        'failure_count' => $failure_count,
                    ) );
                } else {
                    // Do NOT persist BAWebhooksCreated on partial/failed creation so future attempts can retry.
                    brandagent_log( 'BrandAgent Config Update: Webhook creation incomplete; will retry on next update', array(
                        'webhook_count' => $webhook_count,
                        'success_count' => $success_count,
                        'failure_count' => $failure_count,
                    ) );
                }
            } else {
                brandagent_log( 'BrandAgent Config Update: BrandAgent_Webhooks class not available for store approval webhook creation' );
            }
        } else {
            brandagent_log( 'BrandAgent Config Update: No onboarding side effects required', array(
                'new_value'     => $new_value ? 'true' : 'false',
                'oauth_success' => get_option( 'BAOauthSuccess' ) == 1,
            ) );
        }

        wp_send_json_success( array(
            'message' => 'Configuration updated',
            'BAInjectFrontendScript' => $new_value ? 'true' : 'false'
        ) );
    }

    /**
     * Handle api/content/fetch endpoint
     *
     * Serves the site's own content (posts/pages) to the BrandAgent backend for
     * indexing. Backend-to-plugin call, authenticated with the same X-BA-* inbound
     * HMAC contract as config/update (signature over store_url + timestamp + sha256(raw body)).
     * Content is read server-side via WP_Query, so it is reachable regardless of which
     * post types opt into the public REST API and works on any WordPress (no WooCommerce).
     */
    private static function handle_content_fetch() {
        header( 'Cache-Control: no-store' );

        $signature = isset( $_SERVER['HTTP_X_BA_SIGNATURE'] )
            ? sanitize_text_field( $_SERVER['HTTP_X_BA_SIGNATURE'] )
            : '';
        $timestamp = isset( $_SERVER['HTTP_X_BA_TIMESTAMP'] )
            ? sanitize_text_field( $_SERVER['HTTP_X_BA_TIMESTAMP'] )
            : '';
        $store_url_header = isset( $_SERVER['HTTP_X_BA_STORE_URL'] )
            ? sanitize_text_field( $_SERVER['HTTP_X_BA_STORE_URL'] )
            : '';

        if ( empty( $signature ) || empty( $timestamp ) || empty( $store_url_header ) ) {
            brandagent_log( 'BrandAgent Content Fetch: Missing required authentication headers' );
            wp_send_json_error( array( 'message' => 'Missing authentication headers' ), 401 );
        }

        if ( $store_url_header !== home_url() ) {
            brandagent_log( 'BrandAgent Content Fetch: Store URL mismatch', array(
                'expected_store_url' => home_url(),
                'received_store_url' => $store_url_header,
            ) );
            wp_send_json_error( array( 'message' => 'Store URL mismatch' ), 403 );
        }

        $raw_body = file_get_contents( 'php://input' );
        if ( ! brandagent_verify_incoming_hmac_signature( $signature, $timestamp, (string) $raw_body ) ) {
            brandagent_log( 'BrandAgent Content Fetch: HMAC signature verification failed' );
            wp_send_json_error( array( 'message' => 'Invalid signature' ), 401 );
        }

        $req = json_decode( (string) $raw_body, true );
        if ( ! is_array( $req ) ) {
            $req = array();
        }

        // Restrict to an explicit allowlist so a caller cannot pull private or PII-bearing
        // custom post types through WP_Query. Sites can widen it via the filter.
        $allowed_types   = apply_filters( 'brandagent_content_fetch_allowed_post_types', array( 'post', 'page' ) );
        $requested_types = ( isset( $req['types'] ) && is_array( $req['types'] ) )
            ? array_values( array_map( 'sanitize_key', $req['types'] ) )
            : array();
        $types = array_values( array_intersect( $requested_types, $allowed_types ) );
        if ( empty( $types ) ) {
            $types = $allowed_types;
        }
        $page     = isset( $req['page'] ) ? max( 1, intval( $req['page'] ) ) : 1;
        $per_page = isset( $req['per_page'] ) ? min( 100, max( 1, intval( $req['per_page'] ) ) ) : 50;

        $query = new WP_Query( array(
            'post_type'           => $types,
            'post_status'         => 'publish',
            'posts_per_page'      => $per_page,
            'paged'               => $page,
            'orderby'             => 'ID',
            'order'               => 'ASC',
            'ignore_sticky_posts' => true,
            'has_password'        => false,
        ) );

        $items = array();
        foreach ( $query->posts as $post ) {
            // Shared builder (includes/brandagent-content-webhooks.php) — the single source of truth for
            // the content item shape, so the bulk fetch here and the incremental webhooks stay identical.
            $items[] = brandagent_build_content_item( $post );
        }

        wp_send_json_success( array(
            'page'        => $page,
            'per_page'    => $per_page,
            'total'       => (int) $query->found_posts,
            'total_pages' => (int) $query->max_num_pages,
            'count'       => count( $items ),
            'items'       => $items,
        ) );
    }

    /**
     * Handle api/config/status endpoint
     * Returns current configuration values (read-only, no auth required)
     */
    private static function handle_config_status() {
        $ba_inject_enabled = get_option( 'BAInjectFrontendScript', 'false' );
        $ba_oauth_success = get_option( 'BAOauthSuccess', '0' );

        wp_send_json_success( array(
            'BAInjectFrontendScript' => $ba_inject_enabled,
            'BAOauthSuccess' => $ba_oauth_success,
            'pluginVersion' => get_installed_plugin_version(),
        ) );
    }
}

// Run the handler immediately when file is included
BrandAgent_Endpoint::handle_request();
