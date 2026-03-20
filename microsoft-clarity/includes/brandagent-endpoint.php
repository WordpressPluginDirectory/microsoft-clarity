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
            wp_send_json_error( array( 'message' => 'HMAC secret not found. Please complete onboarding.' ), 401 );
        }

        // Generate HMAC signature for this request
        $client_id = brandagent_get_client_id();
        if ( ! $client_id ) {
            wp_send_json_error( array( 'message' => 'No clientId provided' ), 400 );
        }

        $timestamp = time();
        $signature = brandagent_generate_hmac_signature( $client_id, $timestamp, $secret_key );

        // Call the config endpoint directly with HMAC parameters
        $config_url = BrandAgent_Config::get_backend_base_url() . '/api/config/read';

        // Pass through all the original request parameters
        $config_query = $_GET;

        // Handle clientInformation separately to avoid double escaping
        $client_info = '';
        if ( isset( $config_query['clientInformation'] ) ) {
            // Get the raw value and clean it up
            $raw_client_info = $config_query['clientInformation'];

            // Remove any existing escaping
            $clean_json = stripslashes( $raw_client_info );

            // Validate it's valid JSON
            $decoded = json_decode( $clean_json, true );
            if ( $decoded !== null ) {
                // Re-encode as clean JSON
                $clean_json = json_encode( $decoded, JSON_UNESCAPED_SLASHES );
            }

            // URL encode it properly
            $client_info = '&clientInformation=' . rawurlencode( $clean_json );
            unset( $config_query['clientInformation'] ); // Remove from main query
        }

        // Build the main query without clientInformation
        $config_url_with_params = $config_url;
        if ( ! empty( $config_query ) ) {
            $config_url_with_params .= '?' . http_build_query( $config_query );
        }
        $config_url_with_params .= $client_info;

        // Set up headers that ConfigController might need
        $config_headers = array(
            'Content-Type'              => 'application/json',
            'Accept'                    => 'application/json',
            'User-Agent'                => 'BrandAgent-WordPress-Plugin/1.0',
            'ngrok-skip-browser-warning' => 'true', // Bypass ngrok browser warning
            'X-WooCommerce-Client-Id'   => $client_id,
            'X-WooCommerce-Store-Url'   => $store_url,
            'X-WooCommerce-Signature'   => $signature,
            'X-WooCommerce-Timestamp'   => (string) $timestamp,
        );

        // Add any existing headers from the original request that might be needed
        if ( isset( $_SERVER['HTTP_ACCEPT'] ) ) {
            $config_headers['Accept'] = $_SERVER['HTTP_ACCEPT'];
        }
        if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
            $config_headers['User-Agent'] = $_SERVER['HTTP_USER_AGENT'];
        }

        $config_response = wp_remote_get(
            $config_url_with_params,
            array(
                'timeout' => 30,
                'headers' => $config_headers,
            )
        );

        if ( is_wp_error( $config_response ) ) {
            error_log( 'BrandAgent: Failed to get client config: ' . $config_response->get_error_message() );
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
            wp_send_json_error( array( 'message' => 'HMAC secret not found. Please complete onboarding.' ), 401 );
        }

        // Generate HMAC signature for this request
        $client_id = brandagent_get_client_id();
        if ( ! $client_id ) {
            wp_send_json_error( array( 'message' => 'No clientId provided' ), 400 );
        }

        $timestamp = time();
        $signature = brandagent_generate_hmac_signature( $client_id, $timestamp, $secret_key );

        // Call the init endpoint with HMAC parameters
        $init_url = BrandAgent_Config::get_backend_base_url() . '/api/v1/init';

        // Pass through all the original request parameters
        $init_query = $_GET;

        // Handle clientInformation separately to avoid double escaping
        $client_info = '';
        if ( isset( $init_query['clientInformation'] ) ) {
            // Get the raw value and clean it up
            $raw_client_info = $init_query['clientInformation'];

            // Remove any existing escaping
            $clean_json = stripslashes( $raw_client_info );

            // Validate it's valid JSON
            $decoded = json_decode( $clean_json, true );
            if ( $decoded !== null ) {
                // Re-encode as clean JSON
                $clean_json = json_encode( $decoded, JSON_UNESCAPED_SLASHES );
            }

            // URL encode it properly
            $client_info = '&clientInformation=' . rawurlencode( $clean_json );
            unset( $init_query['clientInformation'] ); // Remove from main query
        }

        // Build the main query without clientInformation
        $init_url_with_params = $init_url;
        if ( ! empty( $init_query ) ) {
            $init_url_with_params .= '?' . http_build_query( $init_query );
        }
        $init_url_with_params .= $client_info;

        // Set up headers for SSE request
        $init_headers = array(
            'Accept'                     => 'text/event-stream',
            'Cache-Control'              => 'no-cache',
            'User-Agent'                 => 'BrandAgent-WordPress-Plugin/1.0',
            'ngrok-skip-browser-warning' => 'true', // Bypass ngrok browser warning
            'X-WooCommerce-Client-Id'    => $client_id,
            'X-WooCommerce-Store-Url'    => $store_url,
            'X-WooCommerce-Signature'    => $signature,
            'X-WooCommerce-Timestamp'    => (string) $timestamp,
        );

        // Add any existing headers from the original request that might be needed
        if ( isset( $_SERVER['HTTP_ACCEPT'] ) ) {
            $init_headers['Accept'] = $_SERVER['HTTP_ACCEPT'];
        }
        if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
            $init_headers['User-Agent'] = $_SERVER['HTTP_USER_AGENT'];
        }

        $init_response = wp_remote_get(
            $init_url_with_params,
            array(
                'timeout' => 30,
                'headers' => $init_headers,
            )
        );

        if ( is_wp_error( $init_response ) ) {
            error_log( 'BrandAgent: Failed to initialize chat: ' . $init_response->get_error_message() );
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
            wp_send_json_error( array( 'message' => 'Failed to initialize chat' ), $init_status_code );
        }
    }

    /**
     * Handle api/config/update endpoint
     * Receives configuration updates from the backend server
     */
    private static function handle_config_update() {
        // Only accept POST requests
        if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
            wp_send_json_error( array( 'message' => 'Method not allowed' ), 405 );
        }

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
            error_log( 'BrandAgent: Missing required authentication headers' );
            wp_send_json_error( array( 'message' => 'Missing authentication headers' ), 401 );
        }

        // Verify store URL matches this site
        if ( $store_url_header !== home_url() ) {
            error_log( 'BrandAgent: Store URL mismatch. Expected: ' . home_url() . ', Got: ' . $store_url_header );
            wp_send_json_error( array( 'message' => 'Store URL mismatch' ), 403 );
        }

        // Get raw request body
        $request_body = file_get_contents( 'php://input' );

        // Verify HMAC signature
        if ( ! brandagent_verify_incoming_hmac_signature( $signature, $timestamp, $request_body ) ) {
            error_log( 'BrandAgent: HMAC signature verification failed' );
            wp_send_json_error( array( 'message' => 'Invalid signature' ), 401 );
        }

        // Parse request body
        $data = json_decode( $request_body, true );
        if ( json_last_error() !== JSON_ERROR_NONE ) {
            wp_send_json_error( array( 'message' => 'Invalid JSON body' ), 400 );
        }

        // Handle BAInjectFrontendScript update
        if ( isset( $data['BAInjectFrontendScript'] ) ) {
            $old_value = get_option( 'BAInjectFrontendScript', 'false' );
            $new_value = $data['BAInjectFrontendScript'] === true || $data['BAInjectFrontendScript'] === 'true';
            update_option( 'BAInjectFrontendScript', $new_value ? 'true' : 'false' );

            error_log( 'BrandAgent: BAInjectFrontendScript updated to: ' . ( $new_value ? 'true' : 'false' ) );

            // If changed to true and agent is enabled, create webhooks and trigger sync
            if ( $old_value !== 'true' && $new_value && get_option( 'BAOauthSuccess' ) == 1 ) {
                // Complete onboarding (HMAC-signed request through Clarity proxy)
                $clarity_domain = BrandAgent_Config::get_clarity_server_url();
                $complete_onboarding_endpoint = $clarity_domain . '/woocommerce/complete-onboarding';
                $response = brandagent_sign_outbound_request( $complete_onboarding_endpoint, wp_json_encode( array( 'storeUrl' => home_url() ) ) );

                if ( is_wp_error( $response ) ) {
                    error_log( 'BrandAgent: Failed to notify complete-onboarding: ' . $response->get_error_message() );
                } else {
                    $status_code = wp_remote_retrieve_response_code( $response );
                    if ( $status_code === 200 ) {
                        // Create/update all webhooks only on successful onboarding
                        if ( class_exists( 'BrandAgent_Webhooks' ) ) {
                            $results = BrandAgent_Webhooks::create_webhooks();
                            error_log( 'BrandAgent: Webhooks created on store approval: ' . print_r( $results, true ) );
                        }
                    } else {
                        error_log( 'BrandAgent: complete-onboarding returned status ' . $status_code . ', skipping webhook creation' );
                    }
                }
            }

            wp_send_json_success( array(
                'message' => 'Configuration updated',
                'BAInjectFrontendScript' => $new_value ? 'true' : 'false'
            ) );
        }

        wp_send_json_error( array( 'message' => 'No valid configuration key provided' ), 400 );
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
        ) );
    }
}

// Run the handler immediately when file is included
BrandAgent_Endpoint::handle_request();
