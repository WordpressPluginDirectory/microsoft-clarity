<?php
/**
 * Brand Agent Configuration
 *
 * @package MicrosoftClarity
 * @since 0.10.21
 */

// Exit if accessed directly
defined( 'ABSPATH' ) || exit;

/**
 * Base URL path for all BrandAgent webhooks
 */
if ( ! defined( 'BRANDAGENT_WEBHOOK_BASE_URL' ) ) {
    define( 'BRANDAGENT_WEBHOOK_BASE_URL', '/api/v1/woocommerce/webhooks/' );
}

/**
 * HMAC timestamp validation window in seconds (5 minutes)
 * Used for replay attack prevention
 */
if ( ! defined( 'BRANDAGENT_HMAC_TIMESTAMP_WINDOW' ) ) {
    define( 'BRANDAGENT_HMAC_TIMESTAMP_WINDOW', 300 );
}

/**
 * Cookie name used to store BrandAgent cart attributes in the browser.
 */
if ( ! defined( 'BRANDAGENT_ATTRS_COOKIE_NAME' ) ) {
    define( 'BRANDAGENT_ATTRS_COOKIE_NAME', 'brandagent_attrs' );
}

/**
 * Lifetime of the BrandAgent attributes cookie in seconds (2 hours).
 */
if ( ! defined( 'BRANDAGENT_ATTRS_COOKIE_TTL' ) ) {
    define( 'BRANDAGENT_ATTRS_COOKIE_TTL', 2 * HOUR_IN_SECONDS );
}

/**
 * Logging helper — writes to wp-content/debug.log and Query Monitor.
 * Only logs when WP_DEBUG is enabled to avoid information disclosure in production.
 *
 * @param string $message The message to log.
 */
function brandagent_log( $message ) {
    if ( ! defined( 'WP_DEBUG' ) || ! WP_DEBUG ) {
        return;
    }

    $path = WP_CONTENT_DIR . '/debug.log';
    $line = '[' . date( 'c' ) . '] ' . $message . PHP_EOL;
    @file_put_contents( $path, $line, FILE_APPEND );
}

/**
 * Brand Agent Configuration Class
 */
class BrandAgent_Config {

    /**
     * Clarity server base URL
     *
     * @var string
     */
    private static $clarity_server_url = 'https://clarity.microsoft.com';

    /**
     * Cache key for backend URL
     *
     * @var string
     */
    private static $cache_key = 'brandagent_backend_url';

    /**
     * Cache duration (24 hours)
     *
     * @var int
     */
    private static $cache_duration = 86400;

    /**
     * Fetch backend base URL from Clarity server
     *
     * @return string|false Backend base URL or false on failure
     */
    private static function fetch_backend_url_from_clarity() {
        $config_endpoint = self::$clarity_server_url . '/woocommerce/brandagent/config';
        
        $response = wp_remote_get( $config_endpoint, array(
            'timeout' => 10,
            'headers' => array(
                'Accept' => 'application/json',
            ),
        ) );

        if ( is_wp_error( $response ) ) {
            brandagent_log( 'BrandAgent Config: Failed to fetch from Clarity server: ' . $response->get_error_message() );
            return false;
        }

        $status_code = wp_remote_retrieve_response_code( $response );
        if ( $status_code !== 200 ) {
            brandagent_log( 'BrandAgent Config: Clarity server returned status ' . $status_code );
            return false;
        }

        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body, true );

        if ( ! isset( $data['backendBaseUrl'] ) ) {
            brandagent_log( 'BrandAgent Config: Invalid response from Clarity server' );
            return false;
        }

        brandagent_log( 'BrandAgent Config: Successfully fetched backend URL from Clarity server: ' . $data['backendBaseUrl'] );
        return $data['backendBaseUrl'];
    }

    /**
     * Get backend base URL
     * Fetches from Clarity server and caches for 24 hours
     *
     * @return string Backend base URL
     */
    public static function get_backend_base_url() {
        // // Try to get from cache first
        // $cached_url = get_transient( self::$cache_key );
        // if ( $cached_url !== false ) {
        //     return $cached_url;
        // }

        // Fetch from Clarity server
        $backend_url = self::fetch_backend_url_from_clarity();
        
        if ( $backend_url === false ) {
            brandagent_log( 'BrandAgent Config: ERROR - Could not fetch backend URL from Clarity server' );
            // Return empty string - plugin cannot function without this
            return '';
        }

        // Cache the result
        set_transient( self::$cache_key, $backend_url, self::$cache_duration );
        
        return $backend_url;
    }

    /**
     * Clear the cached backend URL
     * Useful for testing or forcing a refresh
     *
     * @return void
     */
    public static function clear_cache() {
        delete_transient( self::$cache_key );
    }

    /**
     * Get Clarity server URL
     *
     * @return string Clarity server URL
     */
    public static function get_clarity_server_url() {
        return self::$clarity_server_url;
    }
}

/**
 * ============================================================================
 * Brand Agent Encryption Helper Functions
 * ============================================================================
 * Used to encrypt the HMAC secret at rest in wp_options (AES-256-CBC).
 * The encryption key is derived from wp_salt('auth'), which is defined in
 * wp-config.php and never stored in the database.
 */

/**
 * Derive a 256-bit encryption key from WordPress auth salt.
 *
 * @return string 32-byte binary encryption key
 */
function brandagent_get_encryption_key() {
    return hash( 'sha256', wp_salt( 'auth' ), true );
}

/**
 * Encrypt a value using AES-256-CBC.
 *
 * @param string $plaintext The value to encrypt
 * @return string|false Encrypted value as "iv_base64:ciphertext_base64", or false on failure
 */
function brandagent_encrypt( $plaintext ) {
    $key = brandagent_get_encryption_key();
    $iv = openssl_random_pseudo_bytes( 16 );
    if ( $iv === false ) {
        brandagent_log( 'BrandAgent Encrypt: ERROR - openssl_random_pseudo_bytes failed' );
        return false;
    }
    $ciphertext = openssl_encrypt( $plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv );
    if ( $ciphertext === false ) {
        brandagent_log( 'BrandAgent Encrypt: ERROR - openssl_encrypt failed: ' . openssl_error_string() );
        return false;
    }
    return base64_encode( $iv ) . ':' . base64_encode( $ciphertext );
}

/**
 * Decrypt a value encrypted by brandagent_encrypt().
 *
 * @param string $encrypted The encrypted value in "iv_base64:ciphertext_base64" format
 * @return string|false The decrypted plaintext, or false on failure
 */
function brandagent_decrypt( $encrypted ) {
    $key = brandagent_get_encryption_key();
    $parts = explode( ':', $encrypted, 2 );
    if ( count( $parts ) !== 2 ) {
        brandagent_log( 'BrandAgent Decrypt: ERROR - Invalid encrypted format' );
        return false;
    }
    $iv = base64_decode( $parts[0] );
    $ciphertext = base64_decode( $parts[1] );
    if ( $iv === false || $ciphertext === false ) {
        brandagent_log( 'BrandAgent Decrypt: ERROR - Base64 decoding failed' );
        return false;
    }
    $plaintext = openssl_decrypt( $ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv );
    if ( $plaintext === false ) {
        brandagent_log( 'BrandAgent Decrypt: ERROR - openssl_decrypt failed: ' . openssl_error_string() );
        return false;
    }
    return $plaintext;
}

/**
 * ============================================================================
 * Brand Agent HMAC Helper Functions
 * ============================================================================
 * These functions must be defined here (before clarity-page.php is loaded)
 * because they are called during the OAuth callback which runs at file load time.
 */

/**
 * Generate HMAC signature for WordPress requests
 * Message format: clientId + timestamp, signed with SHA256
 *
 * @param string $client_id The client ID
 * @param int $timestamp Unix timestamp
 * @param string $secret_key The HMAC secret key
 * @return string Base64-encoded HMAC signature
 */
function brandagent_generate_hmac_signature( $client_id, $timestamp, $secret_key ) {
    $message = $client_id . $timestamp;
    return base64_encode( hash_hmac( 'sha256', $message, $secret_key, true ) );
}

/**
 * Normalize store URL for consistent formatting
 * Matches C# backend normalization logic
 *
 * @param string $store_url The store URL to normalize
 * @return string Normalized store URL
 */
function brandagent_normalize_store_url( $store_url ) {
    $normalized = strtolower( str_replace( array( 'https://', 'http://' ), '', rtrim( $store_url, '/' ) ) );
    // Match C# normalization: replace dots and slashes with hyphens
    return str_replace( array( '.', '/' ), '-', $normalized );
}

/**
 * Get client ID from request URL query parameter
 *
 * @return string|false Client ID or false if not found
 */
function brandagent_get_client_id() {
    $client_id = isset( $_GET['clientId'] ) ? sanitize_text_field( $_GET['clientId'] ) : '';
    if ( empty( $client_id ) ) {
        return false;
    }
    return $client_id;
}

/**
 * Store HMAC secret received during OAuth.
 * The secret is encrypted with AES-256-CBC before being stored in wp_options.
 *
 * @param string $hmac_secret The HMAC secret
 * @return bool True on success
 */
function brandagent_store_hmac_secret( $hmac_secret ) {
    $store_url = home_url();
    $normalized_store_url = brandagent_normalize_store_url( $store_url );
    $option_key = 'brandagent_secret_key_' . $normalized_store_url;

    // Clean the HMAC secret
    $hmac_secret_clean = trim( $hmac_secret );
    $hmac_secret_clean = str_replace( array( "\r", "\n", " " ), '', $hmac_secret_clean );

    // Encrypt before storing
    $encrypted = brandagent_encrypt( $hmac_secret_clean );
    if ( $encrypted === false ) {
        return false;
    }

    update_option( $option_key, $encrypted );
    brandagent_log( 'BrandAgent: HMAC secret stored successfully for ' . $store_url );
    return true;
}

/**
 * Get the stored HMAC secret for this store.
 * Decrypts the AES-256-CBC encrypted value from wp_options.
 *
 * @return string|false The HMAC secret key or false if not found
 */
function brandagent_get_hmac_secret() {
    $store_url = home_url();
    $normalized_store_url = brandagent_normalize_store_url( $store_url );
    $option_key = 'brandagent_secret_key_' . $normalized_store_url;

    $stored_value = get_option( $option_key, false );
    if ( $stored_value === false ) {
        return false;
    }

    $decrypted = brandagent_decrypt( $stored_value );
    if ( $decrypted === false ) {
        brandagent_log( 'BrandAgent: ERROR - Decryption failed for HMAC secret' );
        return false;
    }
    return $decrypted;
}

/**
 * Delete the stored HMAC secret for this store.
 * Removes the encrypted HMAC secret from wp_options.
 *
 * @return bool True on success, false on failure
 */
function brandagent_delete_hmac_secret() {
    $store_url = home_url();
    $normalized_store_url = brandagent_normalize_store_url( $store_url );
    $option_key = 'brandagent_secret_key_' . $normalized_store_url;

    $result = delete_option( $option_key );
    if ( $result ) {
        brandagent_log( 'BrandAgent: HMAC secret deleted successfully for ' . $store_url );
    }
    return $result;
}

/**
 * Verify HMAC signature from incoming backend request
 * Used to authenticate requests FROM the BA server TO the WordPress plugin
 *
 * @param string $received_signature The signature from the request header
 * @param string $timestamp Unix timestamp from the request
 * @param string $request_body The raw request body
 * @return bool True if signature is valid
 */
function brandagent_verify_incoming_hmac_signature( $received_signature, $timestamp, $request_body = '' ) {
    $secret_key = brandagent_get_hmac_secret();
    if ( ! $secret_key ) {
        brandagent_log( 'BrandAgent: Cannot verify signature - no HMAC secret stored' );
        return false;
    }

    // Validate timestamp (5-minute window for replay attack prevention)
    $time_difference = abs( time() - intval( $timestamp ) );
    if ( $time_difference > BRANDAGENT_HMAC_TIMESTAMP_WINDOW ) {
        brandagent_log( 'BrandAgent: Request timestamp too old: ' . $time_difference . ' seconds' );
        return false;
    }

    // Message: store_url + timestamp + sha256(body)
    $store_url = home_url();
    $body_hash = hash( 'sha256', $request_body );
    $message = $store_url . $timestamp . $body_hash;

    $expected_signature = base64_encode( hash_hmac( 'sha256', $message, $secret_key, true ) );

    // Constant-time comparison to prevent timing attacks
    return hash_equals( $expected_signature, $received_signature );
}

/**
 * Sign and send an outbound HTTP request to the BrandAgent backend with HMAC authentication
 *
 * @param string $url     The full URL to send the request to
 * @param string $body    The JSON request body (optional)
 * @param string $method  HTTP method: 'POST' or 'GET' (default: 'POST')
 * @param int    $timeout Request timeout in seconds (default: 30)
 * @return array|WP_Error Response array or WP_Error on failure
 */
function brandagent_sign_outbound_request( $url, $body = '', $method = 'POST', $timeout = 30 ) {
    $store_url  = home_url();
    $secret_key = brandagent_get_hmac_secret();
    if ( ! $secret_key ) {
        brandagent_log( 'BrandAgent: Cannot sign request - no HMAC secret available' );
        return new WP_Error( 'hmac_missing', 'HMAC secret not available' );
    }

    $client_id  = brandagent_normalize_store_url( $store_url );
    $timestamp  = time();
    $signature  = brandagent_generate_hmac_signature( $client_id, $timestamp, $secret_key );

    $headers = array(
        'Content-Type'            => 'application/json',
        'X-WooCommerce-Client-Id' => $client_id,
        'X-WooCommerce-Store-Url' => $store_url,
        'X-WooCommerce-Signature' => $signature,
        'X-WooCommerce-Timestamp' => (string) $timestamp,
    );

    $args = array( 'timeout' => $timeout, 'headers' => $headers );
    if ( ! empty( $body ) ) {
        $args['body'] = $body;
    }

    return ( $method === 'GET' )
        ? wp_remote_get( $url, $args )
        : wp_remote_post( $url, $args );
}