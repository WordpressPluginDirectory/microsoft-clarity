<?php
/**
 * BrandAgent REST API Endpoints
 *
 * @package BrandAgent
 * @since 0.10.21
 */

// Exit if accessed directly
defined( 'ABSPATH' ) || exit;

/**
 * Class for registering custom REST API endpoints
 */
class BrandAgent_REST_API {

    /**
     * API namespace
     *
     * @var string
     */
    private $namespace = 'adsagent/v1';

    /**
     * Register routes
     */
    public function register_routes() {
        register_rest_route( $this->namespace, '/cart/updateattributes', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'update_cart_attributes' ),
            'permission_callback' => array( $this, 'verify_nonce_permission' ),
        ) );
    }

    /**
     * Permission callback that validates the WooCommerce nonce.
     *
     * Accepts two nonce types (checked in order):
     *   1. `wc_store_api`  – the Store API nonce injected by WC Blocks
     *      (sent via the standard `Nonce` header)
     *   2. `wp_rest`       – the WordPress REST nonce from `wcSettings.nonce`
     *      (fallback for classic themes that don't load WC Blocks)
     *
     * The nonce is read from (in priority order):
     *   - HTTP header `Nonce` (WooCommerce Store API convention)
     *   - HTTP header `X-WP-Nonce` (WordPress REST convention)
     *   - JSON body field `nonce`
     *
     * @param WP_REST_Request $request Full data about the request.
     * @return true|WP_Error True if permission granted, WP_Error otherwise.
     */
    public function verify_nonce_permission( $request ) {
        // Collect the nonce from all possible transport locations
        $nonce = $request->get_header( 'nonce' );           // "Nonce" header (WC Store API standard)

        if ( ! $nonce ) {
            $nonce = $request->get_header( 'x_wp_nonce' );  // "X-WP-Nonce" header (WP REST standard)
        }

        if ( ! $nonce ) {
            $body  = $request->get_json_params();
            $nonce = $body['nonce'] ?? '';
        }

        if ( empty( $nonce ) ) {
            return new WP_Error(
                'rest_missing_nonce',
                'Missing security nonce. The request must include a valid nonce via the Nonce header or request body.',
                array( 'status' => 401 )
            );
        }

        // Try the Store API nonce action first (preferred)
        if ( wp_verify_nonce( $nonce, 'wc_store_api' ) ) {
            return true;
        }

        // Fallback: try the WordPress REST nonce action
        if ( wp_verify_nonce( $nonce, 'wp_rest' ) ) {
            return true;
        }

        return new WP_Error(
            'rest_invalid_nonce',
            'Invalid security nonce. The nonce has expired or is not recognized.',
            array( 'status' => 403 )
        );
    }

    /**
     * Recursively sanitize the clarityInformation object.
     *
     * @param mixed $info The clarityInformation data to sanitize.
     * @return array Sanitized array.
     */
    private function sanitize_clarity_info( $info ) {
        if ( ! is_array( $info ) ) {
            return array();
        }

        $sanitized = array();
        foreach ( $info as $key => $value ) {
            $clean_key = sanitize_text_field( $key );
            if ( is_array( $value ) ) {
                $sanitized[ $clean_key ] = $this->sanitize_clarity_info( $value );
            } else {
                $sanitized[ $clean_key ] = sanitize_text_field( (string) $value );
            }
        }
        return $sanitized;
    }

    /**
     * Update cart session attributes
     *
     * @param WP_REST_Request $request Full data about the request.
     * @return WP_REST_Response|WP_Error Response object on success, or WP_Error object on failure.
     */
    public function update_cart_attributes( $request ) {
        try {
            // Get request body
            $body = $request->get_json_params();

            if ( empty( $body ) || ! isset( $body['attributes'] ) ) {
                return new WP_Error( 'invalid_request', 'Missing attributes in request body', array( 'status' => 400 ) );
            }

            $raw_attributes = $body['attributes'];

            // Sanitize all input attributes
            $attributes = array(
                'sessionId'          => sanitize_text_field( $raw_attributes['sessionId'] ?? '' ),
                'clientId'           => sanitize_text_field( $raw_attributes['clientId'] ?? '' ),
                'conversationId'     => sanitize_text_field( $raw_attributes['conversationId'] ?? '' ),
                'clarityInformation' => $this->sanitize_clarity_info( $raw_attributes['clarityInformation'] ?? array() ),
                'language'           => sanitize_text_field( $raw_attributes['language'] ?? '' ),
                'currency'           => sanitize_text_field( $raw_attributes['currency'] ?? '' ),
                'country'            => sanitize_text_field( $raw_attributes['country'] ?? '' ),
            );

            // Validate required fields
            if ( empty( $attributes['clientId'] ) ) {
                return new WP_Error( 'missing_client_id', 'Missing required clientId', array( 'status' => 400 ) );
            }

            // Ensure WooCommerce is available
            if ( ! class_exists( 'WC' ) || ! function_exists( 'WC' ) ) {
                return new WP_Error( 'wc_unavailable', 'WooCommerce is not available', array( 'status' => 500 ) );
            }

            // Defensively initialize WC session if needed
            if ( ! WC()->session ) {
                if ( method_exists( WC(), 'initialize_session' ) ) {
                    WC()->initialize_session();
                }

                if ( ! WC()->session ) {
                    return new WP_Error( 'session_unavailable', 'WooCommerce session could not be initialized', array( 'status' => 500 ) );
                }
            }

            $wc_session = WC()->session;

            // Store the attributes in WooCommerce session
            $wc_session->set( 'brandagent_session_id', $attributes['sessionId'] ?? '' );
            $wc_session->set( 'brandagent_client_id', $attributes['clientId'] ?? '' );
            $wc_session->set( 'brandagent_conversation_id', $attributes['conversationId'] ?? '' );
            $wc_session->set( 'brandagent_clarity_information', $attributes['clarityInformation'] ?? array() );
            $wc_session->set( 'brandagent_language', $attributes['language'] ?? '' );
            $wc_session->set( 'brandagent_currency', $attributes['currency'] ?? '' );
            $wc_session->set( 'brandagent_country', $attributes['country'] ?? '' );

            // Store full client info as a single JSON blob in WC session
            $client_info = array(
                'sessionId'            => $attributes['sessionId'] ?? '',
                'clientId'             => $attributes['clientId'] ?? '',
                'conversationId'       => $attributes['conversationId'] ?? '',
                'clarityInformation'   => $attributes['clarityInformation'] ?? array(),
                'language'             => $attributes['language'] ?? '',
                'currency'             => $attributes['currency'] ?? '',
                'country'              => $attributes['country'] ?? '',
            );
            $wc_session->set( 'brandagent_client_info', wp_json_encode( $client_info ) );

            // Persist cart state if cart exists
            if ( WC()->cart ) {
                WC()->cart->set_session();
            }

            // Log for debugging
            if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                error_log( 'BrandAgent: Cart attributes updated for clientId: ' . ( $attributes['clientId'] ?? 'unknown' ) );
            }

            return rest_ensure_response( array(
                'success' => true,
                'message' => 'Cart attributes updated successfully',
            ) );

        } catch ( Exception $e ) {
            error_log( 'BrandAgent: Error updating cart attributes: ' . $e->getMessage() );
            return new WP_Error(
                'update_failed',
                'Failed to update cart attributes: ' . $e->getMessage(),
                array( 'status' => 500 )
            );
        }
    }

    /**
     * Get stored cart attributes
     *
     * @return array|null Stored attributes or null if not found
     */
    public static function get_cart_attributes() {
        // Try WooCommerce session first
        if ( class_exists( 'WC' ) && function_exists( 'WC' ) && WC()->session ) {
            $wc_session = WC()->session;
            $client_info_json = $wc_session->get( 'brandagent_client_info' );

            if ( $client_info_json ) {
                return json_decode( $client_info_json, true );
            }

            // Fallback: construct from individual session values
            $session_id = $wc_session->get( 'brandagent_session_id' );
            if ( $session_id ) {
                return array(
                    'sessionId'            => $session_id,
                    'clientId'             => $wc_session->get( 'brandagent_client_id' ),
                    'conversationId'       => $wc_session->get( 'brandagent_conversation_id' ),
                    'clarityInformation'   => $wc_session->get( 'brandagent_clarity_information' ),
                    'language'             => $wc_session->get( 'brandagent_language' ),
                    'currency'             => $wc_session->get( 'brandagent_currency' ),
                    'country'              => $wc_session->get( 'brandagent_country' ),
                );
            }
        }

        return null;
    }
}
