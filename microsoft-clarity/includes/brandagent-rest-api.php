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
			'permission_callback' => '__return_true',
		) );
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
			$client_info_json = wp_json_encode( $client_info );

			wc_setcookie( BRANDAGENT_ATTRS_COOKIE_NAME, $client_info_json, time() + BRANDAGENT_ATTRS_COOKIE_TTL );
			brandagent_log( 'BrandAgent REST: Cart attributes stored. Full attributes = ' . $client_info_json );

			return rest_ensure_response( array(
				'success' => true,
				'message' => 'Cart attributes updated successfully',
			) );

		} catch ( Exception $e ) {
			brandagent_log( 'BrandAgent REST: Error in update_cart_attributes: ' . $e->getMessage() );
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
		if ( empty( $_COOKIE[ BRANDAGENT_ATTRS_COOKIE_NAME ] ) ) {
			brandagent_log( 'BrandAgent REST: get_cart_attributes - ' . BRANDAGENT_ATTRS_COOKIE_NAME . ' cookie not found, returning null' );
			return null;
		}

		$cookie_json = sanitize_text_field( wp_unslash( $_COOKIE[ BRANDAGENT_ATTRS_COOKIE_NAME ] ) );
		$attrs       = json_decode( $cookie_json, true );

		if ( ! is_array( $attrs ) ) {
			brandagent_log( 'BrandAgent REST: get_cart_attributes - cookie JSON invalid, returning null' );
			return null;
		}

		brandagent_log( 'BrandAgent REST: get_cart_attributes - found attributes = ' . $cookie_json );
		return $attrs;
	}
}
