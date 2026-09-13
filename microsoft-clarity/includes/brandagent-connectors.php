<?php
/**
 * Brand Agent third-party connectors (Square).
 *
 * The Clarity dashboard iframe owns the UI. This file is the privileged HMAC
 * bridge: admin-ajax operations are signed here and sent directly to AdsAgentServer.
 * The browser never receives the merchant secret, advertiser id, or connector id.
 *
 * @package MicrosoftClarity
 */

defined( 'ABSPATH' ) || exit;

define( 'BRANDAGENT_CONNECTORS_PATH', '/api/v1/advertiser/connectors' );
define( 'BRANDAGENT_CONNECTOR_SQUARE_PROVIDER_ID', 'square' );

/**
 * @return bool Whether this site has a usable plain-WordPress Brand Agents connection.
 */
function brandagent_connectors_has_wordpress_connection() {
	return function_exists( 'brandagent_wordpress_has_connection' )
		&& function_exists( 'brandagent_get_hmac_platform' )
		&& 'wordpress' === brandagent_get_hmac_platform()
		&& brandagent_wordpress_has_connection();
}

/**
 * admin-ajax entry point used by js/add_window_listeners.js after a
 * WORDPRESS_CONNECTOR_REQUEST postMessage from the Clarity iframe.
 *
 * The iframe does not send the nonce or connector ids. The parent holds the nonce
 * via wp_localize_script and PHP resolves Square's connector id from status.
 */
add_action( 'wp_ajax_brandagent_connectors', 'brandagent_connectors_ajax' );
function brandagent_connectors_ajax() {
	$nonce = isset( $_POST['nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['nonce'] ) ) : '';
	if ( ! wp_verify_nonce( $nonce, 'wp_ajax_brandagent_connectors' ) ) {
		wp_send_json_error( array( 'message' => 'Invalid nonce.' ), 403 );
	}

	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( array( 'message' => 'WordPress administrator access is required.' ), 403 );
	}

	if ( ! brandagent_connectors_has_wordpress_connection() ) {
		wp_send_json_error(
			array( 'message' => 'Complete the WordPress Brand Agent connection before connecting Square.' ),
			409
		);
	}

	$operation   = isset( $_POST['operation'] ) ? sanitize_key( wp_unslash( $_POST['operation'] ) ) : 'status';
	$provider_id = isset( $_POST['providerId'] ) ? sanitize_key( wp_unslash( $_POST['providerId'] ) ) : '';
	$result      = brandagent_connectors_execute_operation( $operation, $provider_id );

	if ( is_wp_error( $result ) ) {
		$error_data = $result->get_error_data();
		$status     = ( is_array( $error_data ) && isset( $error_data['status'] ) )
			? (int) $error_data['status']
			: 500;
		if ( $status < 400 || $status > 599 ) {
			$status = 500;
		}
		wp_send_json_error(
			array(
				'code'    => $result->get_error_code(),
				'message' => $result->get_error_message(),
			),
			$status
		);
	}

	wp_send_json_success( $result );
}

/**
 * Run one allowlisted Square connector operation.
 *
 * @param string $operation   Requested operation.
 * @param string $provider_id Target provider id (required for every operation but status).
 * @return array|WP_Error Result payload.
 */
function brandagent_connectors_execute_operation( $operation, $provider_id ) {
	if ( 'status' === $operation ) {
		return brandagent_connectors_get_status();
	}

	if ( ! in_array( $operation, array( 'connect', 'reauthorize', 'sync', 'disconnect' ), true ) ) {
		return new WP_Error(
			'invalid_operation',
			'Unsupported connector operation.',
			array( 'status' => 400 )
		);
	}

	if ( BRANDAGENT_CONNECTOR_SQUARE_PROVIDER_ID !== $provider_id ) {
		return new WP_Error(
			'unsupported_provider',
			'This plugin only supports connecting Square.',
			array( 'status' => 400 )
		);
	}

	if ( 'connect' === $operation ) {
		$response = brandagent_connectors_api_request(
			'POST',
			'',
			array( 'providerId' => BRANDAGENT_CONNECTOR_SQUARE_PROVIDER_ID )
		);
		return is_wp_error( $response ) ? $response : brandagent_connectors_validate_authorization_response( $response );
	}

	$status = brandagent_connectors_get_raw_status();
	if ( is_wp_error( $status ) ) {
		return $status;
	}

	$connector = brandagent_connectors_find_provider_item( $status['connectors'], BRANDAGENT_CONNECTOR_SQUARE_PROVIDER_ID );
	if ( empty( $connector['connectorId'] ) ) {
		return new WP_Error(
			'connector_not_found',
			'No Square connector exists for this site.',
			array( 'status' => 404 )
		);
	}

	$connector_id = rawurlencode( $connector['connectorId'] );
	switch ( $operation ) {
		case 'reauthorize':
			$response = brandagent_connectors_api_request( 'POST', '/' . $connector_id . ':reauthorize' );
			return is_wp_error( $response ) ? $response : brandagent_connectors_validate_authorization_response( $response );
		case 'sync':
			$response = brandagent_connectors_api_request( 'POST', '/' . $connector_id . ':sync' );
			return is_wp_error( $response ) ? $response : brandagent_connectors_project_sync_response_for_ui( $response );
		case 'disconnect':
			$response = brandagent_connectors_api_request( 'DELETE', '/' . $connector_id );
			return is_wp_error( $response ) ? $response : array( 'disconnected' => true );
	}

	return new WP_Error(
		'invalid_operation',
		'Unsupported connector operation.',
		array( 'status' => 400 )
	);
}

/**
 * Get browser-safe Square provider metadata and connector status.
 *
 * @return array|WP_Error Status payload.
 */
function brandagent_connectors_get_status() {
	$status = brandagent_connectors_get_raw_status();
	if ( is_wp_error( $status ) ) {
		return $status;
	}

	return array(
		'providers'            => array_map( 'brandagent_connectors_project_provider_for_ui', $status['providers'] ),
		'connectors'           => array_map( 'brandagent_connectors_project_connector_for_ui', $status['connectors'] ),
		'supportedProviderIds' => array( BRANDAGENT_CONNECTOR_SQUARE_PROVIDER_ID ),
		'descriptions'         => array(
			BRANDAGENT_CONNECTOR_SQUARE_PROVIDER_ID => 'Connect Square to enable bookings on Brand Agents, and measure impact in Clarity.',
		),
	);
}

/**
 * Get raw Square provider and connector objects for server-side operations.
 *
 * @return array|WP_Error Raw status payload.
 */
function brandagent_connectors_get_raw_status() {
	$providers = brandagent_connectors_api_request( 'GET', '/providers' );
	if ( is_wp_error( $providers ) ) {
		return $providers;
	}

	$connectors = brandagent_connectors_api_request( 'GET' );
	if ( is_wp_error( $connectors ) ) {
		return $connectors;
	}

	return array(
		'providers'  => brandagent_connectors_only_square_items( $providers ),
		'connectors' => brandagent_connectors_only_square_items( $connectors ),
	);
}

/**
 * Project provider metadata onto the fields required by the dashboard.
 *
 * @param mixed $provider Raw provider object.
 * @return array Browser-safe provider object.
 */
function brandagent_connectors_project_provider_for_ui( $provider ) {
	return brandagent_connectors_copy_allowed_fields(
		$provider,
		array(
			'providerId',
			'displayName',
			'description',
			'capabilities',
			'supportsMultipleConnections',
			'supportsConfiguration',
		)
	);
}

/**
 * Project connector state without exposing its id or provider-specific account details.
 *
 * @param mixed $connector Raw connector object.
 * @return array Browser-safe connector object.
 */
function brandagent_connectors_project_connector_for_ui( $connector ) {
	$projected = brandagent_connectors_copy_allowed_fields(
		$connector,
		array(
			'providerId',
			'authorizationStatus',
			'readinessStatus',
			'failureCode',
			'lastSynchronizedAtUtc',
			'canReauthorize',
			'canSynchronize',
			'canDisconnect',
			'supportsConfiguration',
		)
	);

	if ( is_array( $connector ) && isset( $connector['capabilities'] ) && is_array( $connector['capabilities'] ) ) {
		$projected['capabilities'] = array_map(
			'brandagent_connectors_project_capability_for_ui',
			$connector['capabilities']
		);
	}

	return $projected;
}

/**
 * Project one connector capability.
 *
 * @param mixed $capability Raw capability object.
 * @return array Browser-safe capability object.
 */
function brandagent_connectors_project_capability_for_ui( $capability ) {
	return brandagent_connectors_copy_allowed_fields( $capability, array( 'name', 'isReady' ) );
}

/**
 * Project a synchronization result and its nested connector state.
 *
 * @param mixed $response Raw synchronization response.
 * @return array Browser-safe synchronization response.
 */
function brandagent_connectors_project_sync_response_for_ui( $response ) {
	$projected = brandagent_connectors_copy_allowed_fields(
		$response,
		array(
			'synchronizationStatus',
			'failureCode',
		)
	);

	if ( is_array( $response ) && isset( $response['connector'] ) && is_array( $response['connector'] ) ) {
		$projected['connector'] = brandagent_connectors_project_connector_for_ui( $response['connector'] );
	}

	return $projected;
}

/**
 * Copy only explicitly allowlisted fields from an API object.
 *
 * @param mixed $item   API object.
 * @param array $fields Allowed field names.
 * @return array
 */
function brandagent_connectors_copy_allowed_fields( $item, $fields ) {
	$projected = array();
	if ( ! is_array( $item ) ) {
		return $projected;
	}

	foreach ( $fields as $field ) {
		if ( array_key_exists( $field, $item ) ) {
			$projected[ $field ] = $item[ $field ];
		}
	}

	return $projected;
}

/**
 * Keep only Square entries from a connector/provider list.
 *
 * @param mixed $items API list.
 * @return array
 */
function brandagent_connectors_only_square_items( $items ) {
	$square = array();
	if ( ! is_array( $items ) ) {
		return $square;
	}

	foreach ( $items as $item ) {
		if (
			is_array( $item )
			&& isset( $item['providerId'] )
			&& 0 === strcasecmp( (string) $item['providerId'], BRANDAGENT_CONNECTOR_SQUARE_PROVIDER_ID )
		) {
			$square[] = $item;
		}
	}

	return array_values( $square );
}

/**
 * Find a provider-owned item in an API list.
 *
 * @param mixed  $items       API response.
 * @param string $provider_id Provider id.
 * @return array|null Matching item.
 */
function brandagent_connectors_find_provider_item( $items, $provider_id ) {
	if ( ! is_array( $items ) ) {
		return null;
	}

	foreach ( $items as $item ) {
		if (
			is_array( $item )
			&& isset( $item['providerId'] )
			&& 0 === strcasecmp( (string) $item['providerId'], $provider_id )
		) {
			return $item;
		}
	}

	return null;
}

/**
 * Validate that an authorization response contains a safe OAuth URL.
 *
 * @param mixed $response API response.
 * @return array|WP_Error Valid response.
 */
function brandagent_connectors_validate_authorization_response( $response ) {
	$url = is_array( $response ) && isset( $response['authorizationUrl'] )
		? $response['authorizationUrl']
		: '';

	if ( ! wp_http_validate_url( $url ) || 'https' !== wp_parse_url( $url, PHP_URL_SCHEME ) ) {
		return new WP_Error(
			'invalid_authorization_url',
			'AdsAgentServer did not return a valid HTTPS authorization URL.',
			array( 'status' => 502 )
		);
	}

	return array( 'authorizationUrl' => $url );
}

/**
 * Call the advertiser-scoped connector facade with the site's WordPress HMAC credential.
 *
 * @param string     $method  HTTP method.
 * @param string     $suffix  Path suffix.
 * @param array|null $payload Optional JSON payload.
 * @return array|WP_Error Decoded response.
 */
function brandagent_connectors_api_request( $method, $suffix = '', $payload = null ) {
	if ( ! class_exists( 'BrandAgent_Config' ) || ! method_exists( 'BrandAgent_Config', 'get_backend_base_url' ) ) {
		return new WP_Error(
			'backend_unavailable',
			'Brand Agent backend URL is unavailable.',
			array( 'status' => 503 )
		);
	}

	$backend = BrandAgent_Config::get_backend_base_url();
	if ( empty( $backend ) || ! wp_http_validate_url( $backend ) ) {
		return new WP_Error(
			'backend_unavailable',
			'Brand Agent backend URL is unavailable.',
			array( 'status' => 503 )
		);
	}

	$path = BRANDAGENT_CONNECTORS_PATH . $suffix;
	$url  = rtrim( $backend, '/' ) . $path;
	$body = null === $payload ? '' : wp_json_encode( $payload );
	if ( false === $body ) {
		return new WP_Error(
			'request_encoding_failed',
			'Could not encode the connector request.',
			array( 'status' => 500 )
		);
	}

	$response = brandagent_wordpress_sign_outbound_request( $url, $path, $body, $method );
	if ( is_wp_error( $response ) ) {
		return new WP_Error(
			'connector_transport_failed',
			$response->get_error_message(),
			array( 'status' => 502 )
		);
	}

	$status = (int) wp_remote_retrieve_response_code( $response );
	if ( 204 === $status ) {
		return array();
	}

	$raw     = wp_remote_retrieve_body( $response );
	$decoded = json_decode( $raw, true );
	if ( $status < 200 || $status >= 300 ) {
		$code = 'connector_request_failed';
		if ( is_array( $decoded ) && ! empty( $decoded['code'] ) ) {
			$code = sanitize_key( $decoded['code'] );
		} elseif ( is_array( $decoded ) && ! empty( $decoded['error'] ) ) {
			$code = sanitize_key( $decoded['error'] );
		}

		$message = '';
		foreach ( array( 'detail', 'title', 'error' ) as $message_key ) {
			if ( is_array( $decoded ) && ! empty( $decoded[ $message_key ] ) ) {
				$message = sanitize_text_field( $decoded[ $message_key ] );
				break;
			}
		}
		if ( '' === $message ) {
			$message = sprintf(
				'AdsAgentServer rejected the connector request (HTTP %d).',
				$status
			);
		}
		return new WP_Error( $code, $message, array( 'status' => $status ) );
	}

	if ( ! is_array( $decoded ) ) {
		return new WP_Error(
			'invalid_connector_response',
			'AdsAgentServer returned an invalid connector response.',
			array( 'status' => 502 )
		);
	}

	return $decoded;
}
