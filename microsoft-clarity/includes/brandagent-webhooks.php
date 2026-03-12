<?php
/**
 * BrandAgent Webhooks Management Class
 *
 * Handles creation, validation, and management of WooCommerce webhooks for BrandAgent
 *
 * @package MicrosoftClarity
 * @since 0.10.21
 */

// Exit if accessed directly
defined( 'ABSPATH' ) || exit;

/**
 * Webhooks management class
 */
/**
 * Add HMAC authentication headers to WooCommerce webhook deliveries.
 * This ensures the Brand Agent server can verify webhook requests
 * using the same HMAC scheme as other authenticated endpoints.
 *
 * @param array  $http_args  The webhook HTTP request arguments.
 * @param string $arg        The webhook payload body.
 * @param int    $webhook_id The webhook ID.
 * @return array Modified HTTP request arguments with HMAC headers.
 */
function brandagent_add_hmac_to_webhook( $http_args, $arg, $webhook_id ) {
	$webhook = wc_get_webhook( $webhook_id );
	if ( ! $webhook || strpos( $webhook->get_name(), 'BrandAgent' ) !== 0 ) {
		return $http_args;
	}

	$secret_key = brandagent_get_hmac_secret();
	if ( ! $secret_key ) {
		return $http_args;
	}

	$store_url = home_url();
	$client_id = brandagent_normalize_store_url( $store_url );
	$timestamp = time();
	$signature = brandagent_generate_hmac_signature( $client_id, $timestamp, $secret_key );

	$http_args['headers']['X-WooCommerce-Client-Id'] = $client_id;
	$http_args['headers']['X-WooCommerce-Store-Url'] = $store_url;
	$http_args['headers']['X-WooCommerce-Signature'] = $signature;
	$http_args['headers']['X-WooCommerce-Timestamp'] = (string) $timestamp;

	return $http_args;
}
add_filter( 'woocommerce_webhook_http_args', 'brandagent_add_hmac_to_webhook', 10, 3 );

class BrandAgent_Webhooks {

	/**
	 * Create all BrandAgent webhooks
	 * Loops through all webhook configuration files and creates/updates them
	 *
	 * @return array Array of results with webhook names and success status
	 */
	public static function create_webhooks() {
		$results = array();
		$webhook_configs = self::get_webhook_configs();

		foreach ( $webhook_configs as $config_file => $config ) {
			$success = self::create_or_update_webhook( $config );
			$results[ $config['name'] ] = $success;
		}

		return $results;
	}

	/**
	 * Get all webhook configurations from the webhooks folder
	 *
	 * @return array Array of webhook configurations
	 */
	private static function get_webhook_configs() {
		$configs = array();
		$webhooks_dir = plugin_dir_path( __FILE__ ) . 'webhooks/';

		// Check if webhooks directory exists
		if ( ! is_dir( $webhooks_dir ) ) {
			error_log( 'BrandAgent: Webhooks directory not found: ' . $webhooks_dir );
			return $configs;
		}

		// Get all PHP files in the webhooks directory
		$files = glob( $webhooks_dir . '*.php' );

		foreach ( $files as $file ) {
			$config = include $file;

			// Validate config structure
			if ( is_array( $config ) && isset( $config['name'], $config['topic'], $config['endpoint'] ) ) {
				$configs[ basename( $file ) ] = $config;
			} else {
				error_log( 'BrandAgent: Invalid webhook config in file: ' . basename( $file ) );
			}
		}

		return $configs;
	}

	/**
	 * Create or update a webhook based on configuration
	 *
	 * @param array $config Webhook configuration array
	 * @return bool True on success, false on failure
	 */
	private static function create_or_update_webhook( $config ) {
		// Check if WooCommerce is loaded
		if ( ! class_exists( 'WC_Webhook' ) ) {
			error_log( 'BrandAgent: WooCommerce webhook class not available. Cannot create webhook.' );
			return false;
		}

		// Build delivery URL
		$backend_base_url = BrandAgent_Config::get_backend_base_url();
		$store_url = home_url();
		$delivery_url = $backend_base_url . $config['endpoint'] . '?store_url=' . rawurlencode( $store_url );

		// Get HMAC secret for webhook signature validation
		$hmac_secret = brandagent_get_hmac_secret();

		// Find existing webhook by name and topic
		$existing_webhook = self::find_webhook_by_name_and_topic( $config['name'], $config['topic'] );

		if ( $existing_webhook ) {
			return self::update_webhook( $existing_webhook, $delivery_url, $hmac_secret, $config['topic'] );
		} else {
			return self::create_webhook( $config['name'], $config['topic'], $delivery_url, $hmac_secret );
		}
	}

	/**
	 * Find a webhook by name and topic
	 *
	 * @param string $webhook_name The webhook name to search for
	 * @param string $webhook_topic The webhook topic to search for
	 * @return WC_Webhook|null The webhook object if found, null otherwise
	 */
	private static function find_webhook_by_name_and_topic( $webhook_name, $webhook_topic ) {
		$webhook_ids = self::find_all_webhooks();

		// Search through webhooks to find a match
		foreach ( $webhook_ids as $webhook_id ) {
			$webhook = wc_get_webhook( $webhook_id );

			// If WooCommerce can't load the webhook object, check metadata directly
			if ( ! $webhook ) {
				self::handle_broken_webhook( $webhook_id, $webhook_name, $webhook_topic );
				continue;
			}

			// Check if this webhook matches our criteria (by name AND topic)
			if ( $webhook->get_name() === $webhook_name && $webhook->get_topic() === $webhook_topic ) {
				return $webhook;
			}
		}

		return null;
	}

	/**
	 * Handle broken webhooks that can't be loaded by WooCommerce
	 *
	 * @param int $webhook_id The webhook ID
	 * @param string $webhook_name The expected webhook name
	 * @param string $webhook_topic The expected webhook topic
	 */
	private static function handle_broken_webhook( $webhook_id, $webhook_name, $webhook_topic ) {
		global $wpdb;
		$meta_topic = get_post_meta( $webhook_id, '_webhook_topic', true );
		$post_title = $wpdb->get_var( $wpdb->prepare( "SELECT post_title FROM {$wpdb->posts} WHERE ID = %d", $webhook_id ) );

		// Check if this webhook matches by metadata - if so, delete it (it's broken)
		if ( $post_title === $webhook_name && $meta_topic === $webhook_topic ) {
			wp_delete_post( $webhook_id, true );
			error_log( 'BrandAgent: Deleted broken webhook (ID: ' . $webhook_id . '), will create fresh one' );
		}
	}

	/**
	 * Create a new webhook
	 *
	 * @param string $webhook_name The webhook name
	 * @param string $webhook_topic The webhook topic
	 * @param string $delivery_url The delivery URL
	 * @param string $hmac_secret The HMAC secret for signature validation
	 * @return bool True on success, false on failure
	 */
	private static function create_webhook( $webhook_name, $webhook_topic, $delivery_url, $hmac_secret ) {
		$webhook = new WC_Webhook();
		$webhook->set_name( $webhook_name );
		$webhook->set_topic( $webhook_topic );
		$webhook->set_delivery_url( $delivery_url );
		$webhook->set_secret( $hmac_secret );
		$webhook->set_status( 'active' );

		// IMPORTANT: Set the user ID to an admin user who has permission to view products
		// This is required for WooCommerce to authenticate the webhook requests
		$current_user_id = get_current_user_id();
		if ( $current_user_id && user_can( $current_user_id, 'manage_woocommerce' ) ) {
			$webhook->set_user_id( $current_user_id );
		} else {
			// Current user is not an admin or not logged in - find an admin user
			$admin_users = get_users( array( 'role' => 'administrator', 'number' => 1 ) );
			if ( ! empty( $admin_users ) ) {
				$webhook->set_user_id( $admin_users[0]->ID );
			} else {
				error_log( 'BrandAgent: Warning - No admin user found for webhook authentication' );
			}
		}

		$webhook_id = $webhook->save();

		if ( $webhook_id ) {
			// Manually save metadata as a workaround for WooCommerce not persisting it properly
			update_post_meta( $webhook_id, '_webhook_topic', $webhook_topic );
			update_post_meta( $webhook_id, '_webhook_delivery_url', $delivery_url );
			update_post_meta( $webhook_id, '_webhook_secret', $hmac_secret );
			update_post_meta( $webhook_id, '_webhook_status', 'active' );

			error_log( 'BrandAgent: Successfully created webhook "' . $webhook_name . '" (ID: ' . $webhook_id . ')' );
			return true;
		} else {
			error_log( 'BrandAgent: Failed to create webhook "' . $webhook_name . '"' );
			return false;
		}
	}

	/**
	 * Update an existing webhook
	 *
	 * @param WC_Webhook $webhook The webhook object to update
	 * @param string $delivery_url The new delivery URL
	 * @param string $hmac_secret The new HMAC secret
	 * @param string $webhook_topic The webhook topic
	 * @return bool True if updated or already up-to-date, false on failure
	 */
	private static function update_webhook( $webhook, $delivery_url, $hmac_secret, $webhook_topic ) {
		$needs_update = false;

		if ( $webhook->get_delivery_url() !== $delivery_url ) {
			$webhook->set_delivery_url( $delivery_url );
			$needs_update = true;
		}

		if ( $webhook->get_secret() !== $hmac_secret ) {
			$webhook->set_secret( $hmac_secret );
			$needs_update = true;
		}

		if ( $webhook->get_status() !== 'active' ) {
			$webhook->set_status( 'active' );
			$needs_update = true;
		}

		// Ensure the webhook has a user ID for authentication
		if ( ! $webhook->get_user_id() ) {
			$current_user_id = get_current_user_id();
			if ( $current_user_id && user_can( $current_user_id, 'manage_woocommerce' ) ) {
				$webhook->set_user_id( $current_user_id );
			} else {
				// Current user is not an admin or not logged in - find an admin user
				$admin_users = get_users( array( 'role' => 'administrator', 'number' => 1 ) );
				if ( ! empty( $admin_users ) ) {
					$webhook->set_user_id( $admin_users[0]->ID );
				}
			}
			$needs_update = true;
		}

		if ( $needs_update ) {
			$webhook->save();

			// Manually update metadata as well to ensure persistence
			update_post_meta( $webhook->get_id(), '_webhook_topic', $webhook_topic );
			update_post_meta( $webhook->get_id(), '_webhook_delivery_url', $delivery_url );
			update_post_meta( $webhook->get_id(), '_webhook_secret', $hmac_secret );
			update_post_meta( $webhook->get_id(), '_webhook_status', 'active' );

			error_log( 'BrandAgent: Updated existing webhook (ID: ' . $webhook->get_id() . ')' );
		} else {
			error_log( 'BrandAgent: Webhook already exists and is up-to-date (ID: ' . $webhook->get_id() . ')' );
		}

		return true;
	}

	/**
	 * Find all webhooks using multiple methods
	 * Tries WooCommerce API first, then falls back to direct database queries
	 *
	 * @return array Array of webhook IDs
	 */
	private static function find_all_webhooks() {
		$webhook_ids = array();

		// Method 1: Try WooCommerce data store search (works for all statuses)
		try {
			$data_store = WC_Data_Store::load( 'webhook' );
			$webhook_ids = $data_store->search_webhooks( array(
				'status' => '',  // Empty string = all statuses
				'limit'  => -1,
			) );
			
			if ( ! empty( $webhook_ids ) ) {
				error_log( 'BrandAgent: Found ' . count( $webhook_ids ) . ' webhooks via data store' );
				return $webhook_ids;
			}
		} catch ( Exception $e ) {
			error_log( 'BrandAgent: Data store search failed: ' . $e->getMessage() );
		}

		// Method 2: Direct query to wc_webhooks table (WooCommerce 3.3+)
		global $wpdb;
		$table_name = $wpdb->prefix . 'wc_webhooks';
		
		// Check if the custom webhooks table exists
		$table_exists = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_name ) );
		
		if ( $table_exists ) {
			$webhook_ids = $wpdb->get_col( $wpdb->prepare( "SELECT webhook_id FROM %i", $table_name ) );
			
			if ( ! empty( $webhook_ids ) ) {
				error_log( 'BrandAgent: Found ' . count( $webhook_ids ) . ' webhooks via wc_webhooks table' );
				return $webhook_ids;
			}
		}

		// Method 3: Legacy fallback - posts table (WooCommerce < 3.3)
		$webhook_ids = $wpdb->get_col(
			"SELECT ID FROM {$wpdb->posts} 
			WHERE post_type = 'shop_webhook' 
			ORDER BY ID DESC"
		);
		
		if ( ! empty( $webhook_ids ) ) {
			error_log( 'BrandAgent: Found ' . count( $webhook_ids ) . ' webhooks via posts table (legacy)' );
		}

		return $webhook_ids;
	}

	/**
	 * Pause all BrandAgent webhooks
	 * Sets status to 'paused' instead of deleting them
	 * Useful when disconnecting the plugin
	 *
	 * @return int Number of webhooks paused
	 */
	public static function pause_all_brandagent_webhooks() {
		if ( ! class_exists( 'WC_Webhook' ) ) {
			error_log( 'BrandAgent: WC_Webhook class not available for pausing' );
			return 0;
		}

		$webhook_ids = self::find_all_webhooks();
		error_log( 'BrandAgent: Attempting to pause webhooks, found ' . count( $webhook_ids ) . ' total webhooks' );
		
		$paused_count = 0;

		foreach ( $webhook_ids as $webhook_id ) {
			$webhook = wc_get_webhook( $webhook_id );

			if ( ! $webhook ) {
				error_log( 'BrandAgent: Could not load webhook ID ' . $webhook_id );
				continue;
			}

			$webhook_name = $webhook->get_name();
			
			// Only pause webhooks that belong to BrandAgent
			if ( strpos( $webhook_name, 'BrandAgent' ) === 0 ) {
				if ( $webhook->get_status() === 'active' ) {
					$webhook->set_status( 'paused' );
					$webhook->save();
					error_log( 'BrandAgent: Paused webhook "' . $webhook_name . '" (ID: ' . $webhook_id . ')' );
					$paused_count++;
				} else {
					error_log( 'BrandAgent: Webhook "' . $webhook_name . '" already has status: ' . $webhook->get_status() );
				}
			}
		}

		error_log( 'BrandAgent: Paused ' . $paused_count . ' webhook(s) total' );
		return $paused_count;
	}

	/**
	 * Resume all BrandAgent webhooks
	 * Sets status to 'active' for all paused webhooks
	 * Useful when re-enabling the plugin
	 *
	 * @return int Number of webhooks resumed
	 */
	public static function resume_all_brandagent_webhooks() {
		if ( ! function_exists( 'wc_get_webhook' ) ) {
			return 0;
		}

		$webhook_ids = self::find_all_webhooks();
		$resumed_count = 0;

		foreach ( $webhook_ids as $webhook_id ) {
			$webhook = wc_get_webhook( $webhook_id );

			if ( ! $webhook ) {
				continue;
			}

			// Only resume webhooks that belong to BrandAgent and are paused
			if ( strpos( $webhook->get_name(), 'BrandAgent' ) === 0 && $webhook->get_status() === 'paused' ) {
				$webhook->set_status( 'active' );
				$webhook->save();
				$resumed_count++;
			}
		}

		if ( $resumed_count > 0 ) {
			error_log( 'BrandAgent: Resumed ' . $resumed_count . ' webhook(s)' );
		}

		return $resumed_count;
	}

	/**
	 * Delete all BrandAgent webhooks
	 * Permanently removes all webhooks that belong to BrandAgent
	 * Useful when uninstalling the plugin or resetting configuration
	 *
	 * @return int Number of webhooks deleted
	 */
	public static function delete_all_brandagent_webhooks() {
		if ( ! class_exists( 'WC_Webhook' ) ) {
			error_log( 'BrandAgent: WC_Webhook class not available for deletion' );
			return 0;
		}

		$webhook_ids = self::find_all_webhooks();
		error_log( 'BrandAgent: Attempting to delete webhooks, found ' . count( $webhook_ids ) . ' total webhooks' );
		
		$deleted_count = 0;

		foreach ( $webhook_ids as $webhook_id ) {
			$webhook = wc_get_webhook( $webhook_id );

			if ( ! $webhook ) {
				// Try to delete broken webhook directly from database
				$webhook_name = self::get_webhook_name_from_db( $webhook_id );
				if ( $webhook_name && strpos( $webhook_name, 'BrandAgent' ) === 0 ) {
					self::delete_webhook_from_db( $webhook_id );
					error_log( 'BrandAgent: Deleted broken webhook "' . $webhook_name . '" (ID: ' . $webhook_id . ') directly from DB' );
					$deleted_count++;
				}
				continue;
			}

			$webhook_name = $webhook->get_name();
			
			// Only delete webhooks that belong to BrandAgent
			if ( strpos( $webhook_name, 'BrandAgent' ) === 0 ) {
				$webhook->delete( true );
				error_log( 'BrandAgent: Deleted webhook "' . $webhook_name . '" (ID: ' . $webhook_id . ')' );
				$deleted_count++;
			}
		}

		error_log( 'BrandAgent: Deleted ' . $deleted_count . ' webhook(s) total' );
		return $deleted_count;
	}

	/**
	 * Get webhook name directly from database
	 *
	 * @param int $webhook_id The webhook ID
	 * @return string|null The webhook name or null if not found
	 */
	private static function get_webhook_name_from_db( $webhook_id ) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'wc_webhooks';
		
		// Try custom table first (WooCommerce 3.3+)
		$table_exists = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_name ) );
		if ( $table_exists ) {
			return $wpdb->get_var( $wpdb->prepare( "SELECT name FROM {$table_name} WHERE webhook_id = %d", $webhook_id ) );
		}
		
		// Fallback to posts table
		return get_the_title( $webhook_id );
	}

	/**
	 * Delete webhook directly from database
	 *
	 * @param int $webhook_id The webhook ID
	 */
	private static function delete_webhook_from_db( $webhook_id ) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'wc_webhooks';
		
		// Try custom table first (WooCommerce 3.3+)
		$table_exists = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_name ) );
		if ( $table_exists ) {
			$wpdb->delete( $table_name, array( 'webhook_id' => $webhook_id ), array( '%d' ) );
		}
		
		// Also try posts table for legacy support
		wp_delete_post( $webhook_id, true );
	}
}
