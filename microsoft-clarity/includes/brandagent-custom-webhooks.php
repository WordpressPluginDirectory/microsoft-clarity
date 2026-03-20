<?php
/**
 * BrandAgent Custom Webhooks
 *
 * Registers custom webhook topics for WooCommerce that aren't built-in
 * (e.g., cart updates)
 *
 * @package MicrosoftClarity
 * @since 0.10.21
 */

// Exit if accessed directly
defined( 'ABSPATH' ) || exit;

/**
 * Register 'cart' and 'checkout' as valid webhook resources
 * This is required for WooCommerce to accept 'cart.updated' and 'checkout.started' as valid topics
 *
 * @param array $resources Valid webhook resources (order, product, customer, coupon)
 * @return array Modified resources including 'cart' and 'checkout'
 */
function brandagent_register_custom_webhook_resources( $resources ) {
    $resources[] = 'cart';
    $resources[] = 'checkout';
    return $resources;
}
add_filter( 'woocommerce_valid_webhook_resources', 'brandagent_register_custom_webhook_resources' );

/**
 * Register custom events for custom resources
 * WooCommerce validates topics as {resource}.{event}
 *
 * @param array $events Valid webhook events (created, updated, deleted, restored)
 * @return array Modified events
 */
function brandagent_register_custom_webhook_events( $events ) {
    // 'updated' is already in default events, but let's ensure it
    if ( ! in_array( 'updated', $events, true ) ) {
        $events[] = 'updated';
    }
    // 'created' is already in default events, but ensure it for checkout
    if ( ! in_array( 'created', $events, true ) ) {
        $events[] = 'created';
    }
    return $events;
}
add_filter( 'woocommerce_valid_webhook_events', 'brandagent_register_custom_webhook_events' );

/**
 * Register custom webhook topics for admin dropdown display
 *
 * @param array $topics Existing webhook topics
 * @return array Modified webhook topics
 */
function brandagent_register_custom_webhook_topics( $topics ) {
    $topics['cart.updated'] = __( 'Cart Updated', 'microsoft-clarity' );
    $topics['checkout.created'] = __( 'Checkout Created', 'microsoft-clarity' );
    return $topics;
}
add_filter( 'woocommerce_webhook_topics', 'brandagent_register_custom_webhook_topics' );

/**
 * Register valid webhook events for custom topics
 *
 * @param array $events Valid events for the topic
 * @param string $topic The webhook topic
 * @return array Modified events
 */
function brandagent_register_custom_webhook_topic_events( $events, $topic ) {
    if ( 'cart.updated' === $topic ) {
        $events = array(
            'woocommerce_add_to_cart',
            'woocommerce_cart_item_removed',
            'woocommerce_cart_item_restored',
            'woocommerce_after_cart_item_quantity_update',
        );
    }
    
    if ( 'checkout.created' === $topic ) {
        // This is manually triggered, but we need a placeholder hook
        $events = array(
            'brandagent_checkout_created',
        );
    }
    
    return $events;
}
add_filter( 'woocommerce_webhook_topic_hooks', 'brandagent_register_custom_webhook_topic_events', 10, 2 );

/**
 * Build the payload for cart webhooks
 *
 * @param array $payload The webhook payload
 * @param string $resource The resource type
 * @param int $resource_id The resource ID
 * @param int $webhook_id The webhook ID
 * @return array The modified payload
 */
function brandagent_cart_webhook_payload( $payload, $resource, $resource_id, $webhook_id ) {
    $webhook = wc_get_webhook( $webhook_id );
    
    if ( ! $webhook || $webhook->get_topic() !== 'cart.updated' ) {
        return $payload;
    }
    
    // Get the change context set by the trigger
    $change_context = BrandAgent_Cart_Webhook_Trigger::get_change_context();
    
    // Get current cart data
    $cart = WC()->cart;
    
    // Get cart ID (session-based identifier)
    $cart_id = WC()->session ? WC()->session->get_customer_id() : null;

    // Get store currency
    $currency = get_woocommerce_currency();

    // Retrieve BrandAgent session attributes set by the frontend via the REST API.
    // This is the WooCommerce analog of Shopify's _agentClientInfo note attribute.
    $brandagent_attrs = BrandAgent_REST_API::get_cart_attributes();

    // Fall back to the BrandAgent clientId when WC session is unavailable (cart_id would be null).
    if ( ! $cart_id && ! empty( $brandagent_attrs['clientId'] ) ) {
        $cart_id = $brandagent_attrs['clientId'];
    }

    if ( ! $cart ) {
        return array(
            'event' => 'cart.updated',
            'action' => $change_context['action'] ?? 'unknown',
            'cart_id' => $cart_id,
            'currency' => $currency,
            'changed_item' => null,
            'cart' => null,
            'customer' => array(
                'id' => get_current_user_id(),
                'session_id' => ! empty( $brandagent_attrs['sessionId'] )
                    ? $brandagent_attrs['sessionId']
                    : $cart_id,
            ),
            'brandagent_attributes' => $brandagent_attrs,
            'timestamp' => current_time( 'c' ),
        );
    }
    
    $cart_items = array();
    
    foreach ( $cart->get_cart() as $cart_item_key => $cart_item ) {
        $product = $cart_item['data'];
        $parent_product = null;
        $variant_title = '';
        
        // Get parent product and variant title if this is a variation
        if ( $cart_item['variation_id'] ) {
            $parent_product = wc_get_product( $cart_item['product_id'] );
            $variant_title = $product ? $product->get_name() : '';
        }
        
        $item_data = array(
            'key' => $cart_item_key,
            'product_id' => $cart_item['product_id'],
            'product_title' => $parent_product ? $parent_product->get_name() : ( $product ? $product->get_name() : '' ),
            'variation_id' => $cart_item['variation_id'],
            'variant_title' => $variant_title,
            'quantity' => $cart_item['quantity'],
            'line_total' => $cart_item['line_total'],
            'line_subtotal' => $cart_item['line_subtotal'],
            'product_sku' => $product ? $product->get_sku() : '',
            'product_price' => $product ? $product->get_price() : 0,
        );
        $cart_items[] = $item_data;
    }
    
    // Build the changed item info
    $changed_item = null;
    if ( $change_context ) {
        $changed_item = array(
            'key' => $change_context['cart_item_key'] ?? null,
            'product_id' => $change_context['product_id'] ?? null,
            'product_title' => $change_context['product_title'] ?? null,
            'variation_id' => $change_context['variation_id'] ?? null,
            'variant_title' => $change_context['variant_title'] ?? null,
            'quantity' => $change_context['quantity'] ?? null,
            'old_quantity' => $change_context['old_quantity'] ?? null,
            'product_sku' => $change_context['product_sku'] ?? null,
            'product_price' => $change_context['product_price'] ?? null,
        );
    }
    
    return array(
        'event' => 'cart.updated',
        'action' => $change_context['action'] ?? 'unknown',
        'cart_id' => $cart_id,
        'currency' => $currency,
        'changed_item' => $changed_item,
        'cart' => array(
            'items' => $cart_items,
            'item_count' => $cart->get_cart_contents_count(),
            'total' => $cart->get_cart_contents_total(),
            'subtotal' => $cart->get_subtotal(),
            'tax_total' => $cart->get_cart_contents_tax(),
        ),
        'customer' => array(
            'id' => get_current_user_id(),
            'session_id' => ! empty( $brandagent_attrs['sessionId'] )
                ? $brandagent_attrs['sessionId']
                : $cart_id,
        ),
        'brandagent_attributes' => $brandagent_attrs,
        'timestamp' => current_time( 'c' ),
    );
}
add_filter( 'woocommerce_webhook_payload', 'brandagent_cart_webhook_payload', 10, 4 );

/**
 * Get active webhooks for a specific topic
 *
 * Uses static memoization to avoid repeated database queries within the same
 * request (e.g., multiple cart actions in a single page load).
 *
 * @param string $topic The webhook topic (e.g., 'cart.updated', 'checkout.created')
 * @return array Array of WC_Webhook objects
 */
function brandagent_get_webhooks_by_topic( $topic ) {
    static $cache = array();

    // Return cached result if available for this request
    if ( isset( $cache[ $topic ] ) ) {
        return $cache[ $topic ];
    }

    $data_store = WC_Data_Store::load( 'webhook' );

    // Search for active webhooks
    $webhook_ids = $data_store->search_webhooks(
        array(
            'status' => 'active',
            'limit'  => -1,
        )
    );

    $webhooks = array();
    foreach ( $webhook_ids as $webhook_id ) {
        $webhook = wc_get_webhook( $webhook_id );
        if ( $webhook && $webhook->get_topic() === $topic ) {
            $webhooks[] = $webhook;
        }
    }

    // Cache for subsequent calls within this request
    $cache[ $topic ] = $webhooks;

    return $webhooks;
}

/**
 * Deliver a custom webhook payload
 *
 * @param WC_Webhook $webhook  The webhook to deliver
 * @param string     $resource The resource type (e.g., 'cart', 'checkout')
 * @param string     $topic    The webhook topic (e.g., 'cart.updated', 'checkout.created')
 * @param string     $event    The event type (e.g., 'updated', 'created')
 */
function brandagent_deliver_custom_webhook( $webhook, $resource, $topic, $event ) {
    // Build the payload
    $payload = apply_filters( 'woocommerce_webhook_payload', array(), $resource, 0, $webhook->get_id() );

    if ( empty( $payload ) ) {
        return;
    }

    // Get delivery URL and secret
    $delivery_url = $webhook->get_delivery_url();
    $secret       = $webhook->get_secret();

    // Build signature
    $body      = wp_json_encode( $payload );
    $signature = base64_encode( hash_hmac( 'sha256', $body, $secret, true ) );

    // Get store URL for X-WC-Webhook-Source header (standard WooCommerce header)
    $store_url = home_url();

    // Generate HMAC authentication headers for Brand Agent server
    $hmac_secret    = brandagent_get_hmac_secret();
    $hmac_client_id = brandagent_normalize_store_url( $store_url );
    $hmac_timestamp = time();
    $hmac_signature = $hmac_secret
        ? brandagent_generate_hmac_signature( $hmac_client_id, $hmac_timestamp, $hmac_secret )
        : '';

    // Build headers
    $headers = array(
        'Content-Type'             => 'application/json',
        'X-WC-Webhook-Source'      => $store_url,
        'X-WC-Webhook-Topic'       => $topic,
        'X-WC-Webhook-Resource'    => $resource,
        'X-WC-Webhook-Event'       => $event,
        'X-WC-Webhook-Signature'   => $signature,
        'X-WC-Webhook-ID'          => $webhook->get_id(),
        'X-WC-Webhook-Delivery-ID' => wp_generate_uuid4(),
        'User-Agent'               => 'WooCommerce/' . WC_VERSION . ' Hookshot (WordPress/' . get_bloginfo( 'version' ) . ')',
    );

    // Add HMAC authentication headers if secret is available
    if ( $hmac_secret ) {
        $headers['X-WooCommerce-Client-Id'] = $hmac_client_id;
        $headers['X-WooCommerce-Store-Url'] = $store_url;
        $headers['X-WooCommerce-Signature'] = $hmac_signature;
        $headers['X-WooCommerce-Timestamp'] = (string) $hmac_timestamp;
    }

    // Deliver the webhook (non-blocking to avoid delaying page load)
    $response = wp_remote_post(
        $delivery_url,
        array(
            'method'   => 'POST',
            'timeout'  => 0.01,
            'blocking' => false,
            'headers'  => $headers,
            'body'     => $body,
        )
    );

    // Note: With blocking=false, we can only detect immediate failures (e.g., invalid URL).
    // Network/server errors won't be caught since we don't wait for the response.
    if ( is_wp_error( $response ) ) {
        error_log( 'BrandAgent: ' . ucfirst( $resource ) . ' webhook delivery failed: ' . $response->get_error_message() );
    }
}

/**
 * Manually trigger cart webhooks on cart actions
 * This is needed because cart actions don't follow the standard WooCommerce webhook pattern
 */
class BrandAgent_Cart_Webhook_Trigger {
    
    /**
     * Store the context of what changed in the cart
     * @var array|null
     */
    private static $change_context = null;
    
    /**
     * Get the current change context
     * @return array|null
     */
    public static function get_change_context() {
        return self::$change_context;
    }
    
    /**
     * Initialize cart webhook triggers
     */
    public static function init() {
        // Only register hooks if BrandAgent is enabled to avoid unnecessary processing
        if ( get_option( 'BAInjectFrontendScript' ) !== 'true' ) {
            return;
        }

        // Hook into cart actions with specific handlers
        add_action( 'woocommerce_add_to_cart', array( __CLASS__, 'on_add_to_cart' ), 99, 6 );
        add_action( 'woocommerce_cart_item_removed', array( __CLASS__, 'on_item_removed' ), 99, 2 );
        add_action( 'woocommerce_cart_item_restored', array( __CLASS__, 'on_item_restored' ), 99, 2 );
        add_action( 'woocommerce_after_cart_item_quantity_update', array( __CLASS__, 'on_quantity_update' ), 99, 4 );
    }
    
    /**
     * Handle add to cart action
     * 
     * @param string $cart_item_key Cart item key
     * @param int $product_id Product ID
     * @param int $quantity Quantity added
     * @param int $variation_id Variation ID (0 if not a variation)
     * @param array $variation Variation data
     * @param array $cart_item_data Additional cart item data
     */
    public static function on_add_to_cart( $cart_item_key, $product_id, $quantity, $variation_id, $variation, $cart_item_data ) {
        $product = wc_get_product( $variation_id ? $variation_id : $product_id );
        $parent_product = $variation_id ? wc_get_product( $product_id ) : null;
        
        // Get product title (parent product name for variations)
        $product_title = $parent_product ? $parent_product->get_name() : ( $product ? $product->get_name() : '' );
        // Get variant title (only for variations)
        $variant_title = $variation_id && $product ? $product->get_name() : '';
        
        self::$change_context = array(
            'action' => 'added',
            'cart_item_key' => $cart_item_key,
            'product_id' => $product_id,
            'product_title' => $product_title,
            'variation_id' => $variation_id,
            'variant_title' => $variant_title,
            'quantity' => $quantity,
            'old_quantity' => 0,
            'product_sku' => $product ? $product->get_sku() : '',
            'product_price' => $product ? $product->get_price() : 0,
        );
        
        self::trigger_webhooks();
    }
    
    /**
     * Handle item removed action
     * Note: The item is already removed from cart when this fires
     * 
     * @param string $cart_item_key Cart item key
     * @param WC_Cart $cart Cart object
     */
    public static function on_item_removed( $cart_item_key, $cart ) {
        // Get the removed item from the removed_cart_contents
        $removed_item = isset( $cart->removed_cart_contents[ $cart_item_key ] ) 
            ? $cart->removed_cart_contents[ $cart_item_key ] 
            : null;
        
        $product = null;
        $parent_product = null;
        $product_id = 0;
        $variation_id = 0;
        $quantity = 0;
        $product_title = '';
        $variant_title = '';
        
        if ( $removed_item ) {
            $product_id = $removed_item['product_id'];
            $variation_id = $removed_item['variation_id'];
            $quantity = $removed_item['quantity'];
            $product = isset( $removed_item['data'] ) ? $removed_item['data'] : wc_get_product( $variation_id ? $variation_id : $product_id );
            
            // Get parent product for variations
            if ( $variation_id ) {
                $parent_product = wc_get_product( $product_id );
                $product_title = $parent_product ? $parent_product->get_name() : '';
                $variant_title = $product ? $product->get_name() : '';
            } else {
                $product_title = $product ? $product->get_name() : '';
            }
        }
        
        self::$change_context = array(
            'action' => 'removed',
            'cart_item_key' => $cart_item_key,
            'product_id' => $product_id,
            'product_title' => $product_title,
            'variation_id' => $variation_id,
            'variant_title' => $variant_title,
            'quantity' => 0,
            'old_quantity' => $quantity,
            'product_sku' => $product ? $product->get_sku() : '',
            'product_price' => $product ? $product->get_price() : 0,
        );
        
        self::trigger_webhooks();
    }
    
    /**
     * Handle item restored action
     * 
     * @param string $cart_item_key Cart item key
     * @param WC_Cart $cart Cart object
     */
    public static function on_item_restored( $cart_item_key, $cart ) {
        $cart_item = $cart->get_cart_item( $cart_item_key );
        $product = isset( $cart_item['data'] ) ? $cart_item['data'] : null;
        $product_id = $cart_item['product_id'] ?? 0;
        $variation_id = $cart_item['variation_id'] ?? 0;
        
        // Get parent product for variations
        $parent_product = $variation_id ? wc_get_product( $product_id ) : null;
        $product_title = $parent_product ? $parent_product->get_name() : ( $product ? $product->get_name() : '' );
        $variant_title = $variation_id && $product ? $product->get_name() : '';
        
        self::$change_context = array(
            'action' => 'restored',
            'cart_item_key' => $cart_item_key,
            'product_id' => $product_id,
            'product_title' => $product_title,
            'variation_id' => $variation_id,
            'variant_title' => $variant_title,
            'quantity' => $cart_item['quantity'] ?? 0,
            'old_quantity' => 0,
            'product_sku' => $product ? $product->get_sku() : '',
            'product_price' => $product ? $product->get_price() : 0,
        );
        
        self::trigger_webhooks();
    }
    
    /**
     * Handle quantity update action
     * 
     * @param string $cart_item_key Cart item key
     * @param int $quantity New quantity
     * @param int $old_quantity Previous quantity
     * @param WC_Cart $cart Cart object
     */
    public static function on_quantity_update( $cart_item_key, $quantity, $old_quantity, $cart ) {
        $cart_item = $cart->get_cart_item( $cart_item_key );
        $product = isset( $cart_item['data'] ) ? $cart_item['data'] : null;
        $product_id = $cart_item['product_id'] ?? 0;
        $variation_id = $cart_item['variation_id'] ?? 0;
        
        // Get parent product for variations
        $parent_product = $variation_id ? wc_get_product( $product_id ) : null;
        $product_title = $parent_product ? $parent_product->get_name() : ( $product ? $product->get_name() : '' );
        $variant_title = $variation_id && $product ? $product->get_name() : '';
        
        self::$change_context = array(
            'action' => 'quantity_updated',
            'cart_item_key' => $cart_item_key,
            'product_id' => $product_id,
            'product_title' => $product_title,
            'variation_id' => $variation_id,
            'variant_title' => $variant_title,
            'quantity' => $quantity,
            'old_quantity' => $old_quantity,
            'product_sku' => $product ? $product->get_sku() : '',
            'product_price' => $product ? $product->get_price() : 0,
        );
        
        self::trigger_webhooks();
    }
    
    /**
     * Trigger all cart.updated webhooks
     */
    private static function trigger_webhooks() {
        // Don't trigger if cart not initialized
        if ( ! WC()->cart ) {
            self::$change_context = null;
            return;
        }
        
        // Find all active cart.updated webhooks
        $webhooks = brandagent_get_webhooks_by_topic( 'cart.updated' );
        
        foreach ( $webhooks as $webhook ) {
            if ( $webhook->get_status() === 'active' ) {
                brandagent_deliver_custom_webhook( $webhook, 'cart', 'cart.updated', 'updated' );
            }
        }
        
        // Clear context after delivery
        self::$change_context = null;
    }
}

// Initialize cart webhook triggers when WooCommerce is loaded
add_action( 'woocommerce_loaded', array( 'BrandAgent_Cart_Webhook_Trigger', 'init' ) );

/**
 * Enhance order webhook payload for BrandAgent webhooks
 * Adds product_title, variant_title, ensures currency is included,
 * and includes BrandAgent session attributes for conversion attribution.
 *
 * @param array $payload The webhook payload
 * @param string $resource The resource type
 * @param int $resource_id The resource ID (order ID)
 * @param int $webhook_id The webhook ID
 * @return array The modified payload
 */
function brandagent_order_webhook_payload( $payload, $resource, $resource_id, $webhook_id ) {
    // Only process order webhooks
    if ( $resource !== 'order' ) {
        return $payload;
    }
    
    $webhook = wc_get_webhook( $webhook_id );
    
    // Only enhance BrandAgent webhooks
    if ( ! $webhook || strpos( $webhook->get_name(), 'BrandAgent' ) !== 0 ) {
        return $payload;
    }
    
    // Get the order
    $order = wc_get_order( $resource_id );
    if ( ! $order ) {
        return $payload;
    }
    
    // Get cart ID if available (stored as meta during checkout)
    $cart_id = $order->get_cart_hash();
    if ( ! $cart_id ) {
        $cart_id = $order->get_customer_id() ? 'user_' . $order->get_customer_id() : null;
    }

    // Retrieve BrandAgent session attributes stored as order meta during checkout.
    // These are saved by brandagent_save_attrs_to_order() when the order is created.
    $brandagent_attrs_json = $order->get_meta( '_brandagent_client_info' );
    $brandagent_attrs = $brandagent_attrs_json ? json_decode( $brandagent_attrs_json, true ) : null;

    // Fall back to the BrandAgent clientId when cart_id is unavailable (e.g., guest orders).
    if ( ! $cart_id && ! empty( $brandagent_attrs['clientId'] ) ) {
        $cart_id = $brandagent_attrs['clientId'];
    }

    $payload['cart_id'] = $cart_id;
    $payload['brandagent_attributes'] = $brandagent_attrs;

    // Set session_id from agent attributes (consistent with cart/checkout webhooks).
    if ( ! empty( $brandagent_attrs['sessionId'] ) ) {
        $payload['session_id'] = $brandagent_attrs['sessionId'];
    }
    
    // Enhance line items with product_title and variant_title
    if ( isset( $payload['line_items'] ) && is_array( $payload['line_items'] ) ) {
        foreach ( $payload['line_items'] as $key => $item ) {
            $product_id = $item['product_id'] ?? 0;
            $variation_id = $item['variation_id'] ?? 0;
            
            // Get the product
            $product = wc_get_product( $variation_id ? $variation_id : $product_id );
            $parent_product = $variation_id ? wc_get_product( $product_id ) : null;
            
            // Add product_title (parent product name for variations)
            $payload['line_items'][ $key ]['product_title'] = $parent_product 
                ? $parent_product->get_name() 
                : ( $product ? $product->get_name() : ( $item['name'] ?? '' ) );
            
            // Add variant_title (only for variations)
            $payload['line_items'][ $key ]['variant_title'] = $variation_id && $product 
                ? $product->get_name() 
                : '';
        }
    }

    return $payload;
}
add_filter( 'woocommerce_webhook_payload', 'brandagent_order_webhook_payload', 10, 4 );

/**
 * Save BrandAgent session attributes to order meta when the order is created.
 *
 * By the time the order.updated webhook fires asynchronously, the WooCommerce
 * session may be destroyed. Persisting to order meta at checkout time ensures
 * the attributes survive for the order webhook payload builder to read back.
 *
 * This is the WooCommerce equivalent of how Shopify's _agentClientInfo note
 * attribute travels from cart → checkout → order.
 *
 * @param WC_Order $order The order being created.
 */
function brandagent_save_attrs_to_order( $order ) {
    $attrs = BrandAgent_REST_API::get_cart_attributes();
    if ( $attrs ) {
        $order->update_meta_data( '_brandagent_client_info', wp_json_encode( $attrs ) );
        $order->save();
    }
}
add_action( 'woocommerce_checkout_order_created', 'brandagent_save_attrs_to_order' );          // classic checkout
add_action( 'woocommerce_store_api_checkout_update_order_meta', 'brandagent_save_attrs_to_order' ); // blocks checkout (another way to checkout)

/**
 * Build the payload for checkout webhooks
 *
 * @param array $payload The webhook payload
 * @param string $resource The resource type
 * @param int $resource_id The resource ID
 * @param int $webhook_id The webhook ID
 * @return array The modified payload
 */
function brandagent_checkout_webhook_payload( $payload, $resource, $resource_id, $webhook_id ) {
    $webhook = wc_get_webhook( $webhook_id );
    
    if ( ! $webhook || $webhook->get_topic() !== 'checkout.created' ) {
        return $payload;
    }
    
    // Get current cart data
    $cart = WC()->cart;
    
    // Get cart ID (session-based identifier)
    $cart_id = WC()->session ? WC()->session->get_customer_id() : null;

    // Get store currency
    $currency = get_woocommerce_currency();

    // Retrieve BrandAgent session attributes set by the frontend via the REST API.
    $brandagent_attrs = BrandAgent_REST_API::get_cart_attributes();

    // Fall back to the BrandAgent clientId when WC session is unavailable (cart_id would be null).
    if ( ! $cart_id && ! empty( $brandagent_attrs['clientId'] ) ) {
        $cart_id = $brandagent_attrs['clientId'];
    }

    if ( ! $cart ) {
        return array(
            'event' => 'checkout.created',
            'cart_id' => $cart_id,
            'currency' => $currency,
            'checkout_url' => wc_get_checkout_url(),
            'line_items' => array(),
            'cart' => null,
            'customer' => null,
            'session_id' => ! empty( $brandagent_attrs['sessionId'] )
                ? $brandagent_attrs['sessionId']
                : $cart_id,
            'brandagent_attributes' => $brandagent_attrs,
            'timestamp' => current_time( 'c' ),
        );
    }
    
    // Build line items array similar to order webhook format
    $line_items = array();
    
    foreach ( $cart->get_cart() as $cart_item_key => $cart_item ) {
        $product = $cart_item['data'];
        $parent_product = null;
        $variant_title = '';
        
        // Get parent product and variant title if this is a variation
        if ( $cart_item['variation_id'] ) {
            $parent_product = wc_get_product( $cart_item['product_id'] );
            $variant_title = $product ? $product->get_name() : '';
        }
        
        $line_items[] = array(
            'key' => $cart_item_key,
            'product_id' => $cart_item['product_id'],
            'product_title' => $parent_product ? $parent_product->get_name() : ( $product ? $product->get_name() : '' ),
            'variation_id' => $cart_item['variation_id'],
            'variant_title' => $variant_title,
            'sku' => $product ? $product->get_sku() : '',
            'quantity' => $cart_item['quantity'],
            'price' => $product ? $product->get_price() : 0,
            'line_total' => $cart_item['line_total'],
            'line_subtotal' => $cart_item['line_subtotal'],
            'line_tax' => $cart_item['line_tax'] ?? 0,
        );
    }
    
    // Get customer info
    $customer = WC()->customer;
    $customer_data = null;
    
    if ( $customer ) {
        $customer_data = array(
            'id' => $customer->get_id(),
            'email' => $customer->get_email(),
            'first_name' => $customer->get_first_name(),
            'last_name' => $customer->get_last_name(),
            'billing_address' => array(
                'first_name' => $customer->get_billing_first_name(),
                'last_name' => $customer->get_billing_last_name(),
                'company' => $customer->get_billing_company(),
                'address_1' => $customer->get_billing_address_1(),
                'address_2' => $customer->get_billing_address_2(),
                'city' => $customer->get_billing_city(),
                'state' => $customer->get_billing_state(),
                'postcode' => $customer->get_billing_postcode(),
                'country' => $customer->get_billing_country(),
                'email' => $customer->get_billing_email(),
                'phone' => $customer->get_billing_phone(),
            ),
            'shipping_address' => array(
                'first_name' => $customer->get_shipping_first_name(),
                'last_name' => $customer->get_shipping_last_name(),
                'company' => $customer->get_shipping_company(),
                'address_1' => $customer->get_shipping_address_1(),
                'address_2' => $customer->get_shipping_address_2(),
                'city' => $customer->get_shipping_city(),
                'state' => $customer->get_shipping_state(),
                'postcode' => $customer->get_shipping_postcode(),
                'country' => $customer->get_shipping_country(),
            ),
        );
    }
    
    // Get applied coupons
    $coupons = array();
    foreach ( $cart->get_applied_coupons() as $coupon_code ) {
        $coupon = new WC_Coupon( $coupon_code );
        $coupons[] = array(
            'code' => $coupon_code,
            'discount' => $cart->get_coupon_discount_amount( $coupon_code ),
            'discount_tax' => $cart->get_coupon_discount_tax_amount( $coupon_code ),
        );
    }
    
    return array(
        'event' => 'checkout.created',
        'cart_id' => $cart_id,
        'currency' => $currency,
        'checkout_url' => wc_get_checkout_url(),
        'line_items' => $line_items,
        'line_items_count' => count( $line_items ),
        'cart' => array(
            'item_count' => $cart->get_cart_contents_count(),
            'total' => $cart->get_total( 'edit' ),
            'subtotal' => $cart->get_subtotal(),
            'tax_total' => $cart->get_cart_contents_tax(),
            'shipping_total' => $cart->get_shipping_total(),
            'shipping_tax' => $cart->get_shipping_tax(),
            'discount_total' => $cart->get_discount_total(),
            'discount_tax' => $cart->get_discount_tax(),
            'fees_total' => $cart->get_fee_total(),
            'fees_tax' => $cart->get_fee_tax(),
        ),
        'coupons' => $coupons,
        'customer' => $customer_data,
        'session_id' => ! empty( $brandagent_attrs['sessionId'] )
            ? $brandagent_attrs['sessionId']
            : $cart_id,
        'brandagent_attributes' => $brandagent_attrs,
        'timestamp' => current_time( 'c' ),
    );
}
add_filter( 'woocommerce_webhook_payload', 'brandagent_checkout_webhook_payload', 10, 4 );

/**
 * Trigger checkout.created webhooks when user visits checkout page
 * 
 * Note: WooCommerce checkout URL is configurable and not always at /checkout.
 * We use is_checkout() to properly detect the checkout page.
 */
class BrandAgent_Checkout_Webhook_Trigger {
    
    /**
     * Track if webhook has already been triggered for this request
     * @var bool
     */
    private static $triggered = false;
    
    /**
     * Initialize checkout webhook triggers
     */
    public static function init() {
        // Only register hooks if BrandAgent is enabled to avoid unnecessary processing
        if ( get_option( 'BAInjectFrontendScript' ) !== 'true' ) {
            return;
        }

        // Hook into template_redirect to detect checkout page visits
        // This fires after WooCommerce has set up the checkout page context
        add_action( 'template_redirect', array( __CLASS__, 'on_checkout_page' ), 20 );
    }
    
    /**
     * Handle checkout page visit
     */
    public static function on_checkout_page() {
        // Only trigger on checkout page (not cart, not order-received endpoint)
        if ( ! is_checkout() || is_order_received_page() || is_checkout_pay_page() ) {
            return;
        }
        
        // Prevent duplicate triggers
        if ( self::$triggered ) {
            return;
        }
        
        // Don't trigger for empty carts
        if ( ! WC()->cart || WC()->cart->is_empty() ) {
            return;
        }
        
        self::$triggered = true;
        self::trigger_webhooks();
    }
    
    /**
     * Trigger all checkout.started webhooks
     */
    private static function trigger_webhooks() {
        // Find all active checkout.started webhooks
        $webhooks = brandagent_get_webhooks_by_topic( 'checkout.created' );
        
        foreach ( $webhooks as $webhook ) {
            if ( $webhook->get_status() === 'active' ) {
                brandagent_deliver_custom_webhook( $webhook, 'checkout', 'checkout.created', 'created' );
            }
        }
    }
}

// Initialize checkout webhook triggers when WooCommerce is loaded
add_action( 'woocommerce_loaded', array( 'BrandAgent_Checkout_Webhook_Trigger', 'init' ) );
