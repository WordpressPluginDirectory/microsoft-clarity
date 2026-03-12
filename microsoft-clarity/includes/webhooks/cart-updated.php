<?php
/**
 * BrandAgent Cart Updated Webhook Configuration
 *
 * Custom webhook for tracking cart add/remove/update events
 *
 * @package MicrosoftClarity
 * @since 0.10.21
 */

// Exit if accessed directly
defined( 'ABSPATH' ) || exit;

return array(
    'name'     => 'BrandAgent Cart Updated',
    'topic'    => 'cart.updated',
    'endpoint' => BRANDAGENT_WEBHOOK_BASE_URL . 'cart/updated',
);
