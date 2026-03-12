<?php
/**
 * BrandAgent Checkout Created Webhook Configuration
 *
 * Custom webhook for tracking when users navigate to the checkout page
 *
 * @package MicrosoftClarity
 * @since 0.10.21
 */

// Exit if accessed directly
defined( 'ABSPATH' ) || exit;

return array(
    'name'     => 'BrandAgent Checkout Created',
    'topic'    => 'checkout.created',
    'endpoint' => BRANDAGENT_WEBHOOK_BASE_URL . 'checkout/created',
);
