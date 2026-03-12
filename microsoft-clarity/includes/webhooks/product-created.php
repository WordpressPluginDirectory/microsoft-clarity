<?php
/**
 * Product Created Webhook Configuration
 *
 * @package MicrosoftClarity
 * @since 0.10.21
 */

// Exit if accessed directly
defined( 'ABSPATH' ) || exit;

return array(
	'name'     => 'BrandAgent Product Created',
	'topic'    => 'product.created',
	'endpoint' => BRANDAGENT_WEBHOOK_BASE_URL . 'products/created',
);
