<?php
/**
 * Order Updated Webhook Configuration
 *
 * @package MicrosoftClarity
 * @since 0.10.21
 */

// Exit if accessed directly
defined( 'ABSPATH' ) || exit;

return array(
	'name'     => 'BrandAgent Order Updated',
	'topic'    => 'order.updated',
	'endpoint' => BRANDAGENT_WEBHOOK_BASE_URL . 'orders/updated',
);
