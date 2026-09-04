<?php
/**
 * Brand Agent — WordPress content webhooks (plain-WordPress content sync).
 *
 * Emits push notifications to the Brand Agent backend whenever a post/page is published, edited,
 * unpublished, or deleted, so the backend can incrementally update its Milvus Document index instead
 * of re-crawling the whole site.
 *
 * Unlike the WooCommerce product webhooks in brandagent-webhooks.php (delivered by WC_Webhook, which
 * requires WooCommerce), these are driven by WordPress core hooks and posted directly, so they work on
 * any plain WordPress site. Requests are signed with the dedicated WordPress HMAC contract (X-WordPress-*
 * headers; signature over method + path + timestamp + nonce + sha256(body) + normalized site url +
 * client id), which the backend's WordPressHmac auth scheme validates. This is separate from the
 * WooCommerce product path, which keeps its own X-WooCommerce-* / WooCommerceHmac contract.
 *
 * Delivery: POST {backend}/api/v1/wordpress/webhooks/content/{created|updated|deleted}?store_url=...
 *
 * @package MicrosoftClarity
 */

// Exit if accessed directly
defined( 'ABSPATH' ) || exit;

/**
 * Post types whose changes are synced to the content index. Reuses the same allowlist filter as the
 * content-fetch endpoint so a site that widens one widens both.
 *
 * @return string[]
 */
function brandagent_content_webhook_allowed_types() {
	return apply_filters( 'brandagent_content_fetch_allowed_post_types', array( 'post', 'page' ) );
}

/**
 * Whether content webhooks should currently be emitted. All of the following must hold:
 *   - the store is NOT a WooCommerce store. Content webhooks are the plain-WordPress content path only;
 *     WooCommerce stores sync through the WooCommerce product webhooks (X-WooCommerce-* / WC_Webhook) and
 *     are provisioned with a WooCommerce-keyed secret. Without this guard a WooCommerce store would also
 *     emit its posts/pages here, signed with the wrong (WordPressHmac) contract — a double-emit that fails
 *     backend auth. brandagent_is_woocommerce_store() decides this from the platform recorded with the
 *     stored credential (brandagent_get_hmac_platform()), not from the live plugin state, so the answer
 *     stays stable if WooCommerce is activated or deactivated after onboarding.
 *   - the store is connected (has an HMAC secret);
 *   - the connect handshake completed (BAOauthSuccess);
 *   - the agent has actually been PUBLISHED (BAInjectFrontendScript === 'true'). The backend flips this
 *     via api/config/update only at the end of a successful, RAI-safe publish-agent onboarding — after the
 *     content index is built and the widget is injected (WordPressOnboardingService.OnboardAsync step 4).
 *     Gating on it mirrors WooCommerce, whose webhooks are also created only at publish (the same
 *     BAInjectFrontendScript config-update triggers BrandAgent_Webhooks::create_webhooks). Before publish
 *     there is no Milvus Document collection to apply changes to and the merchant may never publish, so
 *     emitting earlier is wasted work the backend just drops; a blocked/waitlisted (RAI-unsafe) site never
 *     gets the flag, so it never emits. When the agent is later disabled, the flag flips back to 'false'
 *     and emission stops.
 *
 * @return bool
 */
function brandagent_content_webhooks_enabled() {
	if ( brandagent_is_woocommerce_store() ) {
		return false;
	}

	if ( ! brandagent_get_hmac_secret() ) {
		return false;
	}

	if ( (int) get_option( 'BAOauthSuccess' ) !== 1 ) {
		return false;
	}

	// Only after the agent is published and injected (set by the backend at RAI-safe go-live).
	return get_option( 'BAInjectFrontendScript' ) === 'true';
}

/**
 * Build the indexable representation of a single post/page. This is the single source of truth for the
 * content item shape; both the content-fetch endpoint (bulk) and the webhooks (incremental) use it so the
 * two never diverge. Content is returned as the rendered HTML (the_content); tag-stripping / Markdown
 * conversion happens on the Brand Agents server.
 *
 * @param WP_Post $post The post/page.
 * @return array Content item matching the backend WordPressContentItem contract.
 */
function brandagent_build_content_item( $post ) {
	$rendered = apply_filters( 'the_content', $post->post_content );

	$cat_terms = wp_get_post_terms( $post->ID, 'category', array( 'fields' => 'names' ) );
	$tag_terms = wp_get_post_terms( $post->ID, 'post_tag', array( 'fields' => 'names' ) );

	// Prefer the featured image; fall back to the first inline image so image-rich posts still get a card
	// image when no thumbnail is set.
	$feature_image = get_the_post_thumbnail_url( $post, 'full' );
	if ( ! $feature_image && preg_match( '/<img[^>]+src=["\']([^"\']+)["\']/i', (string) $rendered, $img_match ) ) {
		$feature_image = $img_match[1];
	}
	$feature_image = $feature_image ? $feature_image : '';

	return array(
		'id'            => (int) $post->ID,
		'type'          => $post->post_type,
		'title'         => get_the_title( $post ),
		'url'           => get_permalink( $post ),
		'feature_image' => $feature_image,
		'content_text'  => $rendered,
		'excerpt'       => has_excerpt( $post ) ? get_the_excerpt( $post ) : '',
		'modified'      => get_post_modified_time( 'c', true, $post ),
		'author'        => get_the_author_meta( 'display_name', $post->post_author ),
		'categories'    => is_wp_error( $cat_terms ) ? array() : array_values( $cat_terms ),
		'tags'          => is_wp_error( $tag_terms ) ? array() : array_values( $tag_terms ),
	);
}

/**
 * Sign and fire a content webhook to the backend. Non-blocking (fire-and-forget) on the hot path so
 * saving a post is never delayed by the round-trip. blocking=false still surfaces *immediate* failures
 * (invalid URL, DNS, SSL/transport init) as WP_Error; when that happens we enqueue a durable WP-Cron
 * retry (brandagent_retry_content_webhook) so a transient outage at save time doesn't silently diverge
 * the backend index. Failures that only appear mid-flight (server 5xx, network drop after send) are
 * invisible to a non-blocking call and are recovered by a later edit or full reconciliation.
 * Authenticated with the dedicated WordPress HMAC scheme via brandagent_wordpress_build_signed_headers()
 * (X-WordPress-* headers + per-request nonce), which the backend's WordPressHmac auth handler validates.
 *
 * @param string $event One of 'created', 'updated', 'deleted'.
 * @param string $body  JSON request body.
 * @return void
 */
function brandagent_dispatch_content_webhook( $event, $body ) {
	$secret = brandagent_get_hmac_secret();
	if ( ! $secret ) {
		return;
	}

	$backend = BrandAgent_Config::get_backend_base_url();
	if ( empty( $backend ) ) {
		brandagent_log( 'BrandAgent Content Webhook: no backend URL; skipping', array( 'event' => $event ) );
		return;
	}

	list( $url, $headers ) = brandagent_build_content_webhook_request( $event, $body, $backend );

	$result = wp_remote_post( $url, array(
		'timeout'  => 1,
		'blocking' => false,
		'headers'  => $headers,
		'body'     => $body,
	) );

	if ( is_wp_error( $result ) ) {
		brandagent_log(
			'BrandAgent Content Webhook: immediate send failure; scheduling retry',
			array( 'event' => $event, 'error' => $result->get_error_message() )
		);
		brandagent_schedule_content_webhook_retry( $event, $body, 1 );
		return;
	}

	brandagent_log( 'BrandAgent Content Webhook: dispatched', array( 'event' => $event ) );
}

/**
 * Build the absolute delivery URL and signed headers for a content webhook. Shared by the hot-path
 * dispatch and the cron retry so the signed path+query and the URL actually posted to never drift: the
 * WordPressHmac signature is computed over method + path+query (exactly as the backend reconstructs it
 * from HttpRequest.Path + QueryString), so any mismatch between the signed path and the delivered URL
 * fails backend verification.
 *
 * Headers are produced by brandagent_wordpress_build_signed_headers() — the single implementation of the
 * WordPressHmac canonical string, whose backend twin is WordPressAuthUtils::BuildInboundCanonicalRequest.
 * Both callers verify brandagent_get_hmac_secret() before reaching here, so the helper's missing-secret
 * WP_Error is unreachable on this path.
 *
 * @param string $event   One of 'created', 'updated', 'deleted'.
 * @param string $body    JSON request body (bound into the signature via its sha256).
 * @param string $backend Backend base URL (already fetched by the caller).
 * @return array [ 0 => absolute URL string, 1 => headers array ].
 */
function brandagent_build_content_webhook_request( $event, $body, $backend ) {
	$store_url      = home_url();
	$path_and_query = BRANDAGENT_CONTENT_WEBHOOK_BASE_URL . 'content/' . rawurlencode( $event )
		. '?store_url=' . rawurlencode( $store_url );

	$headers                 = brandagent_wordpress_build_signed_headers( $path_and_query, $body, 'POST' );
	$headers['Content-Type'] = 'application/json';

	return array( rtrim( $backend, '/' ) . $path_and_query, $headers );
}

/**
 * Enqueue a single durable WP-Cron retry for a content webhook, de-duplicated on (event, body, attempt)
 * so an identical pending retry is never double-queued.
 *
 * The rendered post body is parked in a transient and only its key is placed in the cron args. WP-Cron
 * stores scheduled events in the `cron` option, which is autoloaded and unserialized on every page load;
 * putting a 60 KB+ rendered post body there — multiplied across a bulk edit or import queued during a
 * backend outage — bloats autoloaded options into the megabytes and can breach the object-cache item
 * ceiling for alloptions, degrading the whole site. The transient is non-autoloaded, so it costs nothing
 * on the hot path, and its key is derived from the same (event, body, attempt) tuple, so dedup is
 * unchanged. TTL is a full day — well past the ~15-minute retry chain — so the snapshot outlives it.
 *
 * @param string $event   One of 'created', 'updated', 'deleted'.
 * @param string $body    JSON request body — the snapshot to redeliver.
 * @param int    $attempt Attempt number this scheduled delivery represents (>= 1).
 * @param int    $delay   Seconds to wait before the retry fires.
 * @return void
 */
function brandagent_schedule_content_webhook_retry( $event, $body, $attempt, $delay = MINUTE_IN_SECONDS ) {
	$body_key = 'brandagent_cw_' . md5( $event . $body . (int) $attempt );
	set_transient( $body_key, $body, DAY_IN_SECONDS );

	$args = array( $event, $body_key, (int) $attempt );
	if ( ! wp_next_scheduled( 'brandagent_retry_content_webhook', $args ) ) {
		wp_schedule_single_event( time() + (int) $delay, 'brandagent_retry_content_webhook', $args );
	}
}

/**
 * WP-Cron handler: redeliver a content webhook that failed to send, with exponential backoff.
 *
 * Unlike the hot-path dispatch this runs in cron with no user request to delay, so it sends blocking and
 * inspects the HTTP status. Headers are re-signed on each attempt (fresh timestamp + nonce) because the
 * WordPressHmac scheme only accepts signatures inside a short timestamp window — replaying stale headers
 * would fail. The redelivered body is the snapshot captured when the change happened; the backend upserts
 * by deterministic id, so a redelivered create/update converges the index and a redelivered delete of an
 * already-removed doc is a safe no-op.
 *
 * @param string $event   One of 'created', 'updated', 'deleted'.
 * @param string $body_key Transient key under which the JSON request body snapshot is parked.
 * @param int    $attempt Attempt number, starting at 1.
 * @return void
 */
function brandagent_retry_content_webhook( $event, $body_key, $attempt = 1 ) {
	// Re-check the same gate as the initial dispatch: a store that disconnected or became a WooCommerce
	// store between scheduling and firing must not deliver.
	if ( ! brandagent_content_webhooks_enabled() ) {
		delete_transient( $body_key );
		return;
	}

	// The snapshot is parked in a transient rather than in the cron args (which live in the autoloaded
	// `cron` option). If it expired, the change is recovered by a later edit or a full reconciliation,
	// same as any other dropped attempt.
	$body = get_transient( $body_key );
	if ( false === $body ) {
		return;
	}

	$secret = brandagent_get_hmac_secret();
	if ( ! $secret ) {
		delete_transient( $body_key );
		return;
	}

	$backend = BrandAgent_Config::get_backend_base_url();
	if ( empty( $backend ) ) {
		delete_transient( $body_key );
		return;
	}

	list( $url, $headers ) = brandagent_build_content_webhook_request( $event, $body, $backend );

	$response = wp_remote_post( $url, array(
		'timeout'  => 10,
		'blocking' => true,
		'headers'  => $headers,
		'body'     => $body,
	) );

	$should_retry  = false;
	$error_message = '';

	if ( is_wp_error( $response ) ) {
		$should_retry  = true;
		$error_message = $response->get_error_message();
	} else {
		$code = (int) wp_remote_retrieve_response_code( $response );
		// Retry only transient failures: no response (0), throttling (429), or server errors (5xx). Other
		// 4xx (400/401/404/...) are deterministic — re-sending the same body fails identically — so we stop
		// and leave recovery to a later edit or full reconciliation.
		if ( 0 === $code || 429 === $code || $code >= 500 ) {
			$should_retry  = true;
			$error_message = 'HTTP ' . $code;
		}
	}

	if ( ! $should_retry ) {
		delete_transient( $body_key );
		brandagent_log( 'BrandAgent Content Webhook: retry succeeded', array( 'event' => $event, 'attempt' => (int) $attempt ) );
		return;
	}

	$max_attempts = 5;
	if ( (int) $attempt >= $max_attempts ) {
		delete_transient( $body_key );
		brandagent_log(
			'BrandAgent Content Webhook: retry attempts exhausted; giving up',
			array( 'event' => $event, 'attempt' => (int) $attempt, 'error' => $error_message )
		);
		return;
	}

	$next_attempt = (int) $attempt + 1;
	// Exponential backoff capped at 1h: 1, 2, 4, 8 minutes for attempts 1..4.
	$delay_seconds = min( HOUR_IN_SECONDS, (int) pow( 2, (int) $attempt - 1 ) * MINUTE_IN_SECONDS );

	brandagent_log(
		'BrandAgent Content Webhook: scheduling retry',
		array(
			'event'         => $event,
			'attempt'       => (int) $attempt,
			'next_attempt'  => $next_attempt,
			'delay_seconds' => $delay_seconds,
			'error'         => $error_message,
		)
	);

	// The next attempt parks its own attempt-scoped snapshot (keyed by attempt), so drop this attempt's
	// copy now rather than stranding one full-post-body transient per attempt for a day.
	delete_transient( $body_key );
	brandagent_schedule_content_webhook_retry( $event, $body, $next_attempt, $delay_seconds );
}
add_action( 'brandagent_retry_content_webhook', 'brandagent_retry_content_webhook', 10, 3 );

/**
 * Emit a create/update webhook carrying the full content item.
 *
 * @param string  $event 'created' or 'updated'.
 * @param WP_Post $post  The post/page.
 * @return void
 */
function brandagent_send_content_upsert_webhook( $event, $post ) {
	brandagent_dispatch_content_webhook( $event, wp_json_encode( brandagent_build_content_item( $post ) ) );
}

/**
 * Emit a delete webhook carrying just the id/type (the backend removes the doc by deterministic id).
 *
 * @param int    $post_id   The post/page id.
 * @param string $post_type The post type.
 * @return void
 */
function brandagent_send_content_delete_webhook( $post_id, $post_type ) {
	brandagent_dispatch_content_webhook( 'deleted', wp_json_encode( array(
		'id'   => (int) $post_id,
		'type' => $post_type,
	) ) );
}

/**
 * Record a pending content event for this request and flush it on shutdown, instead of dispatching
 * inline from transition_post_status.
 *
 * Two reasons to defer. First, timing: transition_post_status fires inside wp_insert_post(), before the
 * REST controller runs handle_featured_media(), handle_terms() and the registered-meta writes — so on the
 * ordinary block-editor flow (write post, set featured image + category, Publish) an inline build ships
 * feature_image:"", categories:[] and tags:[], and stays wrong until some later unrelated edit re-fires
 * the hook. On create_item it is guaranteed wrong because handle_featured_media() always runs after the
 * insert. Building on shutdown means terms, meta and the featured image are already persisted. (We stay on
 * shutdown rather than wp_after_insert_post because the plugin's readme.txt floor is WP 4.0 and that hook
 * is 5.6+.) Second, dedup: with meta boxes registered a single Gutenberg save runs wp_update_post more
 * than once, so keying by post id collapses the repeated saves to one delivery (one the_content render).
 *
 * The shutdown flush is registered exactly once per request — on the first queued event — and its closure
 * captures $queued by reference so entries added by later calls in the same request are still seen.
 *
 * Deletes from before_delete_post are NOT routed here: the row is gone by shutdown, so that handler must
 * dispatch inline.
 *
 * @param int    $post_id   The post/page id.
 * @param string $event     'created', 'updated' or 'deleted'.
 * @param string $post_type Post type, required for the delete payload (build re-fetches the post for upserts).
 * @return void
 */
function brandagent_queue_content_event( $post_id, $event, $post_type = '' ) {
	static $queued = array();

	if ( empty( $queued ) ) {
		add_action( 'shutdown', function () use ( &$queued ) {
			foreach ( $queued as $id => $pending ) {
				if ( 'deleted' === $pending['event'] ) {
					brandagent_send_content_delete_webhook( $id, $pending['type'] );
					continue;
				}

				$post = get_post( $id );
				if ( $post instanceof WP_Post ) {
					brandagent_send_content_upsert_webhook( $pending['event'], $post );
				}
			}
		} );
	}

	$queued[ (int) $post_id ] = array(
		'event' => $event,
		'type'  => $post_type,
	);
}

/**
 * Whether a post is eligible for content webhooks (allowed type, not a revision/autosave, not
 * password-protected). Password-protected posts are excluded to stay identical to the bulk content-fetch
 * endpoint, which filters them out via has_password=false — otherwise gated content would leak into the
 * index through the incremental path but never appear in a full fetch.
 *
 * @param WP_Post|int $post Post object or id.
 * @return bool
 */
function brandagent_content_webhook_eligible_post( $post ) {
	if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
		return false;
	}

	$post = get_post( $post );
	if ( ! $post instanceof WP_Post ) {
		return false;
	}

	if ( wp_is_post_revision( $post ) || wp_is_post_autosave( $post ) ) {
		return false;
	}

	if ( '' !== $post->post_password ) {
		return false;
	}

	return in_array( $post->post_type, brandagent_content_webhook_allowed_types(), true );
}

/**
 * Core create/update/unpublish signal. transition_post_status fires on every insert/update with both the
 * old and new status, so it is the single source of truth:
 *   - non-publish  -> publish      : created (when the new state is indexable)
 *   - publish      -> publish       : updated when still indexable; deleted when it just became
 *                                     non-indexable (password added, or post type left the allowlist)
 *   - publish      -> not-publish   : deleted (unpublished / trashed — remove from the index)
 * Draft-to-draft edits are never indexed, so they are ignored.
 *
 * Eligibility is evaluated per-branch rather than as a single up-front gate: gating the whole handler on
 * brandagent_content_webhook_eligible_post() would suppress the delete when a live, indexed post becomes
 * gated/non-indexable, leaving that content exposed in the backend index.
 *
 * @param string  $new_status New post status.
 * @param string  $old_status Previous post status.
 * @param WP_Post $post       The post.
 * @return void
 */
function brandagent_on_transition_post_status( $new_status, $old_status, $post ) {
	if ( ! brandagent_content_webhooks_enabled() ) {
		return;
	}

	// Structural guard only (never act on autosaves/revisions or a non-post). Deliberately narrower than
	// brandagent_content_webhook_eligible_post(): password / allowlist eligibility is applied per-branch
	// below so a transition from indexable to non-indexable can still emit a delete.
	if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
		return;
	}
	if ( ! $post instanceof WP_Post || wp_is_post_revision( $post ) || wp_is_post_autosave( $post ) ) {
		return;
	}

	$was_published   = ( 'publish' === $old_status );
	$is_published    = ( 'publish' === $new_status );
	$upsert_eligible = brandagent_content_webhook_eligible_post( $post );

	if ( $is_published && ! $was_published ) {
		// Newly published: index it only if indexable. A post first published already gated (password /
		// non-allowlisted type) was never in the index, so there is nothing to delete.
		if ( $upsert_eligible ) {
			brandagent_queue_content_event( $post->ID, 'created' );
		}
	} elseif ( $is_published && $was_published ) {
		// Edit of a live post. Still indexable -> upsert the new content. Just became non-indexable while
		// staying published (password added, or post type moved out of the allowlist) -> delete so gated
		// content is not left in the index. Deleting a doc that was never indexed is a safe backend no-op.
		if ( $upsert_eligible ) {
			brandagent_queue_content_event( $post->ID, 'updated' );
		} else {
			brandagent_queue_content_event( $post->ID, 'deleted', $post->post_type );
		}
	} elseif ( ! $is_published && $was_published ) {
		// Unpublished / trashed -> always remove from the index.
		brandagent_queue_content_event( $post->ID, 'deleted', $post->post_type );
	}
}
add_action( 'transition_post_status', 'brandagent_on_transition_post_status', 10, 3 );

/**
 * Permanent deletion (emptying trash / wp_delete_post). transition_post_status does not fire here, so
 * this ensures a hard-deleted post is removed from the index. Deleting an already-removed document is a
 * safe no-op on the backend, so the overlap with the trash transition above is harmless.
 *
 * @param int $post_id The post id being deleted.
 * @return void
 */
function brandagent_on_before_delete_post( $post_id ) {
	if ( ! brandagent_content_webhooks_enabled() ) {
		return;
	}

	// Reuse the shared eligibility predicate so the delete path applies the exact same rules
	// (allowed type, not a revision/autosave, not password-protected) as create/update.
	if ( ! brandagent_content_webhook_eligible_post( $post_id ) ) {
		return;
	}

	$post = get_post( $post_id );
	brandagent_send_content_delete_webhook( $post->ID, $post->post_type );
}
add_action( 'before_delete_post', 'brandagent_on_before_delete_post', 10, 1 );
