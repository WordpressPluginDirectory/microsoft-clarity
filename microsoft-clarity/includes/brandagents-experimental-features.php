<?php
/**
 * Universal Commerce Protocol (UCP) discovery endpoint.
 *
 * Serves `/.well-known/ucp` from the SITE ROOT and proxies it to the Brand Agent
 * backend, which owns the manifest. The plugin deliberately does not build the
 * manifest locally: the manifest describes the agent endpoints the backend
 * exposes for this store, so the backend is the only component that can keep it
 * correct as those endpoints change. Keeping the plugin a thin proxy means a
 * manifest change never requires a plugin release.
 *
 * The upstream path is keyed by the normalized store URL, which is the same
 * advertiser id used everywhere else in this plugin (see
 * brandagent_normalize_store_url), e.g.
 *   https://<backend>/lezomi-com/.well-known/ucp
 *
 * @package MicrosoftClarity
 */

defined( 'ABSPATH' ) || exit;

/**
 * Query var used when pretty permalinks route the request through WP's rewrite
 * rules. Requests are also matched directly off REQUEST_URI, so the endpoint
 * still works on stores whose permalink structure is plain (which is exactly the
 * case where Brand Agent's other rewrite routes do not resolve) and on installs
 * whose rewrite rules have not been flushed since this plugin version landed.
 */
const BRANDAGENT_UCP_QUERY_VAR = 'brandagent_ucp';

/** Response cache lifetime. The UCP spec requires a public, cacheable manifest. */
const BRANDAGENT_UCP_CACHE_MAX_AGE = 300;

/** Upstream request timeout, in seconds. */
const BRANDAGENT_UCP_TIMEOUT = 10;

/** Admin-configurable UCP-only backend override used for development testing. */
const BRANDAGENT_UCP_BACKEND_BASE_URL_OPTION = 'brandagent_ucp_backend_base_url';

/** Administrator opt-in for publishing the UCP discovery endpoint. */
const BRANDAGENT_UCP_ENABLED_OPTION = 'brandagent_ucp_enabled';

/** Administrator opt-in for sending the UCP flight to the selected backend. */
const BRANDAGENT_UCP_DEVELOPMENT_FLIGHT_OPTION = 'brandagent_ucp_development_flight';

/** Brand Agents flight that exposes the UCP and MCP endpoints. */
const BRANDAGENT_UCP_DEVELOPMENT_FLIGHT = 'EnableUCPMCPEndpoints';

/**
 * Parse a URL while retaining compatibility with the plugin's WordPress 4.0 minimum.
 *
 * WordPress's wp_parse_url() was added after WordPress 4.0. PHP's parse_url()
 * provides the behavior needed here on older installations.
 *
 * @param string $url       URL to parse.
 * @param int    $component Optional PHP_URL_* component.
 * @return mixed Parsed URL value.
 */
function brandagent_ucp_parse_url( $url, $component = -1 ) {
	if ( function_exists( 'wp_parse_url' ) ) {
		return wp_parse_url( $url, $component );
	}

	return parse_url( $url, $component ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Required fallback for the declared WordPress 4.0 minimum.
}

/**
 * Normalize the submitted endpoint opt-in to a stored integer.
 *
 * @param mixed $value Submitted setting value.
 * @return int 1 when enabled; otherwise 0.
 */
function brandagent_ucp_sanitize_enabled( $value ) {
	return 1 === (int) $value ? 1 : 0;
}

/**
 * Validate the optional UCP development backend URL.
 *
 * An empty value disables the override. Only an absolute HTTP(S) origin/path,
 * with optional query parameters, is accepted because the saved value is used
 * as the destination of a server-side request. Invalid submissions leave the
 * previous value unchanged.
 *
 * @param mixed $value Submitted setting value.
 * @return string Sanitized URL, or the previously saved value when invalid.
 */
function brandagent_ucp_sanitize_backend_base_url( $value ) {
	$value = trim( (string) $value );
	if ( '' === $value ) {
		return '';
	}

	$sanitized = esc_url_raw( $value, array( 'http', 'https' ) );
	$parts     = brandagent_ucp_parse_url( $sanitized );
	if (
		empty( $sanitized ) ||
		! is_array( $parts ) ||
		empty( $parts['scheme'] ) ||
		empty( $parts['host'] ) ||
		! in_array( strtolower( $parts['scheme'] ), array( 'http', 'https' ), true ) ||
		isset( $parts['fragment'] )
	) {
		add_settings_error(
			BRANDAGENT_UCP_BACKEND_BASE_URL_OPTION,
			'brandagent_ucp_backend_base_url_invalid',
			'Enter an absolute HTTP(S) URL without a fragment.'
		);
		return (string) get_option( BRANDAGENT_UCP_BACKEND_BASE_URL_OPTION, '' );
	}

	return $sanitized;
}

/** Register the experimental UCP settings with the WordPress Settings API. */
function brandagent_ucp_register_experimental_settings() {
	register_setting(
		'brandagent_ucp_endpoint_toggle',
		BRANDAGENT_UCP_ENABLED_OPTION,
		'brandagent_ucp_sanitize_enabled'
	);

	register_setting(
		'brandagent_ucp_feature_settings',
		BRANDAGENT_UCP_BACKEND_BASE_URL_OPTION,
		'brandagent_ucp_sanitize_backend_base_url'
	);

	register_setting(
		'brandagent_ucp_feature_settings',
		BRANDAGENT_UCP_DEVELOPMENT_FLIGHT_OPTION,
		'brandagent_ucp_sanitize_enabled'
	);
}
add_action( 'admin_init', 'brandagent_ucp_register_experimental_settings' );

/** Register an administrator-only experimental-features page without a menu item. */
function brandagent_add_experimental_features_page() {
	add_submenu_page(
		'',
		'Brand Agents Experimental Features',
		'Brand Agents Experimental Features',
		'manage_options',
		'brandagents-experimental-features',
		'brandagent_render_experimental_features_page'
	);
}
// An empty parent registers an admin.php page without attaching it to a menu.
// Administrators can open it directly with ?page=brandagents-experimental-features.
add_action( 'admin_menu', 'brandagent_add_experimental_features_page' );

/** Render the administrator-only experimental-features settings page. */
function brandagent_render_experimental_features_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	$enabled            = 1 === (int) get_option( BRANDAGENT_UCP_ENABLED_OPTION, 0 );
	$override           = (string) get_option( BRANDAGENT_UCP_BACKEND_BASE_URL_OPTION, '' );
	$development_flight = 1 === (int) get_option( BRANDAGENT_UCP_DEVELOPMENT_FLIGHT_OPTION, 0 );
	?>
	<div class="wrap brandagents-experimental-features">
		<h1>Brand Agents Experimental Features</h1>
		<p>Try Brand Agents features before they are generally available. These settings apply only to this WordPress site.</p>
		<?php settings_errors(); ?>
		<style>
			.brandagents-experimental-features { max-width: 860px; }
			.brandagent-feature-card { background: #fff; border: 1px solid #c3c4c7; border-radius: 4px; box-shadow: 0 1px 1px rgba(0, 0, 0, 0.04); margin-top: 20px; padding: 24px; }
			.brandagent-feature-header { align-items: flex-start; display: flex; gap: 24px; justify-content: space-between; }
			.brandagent-feature-header h2 { margin: 0 0 8px; }
			.brandagent-feature-header p { margin: 0; max-width: 620px; }
			.brandagent-toggle-form { flex: 0 0 auto; margin: 0; }
			.brandagent-toggle { display: inline-block; height: 24px; position: relative; width: 44px; }
			.brandagent-toggle input { height: 1px; opacity: 0; position: absolute; width: 1px; }
			.brandagent-toggle-control { background: #8c8f94; border-radius: 12px; bottom: 0; cursor: pointer; left: 0; position: absolute; right: 0; top: 0; transition: background-color 0.15s ease; }
			.brandagent-toggle-control::before { background: #fff; border-radius: 50%; content: ""; height: 18px; left: 3px; position: absolute; top: 3px; transition: transform 0.15s ease; width: 18px; }
			.brandagent-toggle input:checked + .brandagent-toggle-control { background: #2271b1; }
			.brandagent-toggle input:checked + .brandagent-toggle-control::before { transform: translateX(20px); }
			.brandagent-toggle input:focus + .brandagent-toggle-control { box-shadow: 0 0 0 1px #fff, 0 0 0 3px #2271b1; }
			.brandagent-feature-settings { margin-top: 28px; }
			.brandagent-feature-settings summary { cursor: pointer; font-size: 1.3em; font-weight: 600; line-height: 1.4; }
			.brandagent-feature-settings summary:focus { outline: 2px solid #2271b1; outline-offset: 2px; }
			.brandagent-feature-settings .dashicons { color: #50575e; margin-right: 6px; vertical-align: text-bottom; }
			.brandagent-feature-settings-content { margin-top: 12px; }
			.brandagent-environment { color: #50575e; font-weight: 600; }
			@media screen and (max-width: 782px) {
				.brandagent-feature-header { gap: 16px; }
				.brandagent-feature-card { padding: 20px; }
			}
		</style>
		<div class="brandagent-feature-card">
			<div class="brandagent-feature-header">
				<div>
					<h2>UCP endpoint</h2>
					<p>Publish <code>/.well-known/ucp</code> so compatible agents can discover this store's Brand Agents commerce capabilities. This requires a WooCommerce Brand Agents connection. Production normally requires the Brand Agents <code>global.EnableUCPMCPEndpoints</code> feature flag; test requests can use the feature flight configured below.</p>
				</div>
				<form method="post" action="options.php" class="brandagent-toggle-form">
					<?php settings_fields( 'brandagent_ucp_endpoint_toggle' ); ?>
					<input type="hidden" name="<?php echo esc_attr( BRANDAGENT_UCP_ENABLED_OPTION ); ?>" value="0" />
					<label class="brandagent-toggle" for="brandagent-ucp-enabled">
						<input
							type="checkbox"
							id="brandagent-ucp-enabled"
							name="<?php echo esc_attr( BRANDAGENT_UCP_ENABLED_OPTION ); ?>"
							value="1"
							onchange="this.form.submit();"
							<?php checked( $enabled ); ?>
						/>
						<span class="brandagent-toggle-control" aria-hidden="true"></span>
						<span class="screen-reader-text">Enable UCP endpoint</span>
					</label>
				</form>
			</div>

			<details class="brandagent-feature-settings">
				<summary><span class="dashicons dashicons-admin-generic" aria-hidden="true"></span>Feature Settings</summary>
				<div class="brandagent-feature-settings-content">
					<form method="post" action="options.php">
						<?php settings_fields( 'brandagent_ucp_feature_settings' ); ?>
						<p>Configure development behavior for the UCP endpoint.</p>
						<table class="form-table" role="presentation">
							<tr>
								<th scope="row"><label for="brandagent-ucp-backend-base-url">Development Brand Agents URL</label></th>
								<td>
									<input
										type="url"
										class="regular-text code"
										id="brandagent-ucp-backend-base-url"
										name="<?php echo esc_attr( BRANDAGENT_UCP_BACKEND_BASE_URL_OPTION ); ?>"
										value="<?php echo esc_attr( $override ); ?>"
										placeholder="https://dev-brand-agent.example.com"
									/>
									<p class="description">Leave blank to use the production Brand Agents environment. Paths and query parameters are supported; URL fragments are not.</p>
									<p class="brandagent-environment">Current environment: <?php echo esc_html( empty( $override ) ? 'Production' : 'Custom development' ); ?></p>
									<p class="description">This override affects only the UCP endpoint. Other Brand Agents requests continue using the environment supplied by Clarity.</p>
								</td>
							</tr>
							<tr>
								<th scope="row">UCP development flight</th>
								<td>
									<input type="hidden" name="<?php echo esc_attr( BRANDAGENT_UCP_DEVELOPMENT_FLIGHT_OPTION ); ?>" value="0" />
									<label for="brandagent-ucp-development-flight">
										<input
											type="checkbox"
											id="brandagent-ucp-development-flight"
											name="<?php echo esc_attr( BRANDAGENT_UCP_DEVELOPMENT_FLIGHT_OPTION ); ?>"
											value="1"
											<?php checked( $development_flight ); ?>
										/>
										Send <code>setflight=<?php echo esc_html( BRANDAGENT_UCP_DEVELOPMENT_FLIGHT ); ?></code>
									</label>
									<p class="description">Applied to the selected Brand Agents environment, including production when the development URL is blank. Leave unchecked for normal production requests.</p>
								</td>
							</tr>
						</table>
						<?php submit_button( 'Save Feature Settings' ); ?>
					</form>
				</div>
			</details>
		</div>
	</div>
	<?php
}

/**
 * Register the rewrite rule for /.well-known/ucp.
 *
 * Called from brandagent_register_routes() on `init` and again on activation
 * before flush_rewrite_rules(), matching how the existing Brand Agent proxy
 * routes are registered.
 */
function brandagent_ucp_register_routes() {
	add_rewrite_rule(
		'^\.well-known/ucp/?$',
		'index.php?' . BRANDAGENT_UCP_QUERY_VAR . '=1',
		'top'
	);
}

/**
 * Expose the query var so WP keeps it when the rewrite rule matches.
 *
 * @param array $vars Registered query vars.
 * @return array
 */
function brandagent_ucp_register_query_vars( $vars ) {
	$vars[] = BRANDAGENT_UCP_QUERY_VAR;
	return $vars;
}
add_filter( 'query_vars', 'brandagent_ucp_register_query_vars' );

/**
 * True when the current request is for /.well-known/ucp.
 *
 * Checks the rewritten query var first, then falls back to the raw path so the
 * endpoint does not depend on rewrite rules having been flushed.
 *
 * @return bool
 */
function brandagent_ucp_is_request() {
	if ( intval( get_query_var( BRANDAGENT_UCP_QUERY_VAR ) ) === 1 ) {
		return true;
	}

	if ( ! isset( $_SERVER['REQUEST_URI'] ) ) {
		return false;
	}

	$request_uri = sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) );
	$path        = brandagent_ucp_parse_url( $request_uri, PHP_URL_PATH );

	return is_string( $path ) && rtrim( $path, '/' ) === '/.well-known/ucp';
}

/**
 * Whether this store should advertise a UCP manifest at all.
 *
 * Gated first on the administrator's explicit experimental-feature opt-in, then
 * on the same authoritative onboarding signal the frontend script injection
 * uses. BAOauthSuccess is written only once Brand Agent onboarding completes, so
 * a store that merely has the plugin installed — or that chose "Clarity only" —
 * never advertises an agent endpoint it does not have. A WooCommerce-issued
 * Brand Agents connection is required because UCP describes commerce capabilities.
 *
 * @return bool
 */
function brandagent_ucp_is_enabled() {
	if ( 1 !== (int) get_option( BRANDAGENT_UCP_ENABLED_OPTION, 0 ) ) {
		return false;
	}

	if ( ! brandagent_is_woocommerce_store() ) {
		return false;
	}

	return 1 === (int) get_option( 'BAOauthSuccess' );
}

/**
 * Build the upstream manifest URL for this store.
 *
 * @return string Empty string when the backend URL cannot be resolved.
 */
function brandagent_ucp_build_upstream_url() {
	$backend_base_url   = (string) get_option( BRANDAGENT_UCP_BACKEND_BASE_URL_OPTION, '' );
	$development_flight = 1 === (int) get_option( BRANDAGENT_UCP_DEVELOPMENT_FLIGHT_OPTION, 0 );
	if ( empty( $backend_base_url ) ) {
		$backend_base_url = BrandAgent_Config::get_backend_base_url();
	}
	if ( empty( $backend_base_url ) ) {
		return '';
	}

	$normalized_store_url = brandagent_normalize_store_url( home_url() );
	if ( empty( $normalized_store_url ) ) {
		return '';
	}

	// Append the manifest path before an optional query string so development
	// endpoints can carry routing or version parameters without producing an
	// invalid URL such as https://host?api-version=1/store/.well-known/ucp.
	$query_position = strpos( $backend_base_url, '?' );
	$query_string   = '';
	if ( false !== $query_position ) {
		$query_string     = substr( $backend_base_url, $query_position + 1 );
		$backend_base_url = substr( $backend_base_url, 0, $query_position );
	}

	$url = trailingslashit( $backend_base_url ) . rawurlencode( $normalized_store_url ) . '/.well-known/ucp';
	if ( '' !== $query_string ) {
		$url .= '?' . $query_string;
	}

	// The explicit administrator opt-in may force this feature in any selected
	// environment without changing the server's global rollout.
	if ( $development_flight ) {
		$url = add_query_arg( 'setflight', BRANDAGENT_UCP_DEVELOPMENT_FLIGHT, $url );
	}

	return $url;
}

/** Send a definitive empty 404 response for an unavailable UCP manifest. */
function brandagent_ucp_serve_not_found() {
	status_header( 404 );
	nocache_headers();
	exit;
}

/**
 * Serve /.well-known/ucp by proxying the backend manifest.
 *
 * Hooked on `parse_request` so the response is emitted before WP loads template
 * machinery. When the store is not eligible, or the backend cannot be reached,
 * this sends a definitive 404 before WordPress can route an unknown path to the
 * site's front page. An absent manifest is the correct signal that the store
 * has no agent, and is preferable to publishing an empty or stale one.
 */
function brandagent_ucp_maybe_serve() {
	if ( ! brandagent_ucp_is_request() ) {
		return;
	}

	if ( ! brandagent_ucp_is_enabled() ) {
		brandagent_ucp_serve_not_found();
	}

	$upstream_url = brandagent_ucp_build_upstream_url();
	if ( empty( $upstream_url ) ) {
		brandagent_log( 'BrandAgent UCP: no backend URL available; not serving the manifest' );
		brandagent_ucp_serve_not_found();
	}

	// The destination can be supplied by an administrator for testing, so use
	// WordPress's SSRF-safe request wrapper to reject unsafe hosts and redirects.
	$response = wp_safe_remote_get(
		$upstream_url,
		array(
			'timeout' => BRANDAGENT_UCP_TIMEOUT,
			'headers' => array( 'Accept' => 'application/json' ),
		)
	);

	if ( is_wp_error( $response ) ) {
		brandagent_log(
			'BrandAgent UCP: upstream request failed',
			array( 'error' => $response->get_error_message() )
		);
		brandagent_ucp_serve_not_found();
	}

	$status_code = wp_remote_retrieve_response_code( $response );
	$body        = wp_remote_retrieve_body( $response );

	// Anything other than a 200 means the backend has no manifest for this store
	// (not flighted, not onboarded, unknown advertiser). Return a definitive 404
	// rather than forwarding an error body under a UCP content type.
	if ( 200 !== intval( $status_code ) ) {
		brandagent_log(
			'BrandAgent UCP: upstream did not return a manifest',
			array( 'status' => $status_code )
		);
		brandagent_ucp_serve_not_found();
	}

	$content_type = wp_remote_retrieve_header( $response, 'content-type' );
	if ( empty( $content_type ) ) {
		$content_type = 'application/json; charset=utf-8';
	}

	// nocache_headers() is WordPress's default for non-cacheable routes and is
	// already applied to this request; the UCP spec requires a publicly cacheable
	// manifest, so those headers are removed deliberately rather than merged.
	nocache_headers();
	header_remove( 'Cache-Control' );
	header_remove( 'Pragma' );
	header_remove( 'Expires' );

	status_header( 200 );
	header( 'Content-Type: ' . $content_type );
	header( 'Cache-Control: public, max-age=' . BRANDAGENT_UCP_CACHE_MAX_AGE );

	echo $body; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- verbatim JSON manifest from the Brand Agent backend.
	exit;
}
add_action( 'parse_request', 'brandagent_ucp_maybe_serve' );
