<?php
/**
 * Класс RLS_API_Client
 * Отвечает за коммуникацию с сервером Rybinsk Lab.
 * Версия 2.3.0
 */

if ( ! defined( 'ABSPATH' ) ) {
    die;
}

class RLS_API_Client {

    private static function send_request( $body_data, $blocking = true, $timeout = 15 ) {
        $body_data['license_key'] = self::get_license_key();
        $body_data['plugin_version'] = RLS_VERSION;

        $settings = get_option( 'rls_settings', [] );
        // SECURITY: SSL verification ON by default; admins must explicitly opt-out.
        $ssl_verify = apply_filters( 'rls_api_ssl_verify', ! empty( $settings['ssl_verify_api'] ) );

        $args = [
            'timeout'   => $timeout,
            'body'      => $body_data,
            'blocking'  => $blocking,
            'sslverify' => $ssl_verify,
            'headers'   => [
                'User-Agent' => 'RybinskLabSecurity/' . RLS_VERSION . '; ' . home_url()
            ]
        ];

        $response = wp_remote_post( RLS_API_URL, $args );

        if ( is_wp_error( $response ) ) {
            return $response;
        }

        if ( ! $blocking ) {
            return [ 'status' => 'queued' ];
        }

        $body = wp_remote_retrieve_body( $response );
        $decoded = json_decode( $body, true );
        $status_code = (int) wp_remote_retrieve_response_code( $response );

        if ( $status_code < 200 || $status_code >= 300 ) {
            if ( is_array( $decoded ) && isset( $decoded['status'] ) && $decoded['status'] === 'error' ) {
                return $decoded;
            }

            return new WP_Error( 'rls_api_http_error', 'API HTTP error: ' . $status_code );
        }

        if ( ! is_array( $decoded ) ) {
            return new WP_Error( 'rls_api_invalid_response', 'Invalid API response format' );
        }

        return $decoded;
    }
    
    private static function get_license_key() {
        $settings = get_option( 'rls_settings', [] );
        return $settings['license_key'] ?? '';
    }

    public static function get_global_blacklist() {
        return self::send_request([
            'action' => 'get_global_blacklist'
        ]);
    }

    public static function sync_blacklist_inventory( array $inventory, $blocking = true ) {
        return self::send_request([
            'action'    => 'sync_blacklist_inventory',
            'inventory' => wp_json_encode( $inventory ),
            'site_url'  => home_url(),
        ], $blocking, 30 );
    }

    public static function submit_banned_ip( $ip, $reason, array $context = [] ) {
        $body = [
            'action'    => 'submit_banned_ip',
            'ip'        => $ip,
            'reason'    => $reason,
            'site_url'  => home_url()
        ];

        foreach ( [ 'status', 'source_kind', 'type' ] as $key ) {
            if ( isset( $context[ $key ] ) && $context[ $key ] !== '' ) {
                $body[ $key ] = $context[ $key ];
            }
        }

        self::send_request( $body, false );
    }

    public static function report_activation() {
        global $wp_version;
        $body = [
            'action'         => 'activate_plugin',
            'site_url'       => home_url(),
            'site_title'     => get_bloginfo( 'name' ),
            // SECURITY: do NOT transmit the admin email — it leaks PII and is not required
            // for license activation telemetry.
            'plugin_version' => RLS_VERSION,
            'wp_version'     => $wp_version,
            'php_version'    => phpversion(),
            // SECURITY: server internal IP intentionally omitted to prevent
            // leaking infrastructure details to a third-party service.
            'language'       => get_locale(),
        ];
        return self::send_request( $body, true );
    }

    public static function report_deactivation() {
        self::send_request( [
            'action'   => 'deactivate_plugin',
            'site_url' => home_url()
        ], false );
    }
    
    public static function send_heartbeat() {
        self::send_request( [
            'action'   => 'heartbeat',
            'site_url' => home_url()
        ], false );
    }

    public static function validate_license_key( $license_key ) {
        return self::send_request( [
            'action'      => 'validate_key',
            'license_key' => $license_key,
            'site_url'    => home_url()
        ] );
    }

    public static function get_signatures( $license_key ) {
        return self::send_request( [
            'action'      => 'get_signatures',
            'license_key' => $license_key
        ] );
    }

    public static function get_ai_snippet_limit_bytes( $force_refresh = false ) {
        $cache_key = 'rls_ai_snippet_limit_bytes';

        if ( ! $force_refresh ) {
            $cached = get_transient( $cache_key );
            if ( $cached !== false ) {
                return max( 0, (int) $cached );
            }
        }

        $limit_kb = 200;
        $response = self::send_request( [
            'action' => 'get_ai_config',
        ] );

        if ( ! is_wp_error( $response ) && is_array( $response ) ) {
            $received = $response['data']['snippet_limit_kb'] ?? null;
            if ( $received !== null && $received !== '' ) {
                $limit_kb = max( 0, (int) $received );
            }
        }

        $limit_bytes = $limit_kb > 0 ? $limit_kb * 1024 : 0;
        set_transient( $cache_key, $limit_bytes, MINUTE_IN_SECONDS );

        return $limit_bytes;
    }

    public static function submit_suggestion( $signature ) {
        self::send_request( [
            'action'    => 'submit_suggestion',
            'signature' => $signature,
            'site_url'  => home_url()
        ], false );
    }
    
    public static function report_stats( $stats_data ) {
        return self::send_request( [
            'action'     => 'report_stats',
            'stats_data' => json_encode( $stats_data ),
            'site_url'   => home_url()
        ] );
    }

    public static function report_attack_log_cleanup( $payload ) {
        if ( ! is_array( $payload ) ) {
            $payload = [
                'total' => max( 0, (int) $payload ),
                'types' => [],
            ];
        }

        $total = max( 0, (int) ( $payload['total'] ?? 0 ) );
        $types = isset( $payload['types'] ) && is_array( $payload['types'] ) ? $payload['types'] : [];

        $stats_payload = [
            'attack_log_cleanup' => $total,
        ];

        if ( ! empty( $types ) ) {
            $stats_payload['attack_log_summary'] = $types;
        }

        return self::report_stats( $stats_payload );
    }

    public static function analyze_code_snippet( $snippet ) {
        $response = self::send_request( [
            'action'   => 'analyze_code_snippet',
            'snippet'  => $snippet,
            'site_url' => home_url()
        ] );

        if ( ! is_wp_error( $response ) && is_array( $response ) && isset( $response['status'] ) && $response['status'] === 'success' ) {
            if ( class_exists( 'RLS_Stats_Helper' ) ) {
                RLS_Stats_Helper::increment_stat( 'ai_requests' );
                $tokens = 0;
                if ( isset( $response['data']['tokens_used'] ) ) {
                    $tokens = (int) $response['data']['tokens_used'];
                } elseif ( isset( $response['data']['usage']['total_tokens'] ) ) {
                    $tokens = (int) $response['data']['usage']['total_tokens'];
                }
                if ( $tokens > 0 ) {
                    RLS_Stats_Helper::increment_stat( 'ai_tokens', $tokens );
                }
            }
        }
        return $response;
    }
}


