<?php
/**
 * Класс RLS_API_Client
 * Отвечает за коммуникацию с сервером Rybinsk Lab.
 * Версия 1.5.2
 */

if ( ! defined( 'ABSPATH' ) ) {
    die;
}

class RLS_API_Client {

    private static function send_request( $body_data, $blocking = true ) {
        $body_data['license_key'] = self::get_license_key();
        
        $settings = get_option( 'rls_settings', [] );
        $ssl_verify = ! empty( $settings['ssl_verify_api'] );

        $args = [
            'timeout'   => 15,
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

        $body = wp_remote_retrieve_body( $response );
        return json_decode( $body, true );
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

    public static function submit_banned_ip( $ip, $reason ) {
        self::send_request([
            'action'    => 'submit_banned_ip',
            'ip'        => $ip,
            'reason'    => $reason,
            'site_url'  => home_url()
        ], false);
    }

    public static function report_activation() {
        global $wp_version;
        $body = [
            'action'         => 'activate_plugin',
            'site_url'       => home_url(),
            'site_title'     => get_bloginfo( 'name' ),
            'admin_email'    => get_option( 'admin_email' ),
            'plugin_version' => RLS_VERSION,
            'wp_version'     => $wp_version,
            'php_version'    => phpversion(),
            'server_ip'      => $_SERVER['SERVER_ADDR'] ?? 'unknown',
            'language'       => get_locale()
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