<?php
/**
 * Класс RLS_Logger
 * Отвечает за логирование атак и мгновенную отправку статистики.
 * 
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Logger {

    public static function log_attack( $ip, $type, $reason ) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'rls_attack_log';
        
        if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_name'" ) === $table_name ) {
            $wpdb->insert(
                $table_name,
                [
                    'event_date'  => current_time( 'mysql' ),
                    'ip'          => substr( $ip, 0, 45 ),
                    'type'        => $type,
                    'reason'      => substr( $reason, 0, 255 ),
                    'request_uri' => substr( $_SERVER['REQUEST_URI'] ?? '', 0, 255 ),
                    'user_agent'  => substr( $_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255 )
                ],
                [ '%s', '%s', '%s', '%s', '%s', '%s' ]
            );

            if ( rand( 1, 20 ) === 1 ) {
                $wpdb->query( "DELETE FROM $table_name WHERE id NOT IN (SELECT id FROM (SELECT id FROM $table_name ORDER BY id DESC LIMIT 500) x)" );
            }
        }

        if ( class_exists( 'RLS_Stats_Helper' ) ) {
            RLS_Stats_Helper::increment_stat( 'firewall_blocked' );
            if ( $type === 'brute' ) RLS_Stats_Helper::increment_stat( 'login_attempts_blocked' );
            if ( $type === 'bot' ) RLS_Stats_Helper::increment_stat( 'bad_bots_blocked' );
        }

        self::send_pulse_to_api( $ip, $type, $reason );
    }

    private static function send_pulse_to_api( $ip, $type, $reason ) {
        $last_pulse = get_transient( 'rls_last_pulse_sent' );
        if ( $last_pulse ) return;
        set_transient( 'rls_last_pulse_sent', 1, 5 );

        $body = [
            'action'      => 'report_attack_pulse',
            'license_key' => self::get_license_key(),
            'site_url'    => home_url(),
            'ip'          => $ip,
            'type'        => $type,
            'reason'      => $reason
        ];

        wp_remote_post( RLS_API_URL, [
            'body'      => $body,
            'timeout'   => 5,
            'blocking'  => false,
            'sslverify' => false
        ]);
    }

    private static function get_license_key() {
        $s = get_option( 'rls_settings', [] );
        return $s['license_key'] ?? '';
    }
    
    public static function get_logs( $limit = 50 ) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'rls_attack_log';
        if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_name'" ) != $table_name ) return [];
        return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $table_name ORDER BY id DESC LIMIT %d", $limit ), ARRAY_A );
    }
}