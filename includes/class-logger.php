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

    private static function normalize_log_type( $type ) {
        $type = sanitize_key( strtolower( (string) $type ) );
        return $type !== '' ? $type : 'unknown';
    }

    private static function get_table_name() {
        global $wpdb;
        return $wpdb->prefix . 'rls_attack_log';
    }

    public static function log_attack( $ip, $type, $reason ) {
        global $wpdb;
        $table_name = self::get_table_name();
        $type = self::normalize_log_type( $type );
        
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
            RLS_Stats_Helper::increment_stat( 'details_' . $type );
        }

        self::send_pulse_to_api( $ip, $type, $reason );
    }

    private static function send_pulse_to_api( $ip, $type, $reason ) {
        $pulse_key = 'rls_last_pulse_sent_' . md5( strtolower( (string) $ip ) . '|' . strtolower( (string) $type ) . '|' . substr( (string) $reason, 0, 120 ) );
        $last_pulse = get_transient( $pulse_key );
        if ( $last_pulse ) return;
        set_transient( $pulse_key, 1, 5 );

        $body = [
            'action'      => 'report_attack_pulse',
            'license_key' => self::get_license_key(),
            'site_url'    => home_url(),
            'ip'          => $ip,
            'type'        => $type,
            'reason'      => $reason
        ];

        $settings = get_option( 'rls_settings', [] );
        $ssl_verify = apply_filters( 'rls_logger_ssl_verify', ! empty( $settings['ssl_verify_api'] ) );

        wp_remote_post( RLS_API_URL, [
            'body'      => $body,
            'timeout'   => 5,
            'blocking'  => false,
            'sslverify' => $ssl_verify,
        ] );
    }

    private static function get_license_key() {
        $s = get_option( 'rls_settings', [] );
        return $s['license_key'] ?? '';
    }
    
    public static function get_logs( $limit = 50, $type = 'all' ) {
        global $wpdb;
        $table_name = self::get_table_name();
        if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_name'" ) != $table_name ) return [];

        $sql = "SELECT * FROM $table_name";
        $args = [];

        $type = self::normalize_log_type( $type );
        if ( $type !== 'all' ) {
            $sql .= ' WHERE LOWER(type) = %s';
            $args[] = $type;
        }

        $sql .= ' ORDER BY id DESC';

        if ( (int) $limit > 0 ) {
            $sql .= ' LIMIT %d';
            $args[] = (int) $limit;
        }

        if ( empty( $args ) ) {
            return $wpdb->get_results( $sql, ARRAY_A );
        }

        return $wpdb->get_results( $wpdb->prepare( $sql, $args ), ARRAY_A );
    }

    public static function get_logs_count( $type = 'all' ) {
        global $wpdb;
        $table_name = self::get_table_name();
        if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_name'" ) != $table_name ) return 0;

        $type = self::normalize_log_type( $type );
        if ( $type === 'all' ) {
            return (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_name" );
        }

        return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $table_name WHERE LOWER(type) = %s", $type ) );
    }

    public static function get_log_types() {
        global $wpdb;
        $table_name = self::get_table_name();
        if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_name'" ) != $table_name ) return [];

        $rows = $wpdb->get_col( "SELECT DISTINCT LOWER(type) FROM $table_name ORDER BY LOWER(type) ASC" );
        if ( ! is_array( $rows ) ) {
            return [];
        }

        return array_values( array_filter( array_map( [ __CLASS__, 'normalize_log_type' ], $rows ) ) );
    }

    public static function get_log_summary() {
        global $wpdb;
        $table_name = self::get_table_name();
        if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_name'" ) != $table_name ) {
            return [
                'total' => 0,
                'types' => [],
            ];
        }

        $rows = $wpdb->get_results( "SELECT LOWER(type) AS log_type, COUNT(*) AS total FROM $table_name GROUP BY LOWER(type)", ARRAY_A );
        $summary = [
            'total' => 0,
            'types' => [],
        ];

        if ( is_array( $rows ) ) {
            foreach ( $rows as $row ) {
                $type = self::normalize_log_type( $row['log_type'] ?? 'unknown' );
                $count = (int) ( $row['total'] ?? 0 );
                $summary['types'][ $type ] = $count;
                $summary['total'] += $count;
            }
        }

        return $summary;
    }

    public static function clear_logs() {
        global $wpdb;
        $table_name = self::get_table_name();
        if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_name'" ) != $table_name ) return 0;
        $deleted_count = self::get_logs_count();
        $wpdb->query( "TRUNCATE TABLE $table_name" );
        return $deleted_count;
    }
}
