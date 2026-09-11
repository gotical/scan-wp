<?php
/**
 * GDPR compliance module.
 * - IP anonymization in stored logs
 * - Data retention policy
 * - User data export & erasure (WP privacy tools integration)
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_GDPR {

    const OPT_SETTINGS = 'rls_gdpr_settings';

    public function init() {
        $settings = get_option( self::OPT_SETTINGS, [] );
        if ( ! is_array( $settings ) ) $settings = [];

        // Always register privacy hooks (even when disabled) so erasure requests don't fail silently.
        add_filter( 'wp_privacy_personal_data_exporters', [ $this, 'register_exporter' ] );
        add_filter( 'wp_privacy_personal_data_erasers', [ $this, 'register_eraser' ] );
        add_action( 'rls_cron_daily', [ $this, 'apply_retention_policy' ] );
        add_filter( 'rls_log_ip', [ $this, 'anonymize_ip' ] );

        if ( ! empty( $settings['enabled'] ) ) {
            add_action( 'rls_before_log_attack', [ $this, 'maybe_anonymize_in_log' ], 10, 1 );
            add_action( 'rls_cron_hourly', [ $this, 'apply_retention_policy' ] );
        }
    }

    private static function get_settings() {
        $defaults = [
            'enabled'             => 0,
            'anonymize_ip'        => 1,    // anonymize last octet before storage
            'retention_days'      => 90,   // auto-delete logs older than N days (0 = keep forever)
            'erase_on_user_delete'=> 1,    // run eraser on user deletion
        ];
        $stored = get_option( self::OPT_SETTINGS, [] );
        if ( ! is_array( $stored ) ) $stored = [];
        return array_merge( $defaults, $stored );
    }

    /**
     * Anonymize an IP for GDPR compliance.
     * IPv4: 1.2.3.4 -> 1.2.3.0 (last octet zeroed).
     * IPv6: last 80 bits zeroed (keeps /48 prefix for geographic info).
     */
    public function anonymize_ip( $ip ) {
        $settings = self::get_settings();
        if ( empty( $settings['anonymize_ip'] ) ) return $ip;
        $ip = (string) $ip;
        if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            $parts = explode( '.', $ip );
            $parts[3] = '0';
            return implode( '.', $parts );
        }
        if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
            $packed = inet_pton( $ip );
            if ( $packed === false ) return $ip;
            // Zero last 10 bytes (80 bits), keep first 6 bytes (48 bits).
            $packed = substr( $packed, 0, 6 ) . str_repeat( "\0", 10 );
            $anon = inet_ntop( $packed );
            return $anon === false ? $ip : $anon;
        }
        return $ip;
    }

    public function maybe_anonymize_in_log( $ip ) {
        return $this->anonymize_ip( $ip );
    }

    /**
     * WP privacy tools integration: exporter callback.
     * Returns array of {email, data} groups for the personal-data export.
     */
    public function register_exporter( $exporters ) {
        $exporters['rybinsklab-security'] = [
            'exporter_friendly_name' => __( 'Rybinsk Lab Security', 'rybinsklab-security' ),
            'callback'               => [ $this, 'export_personal_data' ],
        ];
        return $exporters;
    }

    public function register_eraser( $erasers ) {
        $erasers['rybinsklab-security'] = [
            'eraser_friendly_name' => __( 'Rybinsk Lab Security', 'rybinsklab-security' ),
            'callback'             => [ $this, 'erase_personal_data' ],
        ];
        return $erasers;
    }

    public function export_personal_data( $email_address, $page = 1 ) {
        global $wpdb;

        $export_items = [];

        // 1. Data tied to email (admin email or notification recipient).
        $log_table = $wpdb->prefix . 'rls_attack_log';
        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT * FROM $log_table WHERE ip = %s OR request_uri LIKE %s LIMIT 500",
            $email_address,
            '%' . $wpdb->esc_like( $email_address ) . '%'
        ), ARRAY_A );

        if ( ! empty( $rows ) ) {
            $data = [];
            foreach ( $rows as $row ) {
                $data[] = [
                    'name'  => 'Attack log entry',
                    'value' => sprintf(
                        'Date: %s | IP: %s | Type: %s | Reason: %s | URI: %s',
                        $row['event_date'],
                        $row['ip'],
                        $row['type'],
                        $row['reason'],
                        $row['request_uri']
                    ),
                ];
            }
            $export_items[] = [
                'group_id'    => 'rls_logs',
                'group_label' => __( 'Attack Log Entries', 'rybinsklab-security' ),
                'item_id'     => 'logs-' . md5( $email_address ),
                'data'        => $data,
            ];
        }

        // 2. Data tied to user_id (brute-force locks, known IPs).
        $user = get_user_by( 'email', $email_address );
        if ( $user ) {
            $known_ips = (array) get_user_meta( $user->ID, 'rls_known_login_ips', true );
            $last_ip = (string) get_user_meta( $user->ID, 'rls_2fa_last_login_ip', true );
            if ( ! empty( $known_ips ) || $last_ip !== '' ) {
                $data = [];
                if ( $last_ip !== '' ) {
                    $data[] = [
                        'name'  => 'Last 2FA login IP',
                        'value' => $last_ip,
                    ];
                }
                if ( ! empty( $known_ips ) ) {
                    $data[] = [
                        'name'  => 'Known login IPs',
                        'value' => implode( ', ', $known_ips ),
                    ];
                }
                $export_items[] = [
                    'group_id'    => 'rls_user_data',
                    'group_label' => __( 'Login History', 'rybinsklab-security' ),
                    'item_id'     => 'user-data-' . $user->ID,
                    'data'        => $data,
                ];
            }
        }

        return [
            'data' => $export_items,
            'done' => true,
        ];
    }

    public function erase_personal_data( $email_address, $page = 1 ) {
        global $wpdb;
        $count = 0;
        $log_table = $wpdb->prefix . 'rls_attack_log';

        // 1. Remove log entries tied to email.
        $removed = (int) $wpdb->query( $wpdb->prepare(
            "DELETE FROM $log_table WHERE ip = %s OR request_uri LIKE %s",
            $email_address,
            '%' . $wpdb->esc_like( $email_address ) . '%'
        ) );
        $count += $removed;

        // 2. Remove user-meta tied to user_id.
        $user = get_user_by( 'email', $email_address );
        if ( $user ) {
            delete_user_meta( $user->ID, 'rls_known_login_ips' );
            delete_user_meta( $user->ID, 'rls_2fa_last_login_ip' );
            delete_user_meta( $user->ID, 'rls_2fa_secret' );
            delete_user_meta( $user->ID, 'rls_2fa_enabled' );
            delete_user_meta( $user->ID, 'rls_2fa_backup_codes' );
            $count += 6;
        }

        return [
            'items_removed'  => $count,
            'items_retained' => false,
            'messages'       => [],
            'done'           => true,
        ];
    }

    /**
     * Daily retention policy: delete logs older than the configured retention window.
     */
    public function apply_retention_policy() {
        $settings = self::get_settings();
        $days = (int) ( $settings['retention_days'] ?? 0 );
        if ( $days <= 0 ) return;

        global $wpdb;
        $log_table = $wpdb->prefix . 'rls_attack_log';
        $wpdb->query( $wpdb->prepare(
            "DELETE FROM $log_table WHERE event_date < DATE_SUB(%s, INTERVAL %d DAY)",
            current_time( 'mysql' ),
            $days
        ) );
    }
}
