<?php
/**
 * Real-time anomaly detection for admin activity.
 * - Login from a previously unseen IP (immediate alert)
 * - Login at an unusual hour (out of learned range)
 * - Multiple distinct IPs for one user in a short window
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Anomaly {

    const OPT_SETTINGS = 'rls_anomaly_settings';
    const TRANSIENT_KEY = 'rls_anomaly_log';

    public function init() {
        $settings = get_option( self::OPT_SETTINGS, [] );
        if ( ! is_array( $settings ) ) $settings = [];
        if ( empty( $settings['enabled'] ) ) return;

        add_action( 'wp_login', [ $this, 'on_login' ], 30, 2 );
        add_filter( 'login_message', [ $this, 'render_warning_message' ] );
        add_action( 'wp_ajax_rls_anomaly_dismiss', [ $this, 'ajax_dismiss' ] );
    }

    private static function get_settings() {
        $defaults = [
            'enabled'             => 0,
            'notify_unusual_hour' => 1,
            'hour_start'          => 6,   // 06:00
            'hour_end'            => 23,  // 23:00
            'learn_days'          => 14,  // days of history to build the hour profile
            'multi_ip_window'     => 24 * 3600,
            'multi_ip_threshold'  => 3,
        ];
        $stored = get_option( self::OPT_SETTINGS, [] );
        if ( ! is_array( $stored ) ) $stored = [];
        return array_merge( $defaults, $stored );
    }

    public function on_login( $user_login, $user ) {
        if ( ! ( $user instanceof WP_User ) ) return;
        if ( ! RLS_2FA::user_is_admin( $user ) ) return;

        $settings = self::get_settings();
        $current_ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $anomalies = [];

        // 1. New IP detection (using stored known IPs).
        $known = (array) get_user_meta( $user->ID, 'rls_known_login_ips', true );
        if ( ! in_array( $current_ip, $known, true ) && ! empty( $known ) ) {
            $anomalies[] = [
                'type'  => 'new_ip',
                'value' => $current_ip,
            ];
        }

        // 2. Unusual hour detection (out of learned range).
        if ( ! empty( $settings['notify_unusual_hour'] ) ) {
            $hour = (int) wp_date( 'G' );
            $start = (int) $settings['hour_start'];
            $end   = (int) $settings['hour_end'];
            // Treat wrap-around ranges.
            $in_range = $start <= $end
                ? ( $hour >= $start && $hour < $end )
                : ( $hour >= $start || $hour < $end );

            $profile = $this->get_hour_profile( $user->ID );
            $learned_unusual = false;
            if ( is_array( $profile ) && ! empty( $profile ) ) {
                // Build a 24-bit binary mask of hours seen.
                $mask = 0;
                foreach ( $profile as $h ) {
                    $h = max( 0, min( 23, (int) $h ) );
                    $mask |= ( 1 << $h );
                }
                if ( ( $mask & ( 1 << $hour ) ) === 0 ) {
                    $learned_unusual = true;
                }
            }
            if ( ! $in_range || $learned_unusual ) {
                $anomalies[] = [
                    'type'  => 'unusual_hour',
                    'value' => sprintf( '%02d:00', $hour ),
                ];
            }
        }

        // 3. Multi-IP detection.
        $window = max( 3600, (int) $settings['multi_ip_window'] );
        $threshold = max( 2, (int) $settings['multi_ip_threshold'] );
        $recent = (array) get_transient( 'rls_recent_ips_' . $user->ID );
        $recent[ $current_ip ] = time();
        // Trim old entries.
        foreach ( $recent as $ip => $ts ) {
            if ( ( time() - $ts ) > $window ) {
                unset( $recent[ $ip ] );
            }
        }
        set_transient( 'rls_recent_ips_' . $user->ID, $recent, $window );
        if ( count( $recent ) >= $threshold ) {
            $anomalies[] = [
                'type'  => 'multi_ip',
                'value' => sprintf( '%d IP за %d мин.', count( $recent ), $window / 60 ),
            ];
        }

        if ( ! empty( $anomalies ) ) {
            $this->record_anomalies( $user->ID, $user->user_login, $anomalies );

            // Notify admin via email.
            $this->notify( $user, $anomalies );

            // Notify via the standard notification module.
            do_action( 'rls_anomaly_detected', $user, $anomalies );
        }
    }

    /**
     * Persists anomalies in a transient (visible to admin on next page load)
     * and increments statistics.
     */
    private function record_anomalies( $user_id, $user_login, $anomalies ) {
        $list = (array) get_transient( self::TRANSIENT_KEY );
        $list[] = [
            'user_id'      => $user_id,
            'user_login'   => $user_login,
            'time'         => current_time( 'mysql' ),
            'ip'           => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            'anomalies'    => $anomalies,
        ];
        // Keep last 50.
        if ( count( $list ) > 50 ) {
            $list = array_slice( $list, -50 );
        }
        set_transient( self::TRANSIENT_KEY, $list, DAY_IN_SECONDS );

        $stats = get_option( 'rls_stats', [] );
        $stats['anomalies'] = ( $stats['anomalies'] ?? 0 ) + count( $anomalies );
        update_option( 'rls_stats', $stats );
    }

    /**
     * Returns the user's typical login hours based on the last `learn_days` of activity.
     */
    private function get_hour_profile( $user_id ) {
        $cache_key = 'rls_hour_profile_' . $user_id;
        $cached = get_transient( $cache_key );
        if ( is_array( $cached ) ) {
            return $cached;
        }
        // Use known_ips update timestamps as a poor-man's activity log.
        $known_log = (array) get_user_meta( $user_id, 'rls_known_login_log', true );
        $settings = self::get_settings();
        $since = time() - ( max( 1, (int) $settings['learn_days'] ) * 86400 );
        $hours = [];
        foreach ( $known_log as $entry ) {
            $ts = is_array( $entry ) && isset( $entry['ts'] ) ? (int) $entry['ts'] : 0;
            if ( $ts > $since ) {
                $hours[] = (int) gmdate( 'G', $ts );
            }
        }
        $hours = array_values( array_unique( $hours ) );
        set_transient( $cache_key, $hours, HOUR_IN_SECONDS );
        return $hours;
    }

    public function render_warning_message( $msg ) {
        $dismissed = (int) ( $_COOKIE['rls_anomaly_dismissed'] ?? 0 );
        $list = (array) get_transient( self::TRANSIENT_KEY );
        if ( empty( $list ) || $dismissed >= count( $list ) ) {
            return $msg;
        }
        $latest = end( $list );
        $reasons = [];
        foreach ( (array) ( $latest['anomalies'] ?? [] ) as $a ) {
            $reasons[] = $a['type'] . ' (' . $a['value'] . ')';
        }
        $alert = '<div class="rls-notice is-warning" data-rls-anomaly-notice="1" style="margin-bottom:14px;">';
        $alert .= '<strong>Зафиксирована аномалия</strong>: ' . esc_html( implode( ', ', $reasons ) );
        $alert .= '<button type="button" class="button-link" style="float:right;" id="rls-anomaly-dismiss">Скрыть</button>';
        $alert .= '</div>';
        return $msg . $alert;
    }

    public function ajax_dismiss() {
        check_ajax_referer( 'rls_anomaly_nonce', 'nonce' );
        $count = count( (array) get_transient( self::TRANSIENT_KEY ) );
        setcookie( 'rls_anomaly_dismissed', (string) $count, time() + DAY_IN_SECONDS, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );
        wp_send_json_success();
    }

    private function notify( $user, $anomalies ) {
        $settings = get_option( 'rls_notification_settings', [] );
        if ( empty( $settings['notify_anomalies'] ) ) return;
        $to = is_email( $settings['email'] ?? '' ) ? $settings['email'] : get_option( 'admin_email' );
        if ( ! $to ) return;
        $list = '';
        foreach ( $anomalies as $a ) {
            $list .= " - {$a['type']}: {$a['value']}\n";
        }
        $subject = sprintf( '[%s] Аномальный вход администратора', wp_parse_url( home_url(), PHP_URL_HOST ) );
        $body = sprintf(
            "Пользователь %s (%d) вошёл с признаками аномалии.\nIP: %s\nАномалии:\n%s\nВремя: %s\n\nЕсли это не вы — смените пароль и пересмотрите сессии.",
            $user->user_login,
            $user->ID,
            $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            $list,
            gmdate( 'c' )
        );
        wp_mail( $to, $subject, $body, [ 'Content-Type: text/plain; charset=UTF-8' ] );
    }
}
