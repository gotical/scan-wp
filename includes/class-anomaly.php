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

    /**
     * Returns day-of-week activity profile for a user (24x7 matrix).
     */
    public function get_user_activity_matrix( $user_id, $days = 30 ) {
        $matrix = [];
        for ( $dow = 0; $dow < 7; $dow++ ) {
            for ( $hour = 0; $hour < 24; $hour++ ) {
                $matrix[ $dow . '-' . $hour ] = 0;
            }
        }
        $known_log = (array) get_user_meta( $user_id, 'rls_known_login_log', true );
        $since = time() - ( $days * 86400 );
        foreach ( $known_log as $entry ) {
            $ts = is_array( $entry ) && isset( $entry['ts'] ) ? (int) $entry['ts'] : 0;
            if ( $ts < $since || $ts <= 0 ) continue;
            $dow = (int) gmdate( 'w', $ts );
            $hour = (int) gmdate( 'G', $ts );
            $key = $dow . '-' . $hour;
            $matrix[ $key ] = ( $matrix[ $key ] ?? 0 ) + 1;
        }
        return $matrix;
    }

    /**
     * Aggregate anomaly score for a user (0-100).
     * Combines: new IP, unusual hour, multi-IP, day-of-week deviation, UA change.
     */
    public function get_user_anomaly_score( $user_id, $days = 30 ) {
        if ( ! class_exists( 'RLS_Login_Attempts' ) ) return 0;
        global $wpdb;
        $table = RLS_Login_Attempts::table();
        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT user_id, ip, country_code, user_agent, success, event_date, reason
             FROM {$table}
             WHERE user_id = %d AND event_date >= DATE_SUB(%s, INTERVAL %d DAY)
             ORDER BY id DESC LIMIT 200",
            $user_id, current_time( 'mysql' ), $days
        ), ARRAY_A );
        if ( empty( $rows ) ) return 0;

        $ips = [];
        $countries = [];
        $user_agents = [];
        $hours = [];
        $dows = [];
        $failures = 0;
        $total = count( $rows );

        foreach ( $rows as $r ) {
            $ips[ $r['ip'] ] = true;
            if ( $r['country_code'] ) $countries[ $r['country_code'] ] = true;
            if ( $r['user_agent'] ) $user_agents[ md5( $r['user_agent'] ) ] = true;
            $hours[] = (int) gmdate( 'G', strtotime( $r['event_date'] ) );
            $dows[]  = (int) gmdate( 'w', strtotime( $r['event_date'] ) );
            if ( ! $r['success'] ) $failures++;
        }

        $score = 0;

        // Diversity signals (each unique adds to score).
        $score += min( 20, count( $ips ) * 3 );           // Multi-IP
        $score += min( 15, count( $countries ) * 5 );     // Multi-country
        $score += min( 10, count( $user_agents ) * 3 );   // Multi-UA

        // Failure ratio.
        if ( $total > 0 ) {
            $fail_rate = $failures / $total;
            $score += min( 25, (int) ( $fail_rate * 50 ) );
        }

        // Hour distribution entropy (high entropy = unusual pattern).
        $hour_counts = array_count_values( $hours );
        if ( count( $hour_counts ) > 1 ) {
            $entropy = self::shannon_entropy( array_values( $hour_counts ) );
            $max_entropy = log( 24, 2 );
            $entropy_norm = $entropy / $max_entropy;
            $score += min( 15, (int) ( $entropy_norm * 15 ) );
        }

        // Day-of-week spread (legit users typically log in 5-6 days a week).
        $unique_dows = count( array_unique( $dows ) );
        if ( $unique_dows > 7 ) $unique_dows = 7;
        if ( $unique_dows >= 7 ) $score += 5; // Logging in every day
        if ( $unique_dows === 1 && $total > 5 ) $score += 10; // Only 1 day a week — suspicious if high count

        return min( 100, $score );
    }

    private static function shannon_entropy( array $values ) {
        $total = array_sum( $values );
        if ( $total <= 0 ) return 0.0;
        $entropy = 0.0;
        foreach ( $values as $v ) {
            if ( $v <= 0 ) continue;
            $p = $v / $total;
            $entropy -= $p * log( $p, 2 );
        }
        return $entropy;
    }

    /**
     * Returns top N users with highest anomaly scores.
     */
    public static function get_top_anomalous_users( $limit = 20, $days = 30 ) {
        if ( ! class_exists( 'RLS_Login_Attempts' ) ) return [];
        global $wpdb;
        $table = RLS_Login_Attempts::table();
        $users = $wpdb->get_results( $wpdb->prepare(
            "SELECT user_id, COUNT(*) AS attempts,
                    SUM(success = 0) AS failures,
                    COUNT(DISTINCT ip) AS unique_ips,
                    MAX(event_date) AS last_seen
             FROM {$table}
             WHERE user_id IS NOT NULL AND event_date >= DATE_SUB(%s, INTERVAL %d DAY)
             GROUP BY user_id
             ORDER BY attempts DESC
             LIMIT %d",
            current_time( 'mysql' ), $days, $limit
        ), ARRAY_A );

        $anomaly = new self();
        foreach ( $users as &$u ) {
            $u['score'] = $anomaly->get_user_anomaly_score( (int) $u['user_id'], $days );
            $user_obj = get_userdata( (int) $u['user_id'] );
            $u['display_name'] = $user_obj ? $user_obj->display_name : '(deleted)';
            $u['user_email']    = $user_obj ? $user_obj->user_email : '';
            $u['matrix']        = $anomaly->get_user_activity_matrix( (int) $u['user_id'], $days );
        }
        unset( $u );
        usort( $users, function( $a, $b ) {
            return $b['score'] - $a['score'];
        } );
        return $users;
    }

    /**
     * Returns recent anomaly events from the transient log.
     */
    public static function get_recent_anomalies( $limit = 50 ) {
        $list = (array) get_transient( self::TRANSIENT_KEY );
        return array_slice( $list, -$limit );
    }

    /**
     * Aggregates all users' activity into a global 7x24 heatmap.
     */
    public static function get_global_activity_heatmap( $days = 30 ) {
        $matrix = [];
        for ( $dow = 0; $dow < 7; $dow++ ) {
            for ( $hour = 0; $hour < 24; $hour++ ) {
                $matrix[ $dow . '-' . $hour ] = 0;
            }
        }
        if ( ! class_exists( 'RLS_Login_Attempts' ) ) return $matrix;
        global $wpdb;
        $table = RLS_Login_Attempts::table();
        $since = current_time( 'mysql' );
        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT event_date FROM {$table}
             WHERE event_date >= DATE_SUB(%s, INTERVAL %d DAY)",
            $since, $days
        ), ARRAY_A );
        foreach ( $rows as $r ) {
            $dow = (int) gmdate( 'w', strtotime( $r['event_date'] ) );
            $hour = (int) gmdate( 'G', strtotime( $r['event_date'] ) );
            $matrix[ $dow . '-' . $hour ]++;
        }
        return $matrix;
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
