<?php
/**
 * Email notifications for critical security events.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Notifications {

    const OPT_SETTINGS = 'rls_notification_settings';

    public function init() {
        add_action( 'wp_login', [ $this, 'on_wp_login' ], 30, 2 );
        add_action( 'rls_bruteforce_lockout', [ $this, 'on_bruteforce_lockout' ], 10, 2 );
        add_action( 'rls_malware_detected', [ $this, 'on_malware_detected' ], 10, 2 );
        add_action( 'rls_integrity_violation', [ $this, 'on_integrity_violation' ], 10, 1 );
    }

    private static function get_settings() {
        $defaults = [
            'email'                    => get_option( 'admin_email' ),
            'notify_admin_login_new_ip'=> 1,
            'notify_bruteforce'        => 1,
            'notify_malware'           => 1,
            'notify_integrity'         => 1,
            'rate_limit_per_hour'      => 20,
        ];
        $stored = get_option( self::OPT_SETTINGS, [] );
        if ( ! is_array( $stored ) ) $stored = [];
        return array_merge( $defaults, $stored );
    }

    private static function is_rate_limited( $event_key ) {
        $settings = self::get_settings();
        $limit = max( 0, (int) $settings['rate_limit_per_hour'] );
        if ( $limit <= 0 ) return false;
        $key = 'rls_notify_rl_' . md5( $event_key );
        $count = (int) get_transient( $key );
        if ( $count >= $limit ) return true;
        set_transient( $key, $count + 1, HOUR_IN_SECONDS );
        return false;
    }

    private static function send( $subject, $body, $event_key ) {
        if ( self::is_rate_limited( $event_key ) ) return;
        $settings = self::get_settings();
        $to = $settings['email'];
        if ( ! is_email( $to ) ) return;
        $subject = sprintf( '[%s] %s', wp_parse_url( home_url(), PHP_URL_HOST ), $subject );
        $body .= "\n\n— Rybinsk Lab Security\n" . home_url() . "\n" . gmdate( 'c' ) . "\n";
        wp_mail( $to, $subject, $body, [ 'Content-Type: text/plain; charset=UTF-8' ] );
    }

    public function on_wp_login( $user_login, $user ) {
        $settings = self::get_settings();
        if ( empty( $settings['notify_admin_login_new_ip'] ) ) return;
        if ( ! ( $user instanceof WP_User ) ) return;
        // Only notify for privileged users.
        if ( ! RLS_2FA::user_is_admin( $user ) ) return;

        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $known_ips = (array) get_user_meta( $user->ID, 'rls_known_login_ips', true );
        if ( in_array( $ip, $known_ips, true ) ) return;
        // Add to known list (cap at 50).
        $known_ips[] = $ip;
        if ( count( $known_ips ) > 50 ) $known_ips = array_slice( $known_ips, -50 );
        update_user_meta( $user->ID, 'rls_known_login_ips', array_values( array_unique( $known_ips ) ) );

        self::send(
            'Новый вход администратора с незнакомого IP',
            sprintf(
                "Администратор %s (%d) вошёл с нового IP: %s\nUser-Agent: %s\nВремя: %s",
                $user_login,
                $user->ID,
                $ip,
                substr( (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' ), 0, 200 ),
                gmdate( 'c' )
            ),
            'login_new_ip_' . $user->ID
        );
    }

    public function on_bruteforce_lockout( $ip, $lock_seconds ) {
        $settings = self::get_settings();
        if ( empty( $settings['notify_bruteforce'] ) ) return;
        self::send(
            'Массовый brute force: IP заблокирован',
            sprintf(
                "IP %s заблокирован на %d секунд после превышения лимита попыток входа.\nВремя: %s",
                $ip,
                (int) $lock_seconds,
                gmdate( 'c' )
            ),
            'bruteforce_' . $ip
        );
    }

    public function on_malware_detected( $threats, $scan_type ) {
        $settings = self::get_settings();
        if ( empty( $settings['notify_malware'] ) ) return;
        if ( ! is_array( $threats ) || empty( $threats ) ) return;
        $list = '';
        foreach ( array_slice( $threats, 0, 20 ) as $t ) {
            $file = isset( $t['file'] ) ? (string) $t['file'] : '';
            $sig  = isset( $t['signature'] ) ? (string) $t['signature'] : '';
            $list .= " - {$file}  ({$sig})\n";
        }
        self::send(
            'Сканер обнаружил вредоносный код',
            sprintf(
                "Тип сканирования: %s\nУгроз найдено: %d\nСписок:\n%s\nВремя: %s",
                $scan_type,
                count( $threats ),
                $list,
                gmdate( 'c' )
            ),
            'malware_' . gmdate( 'YmdH' )
        );
    }

    public function on_integrity_violation( $changed_files ) {
        $settings = self::get_settings();
        if ( empty( $settings['notify_integrity'] ) ) return;
        $list = '';
        foreach ( (array) $changed_files as $f ) {
            $list .= " - {$f}\n";
        }
        self::send(
            'Нарушена целостность файлов плагина',
            sprintf(
                "Обнаружено изменение файлов плагина Rybinsk Lab Security.\nЭто может означать компрометацию сервера.\nСписок файлов:\n%s\nВремя: %s\n\nРекомендуется немедленно проверить сайт и переустановить плагин из надёжного источника.",
                $list,
                gmdate( 'c' )
            ),
            'integrity_' . gmdate( 'YmdH' )
        );
    }
}
