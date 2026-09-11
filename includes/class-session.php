<?php
/**
 * Admin session hardening.
 * - Session ID rotation on login / privilege escalation
 * - IP + UA fingerprint binding (configurable strictness)
 * - Concurrent session limit
 * - Inactive timeout
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Session {

    const OPT_SETTINGS = 'rls_session_settings';
    const COOKIE       = 'rls_session_meta';
    const META_KEY     = 'session_tokens';

    public function init() {
        $settings = get_option( self::OPT_SETTINGS, [] );
        if ( ! is_array( $settings ) ) $settings = [];

        add_action( 'init', [ $this, 'enforce_session_fingerprint' ], 1 );
        add_action( 'wp_login', [ $this, 'rotate_session_on_login' ], 10, 2 );
        add_action( 'wp_login', [ $this, 'enforce_concurrent_limit' ], 20, 2 );

        if ( ! empty( $settings['inactive_timeout'] ) ) {
            add_action( 'init', [ $this, 'enforce_inactive_timeout' ], 2 );
        }
    }

    private static function get_settings() {
        $defaults = [
            'rotate_on_login'    => 1,
            'bind_ip'            => 1,    // bind session to first IP (X-Forwarded-For aware via firewall)
            'bind_ua'            => 1,
            'max_concurrent'     => 0,    // 0 = unlimited
            'inactive_timeout'   => 0,    // seconds, 0 = disabled
        ];
        $stored = get_option( self::OPT_SETTINGS, [] );
        if ( ! is_array( $stored ) ) $stored = [];
        return array_merge( $defaults, $stored );
    }

    /**
     * Enforce IP/UA binding on every request. If mismatch, destroy session.
     */
    public function enforce_session_fingerprint() {
        if ( ! is_user_logged_in() ) return;
        $settings = self::get_settings();
        $user_id = get_current_user_id();
        $expected = $this->get_stored_fingerprint( $user_id );
        if ( ! is_array( $expected ) ) return;

        $current = $this->compute_fingerprint( $settings );
        $expected_ip = (string) ( $expected['ip'] ?? '' );
        $expected_ua = (string) ( $expected['ua'] ?? '' );

        $mismatch = false;
        if ( ! empty( $settings['bind_ip'] ) && $expected_ip !== '' && $expected_ip !== $current['ip'] ) {
            $mismatch = true;
        }
        if ( ! empty( $settings['bind_ua'] ) && $expected_ua !== '' && ! hash_equals( $expected_ua, $current['ua'] ) ) {
            $mismatch = true;
        }
        if ( $mismatch ) {
            $this->force_logout_with_notice( 'Сессия привязана к другому браузеру или IP.' );
        }
    }

    public function rotate_session_on_login( $user_login, $user ) {
        if ( ! ( $user instanceof WP_User ) ) return;
        $settings = self::get_settings();
        if ( empty( $settings['rotate_on_login'] ) ) return;

        // Rotate session token (regenerate ID and clear old session).
        if ( ! session_id() && ! headers_sent() ) {
            @session_start();
        }
        if ( session_id() ) {
            session_regenerate_id( true );
        }
        // Also rotate WP session token used for cookies.
        if ( function_exists( 'wp_session_token' ) ) {
            WP_Session_Tokens::get_instance( $user->ID );
        }

        // Store new fingerprint.
        $this->set_stored_fingerprint( $user->ID, $this->compute_fingerprint( $settings ) );
    }

    /**
     * Limit concurrent admin sessions.
     */
    public function enforce_concurrent_limit( $user_login, $user ) {
        if ( ! ( $user instanceof WP_User ) ) return;
        if ( ! RLS_2FA::user_is_admin( $user ) ) return;
        $settings = self::get_settings();
        $limit = (int) $settings['max_concurrent'];
        if ( $limit <= 0 ) return;

        $sessions = WP_Session_Tokens::get_instance( $user->ID );
        $all = $sessions->get_all();
        if ( count( $all ) <= $limit ) return;

        // Sort by login time ascending; destroy oldest beyond limit.
        uasort( $all, function( $a, $b ) {
            $ta = isset( $a['login'] ) ? (int) $a['login'] : 0;
            $tb = isset( $b['login'] ) ? (int) $b['login'] : 0;
            return $ta - $tb;
        } );
        $i = 0;
        foreach ( $all as $token => $data ) {
            $i++;
            if ( $i > $limit ) {
                $sessions->destroy( $token );
            }
        }
    }

    public function enforce_inactive_timeout() {
        if ( ! is_user_logged_in() ) return;
        $settings = self::get_settings();
        $timeout = max( 0, (int) $settings['inactive_timeout'] );
        if ( $timeout <= 0 ) return;

        $user_id = get_current_user_id();
        $last_activity = (int) get_user_meta( $user_id, 'rls_last_activity', true );
        if ( $last_activity > 0 && ( time() - $last_activity ) > $timeout ) {
            $this->force_logout_with_notice( 'Сессия истекла из-за неактивности.' );
            return;
        }
        update_user_meta( $user_id, 'rls_last_activity', time() );
    }

    private function compute_fingerprint( $settings ) {
        // Use the firewall's IP helper if available for proxy awareness.
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        if ( class_exists( 'RLS_Firewall' ) ) {
            $fw = new RLS_Firewall();
            if ( method_exists( $fw, 'get_universal_ip' ) ) {
                $ip = $fw->get_universal_ip();
            }
        }
        return [
            'ip' => $ip,
            'ua' => md5( (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ),
        ];
    }

    private function get_stored_fingerprint( $user_id ) {
        return get_user_meta( $user_id, 'rls_session_fingerprint', true );
    }

    private function set_stored_fingerprint( $user_id, $fp ) {
        update_user_meta( $user_id, 'rls_session_fingerprint', $fp );
    }

    private function force_logout_with_notice( $reason ) {
        wp_destroy_current_session();
        wp_clear_auth_cookie();
        wp_set_current_user( 0 );
        $redirect = add_query_arg( 'rls_session_invalid', rawurlencode( $reason ), wp_login_url() );
        wp_safe_redirect( $redirect );
        exit;
    }
}
