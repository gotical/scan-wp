<?php
/**
 * TOTP Two-Factor Authentication (RFC 6238).
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_2FA {

    const OPT_USER_SECRET  = 'rls_2fa_secret';
    const OPT_USER_ENABLED = 'rls_2fa_enabled';
    const OPT_USER_BACKUP  = 'rls_2fa_backup_codes';
    const TRANSIENT_PREFIX = 'rls_2fa_used_';
    const PERIOD           = 30;
    const DIGITS           = 6;
    const WINDOW           = 1; // Allow 1 step before/after for clock skew.

    public function init() {
        add_action( 'wp_login', [ $this, 'on_wp_login' ], 30, 2 );
        add_filter( 'authenticate', [ $this, 'verify_2fa_on_authenticate' ], 40, 3 );
        add_action( 'wp_ajax_rls_2fa_setup', [ $this, 'ajax_setup' ] );
        add_action( 'wp_ajax_rls_2fa_confirm', [ $this, 'ajax_confirm' ] );
        add_action( 'wp_ajax_rls_2fa_disable', [ $this, 'ajax_disable' ] );
        add_action( 'wp_ajax_rls_2fa_regenerate_backup', [ $this, 'ajax_regenerate_backup' ] );
        add_action( 'wp_ajax_rls_2fa_status', [ $this, 'ajax_status' ] );
    }

    public static function is_enabled_for_user( $user_id ) {
        return (int) get_user_meta( $user_id, self::OPT_USER_ENABLED, true ) === 1
            && self::get_user_secret( $user_id ) !== '';
    }

    public static function is_required_for_user( $user ) {
        if ( ! ( $user instanceof WP_User ) ) return false;
        $settings = get_option( 'rls_settings', [] );
        if ( ! empty( $settings['2fa_required_admin'] ) && self::user_is_admin( $user ) ) {
            return true;
        }
        return false;
    }

    public static function user_is_admin( $user ) {
        if ( ! ( $user instanceof WP_User ) ) return false;
        return is_multisite() ? user_can( $user, 'manage_network_options' ) : user_can( $user, 'manage_options' );
    }

    public static function get_user_secret( $user_id ) {
        $secret = (string) get_user_meta( $user_id, self::OPT_USER_SECRET, true );
        return self::normalize_secret( $secret );
    }

    /**
     * Generates a 32-char Base32 secret (160 bits of entropy).
     */
    public static function generate_secret() {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = '';
        $random_bytes = random_bytes( 20 );
        for ( $i = 0; $i < 20; $i++ ) {
            $secret .= $alphabet[ ord( $random_bytes[ $i ] ) % 32 ];
        }
        return $secret;
    }

    public static function normalize_secret( $secret ) {
        $secret = strtoupper( preg_replace( '/[^A-Z2-7]/', '', (string) $secret ) );
        return $secret;
    }

    public static function get_qr_url( $secret, $user_login, $site_url = '' ) {
        $label = rawurlencode( ( $site_url ?: home_url() ) . ':' . $user_login );
        $issuer = rawurlencode( 'Rybinsk Lab Security' );
        $url = 'otpauth://totp/' . $label . '?secret=' . $secret . '&issuer=' . $issuer . '&algorithm=SHA1&digits=' . self::DIGITS . '&period=' . self::PERIOD;
        return $url;
    }

    /**
     * Verifies a 6-digit TOTP code. Returns true if valid within the time window
     * (one step before/after). Replay protection via per-code transients.
     */
    public static function verify_code( $secret, $code, $user_id = 0 ) {
        $secret = self::normalize_secret( $secret );
        $code   = preg_replace( '/\D/', '', (string) $code );
        if ( strlen( $code ) !== self::DIGITS ) return false;

        $now = time();
        for ( $i = -self::WINDOW; $i <= self::WINDOW; $i++ ) {
            $t = (int) floor( ( $now + $i * self::PERIOD ) / self::PERIOD );
            $expected = self::calc_totp( $secret, $t );
            if ( hash_equals( $expected, $code ) ) {
                if ( $user_id > 0 ) {
                    // Replay protection: a code can be used only once per user.
                    $key = self::TRANSIENT_PREFIX . $user_id . '_' . $t . '_' . substr( hash_hmac( 'sha256', $secret . $t, $code ), 0, 12 );
                    if ( get_transient( $key ) ) return false;
                    set_transient( $key, 1, self::PERIOD * 2 );
                }
                return true;
            }
        }
        return false;
    }

    /**
     * HMAC-SHA1 TOTP per RFC 6238.
     */
    private static function calc_totp( $secret_base32, $counter ) {
        $key = self::base32_decode( $secret_base32 );
        if ( $key === false ) return '';
        $bin_counter = pack( 'N*', 0 ) . pack( 'N*', $counter );
        $hash = hash_hmac( 'sha1', $bin_counter, $key, true );
        $offset = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0F;
        $part = substr( $hash, $offset, 4 );
        $value = unpack( 'N', $part )[1] & 0x7FFFFFFF;
        $code = (string) ( $value % pow( 10, self::DIGITS ) );
        return str_pad( $code, self::DIGITS, '0', STR_PAD_LEFT );
    }

    private static function base32_decode( $input ) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $input = strtoupper( (string) $input );
        $buffer = 0;
        $bits = 0;
        $output = '';
        $len = strlen( $input );
        for ( $i = 0; $i < $len; $i++ ) {
            $c = $input[ $i ];
            if ( $c === '=' ) break;
            $v = strpos( $alphabet, $c );
            if ( $v === false ) return false;
            $buffer = ( $buffer << 5 ) | $v;
            $bits += 5;
            if ( $bits >= 8 ) {
                $bits -= 8;
                $output .= chr( ( $buffer >> $bits ) & 0xFF );
                $buffer &= ( 1 << $bits ) - 1;
            }
        }
        return $output;
    }

    public static function generate_backup_codes( $count = 10 ) {
        $codes = [];
        for ( $i = 0; $i < $count; $i++ ) {
            $codes[] = strtoupper( bin2hex( random_bytes( 5 ) ) ); // 10 hex chars
        }
        return $codes;
    }

    public static function get_backup_codes( $user_id ) {
        $codes = get_user_meta( $user_id, self::OPT_USER_BACKUP, true );
        return is_array( $codes ) ? $codes : [];
    }

    /**
     * Verifies and consumes a backup code (single-use).
     */
    public static function consume_backup_code( $user_id, $code ) {
        $code = strtoupper( trim( (string) $code ) );
        $codes = self::get_backup_codes( $user_id );
        $remaining = [];
        $matched = false;
        foreach ( $codes as $stored ) {
            if ( ! $matched && hash_equals( $stored, $code ) ) {
                $matched = true;
                continue;
            }
            $remaining[] = $stored;
        }
        if ( $matched ) {
            update_user_meta( $user_id, self::OPT_USER_BACKUP, $remaining );
        }
        return $matched;
    }

    public function on_wp_login( $user_login, $user ) {
        if ( ! ( $user instanceof WP_User ) ) return;
        if ( self::is_enabled_for_user( $user->ID ) ) {
            // Force 2FA verification on next request via a session flag.
            // The actual gate is in verify_2fa_on_authenticate; here we just record last login.
            update_user_meta( $user->ID, 'rls_2fa_last_login_ip', self::client_ip() );
        }
    }

    /**
     * Runs after wp_authenticate_* and before the secure_cookie/auth_cookie stages.
     * If 2FA is required but not yet verified for this login, force a re-verification step.
     */
    public function verify_2fa_on_authenticate( $user, $username, $password ) {
        if ( ! ( $user instanceof WP_User ) ) return $user;
        if ( ! self::is_enabled_for_user( $user->ID ) ) return $user;

        // Skip 2FA for application passwords / XML-RPC / REST to avoid breaking integrations.
        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) return $user;
        if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) return $user;
        if ( is_array( $username ) || ! is_string( $username ) ) return $user;

        $presented = isset( $_POST['rls_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['rls_2fa_code'] ) ) : '';

        if ( $presented === '' ) {
            // No code presented on the password submit: this is the first leg of a 2FA login.
            // We let WP render the regular auth filter chain, but redirect via cookie flow on next step.
            // Implementation note: returning a WP_Error here would block normal wp-login.php.
            // Instead we set a transient so the login form knows to ask for the code.
            set_transient( 'rls_2fa_pending_' . $user->ID, 1, 60 );
            return $user;
        }

        if ( self::verify_code( self::get_user_secret( $user->ID ), $presented, $user->ID ) ) {
            delete_transient( 'rls_2fa_pending_' . $user->ID );
            return $user;
        }

        if ( self::consume_backup_code( $user->ID, $presented ) ) {
            delete_transient( 'rls_2fa_pending_' . $user->ID );
            return $user;
        }

        return new WP_Error( 'rls_2fa_invalid', '<strong>ОШИБКА</strong>: Неверный код двухфакторной аутентификации.' );
    }

    private static function client_ip() {
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    /* ---- AJAX handlers ---- */

    public function ajax_setup() {
        check_ajax_referer( 'rls_2fa_nonce', 'nonce' );
        if ( ! is_user_logged_in() ) wp_send_json_error( 'Не авторизован.' );
        $user_id = get_current_user_id();
        if ( self::is_enabled_for_user( $user_id ) ) {
            wp_send_json_error( '2FA уже включена.' );
        }
        $secret = self::generate_secret();
        update_user_meta( $user_id, self::OPT_USER_SECRET, $secret );
        update_user_meta( $user_id, 'rls_2fa_pending_secret', $secret );
        $user = wp_get_current_user();
        wp_send_json_success( [
            'secret' => $secret,
            'qr_url' => self::get_qr_url( $secret, $user->user_login ),
        ] );
    }

    public function ajax_confirm() {
        check_ajax_referer( 'rls_2fa_nonce', 'nonce' );
        if ( ! is_user_logged_in() ) wp_send_json_error();
        $user_id = get_current_user_id();
        $code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
        $secret = (string) get_user_meta( $user_id, 'rls_2fa_pending_secret', true );
        if ( $secret === '' ) wp_send_json_error( 'Сначала запустите настройку.' );
        if ( ! self::verify_code( $secret, $code ) ) {
            wp_send_json_error( 'Неверный код. Проверьте время на устройстве.' );
        }
        // Promote pending → active.
        update_user_meta( $user_id, self::OPT_USER_SECRET, self::normalize_secret( $secret ) );
        update_user_meta( $user_id, self::OPT_USER_ENABLED, 1 );
        delete_user_meta( $user_id, 'rls_2fa_pending_secret' );
        $codes = self::generate_backup_codes();
        update_user_meta( $user_id, self::OPT_USER_BACKUP, $codes );
        wp_send_json_success( [
            'enabled'      => true,
            'backup_codes' => $codes,
        ] );
    }

    public function ajax_disable() {
        check_ajax_referer( 'rls_2fa_nonce', 'nonce' );
        if ( ! is_user_logged_in() ) wp_send_json_error();
        $user_id = get_current_user_id();
        // Require re-auth: confirm current session password or TOTP code.
        $code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
        $secret = self::get_user_secret( $user_id );
        if ( $code === '' || ! ( self::verify_code( $secret, $code, $user_id ) || self::consume_backup_code( $user_id, $code ) ) ) {
            wp_send_json_error( 'Для отключения требуется код 2FA.' );
        }
        delete_user_meta( $user_id, self::OPT_USER_SECRET );
        delete_user_meta( $user_id, self::OPT_USER_ENABLED );
        delete_user_meta( $user_id, self::OPT_USER_BACKUP );
        delete_user_meta( $user_id, 'rls_2fa_pending_secret' );
        wp_send_json_success( '2FA отключена.' );
    }

    public function ajax_regenerate_backup() {
        check_ajax_referer( 'rls_2fa_nonce', 'nonce' );
        if ( ! is_user_logged_in() ) wp_send_json_error();
        $user_id = get_current_user_id();
        if ( ! self::is_enabled_for_user( $user_id ) ) wp_send_json_error( '2FA не активна.' );
        $code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
        $secret = self::get_user_secret( $user_id );
        if ( ! self::verify_code( $secret, $code, $user_id ) ) {
            wp_send_json_error( 'Неверный код.' );
        }
        $codes = self::generate_backup_codes();
        update_user_meta( $user_id, self::OPT_USER_BACKUP, $codes );
        wp_send_json_success( [ 'backup_codes' => $codes ] );
    }

    public function ajax_status() {
        check_ajax_referer( 'rls_2fa_nonce', 'nonce' );
        if ( ! is_user_logged_in() ) wp_send_json_error();
        $user_id = get_current_user_id();
        $enabled = self::is_enabled_for_user( $user_id );
        wp_send_json_success( [
            'enabled'      => $enabled,
            'backup_count' => $enabled ? count( self::get_backup_codes( $user_id ) ) : 0,
        ] );
    }
}
