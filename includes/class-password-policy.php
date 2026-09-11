<?php
/**
 * Password policy: minimum length, complexity, and HIBP breach check.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Password_Policy {

    const OPT_SETTINGS = 'rls_password_policy';
    const HIBP_URL     = 'https://api.pwnedpasswords.com/range/';

    public function init() {
        $settings = get_option( self::OPT_SETTINGS, [] );
        if ( ! is_array( $settings ) || empty( $settings['enabled'] ) ) return;

        add_action( 'user_profile_update_errors', [ $this, 'validate_on_profile_update' ], 10, 3 );
        add_action( 'validate_password_reset', [ $this, 'validate_on_reset' ], 10, 2 );
        add_action( 'wp_ajax_rls_check_password_strength', [ $this, 'ajax_check_strength' ] );
    }

    private static function get_settings() {
        $defaults = [
            'enabled'        => 0,
            'min_length'     => 12,
            'require_upper'  => 1,
            'require_lower'  => 1,
            'require_digit'  => 1,
            'require_symbol' => 1,
            'hibp_check'     => 1,
        ];
        $stored = get_option( self::OPT_SETTINGS, [] );
        if ( ! is_array( $stored ) ) $stored = [];
        return array_merge( $defaults, $stored );
    }

    public static function evaluate( $password ) {
        $settings = self::get_settings();
        $errors = [];
        $score  = 0;

        $length = strlen( $password );
        if ( $length < (int) $settings['min_length'] ) {
            $errors[] = sprintf( 'Минимум %d символов.', (int) $settings['min_length'] );
        } else {
            $score += 1;
        }
        if ( ! empty( $settings['require_upper'] ) && ! preg_match( '/[A-Z]/', $password ) ) {
            $errors[] = 'Требуется заглавная буква.';
        } elseif ( ! empty( $settings['require_upper'] ) ) {
            $score += 1;
        }
        if ( ! empty( $settings['require_lower'] ) && ! preg_match( '/[a-z]/', $password ) ) {
            $errors[] = 'Требуется строчная буква.';
        } elseif ( ! empty( $settings['require_lower'] ) ) {
            $score += 1;
        }
        if ( ! empty( $settings['require_digit'] ) && ! preg_match( '/\d/', $password ) ) {
            $errors[] = 'Требуется цифра.';
        } elseif ( ! empty( $settings['require_digit'] ) ) {
            $score += 1;
        }
        if ( ! empty( $settings['require_symbol'] ) && ! preg_match( '/[^A-Za-z0-9]/', $password ) ) {
            $errors[] = 'Требуется спецсимвол.';
        } elseif ( ! empty( $settings['require_symbol'] ) ) {
            $score += 1;
        }
        if ( $length >= 16 ) $score += 1;
        if ( $length >= 24 ) $score += 1;

        return [
            'valid'  => empty( $errors ),
            'errors' => $errors,
            'score'  => $score, // 0..7
        ];
    }

    /**
     * Returns the count of breaches found via HIBP k-Anonymity API, or -1 on error.
     * Only the first 5 chars of the SHA-1 hash are sent.
     */
    public static function hibp_breach_count( $password ) {
        $sha1 = strtoupper( sha1( $password ) );
        $prefix = substr( $sha1, 0, 5 );
        $suffix = substr( $sha1, 5 );
        $response = wp_remote_get( self::HIBP_URL . $prefix, [
            'timeout' => 6,
            'sslverify' => true,
            'headers' => [ 'User-Agent' => 'RybinskLabSecurity-PasswordCheck/' . RLS_VERSION ],
        ] );
        if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
            return -1;
        }
        $body = wp_remote_retrieve_body( $response );
        foreach ( preg_split( '/\r\n|\r|\n/', (string) $body ) as $line ) {
            if ( strpos( $line, ':' ) === false ) continue;
            list( $hash_suffix, $count ) = explode( ':', $line, 2 );
            if ( strcasecmp( trim( $hash_suffix ), $suffix ) === 0 ) {
                return (int) trim( $count );
            }
        }
        return 0;
    }

    public function validate_on_profile_update( $errors, $update, $user ) {
        if ( empty( $_POST['pass1'] ) || trim( (string) $_POST['pass1'] ) === '' ) return;
        $password = (string) wp_unslash( $_POST['pass1'] );
        $this->assert_strong( $password, $errors );
    }

    public function validate_on_reset( $errors, $user ) {
        if ( empty( $_POST['pass1'] ) ) return;
        $password = (string) wp_unslash( $_POST['pass1'] );
        $this->assert_strong( $password, $errors );
    }

    private function assert_strong( $password, $errors ) {
        $eval = self::evaluate( $password );
        foreach ( $eval['errors'] as $msg ) {
            $errors->add( 'rls_weak_password', $msg );
        }
        $settings = self::get_settings();
        if ( ! empty( $settings['hibp_check'] ) ) {
            $count = self::hibp_breach_count( $password );
            if ( $count > 0 ) {
                $errors->add(
                    'rls_pwned_password',
                    sprintf(
                        'Этот пароль найден в %s известных утечках. Выберите другой.',
                        number_format_i18n( $count )
                    )
                );
            }
        }
    }

    public function ajax_check_strength() {
        check_ajax_referer( 'rls_password_strength', 'nonce' );
        if ( ! is_user_logged_in() ) wp_send_json_error();
        $password = isset( $_POST['password'] ) ? (string) wp_unslash( $_POST['password'] ) : '';
        if ( strlen( $password ) > 1024 ) {
            wp_send_json_success( [ 'valid' => false, 'errors' => [ 'Пароль слишком длинный.' ] ] );
        }
        $eval = self::evaluate( $password );
        $settings = self::get_settings();
        $breach_count = -1;
        if ( ! empty( $settings['hibp_check'] ) && strlen( $password ) >= 4 ) {
            $breach_count = self::hibp_breach_count( $password );
        }
        wp_send_json_success( [
            'valid'        => $eval['valid'],
            'errors'       => $eval['errors'],
            'score'        => $eval['score'],
            'breach_count' => $breach_count,
        ] );
    }
}
