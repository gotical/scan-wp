<?php
/**
 * Unified CAPTCHA handler: Google reCAPTCHA (v2/v3) + Yandex SmartCaptcha.
 *
 * - Provider selection (Google or Yandex)
 * - Version selection (v2 checkbox / v2 invisible / v3 score-based for Google;
 *   Standard / Invisible / Advanced for Yandex)
 * - Server-side token verification with proper error handling
 * - Form-by-form enable/disable
 * - Score threshold for v3
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Captcha {

    const OPT_SETTINGS = 'rls_captcha_settings';

    const PROVIDER_GOOGLE = 'google';
    const PROVIDER_YANDEX = 'yandex';

    /* === Settings === */

    public static function get_settings() {
        $defaults = [
            'enabled'       => 0,
            'provider'      => self::PROVIDER_GOOGLE,

            // Google reCAPTCHA.
            'google_site_key'   => '',
            'google_secret_key' => '',
            'google_version'    => 'v2',           // 'v2' | 'v3'
            'google_v2_type'    => 'checkbox',    // 'checkbox' | 'invisible'
            'google_v3_threshold' => 0.5,         // 0.0 - 1.0
            'google_language'   => '',            // 'en', 'ru', etc. (auto if empty)
            'google_theme'      => 'light',       // 'light' | 'dark'

            // Yandex SmartCaptcha.
            'yandex_client_key' => '',
            'yandex_server_key' => '',
            'yandex_mode'       => 'standard',    // 'standard' | 'invisible' | 'advanced'
            'yandex_language'   => 'ru',

            // Per-form toggles.
            'forms' => [
                'login'           => 1,
                'register'        => 0,    // disabled by default; can break UX
                'comment'         => 0,
                'lostpassword'    => 0,
                'resetpassword'   => 0,
                'admin_login'     => 0,    // legacy from v2.3
            ],
        ];
        $stored = get_option( self::OPT_SETTINGS, [] );
        if ( ! is_array( $stored ) ) $stored = [];
        return array_replace_recursive( $defaults, $stored );
    }

    public static function update_settings( $input ) {
        $current = self::get_settings();

        $current['enabled']             = ! empty( $input['enabled'] ) ? 1 : 0;
        $current['provider']            = in_array( $input['provider'] ?? '', [ self::PROVIDER_GOOGLE, self::PROVIDER_YANDEX ], true )
            ? $input['provider']
            : self::PROVIDER_GOOGLE;

        // Google.
        $current['google_site_key']     = sanitize_text_field( $input['google_site_key'] ?? '' );
        $current['google_secret_key']   = sanitize_text_field( $input['google_secret_key'] ?? '' );
        $current['google_version']      = in_array( $input['google_version'] ?? '', [ 'v2', 'v3' ], true )
            ? $input['google_version']
            : 'v2';
        $current['google_v2_type']      = in_array( $input['google_v2_type'] ?? '', [ 'checkbox', 'invisible' ], true )
            ? $input['google_v2_type']
            : 'checkbox';
        $current['google_v3_threshold'] = max( 0.0, min( 1.0, (float) ( $input['google_v3_threshold'] ?? 0.5 ) ) );
        $current['google_language']     = sanitize_text_field( $input['google_language'] ?? '' );
        $current['google_theme']        = in_array( $input['google_theme'] ?? '', [ 'light', 'dark' ], true )
            ? $input['google_theme']
            : 'light';

        // Yandex.
        $current['yandex_client_key']   = sanitize_text_field( $input['yandex_client_key'] ?? '' );
        $current['yandex_server_key']   = sanitize_text_field( $input['yandex_server_key'] ?? '' );
        $current['yandex_mode']         = in_array( $input['yandex_mode'] ?? '', [ 'standard', 'invisible', 'advanced' ], true )
            ? $input['yandex_mode']
            : 'standard';
        $current['yandex_language']     = sanitize_text_field( $input['yandex_language'] ?? 'ru' );

        // Forms.
        $forms = [];
        foreach ( [ 'login', 'register', 'comment', 'lostpassword', 'resetpassword', 'admin_login' ] as $form ) {
            $forms[ $form ] = ! empty( $input['forms'][ $form ] ) ? 1 : 0;
        }
        $current['forms'] = $forms;

        update_option( self::OPT_SETTINGS, $current );
        return $current;
    }

    /* === Public state === */

    public static function is_enabled() {
        $s = self::get_settings();
        return ! empty( $s['enabled'] );
    }

    public static function is_form_enabled( $form ) {
        $s = self::get_settings();
        return ! empty( $s['forms'][ $form ] );
    }

    public static function get_active_provider() {
        $s = self::get_settings();
        return $s['provider'] ?? self::PROVIDER_GOOGLE;
    }

    public static function is_configured() {
        $s = self::get_settings();
        if ( $s['provider'] === self::PROVIDER_GOOGLE ) {
            return ! empty( $s['google_site_key'] ) && ! empty( $s['google_secret_key'] );
        }
        return ! empty( $s['yandex_client_key'] ) && ! empty( $s['yandex_server_key'] );
    }

    /* === Server-side verification === */

    /**
     * Verify a CAPTCHA token server-side.
     * Returns: true on success, WP_Error with reason on failure.
     */
    public static function verify_token( $token, $ip = null ) {
        if ( empty( $token ) ) {
            return new WP_Error( 'rls_captcha_missing', 'CAPTCHA token отсутствует.' );
        }
        $s = self::get_settings();
        $provider = $s['provider'] ?? self::PROVIDER_GOOGLE;

        if ( $provider === self::PROVIDER_GOOGLE ) {
            return self::verify_google( $token, $ip, $s );
        }
        return self::verify_yandex( $token, $ip, $s );
    }

    /**
     * Verify Google reCAPTCHA token.
     * Works for both v2 and v3 (returns score for v3, success boolean for v2).
     */
    private static function verify_google( $token, $ip, $s ) {
        $secret = $s['google_secret_key'] ?? '';
        if ( empty( $secret ) ) {
            return new WP_Error( 'rls_captcha_misconfigured', 'Google reCAPTCHA secret key не настроен.' );
        }
        $response = wp_remote_post( 'https://www.google.com/recaptcha/api/siteverify', [
            'body'      => [
                'secret'    => $secret,
                'response'  => $token,
                'remoteip'  => $ip ?: ( $_SERVER['REMOTE_ADDR'] ?? '' ),
            ],
            'timeout'   => 5,
            'sslverify' => true,
        ] );
        if ( is_wp_error( $response ) ) {
            return new WP_Error( 'rls_captcha_unreachable', 'Не удалось связаться с Google: ' . $response->get_error_message() );
        }
        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( ! is_array( $body ) ) {
            return new WP_Error( 'rls_captcha_invalid_response', 'Некорректный ответ от Google.' );
        }
        if ( empty( $body['success'] ) ) {
            $errors = isset( $body['error-codes'] ) ? implode( ', ', (array) $body['error-codes'] ) : 'unknown';
            return new WP_Error( 'rls_captcha_failed', 'Google reCAPTCHA: проверка не пройдена (' . $errors . ').' );
        }
        // For v3, additionally check the score.
        if ( ( $s['google_version'] ?? 'v2' ) === 'v3' ) {
            $threshold = (float) ( $s['google_v3_threshold'] ?? 0.5 );
            $score = (float) ( $body['score'] ?? 0 );
            if ( $score < $threshold ) {
                return new WP_Error( 'rls_captcha_low_score', sprintf(
                    'Google reCAPTCHA: низкий score (%.2f < %.2f).',
                    $score,
                    $threshold
                ) );
            }
        }
        return true;
    }

    /**
     * Verify Yandex SmartCaptcha token.
     * Endpoint: https://smartcaptcha.yandexcloud.net/validate
     * Params: secret, token, ip (optional)
     * Response: { "status": "ok"|"failed", "message": "" }
     */
    private static function verify_yandex( $token, $ip, $s ) {
        $secret = $s['yandex_server_key'] ?? '';
        if ( empty( $secret ) ) {
            return new WP_Error( 'rls_captcha_misconfigured', 'Yandex SmartCaptcha server key не настроен.' );
        }
        $response = wp_remote_post( 'https://smartcaptcha.yandexcloud.net/validate', [
            'body'      => [
                'secret' => $secret,
                'token'  => $token,
                'ip'     => $ip ?: ( $_SERVER['REMOTE_ADDR'] ?? '' ),
            ],
            'timeout'   => 5,
            'sslverify' => true,
        ] );
        if ( is_wp_error( $response ) ) {
            return new WP_Error( 'rls_captcha_unreachable', 'Не удалось связаться с Yandex: ' . $response->get_error_message() );
        }
        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( ! is_array( $body ) ) {
            return new WP_Error( 'rls_captcha_invalid_response', 'Некорректный ответ от Yandex.' );
        }
        if ( ( $body['status'] ?? '' ) !== 'ok' ) {
            $message = (string) ( $body['message'] ?? 'unknown' );
            return new WP_Error( 'rls_captcha_failed', 'Yandex SmartCaptcha: проверка не пройдена (' . $message . ').' );
        }
        return true;
    }

    /* === Frontend rendering === */

    /**
     * Render the CAPTCHA widget HTML for a given form.
     * Returns empty string if disabled or misconfigured.
     */
    public static function render( $form = '', $echo = false ) {
        if ( ! self::is_enabled() ) return '';
        if ( $form !== '' && ! self::is_form_enabled( $form ) ) return '';
        if ( ! self::is_configured() ) return '';

        $s = self::get_settings();
        if ( $s['provider'] === self::PROVIDER_GOOGLE ) {
            $html = self::render_google( $form, $s );
        } else {
            $html = self::render_yandex( $form, $s );
        }
        if ( $echo ) echo $html;
        return $html;
    }

    /**
     * Render Google reCAPTCHA v2 / v3 HTML.
     */
    private static function render_google( $form, $s ) {
        $site_key = $s['google_site_key'] ?? '';
        if ( empty( $site_key ) ) return '';
        $version  = $s['google_version'] ?? 'v2';
        $theme    = $s['google_theme'] ?? 'light';
        $lang     = $s['google_language'] ?? '';

        if ( $version === 'v2' ) {
            $type = $s['google_v2_type'] ?? 'checkbox';
            // v2: render div with class g-recaptcha.
            $attrs = [
                'class'      => 'g-recaptcha',
                'data-sitekey' => $site_key,
                'data-theme'   => $theme,
                'data-type'    => $type,
            ];
            $attr_str = '';
            foreach ( $attrs as $k => $v ) {
                $attr_str .= ' ' . esc_attr( $k ) . '="' . esc_attr( $v ) . '"';
            }
            return '<div' . $attr_str . ' data-rls-form="' . esc_attr( $form ) . '"></div>';
        }
        // v3: invisible, but we still need a placeholder div.
        return sprintf(
            '<div class="rls-recaptcha-v3-placeholder" data-sitekey="%s" data-theme="%s" data-form="%s"></div>',
            esc_attr( $site_key ),
            esc_attr( $theme ),
            esc_attr( $form )
        );
    }

    /**
     * Render Yandex SmartCaptcha HTML.
     */
    private static function render_yandex( $form, $s ) {
        $client_key = $s['yandex_client_key'] ?? '';
        if ( empty( $client_key ) ) return '';
        // Yandex renders into a div.smart-captcha with data-sitekey.
        return sprintf(
            '<div class="smart-captcha" data-sitekey="%s" data-hl="%s" data-rls-form="%s"></div>',
            esc_attr( $client_key ),
            esc_attr( $s['yandex_language'] ?? 'ru' ),
            esc_attr( $form )
        );
    }

    /**
     * Print enqueue scripts for the active provider.
     */
    public static function enqueue_scripts() {
        if ( ! self::is_enabled() ) return;
        if ( ! self::is_configured() ) return;

        $s = self::get_settings();
        if ( $s['provider'] === self::PROVIDER_GOOGLE ) {
            self::enqueue_google( $s );
        } else {
            self::enqueue_yandex( $s );
        }
    }

    private static function enqueue_google( $s ) {
        $site_key = $s['google_site_key'] ?? '';
        $version  = $s['google_version'] ?? 'v2';
        $lang     = ! empty( $s['google_language'] ) ? '&hl=' . rawurlencode( $s['google_language'] ) : '';
        if ( $version === 'v3' ) {
            wp_enqueue_script(
                'rls-google-recaptcha',
                'https://www.google.com/recaptcha/api.js?render=' . rawurlencode( $site_key ) . $lang,
                [],
                null,
                true
            );
        } else {
            wp_enqueue_script(
                'rls-google-recaptcha',
                'https://www.google.com/recaptcha/api.js' . $lang,
                [],
                null,
                true
            );
        }
        wp_add_inline_script( 'rls-google-recaptcha', self::google_inline_js( $version ), 'before' );
    }

    private static function google_inline_js( $version ) {
        if ( $version === 'v3' ) {
            return "document.addEventListener('DOMContentLoaded',function(){
                if(typeof grecaptcha==='undefined')return;
                var forms=document.querySelectorAll('.rls-recaptcha-v3-placeholder');
                forms.forEach(function(el){
                    var sitekey=el.getAttribute('data-sitekey');
                    var formEl=el.closest('form')||document;
                    var action=el.getAttribute('data-form')||'submit';
                    grecaptcha.ready(function(){
                        grecaptcha.execute(sitekey,{action:action}).then(function(token){
                            var input=document.createElement('input');
                            input.type='hidden';
                            input.name='g-recaptcha-response';
                            input.value=token;
                            formEl.appendChild(input);
                        });
                    });
                });
            });";
        }
        return "document.addEventListener('DOMContentLoaded',function(){
            // v2 forms handled by Google script automatically.
        });";
    }

    private static function enqueue_yandex( $s ) {
        wp_enqueue_script(
            'rls-yandex-smartcaptcha',
            'https://smartcaptcha.yandexcloud.net/captcha.js?render=onload&onload=onloadSmartCaptchaCallback',
            [],
            null,
            true
        );
    }

    /* === WP form hooks === */

    public function init() {
        if ( ! self::is_enabled() ) return;

        // Render on forms.
        add_action( 'login_form', [ $this, 'render_login' ] );
        add_action( 'register_form', [ $this, 'render_register' ] );
        add_action( 'lostpassword_form', [ $this, 'render_lostpassword' ] );
        add_action( 'resetpass_form', [ $this, 'render_resetpassword' ] );
        add_action( 'comment_form', [ $this, 'render_comment' ] );

        // Enqueue frontend scripts.
        add_action( 'login_enqueue_scripts', [ __CLASS__, 'enqueue_scripts' ] );
        add_action( 'wp_enqueue_scripts', [ __CLASS__, 'enqueue_scripts' ] );

        // Verify tokens.
        add_filter( 'authenticate', [ $this, 'verify_login' ], 30, 3 );
        add_filter( 'registration_errors', [ $this, 'verify_register' ], 10, 3 );
        add_action( 'lostpassword_post', [ $this, 'verify_lostpassword' ], 10, 1 );
        add_action( 'validate_password_reset', [ $this, 'verify_resetpassword' ], 10, 2 );
        add_filter( 'preprocess_comment', [ $this, 'verify_comment' ], 10, 1 );
    }

    /* Render callbacks */
    public function render_login()            { echo self::render( 'login' ); }
    public function render_register()         { echo self::render( 'register' ); }
    public function render_lostpassword()     { echo self::render( 'lostpassword' ); }
    public function render_resetpassword()    { echo self::render( 'resetpassword' ); }
    public function render_comment()          { echo self::render( 'comment' ); }

    /* Verify callbacks */
    public function verify_login( $user, $username, $password ) {
        if ( ! self::is_form_enabled( 'login' ) ) return $user;
        if ( ! ( $user instanceof WP_User ) ) return $user;
        if ( empty( $username ) || empty( $password ) ) return $user;
        if ( is_admin() && ! self::is_form_enabled( 'admin_login' ) ) return $user;
        // Skip for non-form submissions.
        if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) return $user;
        $token = self::get_post_token();
        $result = self::verify_token( $token );
        if ( is_wp_error( $result ) ) {
            return new WP_Error( 'rls_captcha_failed', $result->get_error_message() );
        }
        return $user;
    }

    public function verify_register( $errors, $sanitized_user_login, $user_email ) {
        if ( ! self::is_form_enabled( 'register' ) ) return $errors;
        if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) return $errors;
        $token = self::get_post_token();
        $result = self::verify_token( $token );
        if ( is_wp_error( $result ) ) {
            $errors->add( 'rls_captcha_failed', $result->get_error_message() );
        }
        return $errors;
    }

    public function verify_lostpassword( $errors ) {
        if ( ! self::is_form_enabled( 'lostpassword' ) ) return;
        if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) return;
        $token = self::get_post_token();
        $result = self::verify_token( $token );
        if ( is_wp_error( $result ) ) {
            // lostpassword_post receives WP_Error. Convert by re-adding.
            if ( is_wp_error( $errors ) ) {
                $errors->add( 'rls_captcha_failed', $result->get_error_message() );
            }
        }
        return $errors;
    }

    public function verify_resetpassword( $errors, $user ) {
        if ( ! self::is_form_enabled( 'resetpassword' ) ) return $errors;
        if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) return $errors;
        $token = self::get_post_token();
        $result = self::verify_token( $token );
        if ( is_wp_error( $result ) ) {
            $errors->add( 'rls_captcha_failed', $result->get_error_message() );
        }
        return $errors;
    }

    public function verify_comment( $commentdata ) {
        if ( ! self::is_form_enabled( 'comment' ) ) return $commentdata;
        if ( is_admin() ) return $commentdata;
        $token = self::get_post_token();
        $result = self::verify_token( $token );
        if ( is_wp_error( $result ) ) {
            wp_die( esc_html( $result->get_error_message() ), esc_html__( 'CAPTCHA Error', 'rybinsklab-security' ), [ 'response' => 403 ] );
        }
        return $commentdata;
    }

    private static function get_post_token() {
        $key = self::get_settings()['provider'] === self::PROVIDER_GOOGLE
            ? 'g-recaptcha-response'
            : 'smart-captcha-token';
        return isset( $_POST[ $key ] ) ? sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) : '';
    }

    /* === Test endpoint (AJAX) === */

    public static function ajax_test() {
        check_ajax_referer( 'rls_captcha_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( 'Access Denied' );
        $token = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
        if ( empty( $token ) ) wp_send_json_error( 'No token provided' );
        $result = self::verify_token( $token );
        if ( is_wp_error( $result ) ) {
            wp_send_json_error( $result->get_error_message() );
        }
        wp_send_json_success( 'CAPTCHA verification passed.' );
    }
}
