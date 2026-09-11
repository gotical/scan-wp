<?php
/**
 * Comment spam protection: honeypot field + time token + URL link cap.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Antispam {

    const OPT_SETTINGS = 'rls_antispam_settings';
    const NONCE_ACTION = 'rls_antispam_form';
    const TIME_FIELD   = 'rls_ts';

    public function init() {
        $settings = get_option( self::OPT_SETTINGS, [] );
        if ( ! is_array( $settings ) ) $settings = [];
        if ( empty( $settings['enabled'] ) ) return;

        add_action( 'comment_form_after_fields', [ $this, 'render_honeypot' ] );
        add_filter( 'preprocess_comment', [ $this, 'verify_comment' ], 1 );
        add_filter( 'comment_max_links', [ $this, 'cap_link_count' ] );
    }

    public function render_honeypot() {
        // Render hidden honeypot field (real users don't fill this).
        printf(
            '<p style="position:absolute !important;left:-9999px !important;top:-9999px !important;height:0 !important;width:0 !important;overflow:hidden;" aria-hidden="true"><label for="rls-url">Website</label><input id="rls-url" type="text" name="rls_url" value="" tabindex="-1" autocomplete="off" /></p>'
        );
        // Time token: set when the form was rendered; comment must be posted >=N seconds later.
        printf(
            '<input type="hidden" name="%s" value="%d" />',
            esc_attr( self::TIME_FIELD ),
            (int) time()
        );
        wp_nonce_field( self::NONCE_ACTION, 'rls_antispam_nonce' );
    }

    public function verify_comment( $commentdata ) {
        $settings = get_option( self::OPT_SETTINGS, [] );
        $min_seconds = isset( $settings['min_seconds'] ) ? max( 0, (int) $settings['min_seconds'] ) : 4;

        // 1. Honeypot must be empty.
        $hp = isset( $_POST['rls_url'] ) ? trim( (string) wp_unslash( $_POST['rls_url'] ) ) : '';
        if ( $hp !== '' ) {
            $this->block( 'honeypot' );
        }

        // 2. Time token must be present and >= min_seconds.
        $ts = isset( $_POST[ self::TIME_FIELD ] ) ? (int) $_POST[ self::TIME_FIELD ] : 0;
        if ( $ts <= 0 || ( time() - $ts ) < $min_seconds ) {
            $this->block( 'time-token' );
        }

        // 3. Nonce must be valid.
        $nonce = isset( $_POST['rls_antispam_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['rls_antispam_nonce'] ) ) : '';
        if ( ! $nonce || ! wp_verify_nonce( $nonce, self::NONCE_ACTION ) ) {
            // Soft fail: only block if min_seconds also requires nonce — keep nonce as optional defense-in-depth.
            // We choose not to block here to avoid breaking legacy comment forms that don't render our hidden fields.
        }

        return $commentdata;
    }

    public function cap_link_count( $max_links ) {
        $settings = get_option( self::OPT_SETTINGS, [] );
        $cap = isset( $settings['max_links'] ) ? (int) $settings['max_links'] : 0;
        if ( $cap > 0 ) return $cap;
        return $max_links;
    }

    private function block( $reason ) {
        $msg = apply_filters(
            'rls_antispam_block_message',
            __( 'Комментарий отклонён антиспам-модулем.', 'rybinsklab-security' ),
            $reason
        );
        if ( class_exists( 'RLS_Logger' ) ) {
            RLS_Logger::log_attack(
                $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
                'spam',
                'Comment blocked: ' . $reason
            );
        }
        wp_die(
            esc_html( $msg ),
            esc_html__( 'Комментарий отклонён', 'rybinsklab-security' ),
            [ 'response' => 403 ]
        );
    }
}
