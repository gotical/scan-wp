<?php
/**
 * Webhooks for external notifications (Slack, Discord, Telegram, custom).
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Webhooks {

    const OPT_SETTINGS = 'rls_webhooks';

    public function init() {
        $settings = get_option( self::OPT_SETTINGS, [] );
        if ( ! is_array( $settings ) ) $settings = [];
        if ( empty( $settings['enabled'] ) ) return;

        add_action( 'rls_malware_detected', [ $this, 'on_malware' ], 10, 2 );
        add_action( 'rls_integrity_violation', [ $this, 'on_integrity' ], 10, 1 );
        add_action( 'rls_bruteforce_lockout', [ $this, 'on_bruteforce' ], 10, 2 );
    }

    private static function get_settings() {
        $defaults = [
            'enabled'   => 0,
            'slack'     => [ 'url' => '' ],
            'discord'   => [ 'url' => '' ],
            'telegram'  => [ 'token' => '', 'chat_id' => '' ],
            'custom'    => [ 'url' => '', 'method' => 'POST' ],
            'events'    => [
                'malware'      => 1,
                'integrity'    => 1,
                'bruteforce'   => 1,
            ],
            'min_severity' => 50,
        ];
        $stored = get_option( self::OPT_SETTINGS, [] );
        if ( ! is_array( $stored ) ) $stored = [];
        return array_replace_recursive( $defaults, $stored );
    }

    /**
     * Send a payload to all enabled webhooks.
     */
    public static function dispatch( $event, $title, $message, $severity = 50, $extra = [] ) {
        $settings = self::get_settings();
        if ( empty( $settings['enabled'] ) ) return;
        if ( empty( $settings['events'][ $event ] ) ) return;
        if ( $severity < (int) ( $settings['min_severity'] ?? 0 ) ) return;

        $payload = [
            'event'     => $event,
            'title'     => $title,
            'message'   => $message,
            'severity'  => $severity,
            'site'      => home_url(),
            'timestamp' => gmdate( 'c' ),
        ];
        if ( ! empty( $extra ) ) {
            $payload = array_merge( $payload, $extra );
        }

        if ( ! empty( $settings['slack']['url'] ) ) {
            self::send_slack( $settings['slack']['url'], $payload );
        }
        if ( ! empty( $settings['discord']['url'] ) ) {
            self::send_discord( $settings['discord']['url'], $payload );
        }
        if ( ! empty( $settings['telegram']['token'] ) && ! empty( $settings['telegram']['chat_id'] ) ) {
            self::send_telegram( $settings['telegram']['token'], $settings['telegram']['chat_id'], $payload );
        }
        if ( ! empty( $settings['custom']['url'] ) ) {
            self::send_custom( $settings['custom']['url'], $payload, $settings['custom']['method'] ?? 'POST' );
        }
    }

    /**
     * Slack incoming webhook.
     */
    private static function send_slack( $url, $payload ) {
        $body = [
            'text'    => sprintf( "🚨 *[%s]* %s\n%s", strtoupper( $payload['severity'] ), $payload['title'], $payload['message'] ),
            'blocks'  => [
                [ 'type' => 'section', 'text' => [ 'type' => 'mrkdwn', 'text' => '*' . $payload['title'] . '*' ] ],
                [ 'type' => 'section', 'text' => [ 'type' => 'mrkdwn', 'text' => $payload['message'] ] ],
                [ 'type' => 'context', 'elements' => [ [ 'type' => 'mrkdwn', 'text' => $payload['site'] . ' · ' . $payload['timestamp'] ] ] ],
            ],
        ];
        wp_remote_post( $url, [
            'body'      => wp_json_encode( $body ),
            'headers'   => [ 'Content-Type' => 'application/json' ],
            'timeout'   => 5,
            'blocking'  => false,
            'sslverify' => true,
        ] );
    }

    /**
     * Discord webhook.
     */
    private static function send_discord( $url, $payload ) {
        $color = $payload['severity'] >= 80 ? 0xdc2626 : ( $payload['severity'] >= 50 ? 0xd97706 : 0x16a34a );
        $body = [
            'embeds' => [
                [
                    'title'       => $payload['title'],
                    'description' => $payload['message'],
                    'color'       => $color,
                    'footer'      => [ 'text' => $payload['site'] ],
                    'timestamp'   => $payload['timestamp'],
                ],
            ],
        ];
        wp_remote_post( $url, [
            'body'      => wp_json_encode( $body ),
            'headers'   => [ 'Content-Type' => 'application/json' ],
            'timeout'   => 5,
            'blocking'  => false,
            'sslverify' => true,
        ] );
    }

    /**
     * Telegram bot API.
     */
    private static function send_telegram( $token, $chat_id, $payload ) {
        $text = sprintf( "🚨 *[%s]* %s\n\n%s\n\n`%s · %s`",
            strtoupper( $payload['severity'] ),
            $payload['title'],
            $payload['message'],
            $payload['site'],
            $payload['timestamp']
        );
        wp_remote_post( "https://api.telegram.org/bot{$token}/sendMessage", [
            'body'      => [
                'chat_id'    => $chat_id,
                'text'       => $text,
                'parse_mode' => 'Markdown',
            ],
            'timeout'   => 5,
            'blocking'  => false,
            'sslverify' => true,
        ] );
    }

    /**
     * Custom generic webhook.
     */
    private static function send_custom( $url, $payload, $method = 'POST' ) {
        wp_remote_request( $url, [
            'method'    => $method,
            'body'      => wp_json_encode( $payload ),
            'headers'   => [ 'Content-Type' => 'application/json' ],
            'timeout'   => 5,
            'blocking'  => false,
            'sslverify' => true,
        ] );
    }

    public function on_malware( $threats, $scan_type ) {
        $count = count( $threats );
        if ( ! $count ) return;
        $max_severity = max( array_column( $threats, 'risk_score' ) ?: [ 0 ] );
        $sample = array_slice( $threats, 0, 3 );
        $list = '';
        foreach ( $sample as $t ) {
            $list .= "\n• " . ( $t['file'] ?? '' ) . ' — ' . ( $t['rule_name'] ?? $t['signature'] ?? 'threat' );
        }
        self::dispatch(
            'malware',
            sprintf( 'Malware detected (%d threats)', $count ),
            "Scan type: {$scan_type}\n{$list}",
            $max_severity,
            [ 'scan_type' => $scan_type, 'count' => $count ]
        );
    }

    public function on_integrity( $changed_files ) {
        $list = implode( "\n• ", (array) $changed_files );
        self::dispatch(
            'integrity',
            'Plugin file integrity violation',
            "Следующие файлы плагина изменены:\n• {$list}",
            90,
            [ 'files' => $changed_files ]
        );
    }

    public function on_bruteforce( $ip, $lock_seconds ) {
        self::dispatch(
            'bruteforce',
            sprintf( 'Brute force lockout: %s', $ip ),
            "IP {$ip} заблокирован на {$lock_seconds} сек после превышения лимита попыток входа.",
            70,
            [ 'ip' => $ip ]
        );
    }
}
