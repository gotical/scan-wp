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

    const OPT_SETTINGS    = 'rls_webhooks';
    const OPT_EVENT_LOG   = 'rls_webhook_events';
    const MAX_LOG_ENTRIES = 200;

    public function init() {
        $settings = get_option( self::OPT_SETTINGS, [] );
        if ( ! is_array( $settings ) ) $settings = [];
        if ( empty( $settings['enabled'] ) ) return;

        add_action( 'rls_malware_detected',     [ $this, 'on_malware' ], 10, 2 );
        add_action( 'rls_integrity_violation', [ $this, 'on_integrity' ], 10, 1 );
        add_action( 'rls_bruteforce_lockout',  [ $this, 'on_bruteforce' ], 10, 2 );
        add_action( 'rls_anomaly_detected',    [ $this, 'on_anomaly' ], 10, 2 );
    }

    public static function get_settings() {
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
                'anomaly'      => 1,
            ],
            'min_severity' => 50,
        ];
        $stored = get_option( self::OPT_SETTINGS, [] );
        if ( ! is_array( $stored ) ) $stored = [];
        return array_replace_recursive( $defaults, $stored );
    }

    public static function update_settings( $input ) {
        $current = self::get_settings();
        $current['enabled'] = ! empty( $input['enabled'] ) ? 1 : 0;

        $current['slack']['url']  = esc_url_raw( $input['slack']['url'] ?? '' );
        $current['discord']['url'] = esc_url_raw( $input['discord']['url'] ?? '' );
        $current['telegram']['token']  = sanitize_text_field( $input['telegram']['token'] ?? '' );
        $current['telegram']['chat_id'] = sanitize_text_field( $input['telegram']['chat_id'] ?? '' );
        $current['custom']['url']    = esc_url_raw( $input['custom']['url'] ?? '' );
        $current['custom']['method'] = in_array( strtoupper( $input['custom']['method'] ?? 'POST' ), [ 'POST', 'PUT' ], true )
            ? strtoupper( $input['custom']['method'] )
            : 'POST';

        foreach ( [ 'malware', 'integrity', 'bruteforce', 'anomaly' ] as $evt ) {
            $current['events'][ $evt ] = ! empty( $input['events'][ $evt ] ) ? 1 : 0;
        }

        $current['min_severity'] = max( 0, min( 100, (int) ( $input['min_severity'] ?? 50 ) ) );

        update_option( self::OPT_SETTINGS, $current );
        return $current;
    }

    public static function is_configured() {
        $s = self::get_settings();
        if ( empty( $s['enabled'] ) ) return false;
        $has_dest = ! empty( $s['slack']['url'] )
                  || ! empty( $s['discord']['url'] )
                  || ( ! empty( $s['telegram']['token'] ) && ! empty( $s['telegram']['chat_id'] ) )
                  || ! empty( $s['custom']['url'] );
        return $has_dest;
    }

    /**
     * Send a payload to all enabled webhooks.
     */
    public static function dispatch( $event, $title, $message, $severity = 50, $extra = [] ) {
        $settings = self::get_settings();
        if ( empty( $settings['enabled'] ) ) return false;
        if ( empty( $settings['events'][ $event ] ) ) return false;
        if ( $severity < (int) ( $settings['min_severity'] ?? 0 ) ) return false;

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

        $results = [
            'slack'    => null,
            'discord'  => null,
            'telegram' => null,
            'custom'   => null,
        ];

        if ( ! empty( $settings['slack']['url'] ) ) {
            $results['slack'] = self::send_slack( $settings['slack']['url'], $payload );
        }
        if ( ! empty( $settings['discord']['url'] ) ) {
            $results['discord'] = self::send_discord( $settings['discord']['url'], $payload );
        }
        if ( ! empty( $settings['telegram']['token'] ) && ! empty( $settings['telegram']['chat_id'] ) ) {
            $results['telegram'] = self::send_telegram( $settings['telegram']['token'], $settings['telegram']['chat_id'], $payload );
        }
        if ( ! empty( $settings['custom']['url'] ) ) {
            $results['custom'] = self::send_custom( $settings['custom']['url'], $payload, $settings['custom']['method'] ?? 'POST' );
        }

        self::log_event( $event, $title, $severity, $results );

        return $results;
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
        $response = wp_remote_post( $url, [
            'body'      => wp_json_encode( $body ),
            'headers'   => [ 'Content-Type' => 'application/json' ],
            'timeout'   => 8,
            'blocking'  => true,
            'sslverify' => true,
        ] );
        return self::response_to_status( $response, 'slack' );
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
        $response = wp_remote_post( $url, [
            'body'      => wp_json_encode( $body ),
            'headers'   => [ 'Content-Type' => 'application/json' ],
            'timeout'   => 8,
            'blocking'  => true,
            'sslverify' => true,
        ] );
        return self::response_to_status( $response, 'discord' );
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
        $response = wp_remote_post( "https://api.telegram.org/bot{$token}/sendMessage", [
            'body'      => [
                'chat_id'    => $chat_id,
                'text'       => $text,
                'parse_mode' => 'Markdown',
            ],
            'timeout'   => 8,
            'blocking'  => true,
            'sslverify' => true,
        ] );
        return self::response_to_status( $response, 'telegram' );
    }

    /**
     * Custom generic webhook.
     */
    private static function send_custom( $url, $payload, $method = 'POST' ) {
        $response = wp_remote_request( $url, [
            'method'    => $method,
            'body'      => wp_json_encode( $payload ),
            'headers'   => [ 'Content-Type' => 'application/json' ],
            'timeout'   => 8,
            'blocking'  => true,
            'sslverify' => true,
        ] );
        return self::response_to_status( $response, 'custom' );
    }

    private static function response_to_status( $response, $channel ) {
        if ( is_wp_error( $response ) ) {
            return [ 'channel' => $channel, 'success' => false, 'error' => $response->get_error_message() ];
        }
        $code = (int) wp_remote_retrieve_response_code( $response );
        $body = wp_remote_retrieve_body( $response );
        $ok = $code >= 200 && $code < 300;
        // For Telegram, success body is JSON with ok:true.
        if ( 'telegram' === $channel && $ok ) {
            $decoded = json_decode( $body, true );
            if ( ! is_array( $decoded ) || empty( $decoded['ok'] ) ) {
                $ok = false;
            }
        }
        return [
            'channel'    => $channel,
            'success'    => $ok,
            'http_code'  => $code,
            'response'   => substr( (string) $body, 0, 300 ),
        ];
    }

    /* === Event log === */

    private static function log_event( $event, $title, $severity, $results ) {
        $log = get_option( self::OPT_EVENT_LOG, [] );
        if ( ! is_array( $log ) ) $log = [];
        $log[] = [
            'time'     => current_time( 'mysql' ),
            'event'    => $event,
            'title'    => $title,
            'severity' => (int) $severity,
            'results'  => $results,
        ];
        if ( count( $log ) > self::MAX_LOG_ENTRIES ) {
            $log = array_slice( $log, -self::MAX_LOG_ENTRIES );
        }
        update_option( self::OPT_EVENT_LOG, $log, false );
    }

    public static function get_event_log( $limit = 50 ) {
        $log = get_option( self::OPT_EVENT_LOG, [] );
        if ( ! is_array( $log ) ) return [];
        return array_slice( array_reverse( $log ), 0, $limit );
    }

    public static function clear_event_log() {
        update_option( self::OPT_EVENT_LOG, [], false );
    }

    /* === Event handlers === */

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
            sprintf( '🦠 Malware detected (%d threats)', $count ),
            "Scan type: {$scan_type}\n{$list}",
            max( 70, $max_severity ),
            [ 'scan_type' => $scan_type, 'count' => $count ]
        );
    }

    public function on_integrity( $changed_files ) {
        $list = implode( "\n• ", (array) $changed_files );
        self::dispatch(
            'integrity',
            '⚠️ Plugin file integrity violation',
            "Следующие файлы плагина изменены:\n• {$list}",
            90,
            [ 'files' => $changed_files ]
        );
    }

    public function on_bruteforce( $ip, $lock_seconds ) {
        self::dispatch(
            'bruteforce',
            sprintf( '🔒 Brute force lockout: %s', $ip ),
            "IP {$ip} заблокирован на {$lock_seconds} сек после превышения лимита попыток входа.",
            70,
            [ 'ip' => $ip ]
        );
    }

    public function on_anomaly( $user, $anomalies ) {
        if ( ! ( $user instanceof WP_User ) ) return;
        $max_sev = 60;
        $reasons = [];
        foreach ( (array) $anomalies as $a ) {
            $reasons[] = ( $a['type'] ?? '' ) . ' (' . ( $a['value'] ?? '' ) . ')';
        }
        $severity = 60 + min( 30, count( $anomalies ) * 5 );
        self::dispatch(
            'anomaly',
            sprintf( '🟡 Аномальный вход: %s', $user->user_login ),
            "Обнаружены аномалии:\n• " . implode( "\n• ", $reasons ),
            $severity,
            [ 'user_id' => $user->ID, 'user_login' => $user->user_login, 'anomalies' => $anomalies ]
        );
    }

    /* === Test endpoint === */

    public static function ajax_test() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( 'Access denied' );
        $channel = isset( $_POST['channel'] ) ? sanitize_key( $_POST['channel'] ) : '';
        $valid = [ 'slack', 'discord', 'telegram', 'custom', 'all' ];
        if ( ! in_array( $channel, $valid, true ) ) {
            wp_send_json_error( 'Неизвестный канал.' );
        }

        $payload = [
            'event'     => 'test',
            'title'     => '✅ Тестовое уведомление Rybinsk Lab Security',
            'message'   => 'Если вы видите это сообщение — интеграция работает корректно!',
            'severity'  => 50,
            'site'      => home_url(),
            'timestamp' => gmdate( 'c' ),
        ];
        $settings = self::get_settings();
        $results = [];

        $test_channel = function( $name, $fn ) use ( $settings, $channel, $payload ) {
            if ( $channel !== 'all' && $channel !== $name ) return;
            $has_config = false;
            if ( 'slack' === $name )    $has_config = ! empty( $settings['slack']['url'] );
            if ( 'discord' === $name )  $has_config = ! empty( $settings['discord']['url'] );
            if ( 'telegram' === $name ) $has_config = ! empty( $settings['telegram']['token'] ) && ! empty( $settings['telegram']['chat_id'] );
            if ( 'custom' === $name )   $has_config = ! empty( $settings['custom']['url'] );
            if ( ! $has_config ) {
                $GLOBALS['rls_webhook_test_results'][$name] = [ 'channel' => $name, 'success' => false, 'error' => 'Не настроен' ];
                return;
            }
            $GLOBALS['rls_webhook_test_results'][$name] = $fn( $settings[ $name ], $payload );
        };

        $GLOBALS['rls_webhook_test_results'] = [];
        $test_channel( 'slack',    function( $cfg, $p ) { return self::send_slack( $cfg['url'], $p ); } );
        $test_channel( 'discord',  function( $cfg, $p ) { return self::send_discord( $cfg['url'], $p ); } );
        $test_channel( 'telegram', function( $cfg, $p ) { return self::send_telegram( $cfg['token'], $cfg['chat_id'], $p ); } );
        $test_channel( 'custom',   function( $cfg, $p ) { return self::send_custom( $cfg['url'], $p, $cfg['method'] ?? 'POST' ); } );

        self::log_event( 'test', 'Test notification', 50, $GLOBALS['rls_webhook_test_results'] );

        wp_send_json_success( [
            'message' => 'Тестовое уведомление отправлено',
            'results' => $GLOBALS['rls_webhook_test_results'],
        ] );
    }
}

