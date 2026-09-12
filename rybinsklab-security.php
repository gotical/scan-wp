<?php
/**
 * Plugin Name:       Rybinsk Lab Security
 * Plugin URI:        https://rybinsklab.ru/scan-wp/
 * Description:       Комплексная защита WordPress: WAF, глобальный черный список IP, сканер, защита входа и журнал атак.
 * Version:           3.1.0
 * Author:            Усачёв Денис
 * Author URI:        https://rybinsklab.ru/
 * License:           GPL v2 or later
 * Text Domain:       rybinsklab-security
 * Domain Path:       /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ
 */
define( 'RLS_VERSION', '3.1.0' );
define( 'RLS_API_URL', 'https://rybinsklab.ru/scan-wp/api/index.php' );
define( 'RLS_PLUGIN_FILE', __FILE__ );
define( 'RLS_PLUGIN_PATH', plugin_dir_path( __FILE__ ) );
define( 'RLS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

if ( ! function_exists( 'rls_plural_form' ) ) {
    function rls_plural_form( $number, array $forms ) {
        $number = abs( (int) $number );
        $mod10 = $number % 10;
        $mod100 = $number % 100;

        if ( $mod100 >= 11 && $mod100 <= 19 ) {
            return $forms[2];
        }

        if ( $mod10 === 1 ) {
            return $forms[0];
        }

        if ( $mod10 >= 2 && $mod10 <= 4 ) {
            return $forms[1];
        }

        return $forms[2];
    }
}

if ( ! function_exists( 'rls_store_license_meta' ) ) {
    function rls_store_license_meta( $status, array $license_data = [] ) {
        update_option( 'rls_license_status', $status );

        if ( $status !== 'valid' ) {
            delete_option( 'rls_license_expires_at' );
            delete_option( 'rls_license_max_domains' );
            return;
        }

        $expires_at = '';
        if ( isset( $license_data['expires_at'] ) ) {
            $expires_at = sanitize_text_field( (string) $license_data['expires_at'] );
        }

        if ( $expires_at !== '' ) {
            update_option( 'rls_license_expires_at', $expires_at );
        } else {
            delete_option( 'rls_license_expires_at' );
        }

        if ( array_key_exists( 'max_domains', $license_data ) ) {
            update_option( 'rls_license_max_domains', max( 0, (int) $license_data['max_domains'] ) );
        }
    }
}

if ( ! function_exists( 'rls_get_license_expiration_timestamp' ) ) {
    function rls_get_license_expiration_timestamp() {
        $expires_at = (string) get_option( 'rls_license_expires_at', '' );
        if ( $expires_at === '' ) {
            return null;
        }

        $timestamp = strtotime( $expires_at );
        return $timestamp > 0 ? $timestamp : null;
    }
}

if ( ! function_exists( 'rls_get_license_time_left_label' ) ) {
    function rls_get_license_time_left_label( $expiration_timestamp = null ) {
        if ( empty( $expiration_timestamp ) ) {
            return '';
        }

        $now = function_exists( 'current_time' ) ? (int) current_time( 'timestamp' ) : time();
        $seconds_left = (int) $expiration_timestamp - $now;

        if ( $seconds_left <= 0 ) {
            return 'Лицензия истекла';
        }

        if ( $seconds_left <= DAY_IN_SECONDS ) {
            $hours_left = max( 1, (int) ceil( $seconds_left / HOUR_IN_SECONDS ) );
            return 'Осталось ' . $hours_left . ' ' . rls_plural_form( $hours_left, [ 'час', 'часа', 'часов' ] );
        }

        $days_left = max( 1, (int) ceil( $seconds_left / DAY_IN_SECONDS ) );
        return 'Осталось ' . $days_left . ' ' . rls_plural_form( $days_left, [ 'день', 'дня', 'дней' ] );
    }
}

if ( ! function_exists( 'rls_get_license_ui_state' ) ) {
    function rls_get_license_ui_state() {
        $status = (string) get_option( 'rls_license_status', '' );
        $expiration_timestamp = rls_get_license_expiration_timestamp();
        $max_domains = (int) get_option( 'rls_license_max_domains', 0 );
        $remaining_label = rls_get_license_time_left_label( $expiration_timestamp );
        $is_expired = ( $remaining_label === 'Лицензия истекла' );

        $state = [
            'status' => $status,
            'badge_text' => 'FREE',
            'badge_background' => '#e5e5e5',
            'badge_color' => '#333333',
            'headline' => 'Бесплатная версия',
            'status_text' => 'Бесплатная версия активна',
            'remaining_text' => '',
            'expires_text' => '',
            'domains_text' => '',
            'is_premium' => false,
        ];

        if ( $status === 'valid' && ! $is_expired ) {
            $state['badge_text'] = 'PREMIUM';
            $state['badge_background'] = '#f0ad4e';
            $state['badge_color'] = '#ffffff';
            $state['headline'] = $remaining_label !== '' ? 'Premium: ' . $remaining_label : 'Premium активен';
            $state['status_text'] = 'Премиум-версия активна';
            $state['remaining_text'] = $remaining_label;
            $state['is_premium'] = true;
        } elseif ( $status === 'invalid' || $is_expired ) {
            $state['badge_text'] = 'EXPIRED';
            $state['badge_background'] = '#dc3545';
            $state['badge_color'] = '#ffffff';
            $state['headline'] = 'Лицензия требует проверки';
            $state['status_text'] = 'Ключ недействителен или срок лицензии истек';
            $state['remaining_text'] = $remaining_label;
        }

        if ( ! empty( $expiration_timestamp ) ) {
            $state['expires_text'] = 'Действует до ' . wp_date( 'd.m.Y H:i', $expiration_timestamp );
        }

        if ( $max_domains > 0 ) {
            $state['domains_text'] = 'Лимит сайтов: ' . $max_domains;
        }

        return $state;
    }
}

/**
 * пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅ
 */

// пїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅ
if ( ! function_exists( 'rls_get_protection_mode' ) ) {
    function rls_get_protection_mode() {
        $settings = get_option( 'rls_settings', [] );
        $mode = sanitize_key( (string) ( $settings['protection_mode'] ?? 'full' ) );

        return in_array( $mode, [ 'light', 'full', 'scanner_only' ], true ) ? $mode : 'full';
    }
}

if ( ! function_exists( 'rls_is_full_protection_mode' ) ) {
    function rls_is_full_protection_mode() {
        return rls_get_protection_mode() === 'full';
    }
}

if ( ! function_exists( 'rls_is_light_protection_mode' ) ) {
    function rls_is_light_protection_mode() {
        return rls_get_protection_mode() === 'light';
    }
}

if ( ! function_exists( 'rls_is_scanner_only_mode' ) ) {
    function rls_is_scanner_only_mode() {
        return rls_get_protection_mode() === 'scanner_only';
    }
}

if ( ! function_exists( 'rls_is_premium_license_active' ) ) {
    function rls_is_premium_license_active() {
        $license_ui = rls_get_license_ui_state();

        return ! empty( $license_ui['is_premium'] );
    }
}

if ( ! function_exists( 'rls_should_run_strict_bot_protection' ) ) {
    function rls_should_run_strict_bot_protection() {
        return rls_get_protection_mode() === 'full';
    }
}

if ( ! function_exists( 'rls_is_firewall_runtime_enabled' ) ) {
    function rls_is_firewall_runtime_enabled( $settings = null ) {
        if ( ! is_array( $settings ) ) {
            $settings = get_option( 'rls_settings', [] );
        }

        if ( rls_is_scanner_only_mode() ) {
            return false;
        }

        return ! empty( $settings['enable_firewall'] );
    }
}

if ( ! function_exists( 'rls_is_global_blacklist_runtime_enabled' ) ) {
    function rls_is_global_blacklist_runtime_enabled( $settings = null ) {
        if ( ! is_array( $settings ) ) {
            $settings = get_option( 'rls_settings', [] );
        }

        if ( ! rls_is_premium_license_active() || rls_is_scanner_only_mode() ) {
            return false;
        }

        if ( rls_is_full_protection_mode() ) {
            return true;
        }

        return ! empty( $settings['global_blacklist_enabled'] );
    }
}

if ( ! function_exists( 'rls_get_protection_mode_ui_state' ) ) {
    function rls_get_protection_mode_ui_state() {
        $mode = rls_get_protection_mode();

        $states = [
            'full' => [
                'mode' => 'full',
                'label' => 'Полная защита',
                'short_label' => 'Полная',
                'badge_background' => '#198754',
                'badge_color' => '#ffffff',
                'status_text' => 'Включены все защитные модули. Доступны расширенные фильтры по ботам, языкам и странам.',
                'warning_text' => '',
                'login_branding_text' => 'Полная защита активна',
            ],
            'light' => [
                'mode' => 'light',
                'label' => 'Легкая защита',
                'short_label' => 'Легкая',
                'badge_background' => '#f0ad4e',
                'badge_color' => '#ffffff',
                'status_text' => 'Работают базовые модули защиты: WAF, IP-списки и защита входа. Фильтрация по языку, строгая фильтрация ботов и GeoIP отключены. Простые проверки доступности страниц пропускаются.',
                'warning_text' => '',
                'login_branding_text' => 'Легкая защита активна',
            ],
            'scanner_only' => [
                'mode' => 'scanner_only',
                'label' => 'Только сканер вирусов',
                'short_label' => 'Сканер',
                'badge_background' => '#dc3545',
                'badge_color' => '#ffffff',
                'status_text' => 'Защитные модули отключены. Плагин работает только как сканер вирусов.',
                'warning_text' => 'Сайт сейчас не защищается фаерволом и защитой входа. Рекомендуем включить легкую или полную защиту.',
                'login_branding_text' => 'Защита сайта отключена',
            ],
        ];

        return $states[ $mode ];
    }
}

require_once RLS_PLUGIN_PATH . 'includes/class-firewall.php';
require_once RLS_PLUGIN_PATH . 'includes/class-login-security.php';
require_once RLS_PLUGIN_PATH . 'includes/class-hardening.php';
require_once RLS_PLUGIN_PATH . 'includes/class-captcha.php';
require_once RLS_PLUGIN_PATH . 'includes/class-login-attempts.php';
require_once RLS_PLUGIN_PATH . 'includes/class-attack-analytics.php';
require_once RLS_PLUGIN_PATH . 'includes/class-attack-types.php';
require_once RLS_PLUGIN_PATH . 'includes/class-attack-map.php';
require_once RLS_PLUGIN_PATH . 'includes/class-attack-correlation.php';
require_once RLS_PLUGIN_PATH . 'includes/class-reports.php';
require_once RLS_PLUGIN_PATH . 'includes/class-2fa.php';
require_once RLS_PLUGIN_PATH . 'includes/class-notifications.php';
require_once RLS_PLUGIN_PATH . 'includes/class-antispam.php';
require_once RLS_PLUGIN_PATH . 'includes/class-password-policy.php';
require_once RLS_PLUGIN_PATH . 'includes/class-gdpr.php';
require_once RLS_PLUGIN_PATH . 'includes/class-session.php';
require_once RLS_PLUGIN_PATH . 'includes/class-anomaly.php';
require_once RLS_PLUGIN_PATH . 'includes/class-cache-compat.php';
require_once RLS_PLUGIN_PATH . 'includes/class-health.php';
require_once RLS_PLUGIN_PATH . 'includes/class-multisite.php';
require_once RLS_PLUGIN_PATH . 'includes/class-mode-manager.php';
require_once RLS_PLUGIN_PATH . 'includes/class-webhooks.php';

// Core infrastructure
require_once RLS_PLUGIN_PATH . 'includes/class-api-client.php';
require_once RLS_PLUGIN_PATH . 'includes/class-activator.php';
require_once RLS_PLUGIN_PATH . 'includes/class-cron.php';
require_once RLS_PLUGIN_PATH . 'includes/class-updater.php';
require_once RLS_PLUGIN_PATH . 'includes/class-logger.php';
require_once RLS_PLUGIN_PATH . 'includes/class-geoip.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/class-rls-quarantine.php';

// Scanner & admin
require_once RLS_PLUGIN_PATH . 'includes/scanner/class-scan-history.php';
require_once RLS_PLUGIN_PATH . 'includes/scanner/class-scanner-cache.php';
require_once RLS_PLUGIN_PATH . 'includes/scanner/class-scanner-heuristics.php';
require_once RLS_PLUGIN_PATH . 'includes/scanner/class-scanner-database.php';
require_once RLS_PLUGIN_PATH . 'includes/scanner/class-scanner-checksums.php';
require_once RLS_PLUGIN_PATH . 'includes/scanner/class-scanner-engine.php';
require_once RLS_PLUGIN_PATH . 'includes/admin/class-admin-pages.php';
require_once RLS_PLUGIN_PATH . 'includes/admin/class-dashboard-widget.php';
require_once RLS_PLUGIN_PATH . 'includes/admin/class-monitoring-dashboard.php';
require_once RLS_PLUGIN_PATH . 'includes/admin/class-analytics-page.php';

/**
 * пїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ
 */
register_activation_hook( RLS_PLUGIN_FILE, [ 'RLS_Activator', 'activate' ] );
register_deactivation_hook( RLS_PLUGIN_FILE, [ 'RLS_Activator', 'deactivate' ] );

/**
 * пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ
 */
function rls_run_plugin(): void {
    load_plugin_textdomain(
        'rybinsklab-security',
        false,
        dirname( plugin_basename( RLS_PLUGIN_FILE ) ) . '/languages'
    );

    // Multisite support (no-op on single site)
    ( new RLS_Multisite() )->init();

    // Firewall + WAF (edge)
    ( new RLS_Firewall() )->init();

    // Hardening module (htaccess, headers, version, REST, methods)
    ( new RLS_Hardening() )->init();

    // CAPTCHA module (Google reCAPTCHA / Yandex SmartCaptcha)
    ( new RLS_Captcha() )->init();

    // Login attempts tracker (success/failure analytics)
    ( new RLS_Login_Attempts() )->init();

    // Reports (email + HTML)
    ( new RLS_Reports() )->init();

    // Login protection (brute force, honeypot, captcha)
    ( new RLS_Login_Security() )->init();

    // Two-factor authentication
    ( new RLS_2FA() )->init();

    // Comment spam protection
    ( new RLS_Antispam() )->init();

    // Password policy (HIBP, complexity)
    ( new RLS_Password_Policy() )->init();

    // GDPR compliance
    ( new RLS_GDPR() )->init();

    // Session hardening
    ( new RLS_Session() )->init();

    // Anomaly detection
    ( new RLS_Anomaly() )->init();

    // Cache plugin compatibility
    ( new RLS_Cache_Compat() )->init();

    // Notifications (admin login, brute force, malware)
    ( new RLS_Notifications() )->init();

    // Health check & diagnostics
    ( new RLS_Health() )->init();

    // Webhooks (Slack/Discord/Telegram)
    ( new RLS_Webhooks() )->init();

    // Cron / scheduled tasks
    ( new RLS_Cron() )->init();

    // Auto-updater
    new RLS_Updater(
        RLS_VERSION,
        plugin_basename( RLS_PLUGIN_FILE ),
        RLS_API_URL
    );

    // Admin-only modules
    if ( is_admin() ) {
        ( new RLS_Admin_Pages() )->init();
        ( new RLS_Scanner_Engine() )->init();
        ( new RLS_Dashboard_Widget() )->init();
        ( new RLS_Monitoring_Dashboard() )->init();
        ( new RLS_Analytics_Page() )->init();
    }
}

add_action( 'plugins_loaded', 'rls_run_plugin' );

function rls_seed_geo_database_on_update( $upgrader_object, $options ) {
    if ( empty( $options['action'] ) || $options['action'] !== 'update' ) {
        return;
    }
    if ( empty( $options['type'] ) || $options['type'] !== 'plugin' ) {
        return;
    }
    if ( empty( $options['plugins'] ) || ! is_array( $options['plugins'] ) ) {
        return;
    }
    if ( ! in_array( plugin_basename( RLS_PLUGIN_FILE ), $options['plugins'], true ) ) {
        return;
    }

    if ( class_exists( 'RLS_GeoIP' ) ) {
        // На апдейте перезаписываем seed-файлом, чтобы пользователю доставалась актуальная база из пакета.
        RLS_GeoIP::ensure_seed_database( true );
    }
}
add_action( 'upgrader_process_complete', 'rls_seed_geo_database_on_update', 10, 2 );


