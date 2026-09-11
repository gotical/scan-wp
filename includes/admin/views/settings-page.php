<?php
/**
 * HTML-шаблон для страницы настроек.
 * Версия 1.6.0 (Added: Manual Database Update Buttons)
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

global $rls_settings_section, $rls_settings_initial_tab;

$rls_settings_section = is_string( $rls_settings_section ?? '' ) ? sanitize_key( $rls_settings_section ) : '';
$rls_settings_initial_tab = is_string( $rls_settings_initial_tab ?? '' ) ? sanitize_key( $rls_settings_initial_tab ) : '';
$rls_section_titles = [
    'license'         => 'Лицензия',
    'protection-mode' => 'Режим защиты',
    'firewall'        => 'Фаервол',
    'blacklist'       => 'Черный список',
    'login-security'  => 'Защита входа',
    'settings'        => 'Настройки сканера',
    'hardening'       => 'Hardening',
    '2fa'             => 'Двухфакторная аутентификация',
    'notifications'   => 'Email-уведомления',
];
$rls_section_subtitles = [
    'license'         => 'Статус ключа, Premium-возможности и синхронизация облачных баз.',
    'protection-mode' => 'Выбор уровня защиты сайта без потери расширенных параметров.',
    'firewall'        => 'Правила WAF, XML-RPC, боты, языки, страны и SmartCaptcha.',
    'blacklist'       => 'Белый список, черный список, временные блокировки и облачная база угроз.',
    'login-security'  => 'Контрольные вопросы, honeypot и защита формы входа WordPress.',
    'settings'        => 'Автосканирование, база сигнатур и пользовательские правила поиска.',
    'hardening'       => 'Защита wp-config, блок PHP в uploads, скрытие версии, CSP, REST API.',
    '2fa'             => 'TOTP-аутентификация (Google Authenticator, Authy, 1Password).',
    'notifications'   => 'Уведомления о критических событиях безопасности.',
];
$rls_current_section_title = $rls_section_titles[ $rls_settings_section ] ?? 'Панель защиты сайта';
$rls_current_section_subtitle = $rls_section_subtitles[ $rls_settings_section ] ?? 'Современная панель управления режимами защиты, лицензией, базами угроз, сканером и журналом событий.';
$rls_is_section_page = in_array( $rls_settings_section, [ 'license', 'protection-mode', 'firewall', 'blacklist', 'login-security', 'settings' ], true );

// --- ЛОГИКА РУЧНОЙ ПРОВЕРКИ ЛИЦЕНЗИИ И ОБНОВЛЕНИЯ БАЗ ---
if ( isset( $_POST['rls_action'] ) && $_POST['rls_action'] === 'manual_sync' ) {
    if ( ! check_admin_referer( 'rls_force_sync_nonce', 'rls_sync_nonce_field' ) ) {
        wp_die( 'Ошибка безопасности. Ссылка устарела. Обновите страницу.' );
    }

    $set = get_option( 'rls_settings', [] );
    $key = $set['license_key'] ?? '';

    if ( ! empty( $key ) ) {
        if ( class_exists( 'RLS_Cron' ) ) {
            RLS_Cron::sync_detailed_stats();
        }

        $res = RLS_API_Client::validate_license_key( $key );

        if ( is_array( $res ) && isset( $res['status'] ) && $res['status'] === 'success' ) {
            rls_store_license_meta( 'valid', (array) ( $res['data'] ?? [] ) );

            $sig_res = RLS_API_Client::get_signatures( $key );
            if ( isset( $sig_res['status'] ) && $sig_res['status'] === 'success' ) {
                update_option( 'rls_premium_signatures', $sig_res['data']['signatures'] );
            }

            $ip_res = RLS_API_Client::get_global_blacklist();
            if ( isset( $ip_res['status'] ) && $ip_res['status'] === 'success' ) {
                if ( ! empty( $ip_res['data']['ips'] ) ) {
                    update_option( 'rls_global_blacklist', $ip_res['data']['ips'], false );
                }
            }

            add_settings_error( 'rls_messages', 'rls_success', 'Успешно! Лицензия подтверждена, базы сигнатур и IP обновлены.', 'updated' );
        } else {
            rls_store_license_meta( 'invalid' );
            update_option( 'rls_premium_signatures', [] );
            if ( is_wp_error( $res ) ) {
                $error_message = $res->get_error_message();
            } elseif ( is_array( $res ) && ! empty( $res['message'] ) ) {
                $error_message = (string) $res['message'];
            } else {
                $error_message = 'Ключ недействителен или срок действия истек.';
            }

            add_settings_error( 'rls_messages', 'rls_error', 'Ошибка: ' . esc_html( $error_message ), 'error' );
        }
    } else {
        add_settings_error( 'rls_messages', 'rls_error', 'Пожалуйста, сначала введите и сохраните лицензионный ключ.', 'error' );
    }
}

if ( isset( $_POST['rls_action'] ) && $_POST['rls_action'] === 'sync_blacklists' ) {
    if ( ! check_admin_referer( 'rls_force_sync_nonce', 'rls_sync_nonce_field' ) ) {
        wp_die( 'Ошибка безопасности. Ссылка устарела. Обновите страницу.' );
    }

    if ( class_exists( 'RLS_Cron' ) ) {
        $response = RLS_Cron::sync_local_blacklists( true );

        if ( is_wp_error( $response ) ) {
            add_settings_error( 'rls_messages', 'rls_sync_error', 'Ошибка синхронизации IP: ' . esc_html( $response->get_error_message() ), 'error' );
        } else {
            $processed = 0;
            if ( is_array( $response ) ) {
                if ( isset( $response['data']['processed'] ) ) {
                    $processed = (int) $response['data']['processed'];
                } elseif ( isset( $response['processed'] ) ) {
                    $processed = (int) $response['processed'];
                }
            }

            add_settings_error( 'rls_messages', 'rls_sync_success', 'Локальные IP отправлены на сервер. Обработано: ' . intval( $processed ), 'updated' );
        }
    } else {
        add_settings_error( 'rls_messages', 'rls_sync_error', 'Модуль синхронизации недоступен.', 'error' );
    }
}

if ( isset( $_POST['rls_action'] ) && in_array( $_POST['rls_action'], [ 'download_ip2location_db', 'update_ip2location_db' ], true ) ) {
    if ( ! check_admin_referer( 'rls_download_ip2location_nonce', 'rls_download_ip2location_nonce_field' ) ) {
        wp_die( 'Ошибка безопасности. Обновите страницу и попробуйте снова.' );
    }
    if ( get_option( 'rls_license_status' ) !== 'valid' ) {
        add_settings_error( 'rls_messages', 'rls_geo_premium_only', 'Обновление GeoIP базы доступно только в Premium.', 'error' );
    } else {
        if ( class_exists( 'RLS_GeoIP' ) ) {
            $download_result = RLS_GeoIP::download_lite_database();
            if ( is_wp_error( $download_result ) ) {
                add_settings_error( 'rls_messages', 'rls_geo_error', 'Ошибка загрузки GeoIP базы: ' . esc_html( $download_result->get_error_message() ), 'error' );
            } else {
                add_settings_error( 'rls_messages', 'rls_geo_success', 'База IP2Location успешно загружена.', 'updated' );
            }
        }
    }
}

// --- ПОДГОТОВКА ДАННЫХ ---
$license_status_for_refresh = '';
if ( ! isset( $_POST['rls_action'] ) ) {
    $settings_for_license = get_option( 'rls_settings', [] );
    $license_key_for_refresh = trim( (string) ( $settings_for_license['license_key'] ?? '' ) );
    $license_status_for_refresh = (string) get_option( 'rls_license_status', '' );

    // SECURITY: auto-refresh requires an explicit user action OR a recent transient
    // (set by an admin request) to avoid CSRF-driven API calls on every page load.
    $refresh_allowed = (
        isset( $_GET['rls_license_refresh'] )
        || ( current_user_can( 'manage_options' ) && get_transient( 'rls_license_refresh_requested' ) )
    );

    if ( $refresh_allowed && $license_key_for_refresh !== '' && $license_status_for_refresh !== 'valid' && class_exists( 'RLS_API_Client' ) ) {
        delete_transient( 'rls_license_refresh_requested' );
        $license_refresh = RLS_API_Client::validate_license_key( $license_key_for_refresh );

        if ( is_array( $license_refresh ) && ( $license_refresh['status'] ?? '' ) === 'success' ) {
            rls_store_license_meta( 'valid', (array) ( $license_refresh['data'] ?? [] ) );

            if ( class_exists( 'RLS_Cron' ) ) {
                RLS_Cron::sync_detailed_stats();
            }
        } elseif ( is_wp_error( $license_refresh ) ) {
            add_settings_error(
                'rls_messages',
                'rls_license_refresh_error',
                'Не удалось проверить лицензию автоматически: ' . esc_html( $license_refresh->get_error_message() ),
                'error'
            );
        } elseif ( $license_status_for_refresh !== 'invalid' ) {
            rls_store_license_meta( 'invalid' );
        }
    }
}

$settings = get_option( 'rls_settings', [] );
$license_key = $settings['license_key'] ?? '';
$license_status = get_option( 'rls_license_status' );
$license_ui = function_exists( 'rls_get_license_ui_state' ) ? rls_get_license_ui_state() : [];
$is_premium = ! empty( $license_ui['is_premium'] );
$premium_buy_url = 'https://rybinsklab.ru/scan-wp/';
$setup_completed = (int) get_option( 'rls_setup_completed', 0 ) === 1;
$is_setup_flow = isset( $_GET['rls-setup'] ) && $_GET['rls-setup'] === '1';

$whitelist = get_option( 'rls_ip_whitelist', [] );
$blacklist = get_option( 'rls_manual_blacklist', [] );
$global_blacklist = get_option( 'rls_global_blacklist', [] );
$blocked_ips = get_option( 'rls_blocked_ips', [] );
$locked_ips = get_option( 'rls_locked_ips', [] );

$base_sigs = get_option( 'rls_base_signatures', [] );
$premium_sigs = get_option( 'rls_premium_signatures', [] );
$custom_sigs = get_option( 'rls_custom_signatures', [] );
$total_sigs = count($base_sigs) + count($premium_sigs) + count($custom_sigs);

$all_login_questions = get_option( 'rls_login_questions', [] );
$geo_db_path = class_exists( 'RLS_GeoIP' ) ? RLS_GeoIP::get_database_path() : '';
$geo_db_exists = ! empty( $geo_db_path ) && file_exists( $geo_db_path );
$protection_mode_ui = function_exists( 'rls_get_protection_mode_ui_state' ) ? rls_get_protection_mode_ui_state() : [];
$protection_mode = $protection_mode_ui['mode'] ?? 'full';
$global_blacklist_manual_enabled = ! empty( $settings['global_blacklist_enabled'] );
$global_blacklist_runtime_enabled = function_exists( 'rls_is_global_blacklist_runtime_enabled' )
    ? rls_is_global_blacklist_runtime_enabled( $settings )
    : $global_blacklist_manual_enabled;
$global_blacklist_toggle_disabled = ! $is_premium || $protection_mode !== 'light';
$global_blacklist_hint = 'В легкой защите облачный blacklist выключен по умолчанию и может быть включен вручную.';

if ( ! $is_premium ) {
    $global_blacklist_hint = 'Этот пункт доступен только для премиум пользователей с активированной лицензией.';
} elseif ( $protection_mode === 'full' ) {
    $global_blacklist_hint = 'В полной защите облачный blacklist включается автоматически.';
} elseif ( $protection_mode === 'scanner_only' ) {
    $global_blacklist_hint = 'В режиме только сканер облачный blacklist не применяется.';
}
$mode_label = $protection_mode_ui['label'] ?? 'Полная защита';
$license_headline = $license_ui['headline'] ?? 'Бесплатная версия';
$license_subline = $license_ui['remaining_text'] ?? '';
if ( $license_subline === '' ) {
    $license_subline = $license_ui['expires_text'] ?? '';
}
if ( $license_subline === '' ) {
    $license_subline = $license_ui['status_text'] ?? 'Защита активна и готова к работе.';
}
$geo_status_label = $geo_db_exists ? 'GeoIP база подключена' : 'GeoIP база не загружена';
$geo_status_hint = $geo_db_exists ? 'Фильтрация по странам доступна в полном режиме.' : 'Загрузите базу, чтобы включить фильтрацию по странам.';
$signature_status_label = $total_sigs . ' сигнатур';
$signature_status_hint = 'Базовые, premium и пользовательские правила уже готовы к проверке файлов.';
$log_type_labels = [
    'all' => 'Все',
    'waf' => 'WAF',
    'geo' => 'GEO',
    'blacklist' => 'BLACKLIST',
    'language' => 'LANGUAGE',
    'brute' => 'BRUTE',
    'bot' => 'BOT',
    'virus' => 'VIRUS',
    'sqli' => 'SQLI',
    'xss' => 'XSS',
    'rce' => 'RCE',
    'lfi' => 'LFI',
    'manual' => 'MANUAL',
    'unknown' => 'UNKNOWN',
];
$selected_log_type = isset( $_GET['rls_log_type'] ) ? sanitize_key( (string) $_GET['rls_log_type'] ) : 'all';
if ( ! isset( $log_type_labels[ $selected_log_type ] ) ) {
    $selected_log_type = 'all';
}
$selected_log_view = isset( $_GET['rls_logs_view'] ) ? sanitize_key( (string) $_GET['rls_logs_view'] ) : 'recent';
if ( ! in_array( $selected_log_view, [ 'recent', 'all' ], true ) ) {
    $selected_log_view = 'recent';
}
$log_limit = ( $selected_log_view === 'all' ) ? 0 : 50;
$logs = class_exists( 'RLS_Logger' ) ? RLS_Logger::get_logs( $log_limit, $selected_log_type ) : [];
$logs_count = class_exists( 'RLS_Logger' ) ? RLS_Logger::get_logs_count( $selected_log_type ) : 0;
$log_types = class_exists( 'RLS_Logger' ) ? RLS_Logger::get_log_types() : [];
if ( ! empty( $log_types ) ) {
    foreach ( $log_types as $log_type ) {
        if ( ! isset( $log_type_labels[ $log_type ] ) ) {
            $log_type_labels[ $log_type ] = strtoupper( $log_type );
        }
    }
}
?>

<div class="wrap rls-wrap <?php echo $rls_is_section_page ? 'rls-section-mode' : ''; ?>" data-rls-initial-tab="<?php echo esc_attr( $rls_settings_initial_tab ); ?>" data-rls-section="<?php echo esc_attr( $rls_settings_section ); ?>">
    <h1 class="screen-reader-text">
        Rybinsk Lab Security 
        <span style="font-size: 13px; color: #666; font-weight:normal; background:#e0e0e0; padding:2px 6px; border-radius:4px;">v<?php echo RLS_VERSION; ?></span>
        <span style="font-size: 13px; color: <?php echo esc_attr( $license_ui['badge_color'] ?? '#333333' ); ?>; font-weight:600; background:<?php echo esc_attr( $license_ui['badge_background'] ?? '#e5e5e5' ); ?>; padding:2px 8px; border-radius:999px; margin-left:8px;"><?php echo esc_html( $license_ui['headline'] ?? 'Бесплатная версия' ); ?></span>
    </h1>

    <div class="rls-page-hero">
        <div class="rls-page-hero-top">
            <div>
                <div class="rls-page-kicker">Rybinsk Lab Security</div>
                <h1 class="rls-page-title">
                    <?php echo esc_html( $rls_current_section_title ); ?>
                    <span class="rls-page-version">v<?php echo RLS_VERSION; ?></span>
                </h1>
                <p class="rls-page-subtitle"><?php echo esc_html( $rls_current_section_subtitle ); ?></p>
            </div>
            <div class="rls-hero-actions">
                <button type="button" class="button button-secondary" onclick="document.getElementById('rls-manual-sync-form').submit();">
                    <span class="dashicons dashicons-cloud-upload" style="line-height:1.3"></span> <?php echo $is_premium ? 'Проверить лицензию и обновить базы' : 'Проверить лицензию'; ?>
                </button>
                <button type="button" class="button button-secondary" onclick="document.getElementById('rls-sync-blacklists-form').submit();">
                    <span class="dashicons dashicons-shield" style="line-height:1.3"></span> Отправить локальные IP
                </button>
                <?php if ( $is_premium ): ?>
                    <button type="button" class="button button-secondary" onclick="document.getElementById('rls-download-geo-form').submit();">
                        <span class="dashicons dashicons-download" style="line-height:1.3"></span> Загрузить IP2Location DB1
                    </button>
                <?php else: ?>
                    <a class="button button-primary" target="_blank" rel="noopener noreferrer" href="<?php echo esc_url( $premium_buy_url ); ?>">Купить ключ Premium</a>
                <?php endif; ?>
            </div>
        </div>
        <div class="rls-page-stats">
            <div class="rls-stat-card">
                <span class="rls-stat-label">Режим защиты</span>
                <strong class="rls-stat-value"><?php echo esc_html( $mode_label ); ?></strong>
                <span class="rls-stat-note"><?php echo esc_html( $protection_mode_ui['status_text'] ?? 'Выбранный режим уже применяется к сайту.' ); ?></span>
            </div>
            <div class="rls-stat-card">
                <span class="rls-stat-label">Лицензия</span>
                <strong class="rls-stat-value"><?php echo esc_html( $license_headline ); ?></strong>
                <span class="rls-stat-note"><?php echo esc_html( $license_subline ); ?></span>
            </div>
            <div class="rls-stat-card">
                <span class="rls-stat-label">Сигнатуры</span>
                <strong class="rls-stat-value"><?php echo esc_html( $signature_status_label ); ?></strong>
                <span class="rls-stat-note"><?php echo esc_html( $signature_status_hint ); ?></span>
            </div>
            <div class="rls-stat-card">
                <span class="rls-stat-label">GeoIP</span>
                <strong class="rls-stat-value"><?php echo esc_html( $geo_status_label ); ?></strong>
                <span class="rls-stat-note"><?php echo esc_html( $geo_status_hint ); ?></span>
            </div>
        </div>
    </div>

    <?php settings_errors( 'rls_messages' ); ?>

    <div class="rls-section-nav" aria-label="Разделы Rybinsk Lab Security">
        <?php
$rls_section_nav = [
    'license'         => [ 'label' => 'Лицензия', 'icon' => 'dashicons-admin-network', 'page' => 'rls-license' ],
    'protection-mode' => [ 'label' => 'Режим защиты', 'icon' => 'dashicons-shield-alt', 'page' => 'rls-protection-mode' ],
    'firewall'        => [ 'label' => 'Фаервол', 'icon' => 'dashicons-shield', 'page' => 'rls-firewall' ],
    'blacklist'       => [ 'label' => 'Черный список', 'icon' => 'dashicons-networking', 'page' => 'rls-blacklist' ],
    'login-security'  => [ 'label' => 'Защита входа', 'icon' => 'dashicons-lock', 'page' => 'rls-login-security' ],
    'hardening'       => [ 'label' => 'Hardening', 'icon' => 'dashicons-shield-alt', 'page' => 'rls-hardening' ],
    '2fa'             => [ 'label' => '2FA', 'icon' => 'dashicons-smartphone', 'page' => 'rls-2fa' ],
    'notifications'   => [ 'label' => 'Уведомления', 'icon' => 'dashicons-email-alt', 'page' => 'rls-notifications' ],
    'settings'        => [ 'label' => 'Настройки', 'icon' => 'dashicons-admin-generic', 'page' => 'rls-settings' ],
    'policy'          => [ 'label' => 'Условия и политика', 'icon' => 'dashicons-media-document', 'page' => 'rls-policy' ],
];
        foreach ( $rls_section_nav as $section_key => $section_item ) :
            $section_url = add_query_arg( 'page', $section_item['page'], admin_url( 'admin.php' ) );
            $section_active = ( $section_key === $rls_settings_section ) || ( $section_key === 'settings' && $rls_settings_section === '' );
            ?>
            <a class="rls-section-link <?php echo $section_active ? 'is-active' : ''; ?>" href="<?php echo esc_url( $section_url ); ?>">
                <span class="dashicons <?php echo esc_attr( $section_item['icon'] ); ?>"></span>
                <span><?php echo esc_html( $section_item['label'] ); ?></span>
            </a>
        <?php endforeach; ?>
    </div>

    <?php if ( ! $setup_completed ): ?>
        <div class="notice notice-info" style="padding:12px 14px; margin:12px 0 18px;">
            <p style="margin:0 0 8px;"><strong><?php echo $is_setup_flow ? 'Добро пожаловать в мастер первой настройки' : 'Первичная настройка плагина'; ?></strong></p>
            <p style="margin:0 0 8px;">Выберите один из трех режимов: <strong>Легкая защита</strong>, <strong>Полная защита</strong> или <strong>Только сканер вирусов</strong>, затем сохраните настройки.</p>
            <p style="margin:0;">После первого сохранения этот мастер будет скрыт, но вы всегда сможете переключить режим позже.</p>
        </div>
    <?php endif; ?>
    
    <!-- НАВИГАЦИЯ ПО ВКЛАДКАМ -->
    <div class="nav-tab-wrapper rls-nav-tabs" style="margin-bottom: 20px;">
        <a href="#tab-general" class="nav-tab nav-tab-active"><span class="dashicons dashicons-admin-generic"></span> Основные настройки</a>
        <a href="#tab-firewall" class="nav-tab" data-rls-visible-modes="light,full"><span class="dashicons dashicons-shield"></span> Фаервол (WAF)</a>
        <a href="#tab-lists" class="nav-tab" data-rls-visible-modes="light,full"><span class="dashicons dashicons-networking"></span> IP списки</a>
        <a href="#tab-scanner" class="nav-tab"><span class="dashicons dashicons-search"></span> Сканер и сигнатуры</a>
        <a href="#tab-logs" class="nav-tab rls-nav-tab-accent" data-rls-visible-modes="light,full"><span class="dashicons dashicons-list-view"></span> Журнал атак</a>
    </div>

    <!-- ГЛАВНАЯ ФОРМА СОХРАНЕНИЯ (ОДНА НА ВСЕ ВКЛАДКИ) -->
    <form method="post" action="options.php">
        <?php settings_fields( 'rls_settings_group' ); ?>
        
        <!-- ТАБ 1: ОСНОВНЫЕ -->
        <div class="rls-tab-content active" id="tab-general">

            <!-- Режим защиты управляется на отдельной странице: rls-protection-mode -->
            <div class="rls-box" data-rls-section-box="protection-mode">
                <h2><span class="dashicons dashicons-shield"></span> Режим работы защиты</h2>
                <p>Управление режимами, пресетами и аварийными режимами вынесено на отдельную страницу с предпросмотром изменений.</p>
                <p>
                    <a href="<?php echo esc_url( admin_url( 'admin.php?page=rls-protection-mode' ) ); ?>" class="button button-primary">
                        Открыть управление режимами →
                    </a>
                </p>
                <p style="margin-top:14px; padding:10px 12px; background:var(--rls-surface-alt); border-radius:var(--rls-radius-sm); font-size:13px; color:var(--rls-text-muted);">
                    <strong style="color:var(--rls-text);">Текущий профиль:</strong> <?php echo esc_html( $protection_mode_ui['label'] ?? 'Стандарт' ); ?>.
                    <?php if ( function_exists( 'rls_get_protection_mode' ) && rls_get_protection_mode() === 'scanner_only' ) : ?>
                        <br><span style="color: var(--rls-danger); font-weight: 600;">⚠ Защитные модули отключены.</span>
                    <?php endif; ?>
                </p>
            </div>
            
            <div class="rls-box" data-rls-section-box="license">
                <h2><span class="dashicons dashicons-admin-network"></span> Лицензия и Статус</h2>
                <p>Введите ключ активации для доступа к облачным базам угроз и автоматическим обновлениям.</p>
                
                <div class="rls-license-panel">
                    <div class="rls-license-panel-main">
                        <span class="rls-license-badge" style="color: <?php echo esc_attr( $license_ui['badge_color'] ?? '#333333' ); ?>; background:<?php echo esc_attr( $license_ui['badge_background'] ?? '#e5e5e5' ); ?>;">
                            <?php echo esc_html( $license_ui['headline'] ?? 'Бесплатная версия' ); ?>
                        </span>
                        <strong class="rls-license-title"><?php echo esc_html( $license_headline ); ?></strong>
                        <span class="rls-license-subtitle"><?php echo esc_html( $license_subline ); ?></span>
                    </div>
                    <div class="rls-license-panel-meta">
                        <?php if ( ! empty( $license_ui['expires_text'] ) ): ?>
                            <div class="rls-license-meta-item">
                                <span>Срок действия</span>
                                <strong><?php echo esc_html( $license_ui['expires_text'] ); ?></strong>
                            </div>
                        <?php endif; ?>
                        <?php if ( ! empty( $license_ui['domains_text'] ) ): ?>
                            <div class="rls-license-meta-item">
                                <span>Подключения</span>
                                <strong><?php echo esc_html( $license_ui['domains_text'] ); ?></strong>
                            </div>
                        <?php endif; ?>
                        <div class="rls-license-meta-item">
                            <span>Обновления</span>
                            <strong><?php echo $is_premium ? 'Автоматические обновления доступны' : 'Доступны после активации Premium'; ?></strong>
                        </div>
                    </div>
                </div>

                <table class="form-table rls-form-table-modern">
                    <tr>
                        <th scope="row">Ключ активации</th>
                        <td>
                            <input type="text" name="rls_settings[license_key]" value="<?php echo esc_attr( $license_key ); ?>" class="regular-text" placeholder="SCANWP-XXXX-XXXX" />
                            <div style="margin-top:8px; display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
                                <button type="button" class="button button-primary" id="rls-license-refresh-button">
                                    Обновить статус лицензии
                                </button>
                                <button type="button" class="button button-secondary" id="rls-license-delete-button">
                                    Удалить ключ
                                </button>
                            </div>
                            <p class="description" style="margin-top:6px;">Нажмите Enter, чтобы сохранить и сразу проверить ключ.</p>
                            <br>
                            <div style="margin-top: 10px;">
                                 <strong>Текущий статус:</strong>
                                  <span style="color: <?php echo esc_attr( $license_ui['badge_color'] ?? '#333333' ); ?>; font-weight:bold; background:<?php echo esc_attr( $license_ui['badge_background'] ?? '#e5e5e5' ); ?>; padding:2px 8px; border-radius:4px; border:1px solid rgba(0,0,0,0.08);">
                                    <?php echo esc_html( $license_ui['headline'] ?? 'Бесплатная версия' ); ?>
                                  </span>
                            </div>
                            <?php if ( ! empty( $license_ui['status_text'] ) ): ?>
                                <div style="margin-top:10px; color:#1d2327;">
                                    <?php echo esc_html( $license_ui['status_text'] ); ?>
                                </div>
                            <?php endif; ?>
                            <?php if ( ! empty( $license_ui['remaining_text'] ) ): ?>
                                <div style="margin-top:6px; color:#2271b1; font-weight:600;">
                                    <?php echo esc_html( $license_ui['remaining_text'] ); ?>
                                </div>
                            <?php endif; ?>
                            <?php if ( ! empty( $license_ui['expires_text'] ) ): ?>
                                <div style="margin-top:6px; color:#50575e;">
                                    <?php echo esc_html( $license_ui['expires_text'] ); ?>
                                </div>
                            <?php endif; ?>
                            <?php if ( ! empty( $license_ui['domains_text'] ) ): ?>
                                <div style="margin-top:6px; color:#50575e;">
                                    <?php echo esc_html( $license_ui['domains_text'] ); ?>
                                </div>
                            <?php endif; ?>
                        </td>
                    </tr>
                </table>
            </div>
            
            <div class="rls-box" data-rls-visible-modes="light,full" data-rls-section-box="login-security">
                <h2><span class="dashicons dashicons-lock"></span> Защита Входа (Anti-BruteForce)</h2>
                <p>Настройки для защиты страницы <code>wp-login.php</code> от подбора паролей.</p>
                
                <table class="form-table">
                    <tr>
                        <th scope="row">Активация</th>
                        <td>
                            <label>
                                <input type="checkbox" name="rls_settings[enable_login_security]" id="rls_enable_login_security_cb" value="1" <?php checked( 1, $settings['enable_login_security'] ?? 0 ); ?> /> 
                                <strong>Включить "Контрольные вопросы" и скрытую ловушку (Honeypot)</strong>
                            </label>
                            <p class="description">Добавляет поле с вопросом на форму входа. Боты не умеют на них отвечать.</p>
                        </td>
                    </tr>
                </table>
                
                <div class="rls-inner-panel">
                    <h3>Yandex SmartCaptcha</h3>
                    <p class="description">Бесплатные ключи: <a href="https://yandex.cloud/ru/docs/smartcaptcha/quickstart" target="_blank" rel="noopener noreferrer">инструкция получения ключей</a></p>
                    <p>
                        <label style="display:block; margin-bottom:6px;">
                            <input type="checkbox" name="rls_settings[captcha_enabled_admin]" value="1" <?php checked( 1, $settings['captcha_enabled_admin'] ?? 0 ); ?> />
                            Включить капчу для входа в админку
                        </label>
                        <label style="display:block;">
                            <input type="checkbox" name="rls_settings[captcha_enabled_users]" value="1" <?php checked( 1, $settings['captcha_enabled_users'] ?? 0 ); ?> />
                            Включить капчу для входа пользователей
                        </label>
                    </p>
                    <p><input type="text" name="rls_settings[captcha_client_key]" class="regular-text" style="width:100%; max-width:560px;" value="<?php echo esc_attr( $settings['captcha_client_key'] ?? '' ); ?>" placeholder="Client key" /></p>
                    <p><input type="text" name="rls_settings[captcha_server_key]" class="regular-text" style="width:100%; max-width:560px;" value="<?php echo esc_attr( $settings['captcha_server_key'] ?? '' ); ?>" placeholder="Server key" /></p>
                    <p class="description">По умолчанию выключено. Для работы нужны оба ключа.</p>
                </div>

                <div class="login-questions-settings-row rls-inner-panel">
                    <h3>Настройка вопросов</h3>
                    <p>Количество вопросов при входе: 
                        <select name="rls_settings[login_questions_count]">
                            <option value="1" <?php selected( $settings['login_questions_count'] ?? 1, 1 ); ?>>1</option>
                            <option value="2" <?php selected( $settings['login_questions_count'] ?? 1, 2 ); ?>>2</option>
                            <option value="3" <?php selected( $settings['login_questions_count'] ?? 1, 3 ); ?>>3</option>
                        </select>
                    </p>
                    
                    <table class="wp-list-table widefat striped fixed" style="margin-bottom: 10px;">
                        <thead><tr><th>Вопрос</th><th style="width: 80px;">Действие</th></tr></thead>
                        <tbody id="rls-login-questions-tbody">
                            <?php if ( empty( $all_login_questions ) ): ?>
                                <tr class="no-items"><td colspan="2">Список вопросов пуст. Добавьте хотя бы один.</td></tr>
                            <?php else: foreach ( $all_login_questions as $key => $q_data ): ?>
                                <?php
                                $q_data = is_object( $q_data ) ? (array) $q_data : $q_data;
                                $question_text = is_array( $q_data ) ? ( $q_data['q'] ?? ( $q_data['question'] ?? '' ) ) : '';
                                ?>
                                <tr data-key="<?php echo esc_attr( $key ); ?>">
                                    <td><?php echo esc_html( $question_text ); ?></td>
                                    <td><button class="button-link-delete rls-delete-login-question-button" style="color:#b32d2e;">Удалить</button></td>
                                </tr>
                            <?php endforeach; endif; ?>
                        </tbody>
                    </table>
                    
                    <div style="display:flex; gap:10px; align-items:center;">
                        <input type="text" id="rls-new-login-question" placeholder="Вопрос (Например: 2+2?)" class="regular-text" style="flex:1;">
                        <input type="text" id="rls-new-login-answer" placeholder="Ответ (4)" class="regular-text" style="flex:1;">
                        <button id="rls-add-login-question-button" class="button button-secondary">Добавить</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- ТАБ 2: ФАЕРВОЛ -->
        <div class="rls-tab-content" id="tab-firewall" data-rls-visible-modes="light,full" data-rls-section-box="firewall">
            <div class="rls-box">
                <h2><span class="dashicons dashicons-shield"></span> Настройки WAF (Web Application Firewall)</h2>
                <p>Фаервол анализирует весь входящий трафик и блокирует хакерские запросы до того, как они навредят сайту.</p>
                
                <table class="form-table">
                    <tr>
                        <th scope="row">Основная защита</th>
                        <td>
                            <label>
                                <input type="checkbox" name="rls_settings[enable_firewall]" value="1" <?php checked( 1, $settings['enable_firewall'] ?? 0 ); ?> /> 
                                <strong>Включить WAF</strong>
                            </label>
                            <p class="description">Защищает от SQL-инъекций, XSS, RCE-атак и подозрительных ботов.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Протокол XML-RPC</th>
                        <td>
                            <label>
                                <input type="checkbox" name="rls_settings[disable_xmlrpc]" value="1" <?php checked( 1, $settings['disable_xmlrpc'] ?? 0 ); ?> /> 
                                <strong>Блокировать доступ к <code>xmlrpc.php</code></strong>
                            </label>
                            <p class="description">Рекомендуется включить. Через этот файл часто проводят DDoS-атаки и перебор паролей. Отключите, если используете Jetpack.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Проверка IP-списков</th>
                        <td>
                            <label>
                                <input type="checkbox" name="rls_settings[blacklists_enabled]" value="1" <?php checked( 1, $settings['blacklists_enabled'] ?? 1 ); ?> />
                                <strong>Проверять локальные списки IP (ручной blacklist + временные баны)</strong>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Облачный blacklist</th>
                        <td>
                            <label>
                                <input
                                    type="checkbox"
                                    id="rls-global-blacklist-enabled"
                                    name="rls_settings[global_blacklist_enabled]"
                                    value="1"
                                    data-rls-global-blacklist-toggle="1"
                                    data-premium-available="<?php echo $is_premium ? '1' : '0'; ?>"
                                    <?php checked( 1, $global_blacklist_runtime_enabled ? 1 : 0 ); ?>
                                    <?php disabled( $global_blacklist_toggle_disabled ); ?>
                                />
                                <strong>Проверять IP по глобальной базе угроз (Rybinsk Lab)</strong>
                            </label>
                                <p class="description">Глобальная облачная база доступна в Premium.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Cloudflare / Proxy</th>
                        <td>
                            <label>
                                <input type="checkbox" name="rls_settings[trust_cloudflare]" value="1" <?php checked( 1, $settings['trust_cloudflare'] ?? 0 ); ?> /> 
                                <strong>Я использую Cloudflare (или другой прокси)</strong>
                            </label>
                            <p class="description">Включите это, если реальный IP посетителя не определяется. Плагин будет смотреть заголовок <code>CF-Connecting-IP</code>.</p>
                            <p class="description"><strong>Важно:</strong> если сайт работает за Cloudflare/Reverse Proxy и опция выключена, геоблокировка может определять страну неверно.</p>
                        </td>
                    </tr>
                </table>
                
                <div class="rls-mode-inline-note" data-rls-mode-notice="light">
                    В легком режиме скрыты расширенные блоки по языкам, ботам и GeoIP, чтобы интерфейс оставался проще.
                </div>

                <div data-rls-visible-modes="full">
                <hr>
                <h3>Доступ по языку браузера (Accept-Language)</h3>
                <table class="form-table">
                    <tr>
                        <th scope="row">Включить фильтр</th>
                        <td>
                            <label>
                                <input type="checkbox" name="rls_settings[language_filter_enabled]" value="1" <?php checked( 1, $settings['language_filter_enabled'] ?? 0 ); ?> />
                                <strong>Проверять язык браузера до GeoIP</strong>
                            </label>
                            <p class="description">Если у клиента нет заголовка языка, доступ будет запрещен (когда фильтр включен).</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Режим</th>
                        <td>
                            <?php $lang_mode = $settings['language_mode'] ?? 'allow'; ?>
                            <label style="margin-right:20px;">
                                <input type="radio" name="rls_settings[language_mode]" value="allow" <?php checked( $lang_mode, 'allow' ); ?> />
                                Разрешить только выбранные языки
                            </label>
                            <label>
                                <input type="radio" name="rls_settings[language_mode]" value="block" <?php checked( $lang_mode, 'block' ); ?> />
                                Блокировать выбранные языки
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Коды языков</th>
                        <td>
                            <?php $lang_codes = (array) ( $settings['language_codes'] ?? [ 'ru', 'uk', 'kk' ] ); ?>
                            <input type="text" name="rls_settings[language_codes]" value="<?php echo esc_attr( implode( ',', $lang_codes ) ); ?>" class="regular-text" style="width:100%;max-width:460px;" placeholder="ru,uk,kk">
                            <p class="description">Используйте коды через запятую: например, <code>ru,uk,kk</code>.</p>
                        </td>
                    </tr>
                </table>

                <hr>
                <div class="rls-bot-panel">
                    <h3>Разрешенные поисковые и AI-боты</h3>
                    <p class="description">Отметьте ботов, которых нужно пропускать. При включенной мягкой проверке сомнительные боты логируются без немедленного бана.</p>

                    <div class="rls-bot-toolbar">
                        <label class="rls-bot-soft-mode">
                            <input type="checkbox" name="rls_settings[soft_search_bot_mode]" value="1" <?php checked( 1, $settings['soft_search_bot_mode'] ?? 1 ); ?>>
                            <span>Мягкий режим проверки ботов</span>
                        </label>
                        <div class="rls-bot-actions">
                            <button type="button" class="button button-secondary rls-bot-select-btn" data-mode="recommended">Рекомендованные</button>
                            <button type="button" class="button button-secondary rls-bot-select-btn" data-mode="all">Выбрать все</button>
                            <button type="button" class="button button-secondary rls-bot-select-btn" data-mode="none">Снять все</button>
                        </div>
                    </div>

                    <div class="rls-bot-group">
                        <h4>Поисковые системы</h4>
                        <div class="rls-bot-grid">
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="search" data-bot-recommended="1" type="checkbox" name="rls_settings[allow_googlebot]" value="1" <?php checked( 1, $settings['allow_googlebot'] ?? 1 ); ?>><strong>Googlebot</strong><span>Google Search</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="search" data-bot-recommended="1" type="checkbox" name="rls_settings[allow_yandexbot]" value="1" <?php checked( 1, $settings['allow_yandexbot'] ?? 1 ); ?>><strong>Yandex Bot</strong><span>Yandex Search</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="search" data-bot-recommended="1" type="checkbox" name="rls_settings[allow_bingbot]" value="1" <?php checked( 1, $settings['allow_bingbot'] ?? 0 ); ?>><strong>Bingbot</strong><span>Microsoft Bing</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="search" data-bot-recommended="1" type="checkbox" name="rls_settings[allow_duckduckbot]" value="1" <?php checked( 1, $settings['allow_duckduckbot'] ?? 0 ); ?>><strong>DuckDuckBot</strong><span>DuckDuckGo</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="search" data-bot-recommended="0" type="checkbox" name="rls_settings[allow_applebot]" value="1" <?php checked( 1, $settings['allow_applebot'] ?? 0 ); ?>><strong>Applebot</strong><span>Apple Search</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="search" data-bot-recommended="0" type="checkbox" name="rls_settings[allow_mailru_bot]" value="1" <?php checked( 1, $settings['allow_mailru_bot'] ?? 0 ); ?>><strong>Mail.ru Bot</strong><span>Mail.ru Search</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="search" data-bot-recommended="0" type="checkbox" name="rls_settings[allow_baiduspider]" value="1" <?php checked( 1, $settings['allow_baiduspider'] ?? 0 ); ?>><strong>BaiduSpider</strong><span>Baidu Search</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="search" data-bot-recommended="0" type="checkbox" name="rls_settings[allow_slurp]" value="1" <?php checked( 1, $settings['allow_slurp'] ?? 0 ); ?>><strong>Yahoo Slurp</strong><span>Yahoo Search</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="search" data-bot-recommended="0" type="checkbox" name="rls_settings[allow_seznambot]" value="1" <?php checked( 1, $settings['allow_seznambot'] ?? 0 ); ?>><strong>SeznamBot</strong><span>Seznam Search</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="search" data-bot-recommended="0" type="checkbox" name="rls_settings[allow_naverbot]" value="1" <?php checked( 1, $settings['allow_naverbot'] ?? 0 ); ?>><strong>NaverBot</strong><span>Naver Search</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="search" data-bot-recommended="0" type="checkbox" name="rls_settings[allow_petalbot]" value="1" <?php checked( 1, $settings['allow_petalbot'] ?? 0 ); ?>><strong>PetalBot</strong><span>Huawei Petal Search</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="search" data-bot-recommended="0" type="checkbox" name="rls_settings[allow_sogou]" value="1" <?php checked( 1, $settings['allow_sogou'] ?? 0 ); ?>><strong>Sogou Spider</strong><span>Sogou Search</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="search" data-bot-recommended="0" type="checkbox" name="rls_settings[allow_exabot]" value="1" <?php checked( 1, $settings['allow_exabot'] ?? 0 ); ?>><strong>Exabot</strong><span>Exalead Search</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="search" data-bot-recommended="0" type="checkbox" name="rls_settings[allow_qwantbot]" value="1" <?php checked( 1, $settings['allow_qwantbot'] ?? 0 ); ?>><strong>Qwantify</strong><span>Qwant Search</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="search" data-bot-recommended="0" type="checkbox" name="rls_settings[allow_mojeekbot]" value="1" <?php checked( 1, $settings['allow_mojeekbot'] ?? 0 ); ?>><strong>MojeekBot</strong><span>Mojeek Search</span></label>
                        </div>
                    </div>

                    <div class="rls-bot-group">
                        <h4>AI-боты и AI-поиск</h4>
                        <div class="rls-bot-grid">
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="ai" data-bot-recommended="1" type="checkbox" name="rls_settings[allow_gptbot]" value="1" <?php checked( 1, $settings['allow_gptbot'] ?? 0 ); ?>><strong>GPTBot</strong><span>OpenAI crawler</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="ai" data-bot-recommended="1" type="checkbox" name="rls_settings[allow_chatgpt_user]" value="1" <?php checked( 1, $settings['allow_chatgpt_user'] ?? 0 ); ?>><strong>ChatGPT-User</strong><span>OpenAI browse requests</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="ai" data-bot-recommended="1" type="checkbox" name="rls_settings[allow_oai_searchbot]" value="1" <?php checked( 1, $settings['allow_oai_searchbot'] ?? 0 ); ?>><strong>OAI-SearchBot</strong><span>OpenAI Search</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="ai" data-bot-recommended="1" type="checkbox" name="rls_settings[allow_claudebot]" value="1" <?php checked( 1, $settings['allow_claudebot'] ?? 0 ); ?>><strong>ClaudeBot</strong><span>Anthropic crawler</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="ai" data-bot-recommended="1" type="checkbox" name="rls_settings[allow_perplexitybot]" value="1" <?php checked( 1, $settings['allow_perplexitybot'] ?? 0 ); ?>><strong>PerplexityBot</strong><span>Perplexity crawler</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="ai" data-bot-recommended="0" type="checkbox" name="rls_settings[allow_cohere_ai]" value="1" <?php checked( 1, $settings['allow_cohere_ai'] ?? 0 ); ?>><strong>Cohere-AI</strong><span>Cohere crawler</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="ai" data-bot-recommended="0" type="checkbox" name="rls_settings[allow_amazonbot]" value="1" <?php checked( 1, $settings['allow_amazonbot'] ?? 0 ); ?>><strong>Amazonbot</strong><span>Amazon crawler</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="ai" data-bot-recommended="0" type="checkbox" name="rls_settings[allow_ccbot]" value="1" <?php checked( 1, $settings['allow_ccbot'] ?? 0 ); ?>><strong>CCBot</strong><span>Common Crawl</span></label>
                            <label class="rls-bot-card"><input class="rls-bot-toggle" data-bot-group="ai" data-bot-recommended="0" type="checkbox" name="rls_settings[allow_bytespider]" value="1" <?php checked( 1, $settings['allow_bytespider'] ?? 0 ); ?>><strong>Bytespider</strong><span>ByteDance crawler</span></label>
                        </div>
                    </div>
                </div>

                <hr>
                <h3>Геоблокировка по странам</h3>
                <table class="form-table">
                    <tr>
                        <th scope="row">Включить геоблокировку</th>
                        <td>
                            <label>
                                <input type="checkbox" name="rls_settings[geo_blocking_enabled]" value="1" <?php checked( 1, $settings['geo_blocking_enabled'] ?? 0 ); ?> />
                                <strong>Фильтрация по странам</strong>
                            </label>
                            <?php if ( ! $is_premium ): ?>
                                <p class="description">Free-режим: до 3 стран в разрешенном списке и до 5 стран в запрещенном. Без ограничений только в Premium.</p>
                                <p><a class="button button-primary" target="_blank" rel="noopener noreferrer" href="<?php echo esc_url( $premium_buy_url ); ?>">Купить ключ Premium</a></p>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Режим</th>
                        <td>
                            <?php $geo_mode = $settings['geo_mode'] ?? 'block'; ?>
                            <label style="margin-right:20px;">
                                <input type="radio" name="rls_settings[geo_mode]" value="block" <?php checked( $geo_mode, 'block' ); ?> />
                                Блокировать выбранные страны
                            </label>
                            <label>
                                <input type="radio" name="rls_settings[geo_mode]" value="allow" <?php checked( $geo_mode, 'allow' ); ?> />
                                Разрешить только выбранные страны
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Выбор стран</th>
                        <td>
                            <?php
                                                        $rls_country_list = [
                                'AF'=>'Афганистан','AX'=>'Аландские острова','AL'=>'Албания','DZ'=>'Алжир','AS'=>'Американское Самоа','AD'=>'Андорра','AO'=>'Ангола','AI'=>'Ангилья','AQ'=>'Антарктида','AG'=>'Антигуа и Барбуда',
                                'AR'=>'Аргентина','AM'=>'Армения','AW'=>'Аруба','AU'=>'Австралия','AT'=>'Австрия','AZ'=>'Азербайджан','BS'=>'Багамы','BH'=>'Бахрейн','BD'=>'Бангладеш','BB'=>'Барбадос',
                                'BY'=>'Беларусь','BE'=>'Бельгия','BZ'=>'Белиз','BJ'=>'Бенин','BM'=>'Бермуды','BT'=>'Бутан','BO'=>'Боливия','BQ'=>'Бонэйр, Синт-Эстатиус и Саба','BA'=>'Босния и Герцеговина','BW'=>'Ботсвана',
                                'BV'=>'Остров Буве','BR'=>'Бразилия','IO'=>'Британская территория в Индийском океане','BN'=>'Бруней','BG'=>'Болгария','BF'=>'Буркина-Фасо','BI'=>'Бурунди','CV'=>'Кабо-Верде','KH'=>'Камбоджа','CM'=>'Камерун',
                                'CA'=>'Канада','KY'=>'Каймановы острова','CF'=>'ЦАР','TD'=>'Чад','CL'=>'Чили','CN'=>'Китай','CX'=>'Остров Рождества','CC'=>'Кокосовые острова','CO'=>'Колумбия','KM'=>'Коморы',
                                'CG'=>'Республика Конго','CD'=>'ДР Конго','CK'=>'Острова Кука','CR'=>'Коста-Рика','CI'=>'Кот-д’Ивуар','HR'=>'Хорватия','CU'=>'Куба','CW'=>'Кюрасао','CY'=>'Кипр','CZ'=>'Чехия',
                                'DK'=>'Дания','DJ'=>'Джибути','DM'=>'Доминика','DO'=>'Доминиканская Республика','EC'=>'Эквадор','EG'=>'Египет','SV'=>'Сальвадор','GQ'=>'Экваториальная Гвинея','ER'=>'Эритрея','EE'=>'Эстония',
                                'SZ'=>'Эсватини','ET'=>'Эфиопия','FK'=>'Фолклендские острова','FO'=>'Фарерские острова','FJ'=>'Фиджи','FI'=>'Финляндия','FR'=>'Франция','GF'=>'Французская Гвиана','PF'=>'Французская Полинезия','TF'=>'Французские Южные территории',
                                'GA'=>'Габон','GM'=>'Гамбия','GE'=>'Грузия','DE'=>'Германия','GH'=>'Гана','GI'=>'Гибралтар','GR'=>'Греция','GL'=>'Гренландия','GD'=>'Гренада','GP'=>'Гваделупа',
                                'GU'=>'Гуам','GT'=>'Гватемала','GG'=>'Гернси','GN'=>'Гвинея','GW'=>'Гвинея-Бисау','GY'=>'Гайана','HT'=>'Гаити','HM'=>'Остров Херд и острова Макдональд','VA'=>'Ватикан','HN'=>'Гондурас',
                                'HK'=>'Гонконг','HU'=>'Венгрия','IS'=>'Исландия','IN'=>'Индия','ID'=>'Индонезия','IR'=>'Иран','IQ'=>'Ирак','IE'=>'Ирландия','IM'=>'Остров Мэн','IL'=>'Израиль',
                                'IT'=>'Италия','JM'=>'Ямайка','JP'=>'Япония','JE'=>'Джерси','JO'=>'Иордания','KZ'=>'Казахстан','KE'=>'Кения','KI'=>'Кирибати','KP'=>'КНДР','KR'=>'Южная Корея',
                                'KW'=>'Кувейт','KG'=>'Киргизия','LA'=>'Лаос','LV'=>'Латвия','LB'=>'Ливан','LS'=>'Лесото','LR'=>'Либерия','LY'=>'Ливия','LI'=>'Лихтенштейн','LT'=>'Литва',
                                'LU'=>'Люксембург','MO'=>'Макао','MG'=>'Мадагаскар','MW'=>'Малави','MY'=>'Малайзия','MV'=>'Мальдивы','ML'=>'Мали','MT'=>'Мальта','MH'=>'Маршалловы Острова','MQ'=>'Мартиника',
                                'MR'=>'Мавритания','MU'=>'Маврикий','YT'=>'Майотта','MX'=>'Мексика','FM'=>'Микронезия','MD'=>'Молдова','MC'=>'Монако','MN'=>'Монголия','ME'=>'Черногория','MS'=>'Монтсеррат',
                                'MA'=>'Марокко','MZ'=>'Мозамбик','MM'=>'Мьянма','NA'=>'Намибия','NR'=>'Науру','NP'=>'Непал','NL'=>'Нидерланды','NC'=>'Новая Каледония','NZ'=>'Новая Зеландия','NI'=>'Никарагуа',
                                'NE'=>'Нигер','NG'=>'Нигерия','NU'=>'Ниуэ','NF'=>'Остров Норфолк','MK'=>'Северная Македония','MP'=>'Северные Марианские острова','NO'=>'Норвегия','OM'=>'Оман','PK'=>'Пакистан','PW'=>'Палау',
                                'PS'=>'Палестина','PA'=>'Панама','PG'=>'Папуа — Новая Гвинея','PY'=>'Парагвай','PE'=>'Перу','PH'=>'Филиппины','PN'=>'Острова Питкэрн','PL'=>'Польша','PT'=>'Португалия','PR'=>'Пуэрто-Рико',
                                'QA'=>'Катар','RE'=>'Реюньон','RO'=>'Румыния','RU'=>'Россия','RW'=>'Руанда','BL'=>'Сен-Бартелеми','SH'=>'Остров Святой Елены','KN'=>'Сент-Китс и Невис','LC'=>'Сент-Люсия','MF'=>'Сен-Мартен',
                                'PM'=>'Сен-Пьер и Микелон','VC'=>'Сент-Винсент и Гренадины','WS'=>'Самоа','SM'=>'Сан-Марино','ST'=>'Сан-Томе и Принсипи','SA'=>'Саудовская Аравия','SN'=>'Сенегал','RS'=>'Сербия','SC'=>'Сейшелы','SL'=>'Сьерра-Леоне',
                                'SG'=>'Сингапур','SX'=>'Синт-Мартен','SK'=>'Словакия','SI'=>'Словения','SB'=>'Соломоновы Острова','SO'=>'Сомали','ZA'=>'ЮАР','GS'=>'Южная Георгия и Южные Сандвичевы острова','SS'=>'Южный Судан','ES'=>'Испания',
                                'LK'=>'Шри-Ланка','SD'=>'Судан','SR'=>'Суринам','SJ'=>'Шпицберген и Ян-Майен','SE'=>'Швеция','CH'=>'Швейцария','SY'=>'Сирия','TW'=>'Тайвань','TJ'=>'Таджикистан','TZ'=>'Танзания',
                                'TH'=>'Таиланд','TL'=>'Тимор-Лесте','TG'=>'Того','TK'=>'Токелау','TO'=>'Тонга','TT'=>'Тринидад и Тобаго','TN'=>'Тунис','TR'=>'Турция','TM'=>'Туркменистан','TC'=>'Теркс и Кайкос',
                                'TV'=>'Тувалу','UG'=>'Уганда','UA'=>'Украина','AE'=>'ОАЭ','GB'=>'Великобритания','US'=>'США','UM'=>'Внешние малые острова США','UY'=>'Уругвай','UZ'=>'Узбекистан','VU'=>'Вануату',
                                'VE'=>'Венесуэла','VN'=>'Вьетнам','VG'=>'Британские Виргинские острова','VI'=>'Виргинские острова США','WF'=>'Уоллис и Футуна','EH'=>'Западная Сахара','YE'=>'Йемен','ZM'=>'Замбия','ZW'=>'Зимбабве'
                            ];
                            $selected_geo = array_map( 'strtoupper', (array) ( $settings['geo_countries'] ?? [] ) );
                            $selected_allow = array_map( 'strtoupper', (array) ( $settings['geo_countries_allow'] ?? [] ) );
                            $selected_block = array_map( 'strtoupper', (array) ( $settings['geo_countries_block'] ?? [] ) );
                            ?>
                            <div style="display:grid; gap:12px; max-width:900px;">
                                <input type="text" id="rls-geo-country-search" class="regular-text" style="width:100%;" placeholder="Поиск страны (например: Германия, DE)..." />
                                <select id="rls-geo-country-select" multiple size="20" style="width:100%;">
                                    <?php foreach ( $rls_country_list as $code => $name ): ?>
                                        <option value="<?php echo esc_attr( $code ); ?>">
                                            <?php echo esc_html( $name . ' (' . $code . ')' ); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                                <div style="display:flex; gap:8px; flex-wrap:wrap;">
                                    <button type="button" id="rls-geo-select-visible" class="button button-secondary">Выделить все найденные</button>
                                    <button type="button" id="rls-geo-clear-selection" class="button button-secondary">Снять выделение</button>
                                    <button type="button" id="rls-geo-add-allow" class="button button-secondary">+ В разрешенные (выбранные)</button>
                                    <button type="button" id="rls-geo-add-block" class="button button-secondary">+ В запрещенные (выбранные)</button>
                                    <button type="button" id="rls-geo-add-visible-allow" class="button button-secondary">+ Все найденные в разрешенные</button>
                                    <button type="button" id="rls-geo-add-visible-block" class="button button-secondary">+ Все найденные в запрещенные</button>
                                </div>
                            </div>
                            <div style="display:flex; gap:14px; flex-wrap:wrap; margin-top:10px;">
                                <div style="flex:1; min-width:260px;">
                                    <strong>Разрешенные страны</strong>
                                    <ul id="rls-geo-allow-list" class="rls-ip-list" style="max-height:220px;"></ul>
                                </div>
                                <div style="flex:1; min-width:260px;">
                                    <strong>Запрещенные страны</strong>
                                    <ul id="rls-geo-block-list" class="rls-ip-list" style="max-height:220px;"></ul>
                                </div>
                            </div>
                            <input type="hidden" id="rls-geo-allow-hidden" name="rls_settings[geo_countries_allow]" value="<?php echo esc_attr( implode( ',', $selected_allow ) ); ?>">
                            <input type="hidden" id="rls-geo-block-hidden" name="rls_settings[geo_countries_block]" value="<?php echo esc_attr( implode( ',', $selected_block ) ); ?>">
                            <input type="hidden" name="rls_settings[geo_countries]" value="<?php echo esc_attr( implode( ',', $selected_geo ) ); ?>">
                            <p class="description">Можно выделять несколько стран сразу, использовать поиск и добавлять как выбранные, так и сразу все найденные. В списках доступны удаление (`-`) и быстрый перенос (`↔`).</p>
                            <?php if ( ! $is_premium ): ?>
                                <p class="description"><strong>Лимит Free:</strong> до 3 стран в разрешенные и до 5 стран в запрещенные. Больше стран доступно в Premium.</p>
                                <p><a class="button button-primary" target="_blank" rel="noopener noreferrer" href="<?php echo esc_url( $premium_buy_url ); ?>">Убрать лимиты в Premium</a></p>
                            <?php endif; ?>
                            <p class="description">Статус GeoIP базы: <strong><?php echo $geo_db_exists ? 'загружена' : 'не загружена'; ?></strong><?php if ( $geo_db_exists ) echo ' (' . esc_html( basename( $geo_db_path ) ) . ')'; ?></p>
                            <p class="description">В режиме «Разрешить только выбранные страны» доступ будет заблокирован, если страну по IP определить не удалось.</p>
                            <p style="margin-top:10px;">
                                <button type="button" class="button button-secondary" onclick="document.getElementById('rls-download-geo-form').submit();" <?php disabled( ! $is_premium ); ?>>Загрузить базу Geo IP</button>
                                <button type="button" class="button button-secondary" onclick="document.getElementById('rls-update-geo-form').submit();" style="margin-left:8px;" <?php disabled( ! $is_premium ); ?>>Обновить базу Geo IP</button>
                            </p>
                            <?php if ( ! $is_premium ): ?>
                                <p class="description">Обновление GeoIP базы доступно только в Premium.</p>
                            <?php endif; ?>
                        </td>
                    </tr>
                </table>
            </div>
                </div>
            </div>

        <!-- ТАБ 3: СПИСКИ IP -->
        <div class="rls-tab-content" id="tab-lists" data-rls-visible-modes="light,full" data-rls-section-box="blacklist">
            <div class="rls-row" style="display:flex; gap:20px; flex-wrap: wrap;">
                
                <!-- Белый список -->
                <div class="rls-col rls-box" style="flex:1; min-width: 300px;">
                    <h2 style="color:green; border-bottom: 2px solid green; padding-bottom: 10px;">Белый список IP (Whitelist)</h2>
                    <p class="description">IP из этого списка <strong>полностью игнорируют</strong> все проверки (WAF, Лимиты входа).</p>
                    
                    <div class="rls-ip-input-group" style="display:flex; gap:5px; margin-bottom: 10px;">
                        <input type="text" id="rls-new-white-ip" placeholder="192.168.1.1" style="width:100%;">
                        <button type="button" class="button button-secondary rls-add-ip-btn" data-list="white">Добавить</button>
                    </div>
                    
                    <ul class="rls-ip-list" id="rls-white-list">
                        <?php foreach($whitelist as $ip): ?>
                            <li><span><?php echo esc_html($ip); ?></span> <a href="#" class="rls-del-ip" data-ip="<?php echo esc_attr($ip); ?>" data-list="white">&times;</a></li>
                        <?php endforeach; ?>
                    </ul>
                </div>

                <!-- Черный список -->
                <div class="rls-col rls-box" style="flex:1; min-width: 300px;">
                    <h2 style="color:red; border-bottom: 2px solid red; padding-bottom: 10px;">Черный список IP (Blacklist)</h2>
                    <p class="description">IP из этого списка получают вечный бан (403 Forbidden).</p>
                    
                    <div class="rls-ip-input-group" style="display:flex; gap:5px; margin-bottom: 10px;">
                        <input type="text" id="rls-new-black-ip" placeholder="10.0.0.1" style="width:100%;">
                        <button type="button" class="button button-secondary rls-add-ip-btn" data-list="black">Забанить</button>
                    </div>
                    
                    <ul class="rls-ip-list" id="rls-black-list">
                        <?php foreach($blacklist as $ip): ?>
                            <li><span><?php echo esc_html($ip); ?></span> <a href="#" class="rls-del-ip" data-ip="<?php echo esc_attr($ip); ?>" data-list="black">&times;</a></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            </div>

            <div class="rls-box" style="margin-top:20px;">
                <h2 style="color:#b32d2e; border-bottom:2px solid #d63638; padding-bottom:10px;">Временно заблокированные IP</h2>
                <p class="description">Здесь показаны IP, заблокированные защитой (WAF/BruteForce). Вы можете снять блокировку или добавить IP в белый список.</p>

                <ul class="rls-ip-list" id="rls-blocked-runtime-list">
                    <?php
                    $runtime_items = [];
                    $now_ts = time();
                    if ( is_array( $blocked_ips ) ) {
                        foreach ( $blocked_ips as $ip => $row ) {
                            $exp = is_array( $row ) ? (int) ( $row['expires'] ?? 0 ) : (int) $row;
                            $reason = is_array( $row ) ? (string) ( $row['reason'] ?? 'WAF block' ) : 'WAF block';
                            if ( filter_var( $ip, FILTER_VALIDATE_IP ) && $exp > $now_ts ) {
                                $runtime_items[ $ip ] = [ 'expires' => $exp, 'reason' => $reason ];
                            }
                        }
                    }
                    if ( is_array( $locked_ips ) ) {
                        foreach ( $locked_ips as $ip => $row ) {
                            $exp = is_array( $row ) ? (int) ( $row['expires'] ?? 0 ) : (int) $row;
                            if ( filter_var( $ip, FILTER_VALIDATE_IP ) && $exp > $now_ts ) {
                                if ( ! isset( $runtime_items[ $ip ] ) || $runtime_items[ $ip ]['expires'] < $exp ) {
                                    $runtime_items[ $ip ] = [ 'expires' => $exp, 'reason' => 'BruteForce lockout' ];
                                }
                            }
                        }
                    }
                    if ( ! empty( $runtime_items ) ):
                        foreach ( $runtime_items as $ip => $meta ):
                            $left = max( 0, (int) $meta['expires'] - $now_ts );
                            ?>
                            <li data-ip="<?php echo esc_attr( $ip ); ?>">
                                <span>
                                    <strong><?php echo esc_html( $ip ); ?></strong>
                                    <br><small>Причина: <?php echo esc_html( $meta['reason'] ); ?> | Осталось: <?php echo esc_html( gmdate( 'H:i:s', $left ) ); ?></small>
                                </span>
                                <span style="display:inline-flex; gap:8px; align-items:center;">
                                    <button type="button" class="button button-small rls-move-blocked-to-black" data-ip="<?php echo esc_attr( $ip ); ?>">В черный</button>
                                    <button type="button" class="button button-small rls-move-blocked-to-white" data-ip="<?php echo esc_attr( $ip ); ?>">В белый</button>
                                    <button type="button" class="button button-small rls-unblock-ip" data-ip="<?php echo esc_attr( $ip ); ?>">Снять блок</button>
                                </span>
                            </li>
                            <?php
                        endforeach;
                    else:
                        ?>
                        <li><span>Активных временных блокировок нет.</span></li>
                    <?php endif; ?>
                </ul>
            </div>
            
            <div class="rls-box" style="margin-top: 20px; background: #f0f0f1; border-color: #999;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <h3><span class="dashicons dashicons-cloud"></span> Глобальный Черный список (Rybinsk Lab)</h3>
                        <p>Загружено IP-адресов из облачной базы угроз: <strong style="font-size: 1.2em;"><?php echo count($global_blacklist); ?></strong></p>
                        <p class="description">Этот список обновляется автоматически при наличии лицензии.</p>
                        <?php if ( ! $is_premium ): ?>
                            <p class="description"><strong>Коллективная защита</strong> (облачный blacklist) доступна в Premium.</p>
                            <p><a class="button button-primary" target="_blank" rel="noopener noreferrer" href="<?php echo esc_url( $premium_buy_url ); ?>">Подключить Premium</a></p>
                        <?php endif; ?>
                    </div>
                    <div>
                        <!-- КНОПКА ОБНОВЛЕНИЯ IP -->
                        <button type="button" class="button button-secondary" onclick="document.getElementById('rls-manual-sync-form').submit();" <?php disabled( ! $is_premium ); ?>>
                            <span class="dashicons dashicons-update"></span> Обновить список IP
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- ТАБ 4: СКАНЕР И СИГНАТУРЫ -->
        <div class="rls-tab-content" id="tab-scanner" data-rls-section-box="settings">
             <div class="rls-box">
                <h2>Автоматическое сканирование</h2>
                <p>Как часто плагин должен проверять файлы на наличие вирусов?</p>
                <select name="rls_auto_scan_frequency">
                    <option value="disabled" <?php selected( get_option( 'rls_auto_scan_frequency' ), 'disabled' ); ?>>Отключено (Только вручную)</option>
                    <option value="daily" <?php selected( get_option( 'rls_auto_scan_frequency' ), 'daily' ); ?>>Ежедневно (в фоновом режиме)</option>
                    <option value="weekly" <?php selected( get_option( 'rls_auto_scan_frequency' ), 'weekly' ); ?>>Еженедельно (в фоновом режиме)</option>
                </select>
             </div>
             
             <div class="rls-box">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;">
                    <div>
                        <h2>База Сигнатур Вирусов</h2>
                        <p>Всего активных сигнатур: <strong><?php echo $total_sigs; ?></strong></p>
                        <ul style="list-style:disc; margin-left:20px; color:#666; font-size:13px;">
                            <li>Базовые (Встроенные): <?php echo count($base_sigs); ?></li>
                            <li>Premium (Cloud): <?php echo count($premium_sigs); ?> (доступно с ключом)</li>
                            <li>Пользовательские: <?php echo count($custom_sigs); ?></li>
                        </ul>
                        <?php if ( ! $is_premium ): ?>
                            <p class="description">Расширенная облачная база образцов вирусов и ее автообновления доступны только в Premium.</p>
                            <p><a class="button button-primary" target="_blank" rel="noopener noreferrer" href="<?php echo esc_url( $premium_buy_url ); ?>">Купить Premium-ключ</a></p>
                        <?php endif; ?>
                    </div>
                    <div>
                        <!-- КНОПКА ОБНОВЛЕНИЯ СИГНАТУР -->
                        <button type="button" class="button button-primary" onclick="document.getElementById('rls-manual-sync-form').submit();" <?php disabled( ! $is_premium ); ?>>
                            <span class="dashicons dashicons-update" style="line-height:1.3"></span> Обновить базу сигнатур
                        </button>
                    </div>
                </div>
                
                <hr>
                <h3>Добавить свою сигнатуру</h3>
                <p class="description">Если вы знаете фрагмент кода вируса, добавьте его сюда. Плагин будет искать его в файлах.</p>
                <div style="display:flex; gap:10px; margin-bottom:10px;">
                    <input type="text" id="rls-new-signature-input" class="large-text" placeholder="Пример: eval(base64_decode" style="width:100%;">
                    <button id="rls-add-signature-button" class="button button-secondary">Добавить</button>
                </div>
                
                <table class="wp-list-table widefat striped fixed">
                    <thead><tr><th>Сигнатура</th><th style="width: 80px;">Действие</th></tr></thead>
                    <tbody id="rls-signatures-table-body">
                        <?php if ( empty( $custom_sigs ) ): ?>
                            <tr class="no-items"><td colspan="2">Нет пользовательских сигнатур.</td></tr>
                        <?php else: foreach ( $custom_sigs as $sig ): ?>
                            <tr data-signature="<?php echo esc_attr( $sig ); ?>">
                                <td><code><?php echo esc_html( $sig ); ?></code></td>
                                <td><button class="button-link-delete rls-delete-signature-button" style="color:#b32d2e;">Удалить</button></td>
                            </tr>
                        <?php endforeach; endif; ?>
                    </tbody>
                </table>
             </div>

             <div class="rls-box">
                <h2>Условия и политика</h2>
                <p>Краткий правовой экран по работе плагина, техническим данным, API, лицензии, журналам атак, AI-проверке, GeoIP, SmartCaptcha и сигнатурам.</p>
                <p>
                    <a class="button button-secondary" href="<?php echo esc_url( add_query_arg( 'page', 'rls-policy', admin_url( 'admin.php' ) ) ); ?>">
                        <span class="dashicons dashicons-media-document" style="line-height:1.3"></span> Открыть условия и политику
                    </a>
                </p>
             </div>
        </div>

        <!-- ТАБ 5: ЖУРНАЛ АТАК -->
        <div class="rls-tab-content" id="tab-logs" data-rls-visible-modes="light,full">
            <div class="rls-box">
                <h2>Последние отраженные атаки (Журнал)</h2>
                <p class="description">
                    Здесь можно отфильтровать журнал по типу событий и открыть все записи, а не только последние 50.
                    Перед очисткой сводка будет отправлена на сервер статистики.
                </p>

                <!-- Attack type legend with descriptions -->
                <div class="rls-attack-type-legend" style="margin-bottom:14px;">
                    <?php foreach ( RLS_Attack_Types::all() as $key => $t ) :
                        if ( in_array( $key, [ 'unknown' ], true ) ) continue;
                        echo RLS_Attack_Types::render_badge( $key, false );
                    endforeach; ?>
                </div>
                <p class="description" style="margin-top:-6px;">
                    <strong>Наведите на тип атаки</strong> чтобы увидеть подробное описание, вектор атаки, пример и рекомендации.
                </p>

                <div style="display:flex; justify-content:space-between; align-items:flex-end; gap:12px; flex-wrap:wrap; margin: 0 0 14px;">
                    <div style="display:flex; gap:8px; align-items:flex-end; flex-wrap:wrap; margin:0;">
                        <label style="display:flex; flex-direction:column; gap:6px; font-weight:600;">
                            Тип лога
                            <select id="rls-log-type-filter" style="min-width: 180px;">
                                <?php foreach ( $log_type_labels as $value => $label ) : ?>
                                    <option value="<?php echo esc_attr( $value ); ?>" <?php selected( $selected_log_type, $value ); ?>>
                                        <?php echo esc_html( $label ); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </label>
                        <button type="button" class="button button-primary" id="rls-apply-log-filter">Показать</button>
                    </div>
                    <div style="display:flex; gap:8px; flex-wrap:wrap;">
                        <a class="button button-secondary" href="<?php echo esc_url( add_query_arg( [ 'page' => 'rls-settings', 'tab' => 'tab-logs', 'rls_log_type' => $selected_log_type, 'rls_logs_view' => 'recent' ], admin_url( 'admin.php' ) ) ); ?>">Последние 50</a>
                        <a class="button button-secondary" href="<?php echo esc_url( add_query_arg( [ 'page' => 'rls-settings', 'tab' => 'tab-logs', 'rls_log_type' => $selected_log_type, 'rls_logs_view' => 'all' ], admin_url( 'admin.php' ) ) ); ?>">Все логи</a>
                    </div>
                </div>

                <div style="display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; margin-bottom:12px;">
                    <span class="description">
                        Показано: <strong><?php echo esc_html( $selected_log_view === 'all' ? 'все записи' : 'последние 50' ); ?></strong>,
                        фильтр: <strong><?php echo esc_html( $log_type_labels[ $selected_log_type ] ?? strtoupper( $selected_log_type ) ); ?></strong>,
                        всего в фильтре: <strong id="rls-logs-total"><?php echo intval( $logs_count ); ?></strong>
                    </span>
                    <button type="button" class="button button-secondary" id="rls-clear-attack-logs-button">
                        Очистить историю атак
                    </button>
                </div>
                
                <table class="wp-list-table widefat striped fixed">
                    <thead>
                         <tr>
                            <th style="width: 130px;">Время</th>
                            <th style="width: 130px;">IP Адрес</th>
                            <th style="width: 160px;">Тип атаки</th>
                            <th>Причина / Запрос</th>
                        </tr>
                    </thead>
                    <tbody id="rls-attack-logs-tbody">
                        <?php if ( empty( $logs ) ): ?>
                            <tr><td colspan="4">Журнал пуст. Атак пока не зафиксировано.</td></tr>
                        <?php else: foreach ( $logs as $log ): ?>
                            <tr class="rls-attack-history-row">
                                <td class="time-col"><?php echo date_i18n( 'd.m H:i:s', strtotime( $log['event_date'] ) ); ?></td>
                                <td class="ip-col">
                                    <strong><?php echo esc_html( $log['ip'] ); ?></strong>
                                    <br>
                                    <a href="https://2ip.ru/info/<?php echo esc_attr($log['ip']); ?>/" target="_blank" class="button button-small" style="margin-top:5px; font-size:11px; display:inline-flex; align-items:center; gap:3px;">
                                        Whois (2ip) <span class="dashicons dashicons-external" style="font-size:12px; width:12px; height:12px;"></span>
                                    </a>
                                </td>
                                <td class="type-col">
                                    <?php
                                        $type = strtolower( (string) ( $log['type'] ?? 'unknown' ) );
                                        echo RLS_Attack_Types::render_badge( $type );
                                    ?>
                                </td>
                                <td class="reason-col">
                                    <span style="color:#d63638; font-weight:600;"><?php echo esc_html( $log['reason'] ); ?></span><br>
                                    <code style="font-size:0.85em; color:#666;"><?php echo esc_html( substr($log['request_uri'], 0, 50) ); ?></code>
                                </td>
                            </tr>
                        <?php endforeach; endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- КНОПКА СОХРАНЕНИЯ (ЕДИНАЯ ДЛЯ ВСЕХ ТАБОВ) -->
        <div class="rls-savebar">
            <div>
                <strong class="rls-savebar-title">Настройки готовы к сохранению</strong>
                <span class="rls-savebar-note">Все изменения вступают в силу сразу после сохранения.</span>
            </div>
            <?php if ( ! $setup_completed ): ?>
                <input type="hidden" name="rls_settings[rls_setup_completed]" value="1">
            <?php endif; ?>
            <?php submit_button( 'Сохранить настройки', 'primary', 'submit', false ); ?>
        </div>

    </form>
    
    <!-- ОТДЕЛЬНАЯ ФОРМА ДЛЯ ПРОВЕРКИ ЛИЦЕНЗИИ И ОБНОВЛЕНИЯ БАЗ -->
    <!-- Все кнопки обновления ссылаются на эту скрытую форму -->
    <div style="display:none;">
        <form id="rls-manual-sync-form" method="post" action="">
            <input type="hidden" name="rls_action" value="manual_sync">
            <?php wp_nonce_field( 'rls_force_sync_nonce', 'rls_sync_nonce_field' ); ?>
        </form>
    </div>
    <div style="display:none;">
        <form id="rls-sync-blacklists-form" method="post" action="">
            <input type="hidden" name="rls_action" value="sync_blacklists">
            <?php wp_nonce_field( 'rls_force_sync_nonce', 'rls_sync_nonce_field' ); ?>
        </form>
    </div>
    <div style="display:none;">
        <form id="rls-download-geo-form" method="post" action="">
            <input type="hidden" name="rls_action" value="download_ip2location_db">
            <?php wp_nonce_field( 'rls_download_ip2location_nonce', 'rls_download_ip2location_nonce_field' ); ?>
        </form>
    </div>
    <div style="display:none;">
        <form id="rls-update-geo-form" method="post" action="">
            <input type="hidden" name="rls_action" value="update_ip2location_db">
            <?php wp_nonce_field( 'rls_download_ip2location_nonce', 'rls_download_ip2location_nonce_field' ); ?>
        </form>
    </div>
    
</div>

<style>
/* CSS для интерфейса */
.rls-tab-content { display: none; }
.rls-tab-content.active { display: block; }

.rls-ip-list { margin-top:10px; border:1px solid #ddd; max-height:200px; overflow-y:auto; background:#fff; list-style: none; padding: 0; }
.rls-ip-list li { padding: 8px 10px; border-bottom:1px solid #eee; display:flex; justify-content:space-between; align-items: center; margin:0; }
.rls-ip-list li:nth-child(odd) { background: #f9f9f9; }
.rls-del-ip { color: #dc3545; text-decoration: none; font-weight: bold; font-size: 20px; line-height: 1; }
.rls-del-ip:hover { color: #a71d2a; }

.rls-badge-log { padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 700; color: #fff; text-transform: uppercase; }
.rls-badge-log.red { background: #d63638; }
.rls-badge-log.orange { background: #f0ad4e; }
.rls-badge-log.gray { background: #646970; }
.rls-badge-log.blue { background: #2271b1; }
.rls-badge-log.purple { background: #8e44ad; }
</style>

<script>
document.addEventListener('DOMContentLoaded', function() {
    var isPremium = <?php echo $is_premium ? 'true' : 'false'; ?>;
    var freeAllowLimit = 3;
    var freeBlockLimit = 5;
    var searchInput = document.getElementById('rls-geo-country-search');
    var select = document.getElementById('rls-geo-country-select');
    var addAllowBtn = document.getElementById('rls-geo-add-allow');
    var addBlockBtn = document.getElementById('rls-geo-add-block');
    var addVisibleAllowBtn = document.getElementById('rls-geo-add-visible-allow');
    var addVisibleBlockBtn = document.getElementById('rls-geo-add-visible-block');
    var selectVisibleBtn = document.getElementById('rls-geo-select-visible');
    var clearSelectionBtn = document.getElementById('rls-geo-clear-selection');
    var allowListEl = document.getElementById('rls-geo-allow-list');
    var blockListEl = document.getElementById('rls-geo-block-list');
    var allowHidden = document.getElementById('rls-geo-allow-hidden');
    var blockHidden = document.getElementById('rls-geo-block-hidden');
    if (!searchInput || !select || !allowListEl || !blockListEl || !allowHidden || !blockHidden) return;

    var allCountries = {};
    Array.prototype.forEach.call(select.options, function(opt) {
        allCountries[opt.value] = opt.text;
    });

    function parseCodes(value) {
        return (value || '')
            .split(',')
            .map(function(v) { return v.trim().toUpperCase(); })
            .filter(function(v) { return /^[A-Z]{2}$/.test(v); });
    }
    var allowSet = new Set(parseCodes(allowHidden.value));
    var blockSet = new Set(parseCodes(blockHidden.value));

    function syncHidden() {
        allowHidden.value = Array.from(allowSet).join(',');
        blockHidden.value = Array.from(blockSet).join(',');
    }

    function renderList(el, sourceSet, otherSet, target) {
        el.innerHTML = '';
        Array.from(sourceSet).sort().forEach(function(code) {
            var text = allCountries[code] || code;
            var li = document.createElement('li');
            li.innerHTML = '<span>' + text + '</span>';

            var actions = document.createElement('span');
            actions.style.display = 'inline-flex';
            actions.style.gap = '8px';

            var moveBtn = document.createElement('a');
            moveBtn.href = '#';
            moveBtn.textContent = '↔';
            moveBtn.title = 'Перенести';
            moveBtn.style.textDecoration = 'none';
            moveBtn.onclick = function(e) {
                e.preventDefault();
                sourceSet.delete(code);
                otherSet.add(code);
                syncHidden();
                renderAll();
            };

            var delBtn = document.createElement('a');
            delBtn.href = '#';
            delBtn.textContent = '−';
            delBtn.title = 'Удалить';
            delBtn.className = 'rls-del-ip';
            delBtn.style.fontSize = '18px';
            delBtn.onclick = function(e) {
                e.preventDefault();
                sourceSet.delete(code);
                syncHidden();
                renderAll();
            };

            actions.appendChild(moveBtn);
            actions.appendChild(delBtn);
            li.appendChild(actions);
            el.appendChild(li);
        });
    }

    function renderAll() {
        renderList(allowListEl, allowSet, blockSet, 'allow');
        renderList(blockListEl, blockSet, allowSet, 'block');
    }

    function addSelected(targetSet, otherSet) {
        var targetType = (targetSet === allowSet) ? 'allow' : 'block';
        var limit = (targetType === 'allow') ? freeAllowLimit : freeBlockLimit;
        var skipped = 0;
        Array.prototype.forEach.call(select.selectedOptions, function(opt) {
            var code = (opt.value || '').toUpperCase();
            if (!/^[A-Z]{2}$/.test(code)) return;
            if (!targetSet.has(code) && !isPremium && targetSet.size >= limit) {
                skipped++;
                return;
            }
            targetSet.add(code);
            otherSet.delete(code);
        });
        if (skipped > 0) {
            alert('Лимит Free: до 3 стран в разрешенные и до 5 стран в запрещенные. Часть стран не добавлена.');
        }
        syncHidden();
        renderAll();
    }

    function addVisible(targetSet, otherSet) {
        var targetType = (targetSet === allowSet) ? 'allow' : 'block';
        var limit = (targetType === 'allow') ? freeAllowLimit : freeBlockLimit;
        var skipped = 0;
        Array.prototype.forEach.call(select.options, function(opt) {
            if (opt.style.display === 'none') return;
            var code = (opt.value || '').toUpperCase();
            if (!/^[A-Z]{2}$/.test(code)) return;
            if (!targetSet.has(code) && !isPremium && targetSet.size >= limit) {
                skipped++;
                return;
            }
            targetSet.add(code);
            otherSet.delete(code);
        });
        if (skipped > 0) {
            alert('Лимит Free: до 3 стран в разрешенные и до 5 стран в запрещенные. Часть стран не добавлена.');
        }
        syncHidden();
        renderAll();
    }

    searchInput.addEventListener('input', function() {
        var q = (searchInput.value || '').toLowerCase().trim();
        Array.prototype.forEach.call(select.options, function(opt) {
            var text = (opt.text || '').toLowerCase();
            opt.style.display = (q === '' || text.indexOf(q) !== -1) ? '' : 'none';
        });
    });

    if (addAllowBtn) {
        addAllowBtn.addEventListener('click', function() { addSelected(allowSet, blockSet); });
    }
    if (addBlockBtn) {
        addBlockBtn.addEventListener('click', function() { addSelected(blockSet, allowSet); });
    }
    if (addVisibleAllowBtn) {
        addVisibleAllowBtn.addEventListener('click', function() { addVisible(allowSet, blockSet); });
    }
    if (addVisibleBlockBtn) {
        addVisibleBlockBtn.addEventListener('click', function() { addVisible(blockSet, allowSet); });
    }
    if (selectVisibleBtn) {
        selectVisibleBtn.addEventListener('click', function() {
            Array.prototype.forEach.call(select.options, function(opt) {
                opt.selected = (opt.style.display !== 'none');
            });
        });
    }
    if (clearSelectionBtn) {
        clearSelectionBtn.addEventListener('click', function() {
            Array.prototype.forEach.call(select.options, function(opt) {
                opt.selected = false;
            });
        });
    }

    select.addEventListener('dblclick', function() {
        var modeRadio = document.querySelector('input[name="rls_settings[geo_mode]"]:checked');
        var mode = modeRadio ? modeRadio.value : 'block';
        if (mode === 'allow') {
            addSelected(allowSet, blockSet);
        } else {
            addSelected(blockSet, allowSet);
        }
    });

    renderAll();
});
</script>






