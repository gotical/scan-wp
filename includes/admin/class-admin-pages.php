<?php
/**
 * пїЅпїЅпїЅпїЅпїЅ RLS_Admin_Pages
 * пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ, пїЅпїЅпїЅпїЅ, пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅ AJAX-пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ.
 * пїЅпїЅпїЅпїЅпїЅпїЅ 1.6.0 (Complete: Quarantine Init included)
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

class RLS_Admin_Pages {

    /**
     * пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅ.
     */
    public function init() {
        // Register all admin pages.
        add_action( 'admin_menu', [ $this, 'setup_admin_menu' ] );

        // Enqueue assets.
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_admin_assets' ] );

        // Settings + activation redirect.
        add_action( 'admin_init', [ $this, 'initialize_settings' ] );
        add_action( 'admin_init', [ $this, 'maybe_redirect_after_activation' ] );
        
        // пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅ "пїЅ пїЅпїЅпїЅ" пїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅ
        add_action( 'admin_init', [ $this, 'check_and_send_heartbeat_on_visit' ] );
        
        // пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ (пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ)
        add_action( 'admin_init', [ $this, 'check_and_fix_base_signatures' ] );

        // пїЅпїЅпїЅпїЅпїЅ HTML пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ (пїЅ пїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅ)
        add_action( 'admin_footer', [ $this, 'render_deactivation_modal' ] );

        // пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ (пїЅпїЅпїЅпїЅпїЅ)
        if ( class_exists( 'RLS_Quarantine' ) ) {
            $quarantine = new RLS_Quarantine();
            $quarantine->init();
        }

        // --- AJAX пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ ---

        // пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ
        add_action( 'wp_ajax_rls_save_uninstall_pref', [ $this, 'ajax_save_uninstall_pref' ] );
        add_action( 'wp_ajax_rls_save_license_key', [ $this, 'ajax_save_license_key' ] );
        add_action( 'wp_ajax_rls_delete_license_key', [ $this, 'ajax_delete_license_key' ] );

        // пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ IP
        add_action( 'wp_ajax_rls_add_ip_list', [ $this, 'ajax_add_ip_list' ] );
        add_action( 'wp_ajax_rls_delete_ip_list', [ $this, 'ajax_delete_ip_list' ] );
        add_action( 'wp_ajax_rls_unblock_ip', [ $this, 'ajax_unblock_ip' ] );

        // пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ
        add_action( 'wp_ajax_rls_add_signature', [ $this, 'ajax_add_signature' ] );
        add_action( 'wp_ajax_rls_delete_signature', [ $this, 'ajax_delete_signature' ] );
        
        // пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅ
        add_action( 'wp_ajax_rls_add_login_question', [ $this, 'ajax_add_login_question' ] );
        add_action( 'wp_ajax_rls_delete_login_question', [ $this, 'ajax_delete_login_question' ] );
        
        // AI пїЅпїЅпїЅпїЅпїЅпїЅ пїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅ (пїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅ)
        add_action( 'wp_ajax_rls_neutralize_file', [ $this, 'ajax_neutralize_file' ] );
        
        // пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ
        add_action( 'wp_ajax_rls_sync_stats', [ $this, 'ajax_sync_stats' ] );
        add_action( 'wp_ajax_rls_clear_attack_logs', [ $this, 'ajax_clear_attack_logs' ] );
        // Protection mode AJAX.
        add_action( 'wp_ajax_rls_apply_protection_mode', [ $this, 'ajax_apply_protection_mode' ] );
        add_action( 'wp_ajax_rls_preview_protection_mode', [ $this, 'ajax_preview_protection_mode' ] );
        add_action( 'wp_ajax_rls_activate_emergency_mode', [ $this, 'ajax_activate_emergency_mode' ] );
        add_action( 'wp_ajax_rls_deactivate_emergency_mode', [ $this, 'ajax_deactivate_emergency_mode' ] );
        // CAPTCHA.
        add_action( 'wp_ajax_rls_captcha_test', [ 'RLS_Captcha', 'ajax_test' ] );
        // Analytics.
        add_action( 'wp_ajax_rls_get_analytics', [ 'RLS_Analytics_Page', 'ajax_data' ] );
        add_action( 'wp_ajax_rls_export_attacks', [ 'RLS_Analytics_Page', 'ajax_export_attacks' ] );
        // Reports.
        add_action( 'wp_ajax_rls_preview_report', [ 'RLS_Reports', 'ajax_preview' ] );
        add_action( 'wp_ajax_rls_send_report_now', [ 'RLS_Reports', 'ajax_send_now' ] );
        add_action( 'wp_ajax_rls_download_report', [ 'RLS_Reports', 'ajax_download_html' ] );
        // Webhooks.
        add_action( 'wp_ajax_rls_webhook_test', [ 'RLS_Webhooks', 'ajax_test' ] );
    }
    
    /**
     * пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ Heartbeat пїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅ.
     */
    public function check_and_send_heartbeat_on_visit() {
        if ( isset( $_GET['page'] ) && strpos( $_GET['page'], 'rls-' ) === 0 ) {
            $last_admin_ping = get_transient( 'rls_admin_heartbeat_sent' );
            if ( ! $last_admin_ping ) {
                if ( class_exists( 'RLS_API_Client' ) ) {
                    RLS_API_Client::send_heartbeat(); 
                    set_transient( 'rls_admin_heartbeat_sent', 1, 300 ); // 300 пїЅпїЅпїЅ = 5 пїЅпїЅпїЅ
                }
            }
        }
    }
    
    /**
     * пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ.
     */
    public function check_and_fix_base_signatures() {
        $current_base = get_option( 'rls_base_signatures', [] );
        if ( empty( $current_base ) || count( $current_base ) < 5 ) {
            if ( class_exists( 'RLS_Activator' ) ) {
                update_option( 'rls_base_signatures', RLS_Activator::BASE_SIGNATURES );
            }
        }
    }

    /**
     * Register all admin menu pages with logical grouping.
     * Groups: SETUP, PROTECTION, SCANNER, ANALYTICS, INTEGRATIONS, SYSTEM.
     */
    public function setup_admin_menu() {
        add_menu_page(
            'Rybinsk Lab Security',
            'RL Security',
            'manage_options',
            'rls-scanner',
            [ $this, 'render_scanner_page' ],
            'dashicons-shield-alt',
            26
        );
        
        add_submenu_page(
            'rls-scanner',
            'Сканер',
            'Сканер',
            'manage_options',
            'rls-scanner',
            [ $this, 'render_scanner_page' ]
        );

        // ──── GROUP 1: НАСТРОЙКА ────
        add_submenu_page(
            'rls-scanner',
            'Лицензия',
            'Лицензия',
            'manage_options',
            'rls-license',
            [ $this, 'render_license_page' ]
        );
        add_submenu_page(
            'rls-scanner',
            'Мастер настройки',
            'Мастер настройки',
            'manage_options',
            'rls-wizard',
            [ $this, 'render_wizard_page' ]
        );
        add_submenu_page(
            'rls-scanner',
            'Режим защиты',
            'Режим защиты',
            'manage_options',
            'rls-protection-mode',
            [ $this, 'render_protection_mode_page' ]
        );
        add_submenu_page(
            'rls-scanner',
            'Premium',
            'Premium',
            'manage_options',
            'rls-premium',
            [ $this, 'render_premium_page' ]
        );

        // ──── GROUP 2: ЗАЩИТА ────
        add_submenu_page(
            'rls-scanner',
            'Фаервол',
            'Фаервол',
            'manage_options',
            'rls-firewall',
            [ $this, 'render_firewall_page' ]
        );
        add_submenu_page(
            'rls-scanner',
            'Hardening',
            'Hardening',
            'manage_options',
            'rls-hardening',
            [ $this, 'render_hardening_page' ]
        );
        add_submenu_page(
            'rls-scanner',
            'Черный список',
            'Черный список',
            'manage_options',
            'rls-blacklist',
            [ $this, 'render_blacklist_page' ]
        );
        add_submenu_page(
            'rls-scanner',
            'Защита входа',
            'Защита входа',
            'manage_options',
            'rls-login-security',
            [ $this, 'render_login_security_page' ]
        );
        add_submenu_page(
            'rls-scanner',
            '2FA',
            '2FA',
            'manage_options',
            'rls-2fa',
            [ $this, 'render_2fa_page' ]
        );
        add_submenu_page(
            'rls-scanner',
            'CAPTCHA',
            'CAPTCHA',
            'manage_options',
            'rls-captcha',
            [ $this, 'render_captcha_page' ]
        );

        // ──── GROUP 3: СКАНЕР + МОНИТОРИНГ ────
        add_submenu_page(
            'rls-scanner',
            'Настройки',
            'Настройки',
            'manage_options',
            'rls-settings',
            [ $this, 'render_settings_page' ]
        );
        add_submenu_page(
            'rls-scanner',
            'Мониторинг',
            'Мониторинг',
            'manage_options',
            'rls-monitoring',
            [ $this, 'render_monitoring_page' ]
        );
        add_submenu_page(
            'rls-scanner',
            'Anomaly',
            'Anomaly',
            'manage_options',
            'rls-anomaly',
            [ $this, 'render_anomaly_page' ]
        );

        // ──── GROUP 4: АНАЛИТИКА ────
        add_submenu_page(
            'rls-scanner',
            'Аналитика',
            'Аналитика',
            'manage_options',
            'rls-analytics',
            [ $this, 'render_analytics_page' ]
        );
        add_submenu_page(
            'rls-scanner',
            'Карта атак',
            'Карта атак',
            'manage_options',
            'rls-attack-map',
            [ $this, 'render_attack_map_page' ]
        );
        add_submenu_page(
            'rls-scanner',
            'Корреляция',
            'Корреляция',
            'manage_options',
            'rls-correlation',
            [ $this, 'render_correlation_page' ]
        );
        add_submenu_page(
            'rls-scanner',
            'Типы атак',
            'Типы атак',
            'manage_options',
            'rls-attack-types',
            [ $this, 'render_attack_types_page' ]
        );
        add_submenu_page(
            'rls-scanner',
            'Отчёты',
            'Отчёты',
            'manage_options',
            'rls-reports',
            [ $this, 'render_reports_page' ]
        );

        // ──── GROUP 5: ИНТЕГРАЦИИ + УВЕДОМЛЕНИЯ ────
        add_submenu_page(
            'rls-scanner',
            'Webhooks',
            'Webhooks',
            'manage_options',
            'rls-webhooks',
            [ $this, 'render_webhooks_page' ]
        );
        add_submenu_page(
            'rls-scanner',
            'Уведомления',
            'Уведомления',
            'manage_options',
            'rls-notifications',
            [ $this, 'render_notifications_page' ]
        );

        // ──── GROUP 6: СИСТЕМА ────
        add_submenu_page(
            'rls-scanner',
            'Диагностика',
            'Диагностика',
            'manage_options',
            'rls-health',
            [ $this, 'render_health_page' ]
        );
        add_submenu_page(
            'rls-scanner',
            'Условия и политика',
            'Условия и политика',
            'manage_options',
            'rls-policy',
            [ $this, 'render_policy_page' ]
        );
    }

    /**
     * Enqueue CSS/JS for admin pages.
     */
    public function enqueue_admin_assets( $hook_suffix ) {
        if ( strpos( $hook_suffix, 'rls-' ) === false && $hook_suffix !== 'plugins.php' ) {
            return;
        }

        $is_settings_screen = ( strpos( $hook_suffix, 'rls-' ) !== false && strpos( $hook_suffix, 'rls-scanner' ) === false ) || $hook_suffix === 'plugins.php';
        $is_scanner_screen  = strpos( $hook_suffix, 'rls-scanner' ) !== false;

        wp_enqueue_style( 'rls-admin-styles', plugin_dir_url( RLS_PLUGIN_FILE ) . 'assets/css/admin.css', [], RLS_VERSION );

        // Inline help: tooltip JS for option descriptions.
        wp_enqueue_script( 'rls-tooltip', 'data:text/javascript;base64,' . base64_encode( 'jQuery(function($){$(".rls-tooltip").each(function(){var $t=$(this);if(!$t.attr("title"))return;$t.attr("data-rls-tip",$t.attr("title")).removeAttr("title");});});' ), [], RLS_VERSION, true );

        // UI helpers (toast, confirm, counters, palette, drag-drop).
        wp_enqueue_script( 'rls-ui', plugin_dir_url( RLS_PLUGIN_FILE ) . 'assets/js/ui.js', [ 'jquery' ], RLS_VERSION, true );

        if ( $is_settings_screen ) {
            wp_enqueue_script( 'rls-admin-script', plugin_dir_url( RLS_PLUGIN_FILE ) . 'assets/js/admin.js', [ 'jquery', 'rls-ui' ], RLS_VERSION, true );
            wp_localize_script( 'rls-admin-script', 'rls_admin_data', [
                'ajax_url'         => admin_url( 'admin-ajax.php' ),
                'settings_nonce'   => wp_create_nonce( 'rls_settings_nonce' ),
                'sync_nonce'       => wp_create_nonce( 'rls_sync_nonce' ),
                'questions_nonce'  => wp_create_nonce( 'rls_login_questions_nonce' ),
                'signatures_nonce' => wp_create_nonce( 'rls_signatures_nonce' ),
                'hardening_nonce'  => wp_create_nonce( 'rls_hardening_nonce' ),
                '2fa_nonce'        => wp_create_nonce( 'rls_2fa_nonce' ),
                'password_nonce'   => wp_create_nonce( 'rls_password_strength' ),
                'monitoring_nonce' => wp_create_nonce( 'rls_monitoring_nonce' ),
                'health_nonce'     => wp_create_nonce( 'rls_health_nonce' ),
                'anomaly_nonce'    => wp_create_nonce( 'rls_anomaly_nonce' ),
                'is_premium'       => ( function_exists( 'rls_is_premium_license_active' ) && rls_is_premium_license_active() ) ? 1 : 0,
            ]);
        }

        // Contextual help on settings pages.
        $screen = get_current_screen();
        if ( $screen && strpos( $hook_suffix, 'rls-' ) !== false ) {
            $help_tabs = [
                'overview' => [
                    'title'   => 'Обзор',
                    'content' => '<p>Rybinsk Lab Security — модульная защита WordPress. Все настройки сохраняются единым submit.</p><p>Используйте вкладки для перехода между разделами.</p>',
                ],
                'shortcuts' => [
                    'title'   => 'Горячие клавиши',
                    'content' => '<ul style="list-style: disc; padding-left: 20px;"><li><kbd>Ctrl</kbd>+<kbd>S</kbd> — сохранить настройки</li><li><kbd>Esc</kbd> — закрыть модальные окна</li></ul>',
                ],
                'support' => [
                    'title'   => 'Поддержка',
                    'content' => '<p>Документация: <a href="https://rybinsklab.ru/scan-wp/" target="_blank">rybinsklab.ru/scan-wp</a></p><p>Экспорт диагностики: Диагностика → Экспорт отчёта</p>',
                ],
            ];
            foreach ( $help_tabs as $id => $tab ) {
                $screen->add_help_tab( [
                    'id'      => 'rls_' . $id,
                    'title'   => $tab['title'],
                    'content' => $tab['content'],
                ] );
            }
        }
        
        // пїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅ
        if ( $is_scanner_screen ) {
            wp_enqueue_script( 'rls-scanner-script', plugin_dir_url( RLS_PLUGIN_FILE ) . 'assets/js/scanner.js', [ 'jquery' ], RLS_VERSION, true );
            wp_localize_script( 'rls-scanner-script', 'rls_scanner_data', [
                'ajax_url'        => admin_url( 'admin-ajax.php' ),
                'nonce'           => wp_create_nonce( 'rls_scanner_nonce' ),
                'snapshot_exists' => ( get_option( 'rls_snapshot_time', 0 ) > 0 )
            ]);
        }
    }
    
    // пїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅ
    public function render_scanner_page() {
        require_once RLS_PLUGIN_PATH . 'includes/admin/views/scanner-page.php'; 
    }

    private function render_settings_section_page( $section, $tab = '' ) {
        global $rls_settings_section, $rls_settings_initial_tab;

        $rls_settings_section = $section;
        $rls_settings_initial_tab = $tab;

        // Dedicated views for new top-level sections.
        $section_views = [
            'hardening'     => 'hardening-page.php',
            '2fa'           => '2fa-page.php',
            'notifications' => 'notifications-page.php',
        ];

        if ( isset( $section_views[ $section ] ) ) {
            require RLS_PLUGIN_PATH . 'includes/admin/views/settings-page.php';
            require RLS_PLUGIN_PATH . 'includes/admin/views/' . $section_views[ $section ];
            unset( $rls_settings_section, $rls_settings_initial_tab );
            return;
        }

        require RLS_PLUGIN_PATH . 'includes/admin/views/settings-page.php';

        unset( $rls_settings_section, $rls_settings_initial_tab );
    }

    public function render_license_page() {
        $this->render_page_heading(
            'Лицензия',
            'dashicons-admin-network',
            'Управление лицензионным ключом Premium.'
        );
        $this->render_settings_section_page( 'license', 'tab-general' );
        echo '</div><!-- .rls-wrap -->';
    }

    public function render_protection_mode_page() {
        $this->render_page_heading(
            'Режим защиты',
            'dashicons-shield-alt',
            'Выберите профиль защиты и пресет для вашего сайта.',
            [ 'mode' => true ]
        );
        require RLS_PLUGIN_PATH . 'includes/admin/views/protection-mode-page.php';
        echo '</div><!-- .rls-wrap -->';
    }

    public function ajax_apply_protection_mode() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( 'Access Denied' );
        $profile = sanitize_key( $_POST['profile'] ?? '' );
        $preset  = sanitize_key( $_POST['preset'] ?? '' );
        if ( ! $profile ) wp_send_json_error( 'Не указан профиль.' );
        $result = RLS_Mode_Manager::apply_profile( $profile, $preset ? $preset : null );
        if ( is_wp_error( $result ) ) wp_send_json_error( $result->get_error_message() );
        wp_send_json_success( [
            'message' => 'Профиль применён.',
            'impact'  => $result,
        ] );
    }

    public function ajax_preview_protection_mode() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error();
        $profile = sanitize_key( $_POST['profile'] ?? '' );
        $preset  = sanitize_key( $_POST['preset'] ?? '' );
        if ( ! $profile ) wp_send_json_error();
        $impact = RLS_Mode_Manager::compute_impact_preview( $profile, $preset ? $preset : null );
        wp_send_json_success( $impact );
    }

    public function ajax_activate_emergency_mode() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( 'Access Denied' );
        $mode = sanitize_key( $_POST['mode'] ?? '' );
        $duration = (int) ( $_POST['duration'] ?? 0 );
        $result = RLS_Mode_Manager::set_emergency_mode( $mode, $duration > 0 ? $duration : null );
        if ( is_wp_error( $result ) ) wp_send_json_error( $result->get_error_message() );
        wp_send_json_success( [
            'message' => 'Аварийный режим активирован.',
            'data'    => $result,
        ] );
    }

    public function ajax_deactivate_emergency_mode() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error();
        RLS_Mode_Manager::deactivate_emergency_mode();
        wp_send_json_success( 'Аварийный режим деактивирован.' );
    }

    public function render_firewall_page() {
        $this->render_page_heading(
            'Фаервол',
            'dashicons-shield',
            'WAF: фильтрация SQLi, XSS, RCE, LFI, ботов и подозрительных запросов.'
        );
        $this->render_settings_section_page( 'firewall', 'tab-firewall' );
        echo '</div><!-- .rls-wrap -->';
    }

    public function render_blacklist_page() {
        $this->render_page_heading(
            'Черный список',
            'dashicons-dismiss',
            'Управление whitelist / blacklist IP, временные блокировки.'
        );
        $this->render_settings_section_page( 'blacklist', 'tab-lists' );
        echo '</div><!-- .rls-wrap -->';
    }

    public function render_login_security_page() {
        $this->render_page_heading(
            'Защита входа',
            'dashicons-lock',
            'Brute-force защита, honeypot, контрольные вопросы.'
        );
        $this->render_settings_section_page( 'login-security', 'tab-general' );
        echo '</div><!-- .rls-wrap -->';
    }

    public function render_settings_page() {
        $this->render_page_heading(
            'Сканер: настройки',
            'dashicons-admin-generic',
            'Параметры автоматического сканирования и база сигнатур.'
        );
        $this->render_settings_section_page( 'settings', 'tab-scanner' );
        echo '</div><!-- .rls-wrap -->';
    }

    public function render_policy_page() {
        $this->render_page_heading(
            'Условия и политика',
            'dashicons-media-document',
            'Лицензия, ответственность, правила использования.'
        );
        require_once RLS_PLUGIN_PATH . 'includes/admin/views/policy-page.php';
        echo '</div><!-- .rls-wrap -->';
    }

    public function render_hardening_page() {
        $this->render_page_heading(
            'Hardening',
            'dashicons-shield-alt',
            'Защита wp-config.php, CSP, скрытие версии WordPress.'
        );
        $this->render_settings_section_page( 'hardening', 'tab-general' );
        echo '</div><!-- .rls-wrap -->';
    }

    public function render_2fa_page() {
        $this->render_page_heading(
            '2FA (двухфакторная аутентификация)',
            'dashicons-smartphone',
            'TOTP аутентификация для администраторов (Google Authenticator, Authy, 1Password).'
        );
        $this->render_settings_section_page( '2fa', 'tab-general' );
        echo '</div><!-- .rls-wrap -->';
    }

    public function render_notifications_page() {
        $this->render_page_heading(
            'Email-уведомления',
            'dashicons-email-alt',
            'Настройка событий для email-уведомлений администратору.'
        );
        $this->render_settings_section_page( 'notifications', 'tab-general' );
        echo '</div><!-- .rls-wrap -->';
    }

    public function render_monitoring_page() {
        $this->render_page_heading(
            'Мониторинг',
            'dashicons-dashboard',
            'Real-time дашборд: текущие атаки, страны, типы.'
        );
        $monitor = new RLS_Monitoring_Dashboard();
        $monitor->render_page();
        echo '</div><!-- .rls-wrap -->';
    }

    public function render_health_page() {
        $health = new RLS_Health();
        $checks = $health->run_checks();
        $this->render_page_heading(
            'Диагностика',
            'dashicons-admin-site',
            'Проверка системы, конфликтов плагинов, модулей.'
        );
        echo '<table class="wp-list-table widefat striped"><thead><tr><th>Проверка</th><th>Значение</th><th>Статус</th></tr></thead><tbody>';
        foreach ( $checks as $c ) {
            $status_label = $c['status'] === 'ok' ? 'OK' : ( $c['status'] === 'warn' ? 'WARN' : 'ERR' );
            echo '<tr><td><strong>' . esc_html( $c['label'] ) . '</strong><br><small>' . esc_html( $c['hint'] ) . '</small></td>';
            echo '<td><code>' . esc_html( $c['value'] ) . '</code></td>';
            echo '<td><strong>' . esc_html( $status_label ) . '</strong></td></tr>';
        }
        echo '</tbody></table>';
        echo '<p><a href="' . esc_url( wp_nonce_url( admin_url( 'admin-ajax.php?action=rls_health_export' ), 'rls_health_nonce', 'nonce' ) ) . '" class="button">Экспорт отчёта</a></p>';
        echo '</div><!-- .rls-wrap -->';
    }

    public function render_wizard_page() {
        $this->render_page_heading(
            'Мастер настройки',
            'dashicons-welcome-learn-more',
            'Пошаговая настройка плагина для первого запуска.'
        );
        require_once RLS_PLUGIN_PATH . 'includes/admin/views/wizard.php';
        echo '</div><!-- .rls-wrap -->';
    }

    public function render_captcha_page() {
        if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Access denied' );
        if ( isset( $_POST['rls_captcha_settings'] ) && check_admin_referer( 'rls_captcha_group' ) ) {
            RLS_Captcha::update_settings( $_POST['rls_captcha_settings'] );
            echo '<div class="rls-notice is-success" style="margin:14px 0;">CAPTCHA настройки сохранены.</div>';
        }
        require_once RLS_PLUGIN_PATH . 'includes/admin/views/captcha-page.php';
    }

    public function render_analytics_page() {
        $this->render_page_heading(
            'Аналитика',
            'dashicons-chart-line',
            'Статистика атак, неудачных входов, типов и стран.'
        );
        $analytics = new RLS_Analytics_Page();
        $analytics->render_page();
        echo '</div><!-- .rls-wrap -->';
    }

    public function render_attack_map_page() {
        $this->render_page_heading(
            'Карта атак',
            'dashicons-admin-site',
            'География источников угроз на интерактивной карте мира.'
        );
        require_once RLS_PLUGIN_PATH . 'includes/admin/views/world-map.php';
        echo '</div><!-- .rls-wrap -->';
    }

    public function render_anomaly_page() {
        $this->render_page_heading(
            'Anomaly Detection',
            'dashicons-warning',
            'Обнаружение нетипичных паттернов входа пользователей.'
        );
        require_once RLS_PLUGIN_PATH . 'includes/admin/views/anomaly-heatmap.php';
        echo '</div><!-- .rls-wrap -->';
    }

    public function render_correlation_page() {
        $this->render_page_heading(
            'Корреляция атак',
            'dashicons-networking',
            'Связывание связанных атак в кампании (IP, UA, URI).'
        );
        require_once RLS_PLUGIN_PATH . 'includes/admin/views/correlation-page.php';
        echo '</div><!-- .rls-wrap -->';
    }

    public function render_reports_page() {
        $this->render_page_heading(
            'Отчёты',
            'dashicons-email',
            'Email + HTML отчёты по безопасности (print-ready PDF).'
        );
        require_once RLS_PLUGIN_PATH . 'includes/admin/views/reports-page.php';
        echo '</div><!-- .rls-wrap -->';
    }

    public function render_webhooks_page() {
        $this->render_page_heading(
            'Webhooks',
            'dashicons-rest-api',
            'Slack, Discord, Telegram, Custom.'
        );
        require_once RLS_PLUGIN_PATH . 'includes/admin/views/webhooks-page.php';
        echo '</div><!-- .rls-wrap -->';
    }

    public function render_attack_types_page() {
        $this->render_page_heading(
            'Типы атак',
            'dashicons-warning',
            'Полный справочник 18 типов угроз с подробными описаниями.'
        );
        require_once RLS_PLUGIN_PATH . 'includes/admin/views/attack-types-page.php';
        echo '</div><!-- .rls-wrap -->';
    }

    /**
     * Premium page — renders dedicated upsell or showcase view.
     */
    public function render_premium_page() {
        $is_prem = function_exists( 'rls_is_premium_license_active' ) && rls_is_premium_license_active();
        echo '<div class="wrap"><h1></h1>';
        require_once RLS_PLUGIN_PATH . 'includes/admin/views/premium-page.php';
        echo '</div>';
    }

    /**
     * Helper: render the premium banner (CTA or showcase) for inclusion in other views.
     */
    /**
     * Unified page heading helper.
     * Use this at the top of every page render method for consistent styling.
     */
    public function render_page_heading( $title, $icon = 'dashicons-admin-generic', $subtitle = '', $extra = [] ) {
        $mode = $extra['mode'] ?? '';
        $extra_badge = $extra['badge'] ?? '';
        $version = $extra['version'] ?? ( defined( 'RLS_VERSION' ) ? RLS_VERSION : '' );
        ?>
        <div class="wrap rls-wrap">
            <h1 class="rls-page-heading">
                <span class="dashicons <?php echo esc_attr( $icon ); ?>"></span>
                <?php echo esc_html( $title ); ?>
                <?php if ( $version ) : ?>
                    <span class="rls-page-version">v<?php echo esc_html( $version ); ?></span>
                <?php endif; ?>
                <?php if ( $extra_badge ) : ?>
                    <span class="rls-mode-badge <?php echo esc_attr( $extra['badge_class'] ?? '' ); ?>">
                        <?php echo esc_html( $extra_badge ); ?>
                    </span>
                <?php endif; ?>
                <?php if ( $mode && function_exists( 'rls_get_protection_mode_ui_state' ) ) :
                    $mode_ui = rls_get_protection_mode_ui_state(); ?>
                    <span class="rls-mode-badge <?php echo esc_attr( $mode_ui['mode'] ?? 'full' ); ?>">
                        <?php echo esc_html( $mode_ui['label'] ?? 'Полная защита' ); ?>
                    </span>
                <?php endif; ?>
            </h1>
            <?php if ( $subtitle ) : ?>
                <p class="rls-page-subtitle-block"><?php echo esc_html( $subtitle ); ?></p>
            <?php endif; ?>
        <?php
    }

    public function render_premium_banner( $args = [] ) {
        require_once RLS_PLUGIN_PATH . 'includes/admin/views/premium-banner.php';
    }

    public function maybe_redirect_after_activation() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        if ( wp_doing_ajax() || is_network_admin() ) {
            return;
        }

        if ( ! get_transient( 'rls_activation_redirect' ) ) {
            return;
        }

        delete_transient( 'rls_activation_redirect' );

        if ( isset( $_GET['activate-multi'] ) ) {
            return;
        }

        wp_safe_redirect( admin_url( 'admin.php?page=rls-protection-mode&rls-setup=1' ) );
        exit;
    }

    /**
     * пїЅпїЅпїЅпїЅпїЅпїЅ HTML пїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ.
     */
        public function render_deactivation_modal() {
        $screen = get_current_screen();
        if ( ! $screen || $screen->id !== 'plugins' ) {
            return;
        }
        ?>
        <div id="rls-deactivation-modal" style="display:none;">
            <div class="rls-modal-overlay"></div>
            <div class="rls-modal-content">
                <div id="rls-step-1">
                    <div class="rls-modal-header">
                        <span class="dashicons dashicons-shield-alt" style="color:#2271b1; font-size:40px; width:40px; height:40px;"></span>
                        <h2 style="margin:0; margin-left:15px;">Точно отключить защиту сайта?</h2>
                    </div>
                    <p style="font-size:14px; color:#555; margin-bottom:20px;">Если отключить <strong>Rybinsk Lab Security</strong>, сайт останется без активного WAF, защиты входа и других защитных модулей. Вы уверены, что хотите оставить сайт без защиты?</p>
                    <div style="padding:12px 14px; border:1px solid #f0c36d; background:#fff8e5; border-radius:8px; margin-bottom:20px; color:#7a4b00;">
                        Если передумаете, нажмите «Нет, оставить защиту» и плагин продолжит работать без изменений.
                    </div>

                    <div class="rls-modal-footer">
                        <button class="button button-large rls-cancel-btn">Нет, оставить защиту</button>
                        <button class="button button-primary button-large rls-next-btn">Да, отключить</button>
                    </div>
                </div>

                <div id="rls-step-2" style="display:none;">
                    <div class="rls-modal-header">
                        <span class="dashicons dashicons-database-remove" style="color:#d63638; font-size:40px; width:40px; height:40px;"></span>
                        <h2 style="margin:0; margin-left:15px;">Что делать с данными плагина?</h2>
                    </div>
                    <p style="margin-top:15px; font-size:14px;">Выберите, нужно ли очистить настройки, лицензию, карантин, журналы и локальные данные или оставить их для возможного возврата.</p>

                    <div class="rls-options">
                        <label class="rls-opt">
                            <input type="radio" name="rls_wipe_choice" value="keep" checked>
                            <div>
                                <strong>Оставить данные в памяти (рекомендуется)</strong>
                                <span class="desc">Сохранятся лицензия, настройки, карантин, журналы и другие локальные данные. Это удобно, если вы планируете включить плагин снова.</span>
                            </div>
                        </label>
                        <label class="rls-opt warning">
                            <input type="radio" name="rls_wipe_choice" value="wipe">
                            <div>
                                <strong>Очистить все данные плагина</strong>
                                <span class="desc">Будут удалены настройки, лицензия, карантин, GeoIP-база и журналы. После повторной активации плагин начнет работу как после первой установки.</span>
                            </div>
                        </label>
                    </div>

                    <div class="rls-modal-footer">
                        <button class="button button-large rls-back-btn">Назад</button>
                        <button class="button button-link-delete rls-final-deactivate-btn" style="color:#a00;">Отключить плагин</button>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }

    public function initialize_settings() {
        register_setting( 'rls_settings_group', 'rls_settings', [ $this, 'sanitize_settings_array' ] );
        register_setting( 'rls_settings_group', 'rls_auto_scan_frequency', [ 'sanitize_callback' => 'sanitize_text_field' ] );
        register_setting( 'rls_settings_group', 'rls_antispam_settings', [ $this, 'sanitize_antispam' ] );
        register_setting( 'rls_settings_group', 'rls_password_policy', [ $this, 'sanitize_password_policy' ] );
        register_setting( 'rls_settings_group', 'rls_notification_settings', [ $this, 'sanitize_notifications' ] );
    }

    public function sanitize_antispam( $input ) {
        $defaults = [
            'enabled'     => 0,
            'min_seconds' => 4,
            'max_links'   => 2,
        ];
        $input = is_array( $input ) ? $input : [];
        $out = $defaults;
        $out['enabled'] = ! empty( $input['enabled'] ) ? 1 : 0;
        $out['min_seconds'] = max( 0, min( 60, (int) ( $input['min_seconds'] ?? 4 ) ) );
        $out['max_links'] = max( 0, min( 20, (int) ( $input['max_links'] ?? 2 ) ) );
        return $out;
    }

    public function sanitize_password_policy( $input ) {
        $defaults = [
            'enabled'        => 0,
            'min_length'     => 12,
            'require_upper'  => 1,
            'require_lower'  => 1,
            'require_digit'  => 1,
            'require_symbol' => 1,
            'hibp_check'     => 1,
        ];
        $input = is_array( $input ) ? $input : [];
        $out = $defaults;
        $out['enabled']        = ! empty( $input['enabled'] ) ? 1 : 0;
        $out['min_length']     = max( 6, min( 128, (int) ( $input['min_length'] ?? 12 ) ) );
        $out['require_upper']  = ! empty( $input['require_upper'] ) ? 1 : 0;
        $out['require_lower']  = ! empty( $input['require_lower'] ) ? 1 : 0;
        $out['require_digit']  = ! empty( $input['require_digit'] ) ? 1 : 0;
        $out['require_symbol'] = ! empty( $input['require_symbol'] ) ? 1 : 0;
        $out['hibp_check']     = ! empty( $input['hibp_check'] ) ? 1 : 0;
        return $out;
    }

    public function sanitize_notifications( $input ) {
        $defaults = [
            'email'                    => get_option( 'admin_email' ),
            'notify_admin_login_new_ip'=> 1,
            'notify_bruteforce'        => 1,
            'notify_malware'           => 1,
            'notify_integrity'         => 1,
            'rate_limit_per_hour'      => 20,
        ];
        $input = is_array( $input ) ? $input : [];
        $out = $defaults;
        $email = sanitize_email( $input['email'] ?? '' );
        if ( $email !== '' && is_email( $email ) ) {
            $out['email'] = $email;
        }
        foreach ( [ 'notify_admin_login_new_ip', 'notify_bruteforce', 'notify_malware', 'notify_integrity' ] as $k ) {
            $out[ $k ] = ! empty( $input[ $k ] ) ? 1 : 0;
        }
        $out['rate_limit_per_hour'] = max( 0, min( 200, (int) ( $input['rate_limit_per_hour'] ?? 20 ) ) );
        return $out;
    }
    
    /**
     * пїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ.
     */
    public function sanitize_settings_array( $input ) {
        $old_settings = get_option( 'rls_settings', [] );
        $sanitized_input = $old_settings;

        $protection_mode = sanitize_key( (string) ( $input['protection_mode'] ?? ( $old_settings['protection_mode'] ?? 'full' ) ) );
        $sanitized_input['protection_mode'] = in_array( $protection_mode, [ 'light', 'full', 'scanner_only' ], true ) ? $protection_mode : 'full';
        
        $sanitized_input['enable_firewall'] = ( isset( $input['enable_firewall'] ) && $input['enable_firewall'] == 1 ) ? 1 : 0;
        $sanitized_input['disable_xmlrpc'] = ( isset( $input['disable_xmlrpc'] ) && $input['disable_xmlrpc'] == 1 ) ? 1 : 0;
        $sanitized_input['trust_cloudflare'] = ( isset( $input['trust_cloudflare'] ) && $input['trust_cloudflare'] == 1 ) ? 1 : 0;
        $sanitized_input['enable_login_security'] = ( isset( $input['enable_login_security'] ) && $input['enable_login_security'] == 1 ) ? 1 : 0;
        $sanitized_input['blacklists_enabled'] = ( isset( $input['blacklists_enabled'] ) && $input['blacklists_enabled'] == 1 ) ? 1 : 0;
        $is_premium = function_exists( 'rls_is_premium_license_active' ) && rls_is_premium_license_active();
        if ( $is_premium && $sanitized_input['protection_mode'] === 'light' ) {
            $sanitized_input['global_blacklist_enabled'] = ( isset( $input['global_blacklist_enabled'] ) && $input['global_blacklist_enabled'] == 1 ) ? 1 : 0;
        } else {
            $sanitized_input['global_blacklist_enabled'] = 0;
        }
        
        if ( isset( $input['login_questions_count'] ) ) { 
            $sanitized_input['login_questions_count'] = max( 1, min( 3, intval( $input['login_questions_count'] ) ) ); 
        }
        
        if ( isset( $input['license_key'] ) ) { 
            $sanitized_input['license_key'] = sanitize_text_field( strtoupper( trim( $input['license_key'] ) ) ); 

            $old_license_key = (string) ( $old_settings['license_key'] ?? '' );
            if ( $sanitized_input['license_key'] !== $old_license_key ) {
                rls_store_license_meta( '' );
                update_option( 'rls_premium_signatures', [] );
            }
        }
        
        $sanitized_input['allow_googlebot'] = ( isset( $input['allow_googlebot'] ) && $input['allow_googlebot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_yandexbot'] = ( isset( $input['allow_yandexbot'] ) && $input['allow_yandexbot'] == 1 ) ? 1 : 0;
        $sanitized_input['soft_search_bot_mode'] = ( isset( $input['soft_search_bot_mode'] ) && $input['soft_search_bot_mode'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_mailru_bot'] = ( isset( $input['allow_mailru_bot'] ) && $input['allow_mailru_bot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_bingbot']   = ( isset( $input['allow_bingbot'] ) && $input['allow_bingbot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_duckduckbot']   = ( isset( $input['allow_duckduckbot'] ) && $input['allow_duckduckbot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_baiduspider']   = ( isset( $input['allow_baiduspider'] ) && $input['allow_baiduspider'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_applebot']      = ( isset( $input['allow_applebot'] ) && $input['allow_applebot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_slurp']         = ( isset( $input['allow_slurp'] ) && $input['allow_slurp'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_seznambot']     = ( isset( $input['allow_seznambot'] ) && $input['allow_seznambot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_naverbot']      = ( isset( $input['allow_naverbot'] ) && $input['allow_naverbot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_petalbot']      = ( isset( $input['allow_petalbot'] ) && $input['allow_petalbot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_sogou']         = ( isset( $input['allow_sogou'] ) && $input['allow_sogou'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_exabot']        = ( isset( $input['allow_exabot'] ) && $input['allow_exabot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_qwantbot']      = ( isset( $input['allow_qwantbot'] ) && $input['allow_qwantbot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_mojeekbot']     = ( isset( $input['allow_mojeekbot'] ) && $input['allow_mojeekbot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_gptbot']        = ( isset( $input['allow_gptbot'] ) && $input['allow_gptbot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_chatgpt_user']  = ( isset( $input['allow_chatgpt_user'] ) && $input['allow_chatgpt_user'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_oai_searchbot'] = ( isset( $input['allow_oai_searchbot'] ) && $input['allow_oai_searchbot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_claudebot']     = ( isset( $input['allow_claudebot'] ) && $input['allow_claudebot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_perplexitybot'] = ( isset( $input['allow_perplexitybot'] ) && $input['allow_perplexitybot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_cohere_ai']     = ( isset( $input['allow_cohere_ai'] ) && $input['allow_cohere_ai'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_amazonbot']     = ( isset( $input['allow_amazonbot'] ) && $input['allow_amazonbot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_ccbot']         = ( isset( $input['allow_ccbot'] ) && $input['allow_ccbot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_bytespider']    = ( isset( $input['allow_bytespider'] ) && $input['allow_bytespider'] == 1 ) ? 1 : 0;

        if ( isset( $input['ssl_verify_api'] ) ) {
            $sanitized_input['ssl_verify_api'] = ( $input['ssl_verify_api'] == 1 ) ? 1 : 0;
        }
        $sanitized_input['captcha_enabled_admin'] = ( isset( $input['captcha_enabled_admin'] ) && $input['captcha_enabled_admin'] == 1 ) ? 1 : 0;
        $sanitized_input['captcha_enabled_users'] = ( isset( $input['captcha_enabled_users'] ) && $input['captcha_enabled_users'] == 1 ) ? 1 : 0;
        if ( isset( $input['captcha_client_key'] ) ) {
            $sanitized_input['captcha_client_key'] = sanitize_text_field( trim( $input['captcha_client_key'] ) );
        }
        if ( isset( $input['captcha_server_key'] ) ) {
            $sanitized_input['captcha_server_key'] = sanitize_text_field( trim( $input['captcha_server_key'] ) );
        }

        $is_premium = ( get_option( 'rls_license_status' ) === 'valid' );
        $sanitized_input['language_filter_enabled'] = ( isset( $input['language_filter_enabled'] ) && $input['language_filter_enabled'] == 1 ) ? 1 : 0;
        if ( isset( $input['language_mode'] ) ) {
            $language_mode = sanitize_text_field( $input['language_mode'] );
            $sanitized_input['language_mode'] = in_array( $language_mode, [ 'allow', 'block' ], true ) ? $language_mode : 'allow';
        }
        if ( isset( $input['language_codes'] ) ) {
            $raw = is_array( $input['language_codes'] ) ? $input['language_codes'] : explode( ',', (string) $input['language_codes'] );
            $codes = [];
            foreach ( $raw as $code ) {
                $lang = strtolower( preg_replace( '/[^a-z]/i', '', (string) $code ) );
                if ( preg_match( '/^[a-z]{2,3}$/', $lang ) ) {
                    $codes[] = $lang;
                }
            }
            $sanitized_input['language_codes'] = array_values( array_unique( $codes ) );
        }

        $sanitized_input['geo_blocking_enabled'] = ( isset( $input['geo_blocking_enabled'] ) && $input['geo_blocking_enabled'] == 1 ) ? 1 : 0;
        if ( isset( $input['geo_mode'] ) ) {
            $mode = sanitize_text_field( $input['geo_mode'] );
            $sanitized_input['geo_mode'] = in_array( $mode, [ 'allow', 'block' ], true ) ? $mode : 'block';
        }
        if ( isset( $input['geo_countries'] ) ) {
            $raw = is_array( $input['geo_countries'] ) ? $input['geo_countries'] : explode( ',', (string) $input['geo_countries'] );
            $countries = [];
            foreach ( $raw as $country ) {
                $code = strtoupper( preg_replace( '/[^A-Z]/i', '', (string) $country ) );
                if ( preg_match( '/^[A-Z]{2}$/', $code ) ) {
                    $countries[] = $code;
                }
            }
            $sanitized_input['geo_countries'] = array_values( array_unique( $countries ) );
        }
        if ( isset( $input['geo_countries_allow'] ) ) {
            $raw = is_array( $input['geo_countries_allow'] ) ? $input['geo_countries_allow'] : explode( ',', (string) $input['geo_countries_allow'] );
            $countries = [];
            foreach ( $raw as $country ) {
                $code = strtoupper( preg_replace( '/[^A-Z]/i', '', (string) $country ) );
                if ( preg_match( '/^[A-Z]{2}$/', $code ) ) {
                    $countries[] = $code;
                }
            }
            $countries = array_values( array_unique( $countries ) );
            if ( ! $is_premium ) {
                $countries = array_slice( $countries, 0, 3 );
            }
            $sanitized_input['geo_countries_allow'] = $countries;
        }
        if ( isset( $input['geo_countries_block'] ) ) {
            $raw = is_array( $input['geo_countries_block'] ) ? $input['geo_countries_block'] : explode( ',', (string) $input['geo_countries_block'] );
            $countries = [];
            foreach ( $raw as $country ) {
                $code = strtoupper( preg_replace( '/[^A-Z]/i', '', (string) $country ) );
                if ( preg_match( '/^[A-Z]{2}$/', $code ) ) {
                    $countries[] = $code;
                }
            }
            $countries = array_values( array_unique( $countries ) );
            if ( ! $is_premium ) {
                $countries = array_slice( $countries, 0, 5 );
            }
            $sanitized_input['geo_countries_block'] = $countries;
        }

        // Backward-compat поле синхронизируем с актуальными списками,
        // чтобы поведение GeoIP было предсказуемым при миграции настроек.
        $allow_sync = array_values( (array) ( $sanitized_input['geo_countries_allow'] ?? [] ) );
        $block_sync = array_values( (array) ( $sanitized_input['geo_countries_block'] ?? [] ) );
        $sanitized_input['geo_countries'] = array_values( array_unique( array_merge( $allow_sync, $block_sync ) ) );

        // New hardening toggles.
        $sanitized_input['hardening_enabled']  = ( isset( $input['hardening_enabled'] ) && $input['hardening_enabled'] == 1 ) ? 1 : 0;
        $sanitized_input['2fa_required_admin'] = ( isset( $input['2fa_required_admin'] ) && $input['2fa_required_admin'] == 1 ) ? 1 : 0;
        $sanitized_input['hotlink_protection'] = ( isset( $input['hotlink_protection'] ) && $input['hotlink_protection'] == 1 ) ? 1 : 0;
        $sanitized_input['hotlink_allowed_hosts'] = sanitize_text_field( (string) ( $input['hotlink_allowed_hosts'] ?? '' ) );
        $sanitized_input['security_score_visible'] = ( isset( $input['security_score_visible'] ) && $input['security_score_visible'] == 1 ) ? 1 : 0;

        if ( isset( $input['rls_setup_completed'] ) && (int) $input['rls_setup_completed'] === 1 ) {
            update_option( 'rls_setup_completed', 1 );
        }

        return $sanitized_input;
    }

    // --- AJAX пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ ---

    public function ajax_save_uninstall_pref() {
        if ( ! current_user_can( 'activate_plugins' ) ) wp_send_json_error();
        if ( ! check_ajax_referer( 'rls_settings_nonce', 'nonce', false ) ) wp_send_json_error();

        $wipe = ( isset($_POST['wipe']) && $_POST['wipe'] === 'true' );
        update_option( 'rls_wipe_data_on_uninstall', $wipe );
        wp_send_json_success();
    }

    public function ajax_save_license_key() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Доступ запрещен.' );
        }
        if ( ! check_ajax_referer( 'rls_settings_nonce', 'nonce', false ) ) {
            wp_send_json_error( 'Ошибка безопасности.' );
        }

        $license_key = sanitize_text_field( strtoupper( trim( (string) ( $_POST['license_key'] ?? '' ) ) ) );
        $settings = get_option( 'rls_settings', [] );
        $settings['license_key'] = $license_key;
        update_option( 'rls_settings', $settings );

        if ( $license_key === '' ) {
            rls_store_license_meta( 'invalid' );
            update_option( 'rls_premium_signatures', [] );
            wp_send_json_success( [
                'status' => 'cleared',
                'license_ui' => function_exists( 'rls_get_license_ui_state' ) ? rls_get_license_ui_state() : [],
            ] );
        }

        if ( ! class_exists( 'RLS_API_Client' ) ) {
            wp_send_json_error( 'API недоступно.' );
        }

        $validation = RLS_API_Client::validate_license_key( $license_key );
        if ( is_array( $validation ) && ( $validation['status'] ?? '' ) === 'success' ) {
            rls_store_license_meta( 'valid', (array) ( $validation['data'] ?? [] ) );

            $sig_res = RLS_API_Client::get_signatures( $license_key );
            if ( is_array( $sig_res ) && ( $sig_res['status'] ?? '' ) === 'success' ) {
                if ( isset( $sig_res['data']['signatures'] ) ) {
                    update_option( 'rls_premium_signatures', $sig_res['data']['signatures'], false );
                }
            }

            $ip_res = RLS_API_Client::get_global_blacklist();
            if ( is_array( $ip_res ) && ( $ip_res['status'] ?? '' ) === 'success' && ! empty( $ip_res['data']['ips'] ) ) {
                update_option( 'rls_global_blacklist', $ip_res['data']['ips'], false );
            }

            // Was the previous state free? Then we just activated — flag for confetti.
            $previous_status = get_option( 'rls_license_status', '' );
            $was_free = empty( $previous_status ) || $previous_status === 'invalid';

            wp_send_json_success( [
                'status' => 'valid',
                'license_ui' => function_exists( 'rls_get_license_ui_state' ) ? rls_get_license_ui_state() : [],
                'premium_activated' => $was_free,
            ] );
        }

        rls_store_license_meta( 'invalid' );
        update_option( 'rls_premium_signatures', [] );

        $message = 'Ключ недействителен или срок действия истек.';
        if ( is_wp_error( $validation ) ) {
            $message = $validation->get_error_message();
        } elseif ( is_array( $validation ) && ! empty( $validation['message'] ) ) {
            $message = (string) $validation['message'];
        }

        wp_send_json_error( $message );
    }

    public function ajax_delete_license_key() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Доступ запрещен.' );
        }
        if ( ! check_ajax_referer( 'rls_settings_nonce', 'nonce', false ) ) {
            wp_send_json_error( 'Ошибка безопасности.' );
        }

        $settings = get_option( 'rls_settings', [] );
        $settings['license_key'] = '';
        update_option( 'rls_settings', $settings );
        rls_store_license_meta( 'invalid' );
        update_option( 'rls_premium_signatures', [] );

        wp_send_json_success( [
            'status' => 'cleared',
            'license_ui' => function_exists( 'rls_get_license_ui_state' ) ? rls_get_license_ui_state() : [],
        ] );
    }

    // --- AI-проверка файла (CHECKSUMS + SIZE CHECK) ---
    public function ajax_neutralize_file() {
        check_ajax_referer('rls_scanner_nonce', 'nonce');
        if ( ! current_user_can('manage_options') ) {
            wp_send_json_error('Доступ запрещен.');
        }

        $filepath  = wp_normalize_path( trim( wp_unslash( $_POST['filepath'] ?? '' ) ) );
        $signature = trim( wp_unslash( $_POST['signature'] ?? '' ) );

        if ( empty( $filepath ) ) {
            wp_send_json_error('Путь не указан.');
        }
        if ( ! $this->is_safe_file_path( $filepath ) ) {
            wp_send_json_error('Недопустимый путь.');
        }
        if ( ! file_exists( $filepath ) || ! is_readable( $filepath ) ) {
            wp_send_json_error('Файл недоступен.');
        }

        // 1. Проверка целостности файла ядра WordPress
        require_once( ABSPATH . 'wp-admin/includes/update.php' );
        $relative = str_replace( wp_normalize_path(ABSPATH), '', $filepath );
        global $wp_version;
        $checksums = get_core_checksums( $wp_version, get_locale() );

        if ( is_array($checksums) && isset( $checksums[$relative] ) ) {
            if ( md5_file($filepath) === $checksums[$relative] ) {
                $this->add_to_whitelist($filepath);
                wp_send_json_success(['result' => 'whitelisted']);
                return;
            }
        }

        $filesize = @filesize($filepath);
        $max_ai_bytes = 204800;
        if ( class_exists( 'RLS_API_Client' ) && method_exists( 'RLS_API_Client', 'get_ai_snippet_limit_bytes' ) ) {
            $max_ai_bytes = (int) RLS_API_Client::get_ai_snippet_limit_bytes();
        }

        $snip = "";
        $found_sig = false;

        // Поиск фрагмента вокруг совпадения сигнатуры
        if ( ! empty( $signature ) && strlen( $signature ) <= 255 ) {
            $lines = file( $filepath, FILE_IGNORE_NEW_LINES );
            if ( is_array( $lines ) ) {
                foreach ( $lines as $k => $l ) {
                    if ( strpos( $l, $signature ) !== false ) {
                        $start = max( 0, $k - 3 );
                        $end   = min( count( $lines ) - 1, $k + 3 );
                        for ( $i = $start; $i <= $end; $i++ ) {
                            $snip .= "L" . ( $i + 1 ) . ": " . $lines[ $i ] . "\n";
                        }
                        $found_sig = true;
                        break;
                    }
                }
            }
        }

        // Fallback: head+tail snippet
        if ( ! $found_sig ) {
            $content = file_get_contents( $filepath );
            if ( $content === false ) {
                wp_send_json_error( 'Не удалось прочитать файл.' );
            }
            if ( $max_ai_bytes > 0 && strlen( $content ) > $max_ai_bytes ) {
                $head_bytes = max( 1, (int) floor( $max_ai_bytes / 2 ) );
                $tail_bytes = max( 1, $max_ai_bytes - $head_bytes );
                $head = substr( $content, 0, $head_bytes );
                $tail = substr( $content, -$tail_bytes );
                $snip = $head . "\n...\n" . $tail;
            } else {
                $snip = $content;
            }
            // Free original content from memory; only the snippet leaves the host.
            unset( $content );
        }

        if ( ! $snip ) {
            wp_send_json_error('Не удалось подготовить фрагмент кода.');
        }

        if ( class_exists('RLS_API_Client') ) {
            $ai = RLS_API_Client::analyze_code_snippet($snip);

            if ( ! is_wp_error( $ai ) && isset( $ai['data']['verdict'] ) ) {
                if ( $ai['data']['verdict'] === 'Virus' ) {
                    wp_send_json_success(['result' => 'ai_virus', 'snippet' => $snip]);
                } else {
                    $this->add_to_whitelist($filepath);
                    wp_send_json_success(['result' => 'ai_legitimate']);
                }
            } else {
                wp_send_json_error('Не удалось выполнить AI-анализ.');
            }
        } else {
            wp_send_json_error('API недоступно.');
        }
    }

    /**
     * Whitelist-safe path check shared with the scanner engine.
     */
    private function is_safe_file_path( $filepath ) {
        $filepath = wp_normalize_path( (string) $filepath );
        if ( empty( $filepath ) || strlen( $filepath ) > 1024 ) return false;
        if ( strpos( $filepath, '..' ) !== false || strpos( $filepath, "\0" ) !== false ) return false;
        $abspath    = wp_normalize_path( ABSPATH );
        $wp_content = wp_normalize_path( WP_CONTENT_DIR );
        $inside_root = ( strpos( $filepath, $abspath ) === 0 || strpos( $filepath, $wp_content ) === 0 );
        if ( ! $inside_root ) return false;
        $quarantine = wp_normalize_path( wp_upload_dir()['basedir'] . '/rls-quarantine' );
        if ( strpos( $filepath, $quarantine ) === 0 ) return false;
        if ( strpos( $filepath, wp_normalize_path( WP_PLUGIN_DIR . '/rybinsklab-security' ) ) === 0 ) return false;
        return true;
    }

    private function add_to_whitelist( $filepath ) {
        $filepath = wp_normalize_path( (string) $filepath );
        if ( ! $this->is_safe_file_path( $filepath ) ) return;
        $w = get_option('rls_whitelist', []);
        $w[ $filepath ] = [
            'hash'  => (string) md5_file( $filepath ),
            'mtime' => (int) @filemtime( $filepath ),
        ];
        update_option( 'rls_whitelist', $w, false );
    }

    public function ajax_add_ip_list() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( 'Доступ запрещен.' );

        $ip = sanitize_text_field( $_POST['ip'] );
        $list_type = sanitize_text_field( $_POST['list'] ); 

        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) wp_send_json_error( 'Некорректный IP.' );

        $opt_name = ( $list_type === 'white' ) ? 'rls_ip_whitelist' : 'rls_manual_blacklist';
        $list = get_option( $opt_name, [] );

        if ( ! in_array( $ip, $list ) ) {
            $list[] = $ip;
            update_option( $opt_name, $list );
            
            if ( $list_type === 'black' && class_exists('RLS_API_Client') ) {
                RLS_API_Client::submit_banned_ip( $ip, 'Manual Ban by Admin', [
                    'status' => 'global',
                    'source_kind' => 'manual',
                    'type' => 'manual',
                ] );
            }
        }

        wp_send_json_success( [ 'ip' => $ip, 'list' => $list_type ] );
    }

    public function ajax_delete_ip_list() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( 'Доступ запрещен.' );

        $ip = sanitize_text_field( $_POST['ip'] );
        $list_type = sanitize_text_field( $_POST['list'] );
        
        $opt_name = ( $list_type === 'white' ) ? 'rls_ip_whitelist' : 'rls_manual_blacklist';
        $list = get_option( $opt_name, [] );
        
        $key = array_search( $ip, $list );
        if ( $key !== false ) {
            unset( $list[$key] );
            update_option( $opt_name, array_values( $list ) );
        }
        wp_send_json_success();
    }

    public function ajax_unblock_ip() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( 'Доступ запрещен.' );

        $ip = sanitize_text_field( $_POST['ip'] ?? '' );
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            wp_send_json_error( 'Некорректный IP.' );
        }

        $changed = false;

        $blocked = get_option( 'rls_blocked_ips', [] );
        if ( is_array( $blocked ) && isset( $blocked[ $ip ] ) ) {
            unset( $blocked[ $ip ] );
            update_option( 'rls_blocked_ips', $blocked, false );
            $changed = true;
        }

        $locked = get_option( 'rls_locked_ips', [] );
        if ( is_array( $locked ) && isset( $locked[ $ip ] ) ) {
            unset( $locked[ $ip ] );
            update_option( 'rls_locked_ips', $locked );
            $changed = true;
        }

        wp_send_json_success( [ 'removed' => $changed ] );
    }

    public function ajax_add_signature() {
        check_ajax_referer( 'rls_signatures_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( 'Доступ запрещен.' );
        $signature = trim( stripslashes( $_POST['signature'] ?? '' ) );
        if ( empty( $signature ) ) wp_send_json_error( 'Введите сигнатуру.' );
        $custom = get_option( 'rls_custom_signatures', [] );
        if ( ! in_array( $signature, $custom ) ) {
            $custom[] = $signature;
            update_option( 'rls_custom_signatures', $custom );
            try { RLS_API_Client::submit_suggestion( $signature ); } catch ( Exception $e ) {}
        }
        wp_send_json_success( [ 'signature' => esc_html( $signature ) ] );
    }
    
    public function ajax_delete_signature() {
        check_ajax_referer( 'rls_signatures_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( 'Доступ запрещен.' );
        $signature = trim( stripslashes( $_POST['signature'] ?? '' ) );
        $custom = get_option( 'rls_custom_signatures', [] );
        $key = array_search( $signature, $custom );
        if ( $key !== false ) {
            unset( $custom[ $key ] );
            update_option( 'rls_custom_signatures', array_values( $custom ) );
            wp_cache_delete( 'rls_signatures_' . wp_cache_get( 'rls_signatures_version', 'rls' ), 'rls' );
        }
        wp_send_json_success();
    }

    public function ajax_add_login_question() {
        check_ajax_referer('rls_login_questions_nonce', 'nonce');
        if ( ! current_user_can('manage_options') ) wp_send_json_error();

        $q = trim( wp_unslash( $_POST['question'] ?? '' ) );
        $a = trim( wp_unslash( $_POST['answer'] ?? '' ) );

        if ( $q === '' || $a === '' ) wp_send_json_error();
        // Length caps prevent storage abuse and DoS via massive inputs.
        if ( mb_strlen( $q ) > 255 || mb_strlen( $a ) > 255 ) wp_send_json_error();

        $qs = get_option('rls_login_questions', []);
        $qs[] = [
            'q'     => sanitize_text_field( $q ),
            'a'     => password_hash( $a, PASSWORD_DEFAULT ),
            'plain' => '', // SECURITY: never persist plaintext answers.
        ];
        update_option('rls_login_questions', $qs);
        wp_send_json_success(['key' => count($qs) - 1, 'q' => esc_html( $q )]);
    }

    public function ajax_delete_login_question() {
        check_ajax_referer('rls_login_questions_nonce', 'nonce');
        if ( ! current_user_can('manage_options') ) wp_send_json_error();

        $key = (int) ( $_POST['key'] ?? -1 );
        $qs = get_option('rls_login_questions', []);

        if ( isset( $qs[ $key ] ) ) {
            unset( $qs[ $key ] );
            update_option('rls_login_questions', array_values( $qs ));
        }
        wp_send_json_success();
    }
    
    public function ajax_sync_stats() { 
        wp_send_json_success(); 
    }

    public function ajax_clear_attack_logs() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Доступ запрещен.' );
        }

        if ( ! class_exists( 'RLS_Logger' ) ) {
            wp_send_json_error( 'Логгер недоступен.' );
        }

        $summary = method_exists( 'RLS_Logger', 'get_log_summary' ) ? RLS_Logger::get_log_summary() : [ 'total' => RLS_Logger::get_logs_count(), 'types' => [] ];
        $deleted_count = (int) ( $summary['total'] ?? 0 );

        if ( $deleted_count > 0 && class_exists( 'RLS_API_Client' ) ) {
            $report_response = RLS_API_Client::report_attack_log_cleanup( $summary );

            if ( is_wp_error( $report_response ) || ( is_array( $report_response ) && ( ( $report_response['status'] ?? '' ) !== 'success' ) && ( ( $report_response['status'] ?? '' ) !== 'queued' ) ) ) {
                $message = is_wp_error( $report_response ) ? $report_response->get_error_message() : 'Сервер не подтвердил прием статистики.';
                wp_send_json_error( 'Не удалось отправить статистику на сервер перед очисткой: ' . $message );
            }
        }

        RLS_Logger::clear_logs();

        wp_send_json_success( [ 'deleted_count' => (int) $deleted_count ] );
    }
}
