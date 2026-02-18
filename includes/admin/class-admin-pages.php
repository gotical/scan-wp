<?php
/**
 * Класс RLS_Admin_Pages
 * Управляет административными страницами, меню, сохранением настроек и AJAX-запросами.
 * Версия 1.6.0 (Complete: Quarantine Init included)
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

class RLS_Admin_Pages {

    /**
     * Инициализация всех хуков админки.
     */
    public function init() {
        // Регистрация меню и страниц
        add_action( 'admin_menu', [ $this, 'setup_admin_menu' ] );
        
        // Подключение стилей и скриптов
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_admin_assets' ] );
        
        // Регистрация настроек в базе данных
        add_action( 'admin_init', [ $this, 'initialize_settings' ] );
        
        // Отправка сигнала "Я жив" при посещении админки
        add_action( 'admin_init', [ $this, 'check_and_send_heartbeat_on_visit' ] );
        
        // Проверка наличия базовых сигнатур (самовосстановление)
        add_action( 'admin_init', [ $this, 'check_and_fix_base_signatures' ] );

        // Вывод HTML модального окна деактивации (в футер админки)
        add_action( 'admin_footer', [ $this, 'render_deactivation_modal' ] );

        // ИНИЦИАЛИЗАЦИЯ КАРАНТИНА (НОВОЕ)
        if ( class_exists( 'RLS_Quarantine' ) ) {
            $quarantine = new RLS_Quarantine();
            $quarantine->init();
        }

        // --- AJAX ОБРАБОТЧИКИ ---

        // Сохранение предпочтений при удалении
        add_action( 'wp_ajax_rls_save_uninstall_pref', [ $this, 'ajax_save_uninstall_pref' ] );

        // Управление списками IP
        add_action( 'wp_ajax_rls_add_ip_list', [ $this, 'ajax_add_ip_list' ] );
        add_action( 'wp_ajax_rls_delete_ip_list', [ $this, 'ajax_delete_ip_list' ] );

        // Управление сигнатурами
        add_action( 'wp_ajax_rls_add_signature', [ $this, 'ajax_add_signature' ] );
        add_action( 'wp_ajax_rls_delete_signature', [ $this, 'ajax_delete_signature' ] );
        
        // Управление вопросами входа
        add_action( 'wp_ajax_rls_add_login_question', [ $this, 'ajax_add_login_question' ] );
        add_action( 'wp_ajax_rls_delete_login_question', [ $this, 'ajax_delete_login_question' ] );
        
        // AI Анализ и лечение (С проверкой размера и чексумм)
        add_action( 'wp_ajax_rls_neutralize_file', [ $this, 'ajax_neutralize_file' ] );
        
        // Синхронизация статистики
        add_action( 'wp_ajax_rls_sync_stats', [ $this, 'ajax_sync_stats' ] );
    }
    
    /**
     * Отправка Heartbeat при посещении страниц плагина.
     */
    public function check_and_send_heartbeat_on_visit() {
        if ( isset( $_GET['page'] ) && strpos( $_GET['page'], 'rls-' ) === 0 ) {
            $last_admin_ping = get_transient( 'rls_admin_heartbeat_sent' );
            if ( ! $last_admin_ping ) {
                if ( class_exists( 'RLS_API_Client' ) ) {
                    RLS_API_Client::send_heartbeat(); 
                    set_transient( 'rls_admin_heartbeat_sent', 1, 300 ); // 300 сек = 5 мин
                }
            }
        }
    }
    
    /**
     * Гарантирует наличие базовых сигнатур.
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
     * Создание пунктов меню в админке.
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
        
        add_submenu_page( 
            'rls-scanner', 
            'Настройки', 
            'Настройки', 
            'manage_options', 
            'rls-settings', 
            [ $this, 'render_settings_page' ] 
        );
    }
    
    /**
     * Подключение CSS и JS файлов.
     */
    public function enqueue_admin_assets( $hook_suffix ) {
        // Подключаем стили и скрипты только на страницах плагина И на странице списка плагинов (для модалки)
        if ( strpos( $hook_suffix, 'rls-' ) === false && $hook_suffix !== 'plugins.php' ) {
            return;
        }
        
        wp_enqueue_style( 'rls-admin-styles', plugin_dir_url( RLS_PLUGIN_FILE ) . 'assets/css/admin.css', [], RLS_VERSION );

        // Скрипт для админки (Настройки + Модальное окно)
        if ( $hook_suffix === 'rl-security_page_rls-settings' || $hook_suffix === 'plugins.php' ) {
            wp_enqueue_script( 'rls-admin-script', plugin_dir_url( RLS_PLUGIN_FILE ) . 'assets/js/admin.js', [ 'jquery' ], RLS_VERSION, true );
            wp_localize_script( 'rls-admin-script', 'rls_admin_data', [
                'ajax_url'         => admin_url( 'admin-ajax.php' ), 
                'settings_nonce'   => wp_create_nonce( 'rls_settings_nonce' ),
                'sync_nonce'       => wp_create_nonce( 'rls_sync_nonce' ),
                'questions_nonce'  => wp_create_nonce( 'rls_login_questions_nonce' ),
                'signatures_nonce' => wp_create_nonce( 'rls_signatures_nonce' )
            ]);
        }
        
        // Скрипт для сканера
        if ( $hook_suffix === 'toplevel_page_rls-scanner' || $hook_suffix === 'rl-security_page_rls-scanner' ) {
            wp_enqueue_script( 'rls-scanner-script', plugin_dir_url( RLS_PLUGIN_FILE ) . 'assets/js/scanner.js', [ 'jquery' ], RLS_VERSION, true );
            wp_localize_script( 'rls-scanner-script', 'rls_scanner_data', [
                'ajax_url'        => admin_url( 'admin-ajax.php' ),
                'nonce'           => wp_create_nonce( 'rls_scanner_nonce' ),
                'snapshot_exists' => ( get_option( 'rls_snapshot_time', 0 ) > 0 )
            ]);
        }
    }
    
    // Рендер страниц
    public function render_scanner_page() {
        require_once RLS_PLUGIN_PATH . 'includes/admin/views/scanner-page.php'; 
    }
    
    public function render_settings_page() {
        require_once RLS_PLUGIN_PATH . 'includes/admin/views/settings-page.php'; 
    }

    /**
     * Рендер HTML кода модального окна деактивации.
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
                        <h2 style="margin:0; margin-left:15px;">Приостановить защиту?</h2>
                    </div>
                    <p style="font-size:14px; color:#555; margin-bottom:20px;">Вы деактивируете плагин <strong>Rybinsk Lab Security</strong>. Сайт останется без защиты.</p>
                    
                    <div class="rls-options">
                        <label class="rls-opt">
                            <input type="radio" name="rls_wipe_choice" value="keep" checked>
                            <div>
                                <strong>Временно (Сохранить настройки)</strong>
                                <span class="desc">Я вернусь позже. Сохранить лицензию, журнал атак, белый список и снимки файлов.</span>
                            </div>
                        </label>
                        <label class="rls-opt warning">
                            <input type="radio" name="rls_wipe_choice" value="wipe">
                            <div>
                                <strong>Удалить полностью</strong>
                                <span class="desc">Стереть все данные, включая лицензию и историю проверок. Это действие необратимо.</span>
                            </div>
                        </label>
                    </div>

                    <div class="rls-modal-footer">
                        <button class="button button-large rls-cancel-btn">Отмена</button>
                        <button class="button button-primary button-large rls-next-btn">Продолжить</button>
                    </div>
                </div>

                <div id="rls-step-2" style="display:none;">
                    <div class="rls-modal-header">
                        <span class="dashicons dashicons-heart" style="color:#d63638; font-size:40px; width:40px; height:40px;"></span>
                        <h2 style="margin:0; margin-left:15px;">Подождите, не уходите!</h2>
                    </div>
                    <p style="margin-top:15px; font-size:14px;">Если причина удаления — стоимость или проблемы с настройкой, давайте это обсудим.</p>
                    
                    <div class="rls-offer-box">
                        <p style="margin-bottom:10px;"><strong>Нужен Premium бесплатно?</strong></p>
                        <p>Напишите мне лично в Telegram. Я могу выдать вам <strong>ключ на 1 месяц бесплатно</strong>, чтобы вы оценили полный функционал.</p>
                        <a href="https://t.me/ukiterus" target="_blank" class="button button-primary rls-tg-btn">
                            <span class="dashicons dashicons-location-alt"></span> Написать @ukiterus
                        </a>
                    </div>

                    <div class="rls-modal-footer">
                        <button class="button button-large rls-cancel-btn">Я остаюсь</button>
                        <button class="button button-link-delete rls-final-deactivate-btn" style="color:#a00;">Всё равно удалить данные и деактивировать</button>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }
    
    /**
     * Регистрация настроек.
     */
    public function initialize_settings() { 
        register_setting( 'rls_settings_group', 'rls_settings', [ $this, 'sanitize_settings_array' ] );
        register_setting( 'rls_settings_group', 'rls_auto_scan_frequency', [ 'sanitize_callback' => 'sanitize_text_field' ] );
    }
    
    /**
     * Очистка настроек.
     */
    public function sanitize_settings_array( $input ) {
        $old_settings = get_option( 'rls_settings', [] );
        $sanitized_input = $old_settings;
        
        $sanitized_input['enable_firewall'] = ( isset( $input['enable_firewall'] ) && $input['enable_firewall'] == 1 ) ? 1 : 0;
        $sanitized_input['disable_xmlrpc'] = ( isset( $input['disable_xmlrpc'] ) && $input['disable_xmlrpc'] == 1 ) ? 1 : 0;
        $sanitized_input['trust_cloudflare'] = ( isset( $input['trust_cloudflare'] ) && $input['trust_cloudflare'] == 1 ) ? 1 : 0;
        $sanitized_input['enable_login_security'] = ( isset( $input['enable_login_security'] ) && $input['enable_login_security'] == 1 ) ? 1 : 0;
        
        if ( isset( $input['login_questions_count'] ) ) { 
            $sanitized_input['login_questions_count'] = intval( $input['login_questions_count'] ); 
        }
        
        if ( isset( $input['license_key'] ) ) { 
            $sanitized_input['license_key'] = sanitize_text_field( strtoupper( trim( $input['license_key'] ) ) ); 
        }
        
        $sanitized_input['allow_googlebot'] = ( isset( $input['allow_googlebot'] ) && $input['allow_googlebot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_yandexbot'] = ( isset( $input['allow_yandexbot'] ) && $input['allow_yandexbot'] == 1 ) ? 1 : 0;
        $sanitized_input['allow_bingbot']   = ( isset( $input['allow_bingbot'] ) && $input['allow_bingbot'] == 1 ) ? 1 : 0;

        if ( isset( $input['ssl_verify_api'] ) ) {
            $sanitized_input['ssl_verify_api'] = ( $input['ssl_verify_api'] == 1 ) ? 1 : 0;
        }

        return $sanitized_input;
    }

    // --- AJAX ОБРАБОТЧИКИ ---

    public function ajax_save_uninstall_pref() {
        if ( ! current_user_can( 'activate_plugins' ) ) wp_send_json_error();
        
        $wipe = ( isset($_POST['wipe']) && $_POST['wipe'] === 'true' );
        update_option( 'rls_wipe_data_on_uninstall', $wipe );
        
        if ( $wipe && class_exists('RLS_API_Client') ) {
            RLS_API_Client::report_deactivation();
        }
        wp_send_json_success();
    }

    // --- АНАЛИЗ ФАЙЛА (AI + CHECKSUMS + SIZE CHECK) ---
    public function ajax_neutralize_file() {
        check_ajax_referer('rls_scanner_nonce', 'nonce'); 
        if (!current_user_can('manage_options')) wp_send_json_error('Нет прав.');
        
        // ВАЖНО: Используем wp_normalize_path для согласованности путей
        $filepath = wp_normalize_path( trim(stripslashes($_POST['filepath'] ?? '')) ); 
        $signature = trim(stripslashes($_POST['signature'] ?? ''));
        
        if (empty($filepath) || !file_exists($filepath) || !is_readable($filepath)) wp_send_json_error('Файл недоступен.');
        
        // 1. ПРОВЕРКА ЦЕЛОСТНОСТИ ЯДРА WP
        require_once( ABSPATH . 'wp-admin/includes/update.php' );
        
        // Получаем относительный путь (от корня WP)
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

        // 2. ПРОВЕРКА РАЗМЕРА ФАЙЛА
        $filesize = @filesize($filepath);
        if ( $filesize > 102400 ) { // > 100 КБ
            wp_send_json_success(['result' => 'too_large']);
            return;
        }

        // 3. ПОДГОТОВКА СНИППЕТА
        $lines = file($filepath, FILE_IGNORE_NEW_LINES); 
        $snip = "";
        $found_sig = false;

        // Если сигнатура есть, пытаемся найти контекст
        if ( !empty($signature) ) {
            foreach($lines as $k=>$l) {
                if(strpos($l, $signature) !== false) { 
                    $start = max(0, $k-3); 
                    $end = min(count($lines)-1, $k+3);
                    for($i=$start; $i<=$end; $i++) $snip.="L".($i+1).": ".$lines[$i]."\n"; 
                    $found_sig = true;
                    break; 
                }
            }
        }
        
        // Если сигнатура не найдена (например, измененный файл), берем начало
        if ( !$found_sig ) {
            $content = file_get_contents($filepath);
            $snip = substr($content, 0, 1500); 
        }
        
        if(!$snip) wp_send_json_error('Не удалось прочитать файл.');
        
        // 4. ОТПРАВКА В AI
        if ( class_exists('RLS_API_Client') ) {
            $ai = RLS_API_Client::analyze_code_snippet($snip);
            
            if(!is_wp_error($ai) && isset($ai['data']['verdict'])) {
                if($ai['data']['verdict'] === 'Virus') {
                    wp_send_json_success(['result' => 'ai_virus', 'snippet' => $snip]);
                } else { 
                    $this->add_to_whitelist($filepath); 
                    wp_send_json_success(['result' => 'ai_legitimate']); 
                }
            } else {
                wp_send_json_error('Ошибка ответа AI');
            }
        } else {
            wp_send_json_error('API недоступен');
        }
    }

    private function add_to_whitelist( $filepath ) {
        // Нормализация пути при сохранении
        $filepath = wp_normalize_path( $filepath );
        $w = get_option('rls_whitelist', []); 
        $w[$filepath] = md5_file($filepath); 
        update_option('rls_whitelist', $w, false); 
    }

    public function ajax_add_ip_list() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( 'Нет прав.' );

        $ip = sanitize_text_field( $_POST['ip'] );
        $list_type = sanitize_text_field( $_POST['list'] ); 

        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) wp_send_json_error( 'Некорректный IP' );

        $opt_name = ( $list_type === 'white' ) ? 'rls_ip_whitelist' : 'rls_manual_blacklist';
        $list = get_option( $opt_name, [] );

        if ( ! in_array( $ip, $list ) ) {
            $list[] = $ip;
            update_option( $opt_name, $list );
            
            if ( $list_type === 'black' && class_exists('RLS_API_Client') ) {
                RLS_API_Client::submit_banned_ip( $ip, 'Manual Ban by Admin' );
            }
        }

        wp_send_json_success( [ 'ip' => $ip, 'list' => $list_type ] );
    }

    public function ajax_delete_ip_list() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( 'Нет прав.' );

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

    public function ajax_add_signature() {
        check_ajax_referer( 'rls_signatures_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( 'Нет прав.' );
        $signature = trim( stripslashes( $_POST['signature'] ?? '' ) );
        if ( empty( $signature ) ) wp_send_json_error( 'Пусто.' );
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
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( 'Нет прав.' );
        $signature = trim( stripslashes( $_POST['signature'] ?? '' ) );
        $custom = get_option( 'rls_custom_signatures', [] );
        $key = array_search( $signature, $custom );
        if ( $key !== false ) {
            unset( $custom[ $key ] );
            update_option( 'rls_custom_signatures', array_values( $custom ) );
        }
        wp_send_json_success();
    }

    public function ajax_add_login_question() {
        check_ajax_referer('rls_login_questions_nonce', 'nonce'); 
        if(!current_user_can('manage_options')) wp_send_json_error();
        
        $q = trim(stripslashes($_POST['question'] ?? '')); 
        $a = trim(stripslashes($_POST['answer'] ?? ''));
        
        if($q && $a) { 
            $qs = get_option('rls_login_questions', []); 
            $qs[] = ['q' => $q, 'a' => password_hash($a, PASSWORD_DEFAULT)]; 
            update_option('rls_login_questions', $qs); 
            wp_send_json_success(['key' => count($qs)-1, 'q' => esc_html($q)]); 
        } 
        wp_send_json_error();
    }
    
    public function ajax_delete_login_question() {
        check_ajax_referer('rls_login_questions_nonce', 'nonce'); 
        if(!current_user_can('manage_options')) wp_send_json_error();
        
        $key = intval($_POST['key']); 
        $qs = get_option('rls_login_questions', []); 
        
        if(isset($qs[$key])) { 
            unset($qs[$key]); 
            update_option('rls_login_questions', array_values($qs)); 
        } 
        wp_send_json_success();
    }
    
    public function ajax_sync_stats() { 
        wp_send_json_success(); 
    }
}