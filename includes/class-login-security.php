<?php
/**
 * Класс RLS_Login_Security
 * Защита входа: Контрольные вопросы, Honeypot, Anti-BruteForce.
 * Версия 2.3.0
 * 
 * Исправления:
 * 1. Добавлен stripslashes() для корректной обработки ответов с кавычками.
 * 2. Убран intval() для поддержки строковых ключей вопросов.
 * 3. Улучшена логика проверки ошибок.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Login_Security {

    const MAX_RETRIES = 5; // Максимум попыток
    const LOCKOUT_TIME = 3600; // Время бана (1 час)
    const RETRY_WINDOW = 1800; // Время хранения счетчика попыток (30 минут)
    const CAPTCHA_VERIFY_URL = 'https://smartcaptcha.cloud.yandex.ru/validate';
    const LOCKOUT_LEVELS = [ 3600, 21600, 86400 ]; // 1ч, 6ч, 24ч
    const AUTO_BLACKLIST_AFTER = 3; // После 3 lockout переносим IP в локальный blacklist

    public function init() {
        // Отрисовка полей защиты
        add_action( 'login_form', [ $this, 'render_login_fields' ] );
        add_filter( 'login_form_middle', [ $this, 'inject_login_form_middle' ], 10, 2 );
        
        // Брендирование
        add_action( 'login_footer', [ $this, 'render_login_branding' ] );
        
        // Проверка при входе (с высоким приоритетом)
        add_filter( 'authenticate', [ $this, 'check_login_attempt' ], 30, 3 );
        
        // Логирование неудачных попыток
        add_action( 'wp_login_failed', [ $this, 'log_failed_attempt' ] );
    }
    
    public function render_login_branding() {
        $mode_ui = function_exists( 'rls_get_protection_mode_ui_state' ) ? rls_get_protection_mode_ui_state() : [];
        $brand_color = $mode_ui['badge_background'] ?? '#46b450';
        $branding_text = $mode_ui['login_branding_text'] ?? 'Активна защита';
        ?>
        <div style="text-align: center; width: 100%; margin-top: 20px; padding-bottom: 20px; color: #72777c; font-size: 13px;">
            <p style="margin: 0;">
                <span class="dashicons dashicons-shield-alt" style="color: <?php echo esc_attr( $brand_color ); ?>; vertical-align: bottom; font-size: 18px;"></span>
                <a href="https://rybinsklab.ru/scan-wp/" target="_blank" rel="dofollow" title="Плагин безопасности WordPress" style="color: #72777c; text-decoration: none; border-bottom: 1px dotted #999; transition: color 0.3s;">
                    <?php echo esc_html( $branding_text ); ?>
                </a>
                <span style="margin: 0 5px; color: #ddd;">|</span>
                <a href="https://rybinsklab.ru/" target="_blank" rel="dofollow" title="Разработка и безопасность" style="color: #72777c; text-decoration: none; font-weight: 600; transition: color 0.3s;">
                    РыбинскLAB
                </a>
            </p>
            <style>.login a:hover { color: #2271b1 !important; border-color: #2271b1 !important; }</style>
        </div>
        <?php
    }

    /**
     * Рисует скрытое поле (Honeypot) и вопросы.
     */
    public function render_login_fields() {
        if ( function_exists( 'rls_is_scanner_only_mode' ) && rls_is_scanner_only_mode() ) {
            return;
        }

        // 1. HONEYPOT
        echo '<div style="position: absolute; left: -9999px; top: -9999px;">
            <label>Человеку не заполнять<input type="text" name="rls_honey_trap" value="" tabindex="-1" autocomplete="off" /></label>
        </div>';
        echo '<input type="hidden" name="rls_form_protected" value="1" />';

        // Получаем IP
        $ip = $this->get_ip_address();

        // 2. БЕЛЫЙ СПИСОК
        $is_whitelisted = $this->is_ip_whitelisted( $ip );
        if ( ! $is_whitelisted ) {
            $this->render_smartcaptcha_widget();
        }

        // 3. КОНТРОЛЬНЫЕ ВОПРОСЫ
        $settings = get_option( 'rls_settings', [] );
        if ( empty( $settings['enable_login_security'] ) ) {
            return;
        }
        
        $questions = get_option( 'rls_login_questions', [] );
        if ( empty( $questions ) ) {
            return;
        }

        $normalized_questions = [];
        foreach ( $questions as $question_key => $question_entry ) {
            $normalized = $this->normalize_question_entry( $question_entry );
            if ( $normalized['q'] !== '' && ( $normalized['a'] !== '' || $normalized['plain'] !== '' ) ) {
                $normalized_questions[ $question_key ] = $normalized;
            }
        }
        if ( empty( $normalized_questions ) ) {
            return;
        }
        
        // Выбираем случайные вопросы
        $count = isset( $settings['login_questions_count'] ) ? (int) $settings['login_questions_count'] : 1;
        
        // array_rand может вернуть один ключ или массив, приводим к массиву
        $available_keys = array_keys( $normalized_questions );
        if ( empty( $available_keys ) ) return;

        $count = max( 1, min( $count, count( $available_keys ) ) );

        // Если вопросов меньше чем требуемое количество, берем все
        if ( count( $available_keys ) <= $count ) {
             $selected_keys = $available_keys;
        } else {
             $random_indexes = array_rand( $available_keys, $count );
             $random_indexes = is_array( $random_indexes ) ? $random_indexes : [ $random_indexes ];
             $selected_keys = [];
             foreach ( $random_indexes as $random_index ) {
                 $selected_keys[] = $available_keys[$random_index];
             }
        }
        
        echo '<div class="rls-login-questions" style="margin-bottom:15px; padding:10px; background:#f0f6fc; border-left:4px solid #72aee6;">';
        foreach ( $selected_keys as $key ) {
            if ( ! isset( $normalized_questions[ $key ] ) ) continue;
            echo '<p><label>' . esc_html( $normalized_questions[ $key ]['q'] ) . '<br>';
            // Используем $key как есть (даже если это строка)
            echo '<input type="text" name="rls_q_' . esc_attr( $key ) . '" class="input" value="" size="20" required autocomplete="off" />';
            echo '</label></p>';
        }
        echo '</div>';
    }

    /**
     * Основная проверка перед авторизацией.
     */
    public function inject_login_form_middle( $content, $args ) {
        if ( ! is_string( $content ) ) {
            $content = '';
        }

        ob_start();
        $this->render_login_fields();
        return $content . ob_get_clean();
    }

    public function check_login_attempt( $user, $username, $password ) {
        // Если WP уже вернул ошибку, выходим
        if ( is_wp_error( $user ) ) {
            return $user;
        }

        if ( function_exists( 'rls_is_scanner_only_mode' ) && rls_is_scanner_only_mode() ) {
            return $user;
        }
        
        $ip = $this->get_ip_address();
        
        // 0. ПРОВЕРКА БЕЛОГО СПИСКА
        $is_whitelisted = $this->is_ip_whitelisted( $ip );

        if ( ! $is_whitelisted ) {
            $captcha_error = $this->verify_smartcaptcha( $ip );
            if ( is_wp_error( $captcha_error ) ) {
                return $captcha_error;
            }

        // 1. ПРОВЕРКА БАНА
        if ( $this->is_ip_locked( $ip ) ) {
            $this->log_attack_stat( 'login_attempts_blocked' );
            if ( class_exists( 'RLS_Logger' ) ) RLS_Logger::log_attack( $ip, 'brute', 'Login Attempt (Blocked IP)' );
            return new WP_Error( 'rls_locked', '<strong>ОШИБКА</strong>: Слишком много неудачных попыток. Ваш IP заблокирован на 1 час.' );
        }

        // 2. ПРОВЕРКА HONEYPOT
            if ( ! empty( $_POST['rls_honey_trap'] ) ) {
            $this->lock_ip( $ip );
            $this->log_attack_stat( 'bad_bots_blocked' );
            if ( class_exists( 'RLS_Logger' ) ) RLS_Logger::log_attack( $ip, 'bot', 'Honeypot Triggered' );
            return new WP_Error( 'rls_bot', '<strong>ОШИБКА</strong>: Обнаружена подозрительная активность.' );
            }
        }

        // 3. ПРОВЕРКА ВОПРОСОВ
        $settings = get_option( 'rls_settings', [] );
        if ( ! empty( $settings['enable_login_security'] ) ) {
            $questions = get_option( 'rls_login_questions', [] );
            
            if ( ! empty( $questions ) && $this->is_password_login_request() ) {
                $normalized_questions = [];
                foreach ( $questions as $question_key => $question_entry ) {
                    $normalized = $this->normalize_question_entry( $question_entry );
                    if ( $normalized['q'] !== '' && ( $normalized['a'] !== '' || $normalized['plain'] !== '' ) ) {
                        $normalized_questions[ $question_key ] = $normalized;
                    }
                }

                $valid_question_count = count( $normalized_questions );

                if ( $valid_question_count < 1 ) {
                    return $user;
                }

                $required_answers = isset( $settings['login_questions_count'] ) ? (int) $settings['login_questions_count'] : 1;
                $required_answers = max( 1, min( $required_answers, $valid_question_count ) );
                $valid_answers = 0;

                foreach ( $_POST as $key => $val ) {
                    // Ищем поля rls_q_ID
                    if ( strpos( $key, 'rls_q_' ) === 0 ) {
                        // Получаем ID, убирая префикс. Не используем intval(), чтобы не сломать строковые ключи
                        $q_id = str_replace( 'rls_q_', '', $key );
                        
                        if ( isset( $normalized_questions[ $q_id ] ) ) {
                            if ( is_array( $val ) ) {
                                $this->log_failed_attempt( $username );
                                return new WP_Error( 'rls_wrong_answer', '<strong>ОШИБКА</strong>: Неверный ответ на контрольный вопрос.' );
                            }
                            
                            // ВАЖНО: Убираем экранирование и пробелы
                            $answer = trim( wp_unslash( (string) $val ) );
                            
                            // Сверяем хеш. 
                            // Внимание: Хеши чувствительны к регистру. Ответ должен быть введен так, как был сохранен.
                            if ( ! $this->verify_question_answer( $answer, $normalized_questions[ $q_id ] ) ) {
                                $this->log_failed_attempt( $username ); 
                                return new WP_Error( 'rls_wrong_answer', '<strong>ОШИБКА</strong>: Неверный ответ на контрольный вопрос.' );
                            }

                            $valid_answers++;
                        }
                    }
                }

                if ( $valid_answers < $required_answers ) {
                    $this->log_failed_attempt( $username );
                    return new WP_Error( 'rls_missing_answer', '<strong>ОШИБКА</strong>: Ответьте на контрольный вопрос.' );
                }
                
                // (Опционально) Если вопросы включены, но в POST запросе их нет — это подозрительно (обход формы)
                // Но мы не блокируем здесь жестко, чтобы не сломать XML-RPC или другие методы входа,
                // так как фильтр authenticate срабатывает везде.
            }
        }

        return $user;
    }

    private function is_password_login_request() {
        if ( ( $_SERVER['REQUEST_METHOD'] ?? '' ) !== 'POST' ) {
            return false;
        }

        if ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
            return false;
        }

        if ( function_exists( 'wp_doing_ajax' ) && wp_doing_ajax() ) {
            return false;
        }

        $action = 'login';
        if ( isset( $_REQUEST['action'] ) && ! is_array( $_REQUEST['action'] ) ) {
            $action = sanitize_key( wp_unslash( (string) $_REQUEST['action'] ) );
        }

        if ( $action !== 'login' ) {
            return false;
        }

        return isset( $_POST['log'], $_POST['pwd'] );
    }

    private function normalize_question_entry( $question_entry ) {
        if ( is_object( $question_entry ) ) {
            $question_entry = (array) $question_entry;
        }

        if ( ! is_array( $question_entry ) ) {
            return [ 'q' => '', 'a' => '', 'plain' => '' ];
        }

        $question_text = '';
        foreach ( [ 'q', 'question', 'text' ] as $question_key ) {
            if ( isset( $question_entry[ $question_key ] ) && ! is_array( $question_entry[ $question_key ] ) ) {
                $question_text = trim( wp_unslash( (string) $question_entry[ $question_key ] ) );
                if ( $question_text !== '' ) {
                    break;
                }
            }
        }

        $answer_hash = '';
        foreach ( [ 'a', 'answer_hash', 'hash' ] as $answer_key ) {
            if ( isset( $question_entry[ $answer_key ] ) && ! is_array( $question_entry[ $answer_key ] ) ) {
                $answer_hash = trim( (string) $question_entry[ $answer_key ] );
                if ( $answer_hash !== '' ) {
                    break;
                }
            }
        }

        $answer_plain = '';
        foreach ( [ 'answer', 'plain_answer' ] as $plain_key ) {
            if ( isset( $question_entry[ $plain_key ] ) && ! is_array( $question_entry[ $plain_key ] ) ) {
                $answer_plain = trim( wp_unslash( (string) $question_entry[ $plain_key ] ) );
                if ( $answer_plain !== '' ) {
                    break;
                }
            }
        }

        return [
            'q' => $question_text,
            'a' => $answer_hash,
            'plain' => $answer_plain,
        ];
    }

    private function verify_question_answer( $answer, $normalized_question ) {
        $answer = (string) $answer;

        $stored_hash = isset( $normalized_question['a'] ) ? (string) $normalized_question['a'] : '';
        if ( $stored_hash !== '' ) {
            return password_verify( $answer, $stored_hash );
        }

        $stored_plain = isset( $normalized_question['plain'] ) ? (string) $normalized_question['plain'] : '';
        if ( $stored_plain !== '' ) {
            return hash_equals( $stored_plain, $answer );
        }

        return false;
    }

    /**
     * Логирование неудачной попытки входа.
     */
    public function log_failed_attempt( $username ) {
        $ip = $this->get_ip_address();
        $transient_key = 'rls_login_fail_' . md5( $ip );
        
        $attempts = (int) get_transient( $transient_key );
        $attempts++;
        
        set_transient( $transient_key, $attempts, self::RETRY_WINDOW );
        $this->log_attack_stat( 'login_attempts_blocked' ); 
        
        if ( class_exists( 'RLS_Logger' ) ) {
            RLS_Logger::log_attack( $ip, 'brute', "Failed Login: $username ($attempts/" . self::MAX_RETRIES . ")" );
        }

        if ( $attempts >= self::MAX_RETRIES ) {
            $this->lock_ip( $ip );
            delete_transient( $transient_key );
        }
    }

    private function lock_ip( $ip ) {
        $locked_ips = get_option( 'rls_locked_ips', [] );
        if ( ! is_array( $locked_ips ) ) $locked_ips = [];

        $lockout_meta = get_option( 'rls_bruteforce_lockouts', [] );
        if ( ! is_array( $lockout_meta ) ) $lockout_meta = [];

        $lock_count = (int) ( $lockout_meta[ $ip ]['count'] ?? 0 ) + 1;
        $level_index = $lock_count - 1;
        if ( $level_index < 0 ) $level_index = 0;
        if ( $level_index >= count( self::LOCKOUT_LEVELS ) ) $level_index = count( self::LOCKOUT_LEVELS ) - 1;
        $lock_seconds = (int) self::LOCKOUT_LEVELS[ $level_index ];
        if ( $lock_seconds <= 0 ) $lock_seconds = self::LOCKOUT_TIME;

        $locked_ips[ $ip ] = [
            'expires' => time() + $lock_seconds,
            'level'   => $lock_count
        ];
        update_option( 'rls_locked_ips', $locked_ips );

        $lockout_meta[ $ip ] = [
            'count'     => $lock_count,
            'last_seen' => time()
        ];
        update_option( 'rls_bruteforce_lockouts', $lockout_meta, false );

        if ( class_exists( 'RLS_Logger' ) ) RLS_Logger::log_attack( $ip, 'brute', 'IP Locked Out (' . $lock_seconds . ' sec, level ' . $lock_count . ')' );
        if ( class_exists( 'RLS_API_Client' ) ) {
            RLS_API_Client::submit_banned_ip( $ip, 'Brute Force', [
                'status' => 'pending',
                'source_kind' => 'brute',
                'type' => 'brute',
            ] );
        }

        if ( $lock_count >= self::AUTO_BLACKLIST_AFTER ) {
            $manual_blacklist = get_option( 'rls_manual_blacklist', [] );
            if ( ! is_array( $manual_blacklist ) ) $manual_blacklist = [];

            if ( ! in_array( $ip, $manual_blacklist, true ) ) {
                $manual_blacklist[] = $ip;
                update_option( 'rls_manual_blacklist', $manual_blacklist );
                if ( class_exists( 'RLS_Logger' ) ) RLS_Logger::log_attack( $ip, 'brute', 'IP moved to manual blacklist (repeat brute force)' );
            }
        }
    }

    private function is_ip_locked( $ip ) {
        $locked_ips = get_option( 'rls_locked_ips', [] );
        if ( is_array( $locked_ips ) && isset( $locked_ips[ $ip ] ) ) {
            $lock_row = $locked_ips[ $ip ];
            $expires = 0;
            if ( is_array( $lock_row ) ) {
                $expires = (int) ( $lock_row['expires'] ?? 0 );
            } else {
                // Backward compatibility со старым форматом, где хранился timestamp.
                $expires = (int) $lock_row;
            }

            if ( $expires > 0 && time() < $expires ) {
                return true;
            } else {
                unset( $locked_ips[ $ip ] );
                update_option( 'rls_locked_ips', $locked_ips );
            }
        }
        return false;
    }

    private function log_attack_stat( $key ) {
        $stats = get_option( 'rls_stats', [] );
        if ( ! is_array( $stats ) ) $stats = [];
        if ( ! isset( $stats[ $key ] ) ) $stats[ $key ] = 0;
        $stats[ $key ]++;
        update_option( 'rls_stats', $stats );
    }

    private function get_ip_address() {
        $settings = get_option( 'rls_settings', [] );
        $trust_cf = ! empty( $settings['trust_cloudflare'] );

        if ( $trust_cf ) {
            $header_chain = [
                'HTTP_CF_CONNECTING_IP',
                'HTTP_X_REAL_IP',
                'HTTP_X_FORWARDED_FOR',
            ];

            foreach ( $header_chain as $header_key ) {
                if ( empty( $_SERVER[ $header_key ] ) ) {
                    continue;
                }

                $candidate = (string) $_SERVER[ $header_key ];
                if ( $header_key === 'HTTP_X_FORWARDED_FOR' ) {
                    $parts = explode( ',', $candidate );
                    $candidate = trim( (string) ( $parts[0] ?? '' ) );
                }

                if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
                    return $candidate;
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    private function is_ip_whitelisted( $ip ) {
        $whitelist = get_option( 'rls_ip_whitelist', [] );
        return is_array( $whitelist ) && in_array( $ip, $whitelist );
    }

    private function render_smartcaptcha_widget() {
        if ( ! $this->is_captcha_required_for_current_login() ) {
            return;
        }

        $settings = get_option( 'rls_settings', [] );
        $client_key = trim( (string) ( $settings['captcha_client_key'] ?? '' ) );
        if ( $client_key === '' ) {
            return;
        }

        echo '<div style="margin:12px 0;">';
        echo '<div class="smart-captcha" data-sitekey="' . esc_attr( $client_key ) . '" data-hl="ru"></div>';
        echo '</div>';
        echo '<script src="https://smartcaptcha.cloud.yandex.ru/captcha.js" defer></script>';
    }

    private function is_captcha_required_for_current_login() {
        if ( function_exists( 'rls_is_scanner_only_mode' ) && rls_is_scanner_only_mode() ) {
            return false;
        }

        $action = isset( $_REQUEST['action'] ) ? (string) $_REQUEST['action'] : 'login';
        if ( $action !== 'login' ) {
            return false;
        }

        $settings = get_option( 'rls_settings', [] );
        $for_admin = ! empty( $settings['captcha_enabled_admin'] );
        $for_users = ! empty( $settings['captcha_enabled_users'] );
        if ( ! $for_admin && ! $for_users ) {
            return false;
        }

        $redirect_to = isset( $_REQUEST['redirect_to'] ) ? (string) $_REQUEST['redirect_to'] : '';
        $is_admin_login_context = ( strpos( $redirect_to, '/wp-admin' ) !== false || strpos( $redirect_to, 'wp-admin' ) !== false );

        if ( $is_admin_login_context ) {
            return $for_admin;
        }
        return $for_users;
    }

    private function verify_smartcaptcha( $ip ) {
        if ( ! $this->is_captcha_required_for_current_login() ) {
            return true;
        }

        $settings = get_option( 'rls_settings', [] );
        $server_key = trim( (string) ( $settings['captcha_server_key'] ?? '' ) );
        if ( $server_key === '' ) {
            return new WP_Error( 'rls_captcha_config', '<strong>Ошибка</strong>: не настроен Server key SmartCaptcha.' );
        }

        $token = isset( $_POST['smart-token'] ) ? sanitize_text_field( wp_unslash( $_POST['smart-token'] ) ) : '';
        if ( $token === '' ) {
            return new WP_Error( 'rls_captcha_missing', '<strong>Ошибка</strong>: подтвердите, что вы не робот.' );
        }

        $response = wp_remote_post( self::CAPTCHA_VERIFY_URL, [
            'timeout' => 8,
            'body'    => [
                'secret' => $server_key,
                'token'  => $token,
                'ip'     => $ip,
            ],
        ] );

        if ( is_wp_error( $response ) ) {
            return new WP_Error( 'rls_captcha_network', '<strong>Ошибка</strong>: не удалось проверить капчу. Повторите попытку.' );
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( ! is_array( $body ) || ( $body['status'] ?? 'failed' ) !== 'ok' ) {
            return new WP_Error( 'rls_captcha_failed', '<strong>Ошибка</strong>: капча не пройдена.' );
        }

        return true;
    }
}
