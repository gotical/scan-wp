<?php
/**
 * Класс RLS_Login_Security
 * Защита входа: Контрольные вопросы, Honeypot, Anti-BruteForce.
 * Версия 1.5.5
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

    public function init() {
        // Отрисовка полей защиты
        add_action( 'login_form', [ $this, 'render_login_fields' ] );
        
        // Брендирование
        add_action( 'login_footer', [ $this, 'render_login_branding' ] );
        
        // Проверка при входе (с высоким приоритетом)
        add_filter( 'authenticate', [ $this, 'check_login_attempt' ], 30, 3 );
        
        // Логирование неудачных попыток
        add_action( 'wp_login_failed', [ $this, 'log_failed_attempt' ] );
    }
    
    public function render_login_branding() {
        ?>
        <div style="text-align: center; width: 100%; margin-top: 20px; padding-bottom: 20px; color: #72777c; font-size: 13px;">
            <p style="margin: 0;">
                <span class="dashicons dashicons-shield-alt" style="color: #46b450; vertical-align: bottom; font-size: 18px;"></span>
                <a href="https://rybinsklab.ru/scan-wp/" target="_blank" rel="dofollow" title="Плагин безопасности WordPress" style="color: #72777c; text-decoration: none; border-bottom: 1px dotted #999; transition: color 0.3s;">
                    Активна защита
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
        // 1. HONEYPOT
        echo '<div style="position: absolute; left: -9999px; top: -9999px;">
            <label>Человеку не заполнять<input type="text" name="rls_honey_trap" value="" tabindex="-1" autocomplete="off" /></label>
        </div>';

        // Получаем IP
        $ip = $this->get_ip_address();

        // 2. БЕЛЫЙ СПИСОК
        if ( $this->is_ip_whitelisted( $ip ) ) {
            return;
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
        
        // Выбираем случайные вопросы
        $count = isset( $settings['login_questions_count'] ) ? (int)$settings['login_questions_count'] : 1;
        
        // array_rand может вернуть один ключ или массив, приводим к массиву
        $available_keys = array_keys($questions);
        if (empty($available_keys)) return;

        // Если вопросов меньше чем требуемое количество, берем все
        if (count($questions) <= $count) {
             $selected_keys = $available_keys;
        } else {
             $random_indexes = array_rand($questions, $count);
             $selected_keys = is_array($random_indexes) ? $random_indexes : [$random_indexes];
        }
        
        echo '<div class="rls-login-questions" style="margin-bottom:15px; padding:10px; background:#f0f6fc; border-left:4px solid #72aee6;">';
        foreach ( $selected_keys as $key ) {
            if (!isset($questions[$key])) continue;
            $q = $questions[$key];
            echo '<p><label>' . esc_html( $q['q'] ) . '<br>';
            // Используем $key как есть (даже если это строка)
            echo '<input type="text" name="rls_q_' . esc_attr($key) . '" class="input" value="" size="20" required autocomplete="off" />';
            echo '</label></p>';
        }
        echo '</div>';
    }

    /**
     * Основная проверка перед авторизацией.
     */
    public function check_login_attempt( $user, $username, $password ) {
        // Если WP уже вернул ошибку, выходим
        if ( is_wp_error( $user ) ) {
            return $user;
        }
        
        $ip = $this->get_ip_address();
        
        // 0. ПРОВЕРКА БЕЛОГО СПИСКА
        if ( $this->is_ip_whitelisted( $ip ) ) {
            return $user;
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

        // 3. ПРОВЕРКА ВОПРОСОВ
        $settings = get_option( 'rls_settings', [] );
        if ( ! empty( $settings['enable_login_security'] ) ) {
            $questions = get_option( 'rls_login_questions', [] );
            
            if ( ! empty( $questions ) ) {
                $question_answered = false; // Флаг: был ли найден хоть один ответ

                foreach ( $_POST as $key => $val ) {
                    // Ищем поля rls_q_ID
                    if ( strpos( $key, 'rls_q_' ) === 0 ) {
                        // Получаем ID, убирая префикс. Не используем intval(), чтобы не сломать строковые ключи
                        $q_id = str_replace( 'rls_q_', '', $key );
                        
                        if ( isset( $questions[$q_id] ) ) {
                            $question_answered = true;
                            
                            // ВАЖНО: Убираем экранирование и пробелы
                            $answer = trim( stripslashes( $val ) );
                            
                            // Сверяем хеш. 
                            // Внимание: Хеши чувствительны к регистру. Ответ должен быть введен так, как был сохранен.
                            if ( ! password_verify( $answer, $questions[$q_id]['a'] ) ) {
                                $this->log_failed_attempt( $username ); 
                                return new WP_Error( 'rls_wrong_answer', '<strong>ОШИБКА</strong>: Неверный ответ на контрольный вопрос.' );
                            }
                        }
                    }
                }
                
                // (Опционально) Если вопросы включены, но в POST запросе их нет — это подозрительно (обход формы)
                // Но мы не блокируем здесь жестко, чтобы не сломать XML-RPC или другие методы входа,
                // так как фильтр authenticate срабатывает везде.
            }
        }

        return $user;
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
        
        $locked_ips[ $ip ] = time() + self::LOCKOUT_TIME;
        update_option( 'rls_locked_ips', $locked_ips );
        
        if ( class_exists( 'RLS_Logger' ) ) RLS_Logger::log_attack( $ip, 'brute', 'IP Locked Out' );
        if ( class_exists( 'RLS_API_Client' ) ) RLS_API_Client::submit_banned_ip( $ip, 'Brute Force' );
    }

    private function is_ip_locked( $ip ) {
        $locked_ips = get_option( 'rls_locked_ips', [] );
        if ( is_array( $locked_ips ) && isset( $locked_ips[ $ip ] ) ) {
            if ( time() < $locked_ips[ $ip ] ) {
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
        if ( $trust_cf && isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
            if ( filter_var( $_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP ) ) {
                return $_SERVER['HTTP_CF_CONNECTING_IP'];
            }
        }
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    private function is_ip_whitelisted( $ip ) {
        $whitelist = get_option( 'rls_ip_whitelist', [] );
        return is_array( $whitelist ) && in_array( $ip, $whitelist );
    }
}