<?php
/**
 * Класс RLS_Login_Security
 * Добавляет защиту на страницу входа через глобальные контрольные вопросы.
 * Автор: Усачёв Денис (https://rybinsklab.ru)
 */

if (!defined('WPINC')) {
    die;
}

class RLS_Login_Security {

    /**
     * Инициализатор. Регистрирует хуки, если модуль включен.
     */
    public function init() {
        $settings = get_option('rls_settings', []);
        if (empty($settings['enable_login_security'])) {
            return;
        }

        // Убираем все хуки, связанные с профилем пользователя
        // add_action('show_user_profile', ...); - УДАЛЕНО

        // Оставляем только хуки для страницы входа
        add_action('login_form', [$this, 'render_login_fields']);
        add_filter('authenticate', [$this, 'verify_security_answers'], 30, 3);
    }
    
    /**
     * Отображает случайные контрольные вопросы на странице входа.
     */
    public function render_login_fields() {
        $settings = get_option('rls_settings', ['login_questions_count' => 1]);
        $all_questions = get_option('rls_login_questions', []);
        
        // Прекращаем, если нет настроенных вопросов
        if (empty($all_questions)) return;

        $count_to_show = (int)($settings['login_questions_count'] ?? 1);
        if ($count_to_show <= 0) $count_to_show = 1;
        
        // Выбираем случайные ключи из массива вопросов
        $random_keys = (count($all_questions) <= $count_to_show)
            ? array_keys($all_questions)
            : (array) array_rand($all_questions, $count_to_show);

        // Сохраняем в сессию, какие вопросы мы показали, чтобы потом их проверить
        if (session_status() === PHP_SESSION_NONE) session_start();
        $_SESSION['rls_login_question_keys'] = $random_keys;

        echo '<div class="rls-login-questions">';
        foreach ($random_keys as $key) {
            $question_data = $all_questions[$key];
            echo '<p>
                <label for="rls_security_answer_' . esc_attr($key) . '">' . esc_html($question_data['q']) . '<br/>
                <input type="text" name="rls_security_answers[' . esc_attr($key) . ']" id="rls_security_answer_' . esc_attr($key) . '" class="input" value="" size="20" autocomplete="off" />
                </label>
            </p>';
        }
        echo '</div>';
    }
    
    /**
     * Проверяет ответы на контрольные вопросы при попытке входа.
     */
    public function verify_security_answers($user, $username, $password) {
        if (is_wp_error($user) || !$user instanceof WP_User) return $user;
        
        if (session_status() === PHP_SESSION_NONE) session_start();

        // Получаем ключи вопросов, которые были показаны пользователю
        $question_keys_shown = $_SESSION['rls_login_question_keys'] ?? [];
        unset($_SESSION['rls_login_question_keys']); // Очищаем сессию
        
        // Если вопросов не было показано (например, не настроены), пропускаем
        if (empty($question_keys_shown)) return $user;
        
        $all_questions = get_option('rls_login_questions', []);
        $submitted_answers = $_POST['rls_security_answers'] ?? [];

        foreach ($question_keys_shown as $key) {
            $correct_answer_hash = $all_questions[$key]['a_hash'] ?? null;
            $submitted_answer = trim($submitted_answers[$key] ?? '');

            // Если для вопроса нет хэша или ответ не предоставлен, или ответ неверный
            if (!$correct_answer_hash || !wp_check_password($submitted_answer, $correct_answer_hash)) {
                RLS_Stats_Helper::increment_stat('login_attempts_blocked');
                $error_message = '<strong>ОШИБКА</strong>: Неверный ответ на контрольный вопрос.';
                // Предотвращаем подсказку о том, какой именно ответ неверный
                return new WP_Error('rls_incorrect_answer', $error_message);
            }
        }

        return $user; // Все ответы верные
    }
}