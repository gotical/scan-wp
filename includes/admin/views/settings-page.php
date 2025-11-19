<?php
/**
 * HTML-шаблон для страницы настроек плагина.
 * Финальная версия со всеми модулями, включая фильтр ботов.
 * Автор: Усачёв Денис (https://rybinsklab.ru)
 */

if (!defined('WPINC')) die;

// --- Обработка активации ключа и принудительной синхронизации ---
if (isset($_POST['rls_force_sync_button']) && check_admin_referer('rls_force_sync_nonce')) {
    $settings = get_option('rls_settings', []);
    $license_key = $settings['license_key'] ?? '';
    $current_status = get_option('rls_license_status');
    if (!empty($license_key)) {
        RLS_Cron::sync_stats_with_server();
        $response = RLS_API_Client::validate_license_key($license_key);
        if (is_array($response) && $response['status'] === 'success') {
            update_option('rls_license_status', 'valid');
            update_option('rls_license_expires_at', $response['data']['expires_at']);
            (new RLS_Cron())->run_hourly_signature_update();
            $message = 'Статус лицензии успешно проверен и обновлен. База вирусных сигнатур принудительно обновлена.';
            $message .= ' Накопленная статистика отправлена на сервер.';
            if ($current_status !== 'valid') { $message = 'Ключ успешно активирован! ' . $message; }
            add_settings_error('rls_messages', 'rls_success', $message, 'updated');
        } else {
            update_option('rls_license_status', 'invalid');
            update_option('rls_license_expires_at', '');
            add_settings_error('rls_messages', 'rls_error', 'Ошибка проверки ключа: ' . esc_html($response['message'] ?? 'Произошла ошибка.'), 'error');
        }
    } else {
        add_settings_error('rls_messages', 'rls_error', 'Лицензионный ключ не введен.', 'error');
    }
}

// --- Получаем актуальные данные для отображения ---
$settings = get_option('rls_settings', []);
$license_key_from_settings = $settings['license_key'] ?? '';
$license_status = get_option('rls_license_status');
$license_expires_at = get_option('rls_license_expires_at');
$all_login_questions = get_option('rls_login_questions', []);
$base_signatures = get_option('rls_base_signatures', []);
$premium_signatures = (get_option('rls_license_status') === 'valid') ? get_option('rls_premium_signatures', []) : [];
$custom_signatures = get_option('rls_custom_signatures', []);
$all_signatures = [];
if (is_array($base_signatures)) { foreach ($base_signatures as $sig) { $all_signatures[$sig] = 'Базовая'; }}
if (is_array($premium_signatures)) { foreach ($premium_signatures as $sig) { $all_signatures[$sig] = 'Премиум'; }}
if (is_array($custom_signatures)) { foreach ($custom_signatures as $sig) { $all_signatures[$sig] = 'Пользовательская'; }}
?>

<div class="wrap rls-wrap">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
    <?php settings_errors('rls_messages'); ?>
    <div class="rls-container">
        <div class="rls-main-content">
            <form method="post" action="options.php">
                <?php settings_fields('rls_settings_group'); ?>
                
                <div class="rls-box">
                    <h2>Модули защиты</h2>
                    <table class="form-table">
                        <tr valign="top"><th scope="row">Базовый фаервол (WAF)</th><td><label><input type="checkbox" name="rls_settings[enable_firewall]" value="1" <?php checked(1, $settings['enable_firewall'] ?? 0); ?> /> <strong>Включить защиту в реальном времени</strong></label><p class="description">Блокирует SQL-инъекции, XSS и другие распространенные атаки.</p></td></tr>
                        <tr valign="top"><th scope="row">Защита страницы входа</th><td><label><input type="checkbox" id="rls_enable_login_security_cb" name="rls_settings[enable_login_security]" value="1" <?php checked(1, $settings['enable_login_security'] ?? 0); ?> /> <strong>Включить контрольные вопросы при входе</strong></label><p class="description">Добавляет дополнительный уровень защиты от брутфорс-атак.</p></td></tr>
                        <tr valign="top" class="login-questions-settings-row"><th scope="row">Количество вопросов</th><td><select name="rls_settings[login_questions_count]"><option value="1" <?php selected($settings['login_questions_count'] ?? 1, 1); ?>>Показывать 1 случайный вопрос</option><option value="2" <?php selected($settings['login_questions_count'] ?? 1, 2); ?>>Показывать 2 случайных вопроса</option><option value="3" <?php selected($settings['login_questions_count'] ?? 1, 3); ?>>Показывать 3 случайных вопроса</option></select></td></tr>
                        
                        <!-- НОВЫЙ РАЗДЕЛ: Фильтр ботов -->
                        <tr valign="top">
                            <th scope="row">Фильтр ботов</th>
                            <td>
                                <fieldset>
                                    <legend class="screen-reader-text"><span>Разрешенные боты</span></legend>
                                    <label><input type="checkbox" name="rls_settings[allow_googlebot]" value="1" <?php checked(1, $settings['allow_googlebot'] ?? 1); ?>> Разрешить Google Bot</label><br>
                                    <label><input type="checkbox" name="rls_settings[allow_yandexbot]" value="1" <?php checked(1, $settings['allow_yandexbot'] ?? 1); ?>> Разрешить Яндекс Бот</label><br>
                                    <label><input type="checkbox" name="rls_settings[allow_bingbot]" value="1" <?php checked(1, $settings['allow_bingbot'] ?? 0); ?>> Разрешить Bing Bot</label>
                                    <p class="description">Разрешите известных поисковых ботов, чтобы не мешать индексации сайта. Все остальные боты и сканеры будут блокироваться и учитываться в статистике.</p>
                                </fieldset>
                            </td>
                        </tr>
                    </table>
                </div>

                <div class="rls-box">
                    <h2>Лицензия и обновления</h2>
                    <table class="form-table"><tr valign="top"><th scope="row">Ваш ключ</th><td><input type="text" name="rls_settings[license_key]" value="<?php echo esc_attr($license_key_from_settings); ?>" class="regular-text" placeholder="SCANWP-..." /></td></tr></table>
                </div>
                <?php submit_button('Сохранить все настройки'); ?>
            </form>

            <?php if (!empty($license_key_from_settings)): ?>
            <div class="rls-box license-status-box"><div class="license-status"><strong>Статус лицензии и синхронизация</strong><?php if ($license_status === 'valid') { echo '<span class="status-valid">Активна</span><p>Действительна до: <strong>' . date_i18n('d.m.Y H:i', strtotime($license_expires_at)) . '</strong></p>'; } elseif ($license_status === 'invalid') { echo '<span class="status-invalid">Неверный ключ</span>'; } else { echo '<span class="status-inactive">Не активирована</span>'; } ?><form method="post" action="" style="display:inline-block; margin-top: 10px;"><input type="hidden" name="page" value="rls-settings"><?php wp_nonce_field('rls_force_sync_nonce'); ?><button type="submit" name="rls_force_sync_button" class="button-primary">Проверить статус и обновить базу</button><span class="spinner" style="vertical-align: middle;"></span></form><p class="description">Эта кнопка проверяет статус лицензии, принудительно отправляет накопленную статистику и обновляет базу вирусных сигнатур с сервера.</p></div></div>
            <?php endif; ?>
            
            <div class="rls-box login-questions-settings-row"><div id="rls-login-questions-list"><h2>Управление контрольными вопросами</h2><p>Создайте до 10 глобальных вопросов и ответов. При входе будут показаны случайные вопросы из этого списка.</p><table class="wp-list-table widefat striped"><thead><tr><th>Вопрос</th><th style="width:15%">Действие</th></tr></thead><tbody id="rls-login-questions-tbody"><?php if(empty($all_login_questions)): ?><tr class="no-items"><td colspan="2">Вы еще не добавили ни одного вопроса.</td></tr><?php else: foreach($all_login_questions as $key => $q_data): ?><tr data-key="<?php echo esc_attr($key); ?>"><td><?php echo esc_html($q_data['q']); ?></td><td><button class="button-link-delete rls-delete-login-question-button">Удалить</button></td></tr><?php endforeach; endif; ?></tbody></table></div><div id="rls-add-login-question-form" style="margin-top:20px; padding-top:20px; border-top: 1px solid #ddd;"><h4>Добавить новый вопрос</h4><p><label for="rls-new-login-question">Вопрос:</label><br><input type="text" id="rls-new-login-question" class="large-text"></p><p><label for="rls-new-login-answer">Ответ (чувствителен к регистру):</label><br><input type="text" id="rls-new-login-answer" class="large-text"></p><button id="rls-add-login-question-button" class="button-secondary">Добавить вопрос</button><span class="spinner"></span></div></div>

            <div class="rls-box"><h2>Управление сигнатурами</h2><p>Здесь отображается полный список сигнатур, используемых сканером. Вы можете добавлять свои собственные.</p><div id="rls-add-signature-form" class="rls-add-form"><input type="text" id="rls-new-signature-input" class="large-text" placeholder="Введите новую сигнатуру"><button id="rls-add-signature-button" class="button-secondary">Добавить</button><span class="spinner"></span></div><div class="rls-signatures-list"><table class="wp-list-table widefat striped"><thead><tr><th style="width:70%;">Сигнатура</th><th style="width:20%;">Источник</th><th style="width:10%;">Действие</th></tr></thead><tbody id="rls-signatures-table-body"><?php if (empty($all_signatures)): ?><tr class="no-items"><td colspan="3">Список сигнатур пуст.</td></tr><?php else: ksort($all_signatures); foreach ($all_signatures as $signature => $source): ?><tr data-signature="<?php echo esc_attr($signature); ?>"><td class="signature-code"><code><?php echo esc_html($signature); ?></code></td><td><span class="sig-source sig-source-<?php echo strtolower(esc_attr($source)); ?>"><?php echo esc_html($source); ?></span></td><td><?php if ($source === 'Пользовательская'): ?><button class="button-link-delete rls-delete-signature-button">Удалить</button><?php else: ?><span class="readonly-action">—</span><?php endif; ?></td></tr><?php endforeach; endif; ?></tbody></table></div></div>
        </div>
        <div class="rls-sidebar"><div class="rls-box author-box"><h3>Автор плагина</h3><p><strong>Усачёв Денис</strong></p><p>Плагин разработан для обеспечения комплексной защиты вашего сайта.</p><a href="https://rybinsklab.ru/scan-wp/" target="_blank" class="button-secondary">Страница плагина</a><a href="[ССЫЛКА_НА_ПОКУПКУ_КЛЮЧА]" target="_blank" class="button-primary">Купить ключ</a></div></div>
    </div>
</div>
<style>.rls-add-form,.rls-add-form .spinner,#rls-add-login-question-form .spinner{visibility:hidden}.login-questions-settings-row{display:none}.rls-add-form{display:flex;gap:10px;margin-bottom:10px;align-items:center}.rls-signatures-list{margin-top:20px}.signature-code code{white-space:pre-wrap;word-break:break-all}.sig-source{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#fff}.sig-source-базовая{background-color:#333}.sig-source-премиум{background-color:#007bff}.sig-source-пользовательская{background-color:#dc3545}.readonly-action{color:#999;padding-left:15px}</style>
<script>jQuery(function($){const loginSecurityCheckbox=$('#rls_enable_login_security_cb'),loginQuestionsRows=$('.login-questions-settings-row');loginSecurityCheckbox.on('change',function(){loginQuestionsRows.toggle($(this).is(':checked'))});if(loginSecurityCheckbox.is(':checked')){loginQuestionsRows.show()};$('#rls-add-login-question-button').on('click',function(){const t=$(this),e=t.siblings('.spinner'),s=$('#rls-new-login-question').val().trim(),n=$('#rls-new-login-answer').val().trim();if(!s||!n)return void alert('Вопрос и ответ не могут быть пустыми.');e.css('visibility','visible'),t.prop('disabled',!0),$.post(ajaxurl,{action:'rls_add_login_question',nonce:'<?php echo wp_create_nonce("rls_login_questions_nonce"); ?>',question:s,answer:n}).done(function(e){e.success?($('#rls-login-questions-tbody').append(`<tr data-key="${e.data.key}"><td>${e.data.question}</td><td><button class="button-link-delete rls-delete-login-question-button">Удалить</button></td></tr>`),$('#rls-new-login-question, #rls-new-login-answer').val(''),$('.no-items','#rls-login-questions-tbody').remove()):alert('Ошибка: '+e.data)}).fail(function(){alert('Ошибка сервера.')}).always(function(){e.css('visibility','hidden'),t.prop('disabled',!1)})}),$('#rls-login-questions-tbody').on('click','.rls-delete-login-question-button',function(){if(!confirm('Вы уверены?'))return;const t=$(this),e=t.closest('tr'),s=e.data('key');t.text('Удаление...'),t.prop('disabled',!0),$.post(ajaxurl,{action:'rls_delete_login_question',nonce:'<?php echo wp_create_nonce("rls_login_questions_nonce"); ?>',key:s}).done(function(s){s.success?e.fadeOut(300,function(){$(this).remove()}):(alert('Ошибка: '+s.data),t.text('Удалить'),t.prop('disabled',!1))}).fail(function(){alert('Ошибка сервера.'),t.text('Удалить'),t.prop('disabled',!1)})}),$('#rls-add-signature-button').on('click',function(){const t=$(this),e=$('#rls-new-signature-input'),s=t.siblings('.spinner'),n=e.val().trim();if(!n)return void e.css('border-color','red');e.css('border-color',''),s.css('visibility','visible'),t.prop('disabled',!0),$.post(ajaxurl,{action:'rls_add_signature',nonce:'<?php echo wp_create_nonce("rls_signatures_nonce"); ?>',signature:n}).done(function(s){s.success?($('#rls-signatures-table-body').append(`<tr data-signature="${s.data.signature}"><td class="signature-code"><code>${s.data.signature}</code></td><td><span class="sig-source sig-source-пользовательская">Пользовательская</span></td><td><button class="button-link-delete rls-delete-signature-button">Удалить</button></td></tr>`),e.val(''),$('.no-items','#rls-signatures-table-body').remove()):alert('Ошибка: '+s.data)}).fail(function(){alert('Ошибка сервера.')}).always(function(){s.css('visibility','hidden'),t.prop('disabled',!1)})}),$('#rls-signatures-table-body').on('click','.rls-delete-signature-button',function(){if(!confirm('Вы уверены?'))return;const t=$(this),e=t.closest('tr'),s=e.data('signature');t.text('Удаление...'),t.prop('disabled',!0),$.post(ajaxurl,{action:'rls_delete_signature',nonce:'<?php echo wp_create_nonce("rls_signatures_nonce"); ?>',signature:s}).done(function(s){s.success?e.fadeOut(300,function(){$(this).remove()}):(alert('Ошибка: '+s.data),t.text('Удалить'),t.prop('disabled',!1))}).fail(function(){alert('Ошибка сервера.'),t.text('Удалить'),t.prop('disabled',!1)})})});</script>