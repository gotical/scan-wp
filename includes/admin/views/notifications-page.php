<?php
/**
 * Notifications admin view.
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

$ns = get_option( 'rls_notification_settings', [] );
if ( ! is_array( $ns ) ) $ns = [];
?>
<div class="rls-box">
    <h2><span class="dashicons dashicons-email-alt"></span> Email-уведомления</h2>
    <p>Плагин может отправлять администратору уведомления о подозрительных событиях. По умолчанию — на адрес администратора WordPress.</p>

    <table class="form-table">
        <tr>
            <th>Email получателя</th>
            <td>
                <input type="email" name="rls_notification_settings[email]" value="<?php echo esc_attr( $ns['email'] ?? get_option( 'admin_email' ) ); ?>" class="regular-text" />
            </td>
        </tr>
        <tr>
            <th>Лимит в час</th>
            <td>
                <input type="number" min="0" max="200" name="rls_notification_settings[rate_limit_per_hour]" value="<?php echo esc_attr( $ns['rate_limit_per_hour'] ?? 20 ); ?>" />
                <p class="description">Защита от шторма уведомлений при DoS-атаке.</p>
            </td>
        </tr>
        <tr>
            <th>Вход администратора с нового IP</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_notification_settings[notify_admin_login_new_ip]" value="1" <?php checked( 1, $ns['notify_admin_login_new_ip'] ?? 1 ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
                <span class="description">Уведомлять, если администратор вошёл с IP, которого раньше не было в истории.</span>
            </td>
        </tr>
        <tr>
            <th>Блокировка brute force</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_notification_settings[notify_bruteforce]" value="1" <?php checked( 1, $ns['notify_bruteforce'] ?? 1 ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
            </td>
        </tr>
        <tr>
            <th>Найден вредоносный код</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_notification_settings[notify_malware]" value="1" <?php checked( 1, $ns['notify_malware'] ?? 1 ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
            </td>
        </tr>
        <tr>
            <th>Нарушена целостность файлов</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_notification_settings[notify_integrity]" value="1" <?php checked( 1, $ns['notify_integrity'] ?? 1 ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
                <span class="description">Отправляется при изменении файлов плагина вне штатного обновления.</span>
            </td>
        </tr>
    </table>
</div>
