<?php
/**
 * 2FA admin view.
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

if ( ! is_user_logged_in() ) {
    echo '<div class="rls-notice is-warning">Требуется вход в систему для настройки 2FA.</div>';
    return;
}

$user_id = get_current_user_id();
$enabled = RLS_2FA::is_enabled_for_user( $user_id );
$backup_count = $enabled ? count( RLS_2FA::get_backup_codes( $user_id ) ) : 0;
$settings = get_option( 'rls_settings', [] );
?>
<div class="rls-2fa-status" id="rls-2fa-setup-box">
    <div style="flex:1;">
        <h2 style="margin:0 0 6px;"><span class="dashicons dashicons-smartphone"></span> Двухфакторная аутентификация</h2>
        <p style="margin:0; color:var(--rls-text-muted);">
            <?php if ( $enabled ) : ?>
                <span class="rls-status-pill is-on">Активна</span>
                Резервных кодов: <strong><?php echo intval( $backup_count ); ?></strong>
            <?php else : ?>
                <span class="rls-status-pill is-off">Отключена</span>
                Защитите аккаунт с помощью TOTP (Google Authenticator, Authy, 1Password).
            <?php endif; ?>
        </p>
    </div>
    <div>
        <?php if ( $enabled ) : ?>
            <button id="rls-2fa-regen-button" class="button">Новые резервные коды</button>
            <button id="rls-2fa-disable-button" class="button button-link-delete">Отключить 2FA</button>
        <?php else : ?>
            <button id="rls-2fa-start-button" class="button button-primary">Включить 2FA</button>
        <?php endif; ?>
    </div>
</div>

<?php if ( ! $enabled ) : ?>
<div id="rls-2fa-step-1" style="display:none;"></div>

<div id="rls-2fa-step-2" style="display:none;">
    <div class="rls-box">
        <h2>Шаг 1. Отсканируйте QR-код</h2>
        <p>Откройте приложение-аутентификатор и добавьте новый аккаунт по QR-коду или вручную (секрет ниже).</p>
        <div style="display:flex; gap:24px; flex-wrap:wrap; align-items:center;">
            <div class="rls-2fa-qr"><img id="rls-2fa-qr-img" src="" width="180" height="180" alt="QR" /></div>
            <div style="flex:1; min-width:240px;">
                <p><strong>Секрет (Base32):</strong></p>
                <div class="rls-2fa-secret" id="rls-2fa-secret"></div>
            </div>
        </div>

        <h3>Шаг 2. Подтвердите код</h3>
        <p>Введите 6-значный код из приложения.</p>
        <p>
            <input type="text" id="rls-2fa-code-input" maxlength="6" pattern="\d{6}" placeholder="123456" class="regular-text" style="font-family: var(--rls-mono); letter-spacing: 0.2em; font-size: 18px; width: 180px; text-align: center;" />
        </p>
        <p><button id="rls-2fa-confirm-button" class="button button-primary">Подтвердить</button></p>
    </div>
</div>

<div id="rls-2fa-step-3" style="display:none;">
    <div class="rls-box">
        <h2><span class="dashicons dashicons-yes" style="color:var(--rls-success);"></span> 2FA включена</h2>
        <p>Сохраните резервные коды в безопасном месте. Каждый код можно использовать один раз, если у вас нет доступа к приложению.</p>
        <ul id="rls-2fa-backup-codes" class="rls-backup-codes"></ul>
    </div>
</div>
<?php else : ?>
<div class="rls-box">
    <h2>Резервные коды</h2>
    <p>Каждый код можно использовать однократно для входа без приложения.</p>
    <ul id="rls-2fa-backup-codes" class="rls-backup-codes">
        <?php foreach ( RLS_2FA::get_backup_codes( $user_id ) as $code ) : ?>
            <li><?php echo esc_html( $code ); ?></li>
        <?php endforeach; ?>
    </ul>
</div>
<?php endif; ?>

<div class="rls-box">
    <h2>Требовать 2FA для всех администраторов</h2>
    <table class="form-table">
        <tr>
            <th>Глобальная политика</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_settings[2fa_required_admin]" value="1" <?php checked( 1, $settings['2fa_required_admin'] ?? 0 ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
                <span class="description">Если включено, все администраторы обязаны настроить 2FA. Не применяется к существующим входам — только к новым попыткам авторизации.</span>
            </td>
        </tr>
    </table>
</div>
