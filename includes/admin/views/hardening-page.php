<?php
/**
 * Hardening admin view.
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

$settings = get_option( 'rls_settings', [] );
if ( ! is_array( $settings ) ) $settings = [];
$hardening_applied = (bool) get_option( 'rls_hardening_applied' );
$htaccess_writable = RLS_Hardening::is_htaccess_writable();
?>
<div class="wrap rls-wrap">
    <h1 class="rls-page-heading">
        <span class="dashicons dashicons-shield-alt"></span>
        Hardening
        <span class="rls-page-version">v<?php echo esc_html( RLS_VERSION ); ?></span>
    </h1>

<div class="rls-box">
    <h2><span class="dashicons dashicons-shield"></span> WordPress Hardening</h2>
    <p>Эти правила добавляются в <code>.htaccess</code> в корне сайта и в <code>wp-includes</code>. Они закрывают типовые вектора атак на WordPress.</p>

    <?php if ( ! $htaccess_writable ) : ?>
        <div class="rls-notice is-warning">
            <span class="dashicons dashicons-warning"></span>
            <div><strong>Внимание:</strong> <code>.htaccess</code> недоступен для записи. Установите права 644 или 664 и повторите попытку.</div>
        </div>
    <?php endif; ?>

    <table class="form-table">
        <tr>
            <th>Статус</th>
            <td>
                <?php if ( $hardening_applied ) : ?>
                    <span class="rls-status-pill is-on">Применено</span>
                <?php else : ?>
                    <span class="rls-status-pill is-off">Не применено</span>
                <?php endif; ?>
            </td>
        </tr>
    </table>

    <h3>Что будет сделано</h3>
    <ul style="list-style: disc; padding-left: 20px; color: var(--rls-text-muted); font-size: 13px; line-height: 1.7;">
        <li>Защита <code>wp-config.php</code> от прямого доступа через веб</li>
        <li>Блокировка прямого исполнения PHP в <code>wp-includes</code></li>
        <li>Блокировка исполнения PHP в <code>wp-content/uploads</code></li>
        <li>Отключение листинга директорий (<code>Options -Indexes</code>)</li>
        <li>Скрытие версии WordPress из вывода и URL скриптов</li>
        <li>Блокировка перечисления пользователей (<code>?author=N</code>)</li>
        <li>Ограничение REST API для неавторизованных</li>
        <li>Строгая политика безопасных HTTP-заголовков (CSP, COOP, Permissions-Policy)</li>
        <li>Блокировка опасных HTTP-методов (TRACE, PROPFIND и т.д.)</li>
    </ul>

    <p>
        <?php if ( $hardening_applied ) : ?>
            <button id="rls-hardening-remove" class="button button-secondary">Удалить правила из .htaccess</button>
        <?php else : ?>
            <button id="rls-hardening-apply" class="button button-primary" <?php disabled( ! $htaccess_writable ); ?>>Применить правила</button>
        <?php endif; ?>
    </p>
</div>

<div class="rls-box">
    <h2><span class="dashicons dashicons-admin-network"></span> Скорость и кэширование</h2>
    <p>Эти настройки применяются через фильтры и не требуют модификации <code>wp-config.php</code>.</p>
    <table class="form-table">
        <tr>
            <th>Hardening (общая защита)</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_settings[hardening_enabled]" value="1" <?php checked( 1, $settings['hardening_enabled'] ?? 0 ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
                <span class="description">Включает все перечисленные выше меры защиты.</span>
            </td>
        </tr>
        <tr>
            <th>Hotlink protection</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_settings[hotlink_protection]" value="1" <?php checked( 1, $settings['hotlink_protection'] ?? 0 ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
                <span class="description">Запрещает встраивание изображений из <code>wp-content/uploads</code> на сторонних сайтах.</span>
                <br>
                <input type="text" name="rls_settings[hotlink_allowed_hosts]" class="regular-text" placeholder="cdn.example.com, partner.com" value="<?php echo esc_attr( $settings['hotlink_allowed_hosts'] ?? '' ); ?>" />
                <p class="description">Список хостов-исключений через запятую.</p>
            </td>
        </tr>
    </table>
</div>

</div><!-- .rls-wrap -->
