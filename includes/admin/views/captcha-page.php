<?php
/**
 * CAPTCHA settings page — Google reCAPTCHA / Yandex SmartCaptcha.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

if ( ! class_exists( 'RLS_Captcha' ) ) {
    echo '<div class="rls-notice is-danger">RLS Captcha не загружен.</div>';
    return;
}

$s = RLS_Captcha::get_settings();
$provider = $s['provider'];
$configured = RLS_Captcha::is_configured();
$enabled    = RLS_Captcha::is_enabled();
?>
<div class="rls-page-hero">
    <div class="rls-page-hero-top">
        <div>
            <div class="rls-page-kicker">Rybinsk Lab Security</div>
            <h1 class="rls-page-title">
                CAPTCHA
                <span class="rls-page-version">v<?php echo RLS_VERSION; ?></span>
            </h1>
            <p class="rls-page-subtitle">Защита форм: вход, регистрация, комментарии, восстановление пароля. Поддержка Google reCAPTCHA (v2/v3) и Yandex SmartCaptcha.</p>
        </div>
        <div class="rls-hero-actions">
            <span class="rls-status-pill <?php echo $enabled ? 'is-on' : 'is-off'; ?>" style="background: rgba(255,255,255,0.18); color: #fff;">
                <?php echo $enabled ? 'Активна' : 'Отключена'; ?>
            </span>
        </div>
    </div>
</div>

<div class="rls-box">
    <h2><span class="dashicons dashicons-shield"></span> Выбор провайдера</h2>

    <div class="rls-mode-grid">
        <label class="rls-mode-card">
            <input type="radio" name="rls_captcha_settings[provider]" value="google" <?php checked( $provider, 'google' ); ?> />
            <span class="rls-mode-card-title">🔵 Google reCAPTCHA</span>
            <span class="rls-mode-card-text">v2 (Checkbox/Invisible) + v3 (Score-based). Лучше всего для западных пользователей.</span>
        </label>
        <label class="rls-mode-card">
            <input type="radio" name="rls_captcha_settings[provider]" value="yandex" <?php checked( $provider, 'yandex' ); ?> />
            <span class="rls-mode-card-title">🔴 Yandex SmartCaptcha</span>
            <span class="rls-mode-card-text">Standard/Invisible/Advanced. Лучше для российских пользователей (РКН-совместимо).</span>
        </label>
    </div>
</div>

<?php settings_fields( 'rls_captcha_group' ); ?>

<!-- Google -->
<div class="rls-box" id="rls-captcha-google" style="<?php echo $provider !== 'google' ? 'display:none;' : ''; ?>">
    <h2><span class="dashicons dashicons-google"></span> Google reCAPTCHA — настройки</h2>
    <p>Получите ключи на <a href="https://www.google.com/recaptcha/admin/create" target="_blank" rel="noopener noreferrer">google.com/recaptcha/admin</a>.</p>

    <table class="form-table">
        <tr>
            <th>Включить</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_captcha_settings[enabled]" value="1" <?php checked( 1, $enabled ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
            </td>
        </tr>
        <tr>
            <th>Site Key</th>
            <td>
                <input type="text" name="rls_captcha_settings[google_site_key]" value="<?php echo esc_attr( $s['google_site_key'] ); ?>" class="regular-text" placeholder="6Lc...site_key" />
            </td>
        </tr>
        <tr>
            <th>Secret Key</th>
            <td>
                <input type="text" name="rls_captcha_settings[google_secret_key]" value="<?php echo esc_attr( $s['google_secret_key'] ); ?>" class="regular-text" placeholder="6Lc...secret_key" />
                <p class="description">Хранится в wp_options. Доступ только у администраторов.</p>
            </td>
        </tr>
        <tr>
            <th>Версия</th>
            <td>
                <select name="rls_captcha_settings[google_version]">
                    <option value="v2" <?php selected( $s['google_version'], 'v2' ); ?>>v2 — классическая (чекбокс / невидимая)</option>
                    <option value="v3" <?php selected( $s['google_version'], 'v3' ); ?>>v3 — score-based (без взаимодействия)</option>
                </select>
            </td>
        </tr>
        <tr id="rls-google-v2-type-row" style="<?php echo $s['google_version'] !== 'v2' ? 'display:none;' : ''; ?>">
            <th>v2 Тип</th>
            <td>
                <label><input type="radio" name="rls_captcha_settings[google_v2_type]" value="checkbox" <?php checked( $s['google_v2_type'], 'checkbox' ); ?> /> Чекбокс "Я не робот"</label>
                <label style="margin-left:20px;"><input type="radio" name="rls_captcha_settings[google_v2_type]" value="invisible" <?php checked( $s['google_v2_type'], 'invisible' ); ?> /> Invisible (без UI)</label>
            </td>
        </tr>
        <tr id="rls-google-v3-threshold-row" style="<?php echo $s['google_version'] !== 'v3' ? 'display:none;' : ''; ?>">
            <th>v3 Score threshold</th>
            <td>
                <input type="range" min="0" max="1" step="0.05" name="rls_captcha_settings[google_v3_threshold]" value="<?php echo esc_attr( $s['google_v3_threshold'] ); ?>" />
                <span id="rls-v3-threshold-display"><?php echo esc_html( $s['google_v3_threshold'] ); ?></span>
                <p class="description">0.0 = пропускать всех, 1.0 = блокировать всех. По умолчанию 0.5.</p>
            </td>
        </tr>
        <tr>
            <th>Тема</th>
            <td>
                <select name="rls_captcha_settings[google_theme]">
                    <option value="light" <?php selected( $s['google_theme'], 'light' ); ?>>Светлая</option>
                    <option value="dark" <?php selected( $s['google_theme'], 'dark' ); ?>>Тёмная</option>
                </select>
            </td>
        </tr>
        <tr>
            <th>Язык</th>
            <td>
                <input type="text" name="rls_captcha_settings[google_language]" value="<?php echo esc_attr( $s['google_language'] ); ?>" class="small-text" placeholder="auto" />
                <p class="description">en, ru, uk, de, fr... Пусто = авто по языку браузера.</p>
            </td>
        </tr>
    </table>
</div>

<!-- Yandex -->
<div class="rls-box" id="rls-captcha-yandex" style="<?php echo $provider !== 'yandex' ? 'display:none;' : ''; ?>">
    <h2><span class="dashicons dashicons-shield"></span> Yandex SmartCaptcha — настройки</h2>
    <p>Получите ключи в <a href="https://yandex.cloud/ru/services/smartcaptcha" target="_blank" rel="noopener noreferrer">Yandex Cloud Console</a>.</p>

    <table class="form-table">
        <tr>
            <th>Включить</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_captcha_settings[enabled]" value="1" <?php checked( 1, $enabled ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
            </td>
        </tr>
        <tr>
            <th>Client Key (публичный)</th>
            <td>
                <input type="text" name="rls_captcha_settings[yandex_client_key]" value="<?php echo esc_attr( $s['yandex_client_key'] ); ?>" class="regular-text" placeholder="ck..." />
            </td>
        </tr>
        <tr>
            <th>Server Key (секретный)</th>
            <td>
                <input type="text" name="rls_captcha_settings[yandex_server_key]" value="<?php echo esc_attr( $s['yandex_server_key'] ); ?>" class="regular-text" placeholder="sk..." />
                <p class="description">Используется для серверной валидации. Не показывается пользователям.</p>
            </td>
        </tr>
        <tr>
            <th>Режим</th>
            <td>
                <select name="rls_captcha_settings[yandex_mode]">
                    <option value="standard" <?php selected( $s['yandex_mode'], 'standard' ); ?>>Standard — визуальная капча с кнопкой</option>
                    <option value="invisible" <?php selected( $s['yandex_mode'], 'invisible' ); ?>>Invisible — невидимая (фоновая проверка)</option>
                    <option value="advanced" <?php selected( $s['yandex_mode'], 'advanced' ); ?>>Advanced — поведенческий анализ (новое)</option>
                </select>
            </td>
        </tr>
        <tr>
            <th>Язык</th>
            <td>
                <select name="rls_captcha_settings[yandex_language]">
                    <option value="ru" <?php selected( $s['yandex_language'], 'ru' ); ?>>Русский</option>
                    <option value="en" <?php selected( $s['yandex_language'], 'en' ); ?>>English</option>
                </select>
            </td>
        </tr>
    </table>
</div>

<!-- Forms -->
<div class="rls-box">
    <h2><span class="dashicons dashicons-forms"></span> Защищаемые формы</h2>
    <p>Выберите, на каких формах показывать CAPTCHA.</p>

    <table class="form-table">
        <tr>
            <th>Форма входа</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_captcha_settings[forms][login]" value="1" <?php checked( 1, $s['forms']['login'] ?? 0 ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
                <span class="description">/wp-login.php (форма входа)</span>
            </td>
        </tr>
        <tr>
            <th>Форма регистрации</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_captcha_settings[forms][register]" value="1" <?php checked( 1, $s['forms']['register'] ?? 0 ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
                <span class="description">/wp-login.php?action=register</span>
            </td>
        </tr>
        <tr>
            <th>Забыли пароль</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_captcha_settings[forms][lostpassword]" value="1" <?php checked( 1, $s['forms']['lostpassword'] ?? 0 ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
                <span class="description">Запрос email для восстановления</span>
            </td>
        </tr>
        <tr>
            <th>Сброс пароля</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_captcha_settings[forms][resetpassword]" value="1" <?php checked( 1, $s['forms']['resetpassword'] ?? 0 ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
                <span class="description">Ввод нового пароля по ссылке</span>
            </td>
        </tr>
        <tr>
            <th>Комментарии</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_captcha_settings[forms][comment]" value="1" <?php checked( 1, $s['forms']['comment'] ?? 0 ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
                <span class="description">Форма комментариев</span>
            </td>
        </tr>
        <tr>
            <th>Вход в админку (extra)</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_captcha_settings[forms][admin_login]" value="1" <?php checked( 1, $s['forms']['admin_login'] ?? 0 ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
                <span class="description">Дополнительно к стандартному входу для админов</span>
            </td>
        </tr>
    </table>
</div>

<?php $wc_active = class_exists( 'WooCommerce' ); ?>
<?php if ( $wc_active ) : ?>
<!-- WooCommerce -->
<div class="rls-box">
    <h2><span class="dashicons dashicons-cart"></span> WooCommerce</h2>
    <p>Защита форм WooCommerce: оформление заказа, регистрация, вход, отзывы.</p>

    <table class="form-table">
        <tr>
            <th>Оформление заказа</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_captcha_settings[forms][wc_checkout]" value="1" <?php checked( 1, $s['forms']['wc_checkout'] ?? 0 ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
                <span class="description">Страница /checkout перед кнопкой "Оформить заказ"</span>
            </td>
        </tr>
        <tr>
            <th>Регистрация (My Account)</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_captcha_settings[forms][wc_register]" value="1" <?php checked( 1, $s['forms']['wc_register'] ?? 0 ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
                <span class="description">/my-account/?action=register</span>
            </td>
        </tr>
        <tr>
            <th>Вход (My Account)</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_captcha_settings[forms][wc_login]" value="1" <?php checked( 1, $s['forms']['wc_login'] ?? 0 ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
                <span class="description">/my-account/?action=login (если не включён wp-login)</span>
            </td>
        </tr>
        <tr>
            <th>Восстановление пароля</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_captcha_settings[forms][wc_lostpassword]" value="1" <?php checked( 1, $s['forms']['wc_lostpassword'] ?? 0 ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
            </td>
        </tr>
        <tr>
            <th>Отзывы о товарах</th>
            <td>
                <label class="rls-toggle">
                    <input type="checkbox" name="rls_captcha_settings[forms][wc_review]" value="1" <?php checked( 1, $s['forms']['wc_review'] ?? 0 ); ?> />
                    <span class="rls-toggle-slider"></span>
                </label>
                <span class="description">CAPTCHA на форме отзывов WooCommerce</span>
            </td>
        </tr>
    </table>
</div>
<?php else : ?>
<div class="rls-box" style="opacity: 0.5;">
    <h2><span class="dashicons dashicons-cart"></span> WooCommerce</h2>
    <p>Плагин WooCommerce не обнаружен. Установите WooCommerce для защиты форм заказа, регистрации и отзывов.</p>
</div>
<?php endif; ?>

<!-- Test -->
<div class="rls-box" style="border-left: 4px solid var(--rls-primary);">
    <h2><span class="dashicons dashicons-controls-play"></span> Тест CAPTCHA</h2>
    <p>Проверьте работу с реальным токеном. Скопируйте токен из консоли браузера после решения.</p>
    <p>
        <input type="text" id="rls-captcha-test-token" class="regular-text" style="width:60%;" placeholder="Вставьте токен CAPTCHA..." />
        <button type="button" class="button button-primary" id="rls-captcha-test-button">Проверить</button>
    </p>
    <div id="rls-captcha-test-result" style="margin-top:10px;"></div>
</div>

<!-- Preview -->
<div class="rls-box">
    <h2><span class="dashicons dashicons-visibility"></span> Предпросмотр</h2>
    <p>Так CAPTCHA будет выглядеть на странице входа:</p>
    <div class="rls-captcha-preview" style="padding:20px; background:var(--rls-surface-alt); border-radius:var(--rls-radius); margin-top:10px;">
        <?php echo RLS_Captcha::render( 'login' ); ?>
    </div>
</div>

<?php submit_button( 'Сохранить настройки', 'primary' ); ?>

<?php
$nonce = wp_create_nonce( 'rls_captcha_nonce' );
?>
<script>
document.addEventListener('DOMContentLoaded', function() {
    // Provider switching.
    document.querySelectorAll('input[name="rls_captcha_settings[provider]"]').forEach(function(radio) {
        radio.addEventListener('change', function() {
            document.getElementById('rls-captcha-google').style.display = this.value === 'google' ? '' : 'none';
            document.getElementById('rls-captcha-yandex').style.display  = this.value === 'yandex' ? '' : 'none';
        });
    });
    // Version switching.
    var versionSelect = document.querySelector('select[name="rls_captcha_settings[google_version]"]');
    if (versionSelect) {
        versionSelect.addEventListener('change', function() {
            document.getElementById('rls-google-v2-type-row').style.display     = this.value === 'v2' ? '' : 'none';
            document.getElementById('rls-google-v3-threshold-row').style.display = this.value === 'v3' ? '' : 'none';
        });
    }
    // Threshold display.
    var threshold = document.querySelector('input[name="rls_captcha_settings[google_v3_threshold]"]');
    if (threshold) {
        var display = document.getElementById('rls-v3-threshold-display');
        threshold.addEventListener('input', function() { display.textContent = this.value; });
    }
    // Test.
    var testBtn = document.getElementById('rls-captcha-test-button');
    if (testBtn) {
        testBtn.addEventListener('click', function() {
            var token = document.getElementById('rls-captcha-test-token').value.trim();
            if (!token) { alert('Введите токен'); return; }
            testBtn.disabled = true; testBtn.textContent = 'Проверка...';
            var result = document.getElementById('rls-captcha-test-result');
            result.innerHTML = '<div class="rls-skeleton is-text" style="width:60%;"></div>';
            fetch(ajaxurl || (window.rls_admin_data && rls_admin_data.ajax_url), {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=rls_captcha_test&nonce=<?php echo esc_js( $nonce ); ?>&token=' + encodeURIComponent(token)
            }).then(function(r){ return r.json(); }).then(function(json) {
                if (json && json.success) {
                    result.innerHTML = '<div class="rls-notice is-success" style="margin-top:10px;">✓ ' + json.data + '</div>';
                } else {
                    result.innerHTML = '<div class="rls-notice is-danger" style="margin-top:10px;">✕ ' + (json.data || 'Ошибка') + '</div>';
                }
                testBtn.disabled = false; testBtn.textContent = 'Проверить';
            });
        });
    }
});
</script>
