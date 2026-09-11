<?php
/**
 * First-run wizard.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

$current_step = isset( $_GET['rls_wizard_step'] ) ? max( 1, min( 4, (int) $_GET['rls_wizard_step'] ) ) : 1;
$settings = get_option( 'rls_settings', [] );
?>
<div class="rls-wizard">
    <div class="rls-wizard-progress">
        <div class="rls-wizard-progress-bar" style="width: <?php echo ( ( $current_step - 1 ) / 3 ) * 100; ?>%;"></div>
        <?php for ( $i = 1; $i <= 4; $i++ ) : ?>
            <div class="rls-wizard-step <?php echo $current_step === $i ? 'is-active' : ( $current_step > $i ? 'is-done' : '' ); ?>">
                <span><?php echo $i; ?></span>
            </div>
        <?php endfor; ?>
    </div>

    <div class="rls-wizard-content">
        <?php if ( $current_step === 1 ) : ?>
            <h2 style="margin-top: 0;">👋 Добро пожаловать</h2>
            <p style="font-size: 15px;">Rybinsk Lab Security — профессиональная защита WordPress от угроз. Пройдите короткий мастер, чтобы настроить плагин под ваш сайт.</p>

            <div class="rls-stat-card" style="background: var(--rls-primary-soft); color: var(--rls-text); border: 1px solid var(--rls-border); margin: 20px 0;">
                <span class="rls-stat-label" style="color: var(--rls-text-muted);">Что будет настроено</span>
                <ul style="margin: 8px 0 0; padding-left: 18px; line-height: 1.8;">
                    <li>Режим защиты (лёгкая / полная / только сканер)</li>
                    <li>Firewall, блок XML-RPC, лимиты входа</li>
                    <li>GeoIP и фильтрация по странам</li>
                    <li>Уведомления на email</li>
                </ul>
            </div>
        <?php elseif ( $current_step === 2 ) : ?>
            <h2 style="margin-top: 0;">🛡️ Выберите режим защиты</h2>
            <p>Вы всегда сможете переключить режим позже в настройках.</p>

            <div class="rls-mode-grid">
                <label class="rls-mode-card">
                    <input type="radio" name="protection_mode" value="light" />
                    <span class="rls-mode-card-title">Лёгкая защита</span>
                    <span class="rls-mode-card-text">Базовая защита без GeoIP и фильтрации ботов. Подходит для блогов.</span>
                </label>
                <label class="rls-mode-card">
                    <input type="radio" name="protection_mode" value="full" checked />
                    <span class="rls-mode-card-title">Полная защита</span>
                    <span class="rls-mode-card-text">Все модули: WAF, GeoIP, боты, языки. Рекомендуется для продакшена.</span>
                </label>
                <label class="rls-mode-card">
                    <input type="radio" name="protection_mode" value="scanner_only" />
                    <span class="rls-mode-card-title">Только сканер</span>
                    <span class="rls-mode-card-text">Только проверка файлов. Защитные модули отключены.</span>
                </label>
            </div>
        <?php elseif ( $current_step === 3 ) : ?>
            <h2 style="margin-top: 0;">🔔 Уведомления</h2>
            <p>Куда отправлять оповещения о подозрительной активности?</p>

            <table class="form-table">
                <tr>
                    <th>Email для уведомлений</th>
                    <td>
                        <input type="email" name="notification_email" class="regular-text" value="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>" />
                        <p class="description">Сюда придёт письмо при обнаружении угроз.</p>
                    </td>
                </tr>
                <tr>
                    <th>Уведомлять при</th>
                    <td>
                        <label><input type="checkbox" checked /> Вход администратора с нового IP</label><br>
                        <label><input type="checkbox" checked /> Brute force блокировка</label><br>
                        <label><input type="checkbox" checked /> Найден вредоносный код</label><br>
                        <label><input type="checkbox" checked /> Изменены файлы плагина</label>
                    </td>
                </tr>
            </table>
        <?php else : ?>
            <h2 style="margin-top: 0;">🎉 Готово!</h2>
            <p style="font-size: 15px;">Базовая настройка завершена. Плагин активен и защищает ваш сайт.</p>

            <div class="rls-widget-grid" style="margin-top: 20px;">
                <div class="rls-widget-tile is-ok">
                    <div class="rls-widget-num">✓</div>
                    <div class="rls-widget-label">Firewall</div>
                </div>
                <div class="rls-widget-tile is-ok">
                    <div class="rls-widget-num">✓</div>
                    <div class="rls-widget-label">Brute Force</div>
                </div>
                <div class="rls-widget-tile is-ok">
                    <div class="rls-widget-num">✓</div>
                    <div class="rls-widget-label">Сканер</div>
                </div>
                <div class="rls-widget-tile is-ok">
                    <div class="rls-widget-num">✓</div>
                    <div class="rls-widget-label">Логирование</div>
                </div>
            </div>

            <p style="margin-top: 24px;">Рекомендуем также:</p>
            <ul style="line-height: 1.8;">
                <li><a href="<?php echo admin_url( 'admin.php?page=rls-2fa' ); ?>">Включить 2FA</a> для администраторов</li>
                <li><a href="<?php echo admin_url( 'admin.php?page=rls-hardening' ); ?>">Применить Hardening</a> для дополнительной защиты</li>
                <li><a href="<?php echo admin_url( 'admin.php?page=rls-monitoring' ); ?>">Открыть Мониторинг</a> для аналитики</li>
            </ul>
        <?php endif; ?>
    </div>

    <div class="rls-wizard-actions">
        <?php if ( $current_step > 1 ) : ?>
            <a href="<?php echo esc_url( add_query_arg( 'rls_wizard_step', $current_step - 1 ) ); ?>" class="button">← Назад</a>
        <?php else : ?>
            <span></span>
        <?php endif; ?>
        <?php if ( $current_step < 4 ) : ?>
            <a href="<?php echo esc_url( add_query_arg( 'rls_wizard_step', $current_step + 1 ) ); ?>" class="button button-primary">
                Далее →
            </a>
        <?php else : ?>
            <a href="<?php echo admin_url( 'admin.php?page=rls-settings' ); ?>" class="button button-primary">
                Перейти к настройкам →
            </a>
        <?php endif; ?>
    </div>
</div>
