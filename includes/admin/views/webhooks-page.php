<?php
/**
 * Webhooks settings page (Slack, Discord, Telegram, Custom).
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

if ( ! class_exists( 'RLS_Webhooks' ) ) {
    echo '<div class="rls-notice is-danger">RLS Webhooks не загружен.</div>';
    return;
}

$settings = RLS_Webhooks::get_settings();
$event_log = RLS_Webhooks::get_event_log( 30 );

if ( isset( $_POST['rls_webhooks'] ) && check_admin_referer( 'rls_webhooks_group' ) ) {
    $settings = RLS_Webhooks::update_settings( $_POST['rls_webhooks'] );
    echo '<div class="rls-notice is-success" style="margin:14px 0;">Настройки webhooks сохранены.</div>';
}
?>
<div class="rls-wrap">
    <div class="rls-page-hero">
        <div class="rls-page-hero-top">
            <div>
                <div class="rls-page-kicker">Rybinsk Lab Security</div>
                <h1 class="rls-page-title">
                    Webhooks
                    <span class="rls-page-version">v<?php echo RLS_VERSION; ?></span>
                </h1>
                <p class="rls-page-subtitle">Уведомления в Slack, Discord, Telegram или кастомный webhook. Тест отправки, журнал событий.</p>
            </div>
            <div class="rls-hero-actions">
                <span class="rls-status-pill <?php echo RLS_Webhooks::is_configured() ? 'is-on' : 'is-off'; ?>" style="background: rgba(255,255,255,0.18); color: #fff;">
                    <?php echo RLS_Webhooks::is_configured() ? 'Настроен' : 'Не настроен'; ?>
                </span>
            </div>
        </div>
    </div>

    <?php settings_fields( 'rls_webhooks_group' ); ?>

    <!-- Global toggle -->
    <div class="rls-box">
        <h2><span class="dashicons dashicons-admin-generic"></span> Общие настройки</h2>
        <table class="form-table">
            <tr>
                <th>Включить webhooks</th>
                <td>
                    <label class="rls-toggle">
                        <input type="checkbox" name="rls_webhooks[enabled]" value="1" <?php checked( 1, $settings['enabled'] ); ?> />
                        <span class="rls-toggle-slider"></span>
                    </label>
                </td>
            </tr>
            <tr>
                <th>Минимальный severity</th>
                <td>
                    <input type="range" min="0" max="100" step="5" name="rls_webhooks[min_severity]" value="<?php echo esc_attr( $settings['min_severity'] ); ?>" id="rls-wh-severity" />
                    <span id="rls-wh-severity-display"><strong><?php echo intval( $settings['min_severity'] ); ?></strong></span>
                    <p class="description">Webhook сработает только если severity события ≥ этого значения.</p>
                </td>
            </tr>
        </table>
    </div>

    <!-- SLACK -->
    <div class="rls-box">
        <h2><span style="font-size:18px; color:#4a154b;">💬</span> Slack</h2>
        <p>Создайте <a href="https://api.slack.com/messaging/webhooks" target="_blank">Incoming Webhook</a> в Slack и вставьте URL.</p>
        <table class="form-table">
            <tr>
                <th>Webhook URL</th>
                <td>
                    <input type="url" name="rls_webhooks[slack][url]" value="<?php echo esc_attr( $settings['slack']['url'] ); ?>" class="regular-text" placeholder="https://hooks.slack.com/services/T0.../B0.../XXX" />
                    <button type="button" class="button rls-wh-test" data-channel="slack" style="margin-left:6px;">Test</button>
                </td>
            </tr>
        </table>
    </div>

    <!-- DISCORD -->
    <div class="rls-box">
        <h2><span style="font-size:18px; color:#5865f2;">🎮</span> Discord</h2>
        <p>Создайте Webhook в настройках канала Discord и вставьте URL.</p>
        <table class="form-table">
            <tr>
                <th>Webhook URL</th>
                <td>
                    <input type="url" name="rls_webhooks[discord][url]" value="<?php echo esc_attr( $settings['discord']['url'] ); ?>" class="regular-text" placeholder="https://discord.com/api/webhooks/..." />
                    <button type="button" class="button rls-wh-test" data-channel="discord" style="margin-left:6px;">Test</button>
                </td>
            </tr>
        </table>
    </div>

    <!-- TELEGRAM -->
    <div class="rls-box">
        <h2><span style="font-size:18px; color:#0088cc;">✈️</span> Telegram</h2>
        <p>Создайте бота через <a href="https://t.me/BotFather" target="_blank">@BotFather</a> и получите chat_id.</p>
        <table class="form-table">
            <tr>
                <th>Bot Token</th>
                <td>
                    <input type="text" name="rls_webhooks[telegram][token]" value="<?php echo esc_attr( $settings['telegram']['token'] ); ?>" class="regular-text" placeholder="123456789:ABCdefGHIjklMNOpqrSTUvwxyz" />
                </td>
            </tr>
            <tr>
                <th>Chat ID</th>
                <td>
                    <input type="text" name="rls_webhooks[telegram][chat_id]" value="<?php echo esc_attr( $settings['telegram']['chat_id'] ); ?>" class="regular-text" placeholder="-1001234567890" />
                    <button type="button" class="button rls-wh-test" data-channel="telegram" style="margin-left:6px;">Test</button>
                </td>
            </tr>
        </table>
    </div>

    <!-- CUSTOM -->
    <div class="rls-box">
        <h2><span class="dashicons dashicons-rest-api"></span> Custom Webhook</h2>
        <p>Отправка JSON-payload на любой URL (Zapier, Make.com, n8n, собственный backend).</p>
        <table class="form-table">
            <tr>
                <th>URL</th>
                <td>
                    <input type="url" name="rls_webhooks[custom][url]" value="<?php echo esc_attr( $settings['custom']['url'] ); ?>" class="regular-text" placeholder="https://hooks.zapier.com/..." />
                </td>
            </tr>
            <tr>
                <th>Метод</th>
                <td>
                    <select name="rls_webhooks[custom][method]">
                        <option value="POST" <?php selected( $settings['custom']['method'], 'POST' ); ?>>POST</option>
                        <option value="PUT"  <?php selected( $settings['custom']['method'], 'PUT' );  ?>>PUT</option>
                    </select>
                    <button type="button" class="button rls-wh-test" data-channel="custom" style="margin-left:6px;">Test</button>
                </td>
            </tr>
        </table>
    </div>

    <!-- EVENTS -->
    <div class="rls-box">
        <h2><span class="dashicons dashicons-bell"></span> События</h2>
        <p>Какие события отправлять в webhooks.</p>
        <table class="form-table">
            <?php
            $event_labels = [
                'malware'    => [ '🦠 Malware detected', 'Сканер нашёл угрозы в файлах' ],
                'integrity'  => [ '⚠️ File integrity', 'Изменены файлы плагина' ],
                'bruteforce' => [ '🔒 Brute force lockout', 'IP заблокирован после неудачных попыток' ],
                'anomaly'    => [ '🟡 Login anomaly', 'Аномальный вход администратора' ],
            ];
            foreach ( $event_labels as $key => $label ) : ?>
                <tr>
                    <th><?php echo esc_html( $label[0] ); ?></th>
                    <td>
                        <label class="rls-toggle">
                            <input type="checkbox" name="rls_webhooks[events][<?php echo esc_attr( $key ); ?>]" value="1" <?php checked( 1, $settings['events'][$key] ?? 0 ); ?> />
                            <span class="rls-toggle-slider"></span>
                        </label>
                        <span class="description" style="margin-left:10px;"><?php echo esc_html( $label[1] ); ?></span>
                    </td>
                </tr>
            <?php endforeach; ?>
        </table>
    </div>

    <div id="rls-wh-test-result" style="display:none; margin-bottom:18px;"></div>

    <?php submit_button( 'Сохранить настройки', 'primary' ); ?>

    <!-- EVENT LOG -->
    <div class="rls-box">
        <h2><span class="dashicons dashicons-list-view"></span> Журнал отправок</h2>
        <p>Последние <?php echo count( $event_log ); ?> событий, отправленных в webhooks.</p>
        <?php if ( empty( $event_log ) ) : ?>
            <div class="rls-empty-state">
                <p>Журнал пуст. События появятся здесь после первой отправки.</p>
            </div>
        <?php else : ?>
            <table class="wp-list-table widefat striped">
                <thead>
                    <tr>
                        <th>Время</th>
                        <th>Событие</th>
                        <th>Severity</th>
                        <th>Slack</th>
                        <th>Discord</th>
                        <th>Telegram</th>
                        <th>Custom</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ( $event_log as $entry ) : ?>
                        <tr>
                            <td><small><?php echo esc_html( $entry['time'] ); ?></small></td>
                            <td><strong><?php echo esc_html( $entry['title'] ); ?></strong></td>
                            <td>
                                <span class="rls-status-pill <?php echo $entry['severity'] >= 70 ? 'is-err' : ( $entry['severity'] >= 40 ? 'is-warn' : 'is-on' ); ?>" style="font-size:10px;">
                                    <?php echo intval( $entry['severity'] ); ?>
                                </span>
                            </td>
                            <?php foreach ( [ 'slack', 'discord', 'telegram', 'custom' ] as $ch ) :
                                $r = $entry['results'][ $ch ] ?? null;
                                if ( ! $r ) {
                                    echo '<td><span style="color:var(--rls-text-subtle);">—</span></td>';
                                } elseif ( $r['success'] ) {
                                    echo '<td><span class="rls-status-pill is-on" style="font-size:9px;">✓</span></td>';
                                } else {
                                    $err = $r['error'] ?? ( 'HTTP ' . ( $r['http_code'] ?? '?' ) );
                                    echo '<td><span class="rls-status-pill is-err" title="' . esc_attr( $err ) . '" style="font-size:9px; cursor:help;">✕</span></td>';
                                }
                            endforeach; ?>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    // Severity slider live display.
    var sev = document.getElementById('rls-wh-severity');
    var display = document.getElementById('rls-wh-severity-display');
    if (sev && display) {
        sev.addEventListener('input', function() { display.innerHTML = '<strong>' + this.value + '</strong>'; });
    }

    // Test button handler.
    document.querySelectorAll('.rls-wh-test').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var channel = this.getAttribute('data-channel');
            var result = document.getElementById('rls-wh-test-result');
            this.disabled = true; this.textContent = '...';
            result.style.display = 'block';
            result.innerHTML = '<div class="rls-skeleton is-text" style="width:60%;"></div>';
            fetch(ajaxurl || (window.rls_admin_data && rls_admin_data.ajax_url), {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=rls_webhook_test&nonce=' + (window.rls_admin_data ? rls_admin_data.settings_nonce : '') + '&channel=' + encodeURIComponent(channel)
            }).then(function(r){ return r.json(); }).then(function(j) {
                if (j && j.success) {
                    var results = j.data.results || {};
                    var html = '<div class="rls-box" style="border-left: 4px solid var(--rls-success); margin-bottom:0;">';
                    html += '<strong>Результат отправки:</strong><br>';
                    Object.keys(results).forEach(function(ch) {
                        var r = results[ch];
                        if (r.success) {
                            html += '<span class="rls-status-pill is-on">' + ch + ': ✓ OK</span> ';
                        } else {
                            html += '<span class="rls-status-pill is-err" title="' + (r.error || '') + '">' + ch + ': ✕ ' + (r.error || ('HTTP ' + (r.http_code || '?'))) + '</span> ';
                        }
                    });
                    html += '</div>';
                    result.innerHTML = html;
                } else {
                    result.innerHTML = '<div class="rls-notice is-danger">' + (j.data || 'Ошибка') + '</div>';
                }
                btn.disabled = false; btn.textContent = 'Test';
            });
        });
    });
});
</script>
