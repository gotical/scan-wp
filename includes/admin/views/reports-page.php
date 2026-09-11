<?php
/**
 * Reports settings page.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

if ( ! class_exists( 'RLS_Reports' ) ) {
    echo '<div class="rls-notice is-danger">RLS Reports не загружен.</div>';
    return;
}

$settings = RLS_Reports::get_settings();
$last_sent = get_option( RLS_Reports::OPT_LAST_SENT );
?>
<div class="rls-wrap">
    <div class="rls-page-hero">
        <div class="rls-page-hero-top">
            <div>
                <div class="rls-page-kicker">Rybinsk Lab Security</div>
                <h1 class="rls-page-title">
                    Отчёты
                    <span class="rls-page-version">v<?php echo RLS_VERSION; ?></span>
                </h1>
                <p class="rls-page-subtitle">Email и HTML-отчёты по безопасности. Print-ready для сохранения в PDF.</p>
            </div>
            <div class="rls-hero-actions">
                <?php if ( $last_sent ) : ?>
                    <span class="rls-status-pill is-on" style="background: rgba(255,255,255,0.18); color: #fff;">
                        Последний: <?php echo esc_html( $last_sent ); ?>
                    </span>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <?php if ( isset( $_POST['rls_reports_settings'] ) && check_admin_referer( 'rls_reports_group' ) ) :
        $settings = RLS_Reports::update_settings( $_POST['rls_reports_settings'] );
        echo '<div class="rls-notice is-success">Настройки отчётов сохранены.</div>';
    endif; ?>

    <?php settings_fields( 'rls_reports_group' ); ?>

    <div class="rls-box">
        <h2><span class="dashicons dashicons-email"></span> Расписание</h2>
        <table class="form-table">
            <tr>
                <th>Включить</th>
                <td>
                    <label class="rls-toggle">
                        <input type="checkbox" name="rls_reports_settings[enabled]" value="1" <?php checked( 1, $settings['enabled'] ); ?> />
                        <span class="rls-toggle-slider"></span>
                    </label>
                </td>
            </tr>
            <tr>
                <th>Частота</th>
                <td>
                    <select name="rls_reports_settings[frequency]">
                        <option value="daily"  <?php selected( $settings['frequency'], 'daily' ); ?>>Ежедневно</option>
                        <option value="weekly" <?php selected( $settings['frequency'], 'weekly' ); ?>>Еженедельно</option>
                    </select>
                </td>
            </tr>
            <tr>
                <th>День недели</th>
                <td>
                    <select name="rls_reports_settings[day_of_week]">
                        <?php $days = [ 'monday' => 'Пн', 'tuesday' => 'Вт', 'wednesday' => 'Ср', 'thursday' => 'Чт', 'friday' => 'Пт', 'saturday' => 'Сб', 'sunday' => 'Вс' ];
                        foreach ( $days as $key => $label ) : ?>
                            <option value="<?php echo esc_attr( $key ); ?>" <?php selected( $settings['day_of_week'], $key ); ?>><?php echo $label; ?></option>
                        <?php endforeach; ?>
                    </select>
                    <p class="description">Для еженедельных отчётов</p>
                </td>
            </tr>
            <tr>
                <th>Время</th>
                <td>
                    <select name="rls_reports_settings[hour]">
                        <?php for ( $h = 0; $h < 24; $h++ ) : ?>
                            <option value="<?php echo $h; ?>" <?php selected( $settings['hour'], $h ); ?>><?php echo sprintf( '%02d:00', $h ); ?></option>
                        <?php endfor; ?>
                    </select>
                </td>
            </tr>
            <tr>
                <th>Получатели</th>
                <td>
                    <textarea name="rls_reports_settings[recipients][]" rows="3" class="large-text" placeholder="admin@example.com"><?php echo esc_textarea( implode( "\n", (array) ( $settings['recipients'] ?? [] ) ) ); ?></textarea>
                    <p class="description">По одному email на строку.</p>
                </td>
            </tr>
        </table>
    </div>

    <div class="rls-box">
        <h2><span class="dashicons dashicons-list-view"></span> Секции отчёта</h2>
        <table class="form-table">
            <?php
            $labels = [
                'summary'         => 'Сводка (4 ключевых метрики)',
                'top_attacks'     => 'Распределение по типам атак',
                'top_ips'         => 'Top-10 атакующих IP',
                'countries'       => 'Распределение по странам',
                'failures'        => 'Top-10 неудачных входов',
                'recommendations' => 'Рекомендации (автогенерация)',
            ];
            foreach ( $labels as $key => $label ) : ?>
                <tr>
                    <th><?php echo esc_html( $label ); ?></th>
                    <td>
                        <label class="rls-toggle">
                            <input type="checkbox" name="rls_reports_settings[sections][<?php echo esc_attr( $key ); ?>]" value="1" <?php checked( 1, $settings['sections'][$key] ?? 0 ); ?> />
                            <span class="rls-toggle-slider"></span>
                        </label>
                    </td>
                </tr>
            <?php endforeach; ?>
        </table>
    </div>

    <div class="rls-box">
        <h2><span class="dashicons dashicons-controls-play"></span> Действия</h2>
        <p>
            <button type="button" class="button button-primary" id="rls-report-send-now">📧 Отправить сейчас</button>
            <button type="button" class="button button-secondary" id="rls-report-preview">👁 Предпросмотр</button>
            <a class="button button-secondary" id="rls-report-download" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-ajax.php?action=rls_download_report' ), 'rls_settings_nonce', 'nonce' ) ); ?>" target="_blank">
                ⬇ Скачать HTML
            </a>
        </p>
        <div id="rls-report-preview-area" style="display:none; margin-top:20px;"></div>
    </div>

    <?php submit_button( 'Сохранить настройки', 'primary' ); ?>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('rls-report-send-now').addEventListener('click', function() {
        var btn = this;
        btn.disabled = true; btn.textContent = 'Отправка...';
        fetch(ajaxurl || (window.rls_admin_data && rls_admin_data.ajax_url), {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'action=rls_send_report_now&nonce=' + (window.rls_admin_data ? rls_admin_data.settings_nonce : '')
        }).then(function(r){ return r.json(); }).then(function(j) {
            if (j && j.success) {
                if (window.RLS_Toast) RLS_Toast.success(j.data);
            } else {
                if (window.RLS_Toast) RLS_Toast.danger((j && j.data) || 'Ошибка');
            }
            btn.disabled = false; btn.textContent = '📧 Отправить сейчас';
        });
    });
    document.getElementById('rls-report-preview').addEventListener('click', function() {
        var btn = this;
        var area = document.getElementById('rls-report-preview-area');
        btn.disabled = true; btn.textContent = 'Генерация...';
        area.style.display = 'block';
        area.innerHTML = '<div class="rls-skeleton is-card" style="height:200px;"></div>';
        fetch(ajaxurl || (window.rls_admin_data && rls_admin_data.ajax_url), {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'action=rls_preview_report&nonce=' + (window.rls_admin_data ? rls_admin_data.settings_nonce : '') + '&days=7'
        }).then(function(r){ return r.json(); }).then(function(j) {
            if (j && j.success && j.data && j.data.html) {
                area.innerHTML = '<iframe srcdoc="' + j.data.html.replace(/"/g, '&quot;') + '" style="width:100%; height:800px; border:1px solid var(--rls-border); border-radius:var(--rls-radius);"></iframe>';
            } else {
                area.innerHTML = '<div class="rls-notice is-danger">Ошибка предпросмотра</div>';
            }
            btn.disabled = false; btn.textContent = '👁 Предпросмотр';
        });
    });
});
</script>
