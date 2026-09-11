<?php
/**
 * Attack Correlation page — shows correlated campaigns.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

if ( ! class_exists( 'RLS_Attack_Correlation' ) ) {
    echo '<div class="rls-notice is-danger">RLS Attack Correlation не загружен.</div>';
    return;
}

$days = isset( $_GET['rls_days'] ) ? max( 1, min( 90, (int) $_GET['rls_days'] ) ) : 7;
$summary = RLS_Attack_Correlation::get_correlation_summary( $days );
?>
<div class="rls-wrap">
    <div class="rls-page-hero">
        <div class="rls-page-hero-top">
            <div>
                <div class="rls-page-kicker">Rybinsk Lab Security</div>
                <h1 class="rls-page-title">
                    Корреляция атак
                    <span class="rls-page-version">v<?php echo RLS_VERSION; ?></span>
                </h1>
                <p class="rls-page-subtitle">Связывание атак в кампании: один IP в time window, общий UA от разных IP, общая цель (URI).</p>
            </div>
            <div class="rls-hero-actions">
                <select id="rls-corr-days" style="background: rgba(255,255,255,0.12); color:#fff; border:1px solid rgba(255,255,255,0.18); padding:6px 12px; border-radius:6px;">
                    <option value="1"  <?php selected( $days, 1 ); ?>>24 часа</option>
                    <option value="7"  <?php selected( $days, 7 ); ?>>7 дней</option>
                    <option value="14" <?php selected( $days, 14 ); ?>>14 дней</option>
                    <option value="30" <?php selected( $days, 30 ); ?>>30 дней</option>
                </select>
            </div>
        </div>
    </div>

    <div class="rls-widget-grid">
        <div class="rls-widget-tile is-err">
            <div class="rls-widget-num rls-counter" data-target="<?php echo intval( $summary['ip_campaigns'] ); ?>">0</div>
            <div class="rls-widget-label">IP-кампаний</div>
        </div>
        <div class="rls-widget-tile is-warn">
            <div class="rls-widget-num rls-counter" data-target="<?php echo intval( $summary['ua_clusters'] ); ?>">0</div>
            <div class="rls-widget-label">Ботнетов (UA)</div>
        </div>
        <div class="rls-widget-tile">
            <div class="rls-widget-num rls-counter" data-target="<?php echo intval( $summary['uri_campaigns'] ); ?>">0</div>
            <div class="rls-widget-label">Скан-кампаний (URI)</div>
        </div>
    </div>

    <!-- IP CAMPAIGNS -->
    <div class="rls-box">
        <h2><span class="dashicons dashicons-networking"></span> IP-кампании (один IP, много событий в time window)</h2>
        <table class="wp-list-table widefat striped rls-attack-history-table">
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Страна</th>
                    <th>Событий</th>
                    <th>Типов</th>
                    <th>Длительность</th>
                    <th>Период</th>
                    <th>Severity</th>
                    <th>Действие</th>
                </tr>
            </thead>
            <tbody>
                <?php if ( empty( $summary['top_ip'] ) ) : ?>
                    <tr><td colspan="8" style="text-align:center; color:var(--rls-text-muted); padding:20px;">Кампаний не обнаружено. Плагин не зафиксировал достаточно событий с одного IP.</td></tr>
                <?php else : foreach ( $summary['top_ip'] as $c ) :
                    $level = $c['severity_level'] ?? 'medium';
                    $duration_text = $c['duration_sec'] < 60
                        ? $c['duration_sec'] . ' сек'
                        : ( $c['duration_sec'] < 3600 ? round( $c['duration_sec'] / 60 ) . ' мин' : round( $c['duration_sec'] / 3600, 1 ) . ' ч' );
                    ?>
                    <tr>
                        <td><code><?php echo esc_html( $c['ip'] ); ?></code></td>
                        <td class="country-col"><?php echo esc_html( $c['country'] ?: '—' ); ?></td>
                        <td><strong><?php echo intval( $c['events_count'] ); ?></strong></td>
                        <td>
                            <?php foreach ( (array) ( $c['types'] ?? [] ) as $t ) : ?>
                                <?php echo RLS_Attack_Types::render_badge( $t ); ?>
                            <?php endforeach; ?>
                        </td>
                        <td><?php echo esc_html( $duration_text ); ?></td>
                        <td>
                            <small><?php echo esc_html( $c['first_seen'] ); ?></small><br>
                            <small style="color:var(--rls-text-subtle);">→ <?php echo esc_html( $c['last_seen'] ); ?></small>
                        </td>
                        <td>
                            <div style="display:flex; align-items:center; gap:6px;">
                                <div style="width:60px; height:6px; background:var(--rls-surface-alt); border-radius:3px; overflow:hidden;">
                                    <div style="width:<?php echo intval( $c['severity'] ); ?>%; height:100%; background:<?php echo $c['severity'] >= 70 ? '#dc2626' : ( $c['severity'] >= 40 ? '#d97706' : '#16a34a' ); ?>;"></div>
                                </div>
                                <strong><?php echo intval( $c['severity'] ); ?></strong>
                            </div>
                        </td>
                        <td>
                            <button class="button button-small rls-block-ip" data-ip="<?php echo esc_attr( $c['ip'] ); ?>" style="background:#dc2626; color:#fff; border-color:#dc2626;">Block IP</button>
                        </td>
                    </tr>
                <?php endforeach; endif; ?>
            </tbody>
        </table>
    </div>

    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:18px;">
        <!-- UA CLUSTERS -->
        <div class="rls-box">
            <h2><span class="dashicons dashicons-admin-users"></span> Ботнеты (один UA от многих IP)</h2>
            <table class="wp-list-table widefat striped">
                <thead>
                    <tr>
                        <th>User-Agent</th>
                        <th>IP</th>
                        <th>Атак</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ( empty( $summary['top_ua'] ) ) : ?>
                        <tr><td colspan="3" style="text-align:center; color:var(--rls-text-muted); padding:20px;">Не обнаружено ботнетов.</td></tr>
                    <?php else : foreach ( $summary['top_ua'] as $u ) : ?>
                        <tr>
                            <td>
                                <code style="font-size:11px; word-break:break-all;"><?php echo esc_html( substr( $u['user_agent'], 0, 60 ) ); ?><?php echo strlen( $u['user_agent'] ) > 60 ? '…' : ''; ?></code>
                            </td>
                            <td><strong><?php echo intval( $u['unique_ips'] ); ?></strong></td>
                            <td><?php echo intval( $u['attacks'] ); ?></td>
                        </tr>
                    <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>

        <!-- URI CAMPAIGNS -->
        <div class="rls-box">
            <h2><span class="dashicons dashicons-admin-site"></span> Скан-кампании (одна цель, много IP)</h2>
            <table class="wp-list-table widefat striped">
                <thead>
                    <tr>
                        <th>URI</th>
                        <th>IP</th>
                        <th>Атак</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ( empty( $summary['top_uri'] ) ) : ?>
                        <tr><td colspan="3" style="text-align:center; color:var(--rls-text-muted); padding:20px;">Не обнаружено скан-кампаний.</td></tr>
                    <?php else : foreach ( $summary['top_uri'] as $u ) : ?>
                        <tr>
                            <td><code style="font-size:11px; word-break:break-all;"><?php echo esc_html( $u['request_uri'] ); ?></code></td>
                            <td><strong><?php echo intval( $u['unique_ips'] ); ?></strong></td>
                            <td><?php echo intval( $u['attacks'] ); ?></td>
                        </tr>
                    <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    var daysSelect = document.getElementById('rls-corr-days');
    if (daysSelect) {
        daysSelect.addEventListener('change', function() {
            window.location.href = '?page=rls-correlation&rls_days=' + this.value;
        });
    }
    // Block IP button.
    document.querySelectorAll('.rls-block-ip').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var ip = this.getAttribute('data-ip');
            if (window.RLS_Confirm) {
                RLS_Confirm.show({
                    title: 'Добавить IP в blacklist?',
                    message: 'IP ' + ip + ' будет добавлен в blacklist. Запросы с этого IP будут заблокированы.',
                    confirmText: 'Заблокировать',
                    type: 'danger',
                }).then(function(ok) {
                    if (ok) {
                        fetch(ajaxurl || (window.rls_admin_data && rls_admin_data.ajax_url), {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                            body: 'action=rls_add_ip_list&nonce=' + (window.rls_admin_data ? rls_admin_data.settings_nonce : '') + '&ip=' + encodeURIComponent(ip) + '&list=black'
                        }).then(function(r){ return r.json(); }).then(function(j) {
                            if (j && j.success) {
                                if (window.RLS_Toast) RLS_Toast.success('IP ' + ip + ' заблокирован');
                                location.reload();
                            } else {
                                if (window.RLS_Toast) RLS_Toast.danger((j && j.data) || 'Ошибка');
                            }
                        });
                    }
                });
            }
        });
    });
});
</script>
