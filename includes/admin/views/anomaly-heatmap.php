<?php
/**
 * Anomaly Heatmap — per-user login pattern analysis.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

if ( ! class_exists( 'RLS_Anomaly' ) ) {
    echo '<div class="rls-notice is-danger">RLS Anomaly не загружен.</div>';
    return;
}

$days = isset( $_GET['rls_days'] ) ? max( 7, min( 90, (int) $_GET['rls_days'] ) ) : 30;
$top_users = RLS_Anomaly::get_top_anomalous_users( 15, $days );
$global_matrix = RLS_Anomaly::get_global_activity_heatmap( $days );
$recent_anomalies = RLS_Anomaly::get_recent_anomalies( 20 );
?>
<div class="rls-wrap">
    <div class="rls-page-hero">
        <div class="rls-page-hero-top">
            <div>
                <div class="rls-page-kicker">Rybinsk Lab Security</div>
                <h1 class="rls-page-title">
                    Anomaly Heatmap
                    <span class="rls-page-version">v<?php echo RLS_VERSION; ?></span>
                </h1>
                <p class="rls-page-subtitle">Обнаружение нетипичных паттернов входа по пользователям. Composite score на основе diversity, failure rate, hour entropy.</p>
            </div>
            <div class="rls-hero-actions">
                <select id="rls-anomaly-days" style="background: rgba(255,255,255,0.12); color:#fff; border:1px solid rgba(255,255,255,0.18); padding:6px 12px; border-radius:6px;">
                    <option value="7"  <?php selected( $days, 7 ); ?>>7 дней</option>
                    <option value="14" <?php selected( $days, 14 ); ?>>14 дней</option>
                    <option value="30" <?php selected( $days, 30 ); ?>>30 дней</option>
                    <option value="60" <?php selected( $days, 60 ); ?>>60 дней</option>
                    <option value="90" <?php selected( $days, 90 ); ?>>90 дней</option>
                </select>
            </div>
        </div>
    </div>

    <!-- GLOBAL HEATMAP -->
    <div class="rls-box">
        <h2><span class="dashicons dashicons-chart-area"></span> Глобальная карта активности (день × час)</h2>
        <p>Когда пользователи обычно заходят на сайт. Тёмные ячейки — пиковые часы.</p>
        <div id="rls-global-heatmap" style="display: grid; grid-template-columns: 40px repeat(24, 1fr); gap: 2px; margin: 10px 0;"></div>
        <div style="display:flex; justify-content: space-between; margin-top: 8px; font-size:11px; color:var(--rls-text-muted); padding-left: 46px;">
            <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:00</span>
        </div>
    </div>

    <!-- TOP ANOMALOUS USERS -->
    <div class="rls-box">
        <h2><span class="dashicons dashicons-warning"></span> Топ пользователей с аномалиями</h2>
        <p>Composite score учитывает: diversity IP/UA/country, failure rate, hour entropy.</p>
        <table class="wp-list-table widefat striped">
            <thead>
                <tr>
                    <th>Пользователь</th>
                    <th>Anomaly Score</th>
                    <th>Попыток</th>
                    <th>Неудач</th>
                    <th>Уникальных IP</th>
                    <th>Heatmap (7×24)</th>
                    <th>Последний вход</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ( $top_users as $u ) :
                    $score = (int) $u['score'];
                    $level = $score >= 70 ? 'is-err' : ( $score >= 40 ? 'is-warn' : 'is-ok' );
                    ?>
                    <tr>
                        <td>
                            <strong><?php echo esc_html( $u['display_name'] ); ?></strong>
                            <br><small style="color:var(--rls-text-muted);"><?php echo esc_html( $u['user_email'] ); ?></small>
                        </td>
                        <td>
                            <div style="display:flex; align-items:center; gap:8px;">
                                <div style="width:80px; height:8px; background:var(--rls-surface-alt); border-radius:999px; overflow:hidden;">
                                    <div style="width:<?php echo $score; ?>%; height:100%; background:<?php echo $score >= 70 ? '#dc2626' : ( $score >= 40 ? '#d97706' : '#16a34a' ); ?>;"></div>
                                </div>
                                <strong style="color: <?php echo $score >= 70 ? 'var(--rls-danger)' : ( $score >= 40 ? 'var(--rls-warning)' : 'var(--rls-success)' ); ?>;">
                                    <?php echo $score; ?>
                                </strong>
                            </div>
                        </td>
                        <td><?php echo intval( $u['attempts'] ); ?></td>
                        <td><?php echo intval( $u['failures'] ); ?></td>
                        <td><?php echo intval( $u['unique_ips'] ); ?></td>
                        <td>
                            <div class="rls-user-mini-heatmap" data-matrix="<?php echo esc_attr( wp_json_encode( $u['matrix'] ) ); ?>" style="display:grid; grid-template-columns: repeat(24, 6px); gap:1px; max-width:160px;"></div>
                        </td>
                        <td><?php echo esc_html( $u['last_seen'] ); ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- RECENT ANOMALY EVENTS -->
    <?php if ( ! empty( $recent_anomalies ) ) : ?>
    <div class="rls-box">
        <h2><span class="dashicons dashicons-clock"></span> Последние события аномалий</h2>
        <table class="wp-list-table widefat striped">
            <thead><tr><th>Время</th><th>Пользователь</th><th>IP</th><th>Типы аномалий</th></tr></thead>
            <tbody>
                <?php foreach ( array_reverse( $recent_anomalies ) as $a ) : ?>
                    <tr>
                        <td><?php echo esc_html( $a['time'] ?? '' ); ?></td>
                        <td><code><?php echo esc_html( $a['user_login'] ?? '' ); ?></code></td>
                        <td><code><?php echo esc_html( $a['ip'] ?? '' ); ?></code></td>
                        <td>
                            <?php foreach ( (array) ( $a['anomalies'] ?? [] ) as $anom ) : ?>
                                <span class="rls-badge-log orange" style="margin-right:4px;">
                                    <?php echo esc_html( $anom['type'] ?? '' ); ?>: <?php echo esc_html( (string) ( $anom['value'] ?? '' ) ); ?>
                                </span>
                            <?php endforeach; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</div>

<style>
.rls-anomaly-heatmap-cell {
    aspect-ratio: 1;
    min-height: 18px;
    border-radius: 2px;
    background: rgba(0,0,0,0.05);
    transition: all 0.12s ease;
    cursor: pointer;
}
.rls-anomaly-heatmap-cell:hover {
    outline: 2px solid var(--rls-primary);
    transform: scale(1.4);
    z-index: 10;
}
.rls-user-mini-heatmap .rls-anomaly-heatmap-cell { min-height: 6px; }
.rls-heatmap-axis {
    color: var(--rls-text-muted);
    font-size: 11px;
    display: flex;
    align-items: center;
    justify-content: center;
}
</style>
<script>
document.addEventListener('DOMContentLoaded', function() {
    var daysSelect = document.getElementById('rls-anomaly-days');
    if (daysSelect) {
        daysSelect.addEventListener('change', function() {
            window.location.href = '?page=rls-anomaly&rls_days=' + this.value;
        });
    }

    // Global heatmap render
    var globalMatrix = <?php echo wp_json_encode( $global_matrix ); ?>;
    var globalBox = document.getElementById('rls-global-heatmap');
    if (globalBox) {
        var dowNames = ['Вс', 'Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб'];
        // Find max for intensity.
        var max = 0;
        Object.keys(globalMatrix).forEach(function(k) { max = Math.max(max, globalMatrix[k]); });
        for (var dow = 0; dow < 7; dow++) {
            var label = document.createElement('div');
            label.className = 'rls-heatmap-axis';
            label.textContent = dowNames[dow];
            globalBox.appendChild(label);
            for (var hour = 0; hour < 24; hour++) {
                var cell = document.createElement('div');
                cell.className = 'rls-anomaly-heatmap-cell';
                var v = globalMatrix[dow + '-' + hour] || 0;
                var intensity = max > 0 ? (v / max) : 0;
                cell.style.background = intensity === 0
                    ? 'rgba(0,0,0,0.04)'
                    : 'rgba(99, 102, 241, ' + (0.1 + intensity * 0.85).toFixed(2) + ')';
                cell.title = dowNames[dow] + ' ' + String(hour).padStart(2, '0') + ':00 — ' + v + ' входов';
                globalBox.appendChild(cell);
            }
        }
    }

    // Per-user mini heatmaps
    document.querySelectorAll('.rls-user-mini-heatmap').forEach(function(box) {
        try {
            var matrix = JSON.parse(box.getAttribute('data-matrix'));
            var max = 0;
            Object.keys(matrix).forEach(function(k) { max = Math.max(max, matrix[k]); });
            for (var dow = 0; dow < 7; dow++) {
                for (var hour = 0; hour < 24; hour++) {
                    var cell = document.createElement('div');
                    cell.className = 'rls-anomaly-heatmap-cell';
                    var v = matrix[dow + '-' + hour] || 0;
                    var intensity = max > 0 ? (v / max) : 0;
                    cell.style.background = intensity === 0
                        ? 'rgba(0,0,0,0.04)'
                        : 'rgba(99, 102, 241, ' + (0.1 + intensity * 0.85).toFixed(2) + ')';
                    cell.title = v + ' входов';
                    box.appendChild(cell);
                }
            }
        } catch (e) {}
    });
});
</script>
