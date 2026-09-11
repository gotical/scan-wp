<?php
/**
 * Monitoring dashboard: time-series, top attackers, country stats.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Monitoring_Dashboard {

    public function init() {
        add_action( 'wp_ajax_rls_monitoring_data', [ $this, 'ajax_data' ] );
    }

    public function render_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Access denied' );
        }
        $health = class_exists( 'RLS_Health' ) ? new RLS_Health() : null;
        $checks = $health ? $health->run_checks() : [];
        $health_status = 'ok';
        foreach ( $checks as $c ) {
            if ( $c['status'] === 'err' ) $health_status = 'err';
            elseif ( $c['status'] === 'warn' && $health_status === 'ok' ) $health_status = 'warn';
        }
        ?>
        <div class="rls-wrap">
            <div class="rls-page-hero">
                <div class="rls-page-hero-top">
                    <div>
                        <div class="rls-page-kicker">Rybinsk Lab Security</div>
                        <h1 class="rls-page-title">
                            Мониторинг
                            <span class="rls-page-version">v<?php echo RLS_VERSION; ?></span>
                        </h1>
                        <p class="rls-page-subtitle">Аналитика атак в реальном времени, top-источники угроз и состояние системы.</p>
                    </div>
                    <div class="rls-hero-actions">
                        <button type="button" class="button button-secondary" id="rls-health-refresh">
                            <span class="dashicons dashicons-update"></span> Обновить
                        </button>
                        <button type="button" class="button button-secondary" id="rls-health-export">
                            <span class="dashicons dashicons-download"></span> Экспорт отчёта
                        </button>
                    </div>
                </div>
            </div>

            <div class="rls-score-card" id="rls-health-summary">
                <div class="rls-score-ring" id="rls-health-ring">
                    <span id="rls-health-percent">—</span>
                </div>
                <div class="rls-score-info">
                    <h3>Состояние системы</h3>
                    <p><span class="rls-status-pill" id="rls-health-pill">…</span></p>
                    <p style="margin:0; font-size:12px; color: var(--rls-text-muted);">
                        <a href="#" id="rls-health-details-link">Подробности</a>
                    </p>
                </div>
            </div>

            <div class="rls-widget-grid">
                <div class="rls-widget-tile is-ok">
                    <div class="rls-widget-num rls-counter" id="rls-stat-blocked" data-target="0">0</div>
                    <div class="rls-widget-label">Заблокировано (24ч)</div>
                    <svg class="rls-sparkline" viewBox="0 0 100 32" preserveAspectRatio="none"><polyline id="rls-spark-blocked" fill="none" stroke="currentColor" stroke-width="1.5" points=""/></svg>
                </div>
                <div class="rls-widget-tile is-warn">
                    <div class="rls-widget-num rls-counter" id="rls-stat-unique" data-target="0">0</div>
                    <div class="rls-widget-label">Уникальных IP</div>
                </div>
                <div class="rls-widget-tile is-err">
                    <div class="rls-widget-num rls-counter" id="rls-stat-malware" data-target="0">0</div>
                    <div class="rls-widget-label">Угроз в карантине</div>
                </div>
                <div class="rls-widget-tile">
                    <div class="rls-widget-num rls-counter" id="rls-stat-countries" data-target="0">0</div>
                    <div class="rls-widget-label">Стран атаковало</div>
                </div>
            </div>

            <div class="rls-box">
                <h2><span class="dashicons dashicons-chart-line"></span> Атаки за последние 14 дней</h2>
                <div style="height: 280px;">
                    <div id="rls-chart-attacks-skeleton" class="rls-skeleton is-card" style="height: 100%;"></div>
                    <canvas id="rls-chart-attacks" style="display:none;"></canvas>
                </div>
            </div>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 18px;">
                <div class="rls-box">
                    <h2><span class="dashicons dashicons-networking"></span> Top-10 атакующих IP</h2>
                    <table class="wp-list-table widefat striped rls-attack-history-table" id="rls-table-top-ips">
                        <thead><tr><th>IP</th><th>Тип атаки</th><th>Событий</th></tr></thead>
                        <tbody>
                            <?php for ( $i = 0; $i < 5; $i++ ) : ?>
                                <tr><td colspan="3"><div class="rls-skeleton is-text" style="width:80%;"></div></td></tr>
                            <?php endfor; ?>
                        </tbody>
                    </table>
                </div>

                <div class="rls-box">
                    <h2><span class="dashicons dashicons-chart-pie"></span> Распределение по типам</h2>
                    <div style="height: 280px;">
                        <div id="rls-chart-types-skeleton" class="rls-skeleton is-circle" style="margin: auto; width: 200px; height: 200px;"></div>
                        <canvas id="rls-chart-types" style="display:none;"></canvas>
                    </div>
                </div>

                <div class="rls-box">
                    <h2><span class="dashicons dashicons-admin-site"></span> По странам</h2>
                    <table class="wp-list-table widefat striped" id="rls-table-countries">
                        <thead><tr><th>Страна</th><th>Событий</th></tr></thead>
                        <tbody>
                            <?php for ( $i = 0; $i < 5; $i++ ) : ?>
                                <tr><td><div class="rls-skeleton is-text" style="width:60%;"></div></td><td><div class="rls-skeleton is-text" style="width:30%;"></div></td></tr>
                            <?php endfor; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
        <?php
        $this->render_health_modal( $checks );
    }

    private function render_health_modal( $checks ) {
        ?>
        <div id="rls-health-modal" style="display:none; position: fixed; inset: 0; background: rgba(15,23,42,0.6); z-index: 100000; align-items: center; justify-content: center;">
            <div style="background: #fff; border-radius: 14px; width: 90%; max-width: 720px; max-height: 85vh; overflow: hidden; display: flex; flex-direction: column; box-shadow: 0 25px 50px rgba(0,0,0,0.3);">
                <div style="padding: 18px 24px; border-bottom: 1px solid var(--rls-border); display: flex; justify-content: space-between; align-items: center;">
                    <h2 style="margin:0;">Диагностика системы</h2>
                    <button type="button" class="button" id="rls-health-close">Закрыть</button>
                </div>
                <div style="padding: 24px; overflow-y: auto;">
                    <table class="wp-list-table widefat striped">
                        <thead><tr><th>Проверка</th><th>Значение</th><th>Статус</th></tr></thead>
                        <tbody>
                            <?php foreach ( $checks as $c ) : ?>
                                <tr>
                                    <td><strong><?php echo esc_html( $c['label'] ); ?></strong><br><small style="color: var(--rls-text-muted);"><?php echo esc_html( $c['hint'] ); ?></small></td>
                                    <td><code><?php echo esc_html( $c['value'] ); ?></code></td>
                                    <td>
                                        <?php if ( $c['status'] === 'ok' ) : ?>
                                            <span class="rls-status-pill is-on">OK</span>
                                        <?php elseif ( $c['status'] === 'warn' ) : ?>
                                            <span class="rls-status-pill is-warn">WARN</span>
                                        <?php else : ?>
                                            <span class="rls-status-pill is-err">ERR</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        <?php
    }

    public function ajax_data() {
        check_ajax_referer( 'rls_monitoring_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error();

        global $wpdb;
        $log_table = $wpdb->prefix . 'rls_attack_log';

        // 14-day timeline
        $timeline = $wpdb->get_results( $wpdb->prepare(
            "SELECT DATE(event_date) AS day, COUNT(*) AS total
             FROM $log_table
             WHERE event_date >= DATE_SUB(%s, INTERVAL 14 DAY)
             GROUP BY DATE(event_date)
             ORDER BY day ASC",
            current_time( 'mysql' )
        ), ARRAY_A );

        // Top IPs (24h)
        $top_ips = $wpdb->get_results( $wpdb->prepare(
            "SELECT ip, type, COUNT(*) AS total
             FROM $log_table
             WHERE event_date >= DATE_SUB(%s, INTERVAL 24 HOUR)
             GROUP BY ip, type
             ORDER BY total DESC
             LIMIT 10",
            current_time( 'mysql' )
        ), ARRAY_A );

        // Type distribution (7d)
        $types = $wpdb->get_results( $wpdb->prepare(
            "SELECT LOWER(type) AS type, COUNT(*) AS total
             FROM $log_table
             WHERE event_date >= DATE_SUB(%s, INTERVAL 7 DAY)
             GROUP BY LOWER(type)
             ORDER BY total DESC",
            current_time( 'mysql' )
        ), ARRAY_A );

        // Country stats (last 7 days, joining with GeoIP if available)
        $countries = [];
        if ( class_exists( 'RLS_GeoIP' ) ) {
            $recent_ips = $wpdb->get_col( $wpdb->prepare(
                "SELECT DISTINCT ip FROM $log_table WHERE event_date >= DATE_SUB(%s, INTERVAL 7 DAY) LIMIT 200",
                current_time( 'mysql' )
            ) );
            foreach ( $recent_ips as $ip ) {
                $code = RLS_GeoIP::lookup_country_code( $ip );
                if ( $code ) {
                    if ( ! isset( $countries[ $code ] ) ) $countries[ $code ] = 0;
                    $countries[ $code ]++;
                }
            }
            arsort( $countries );
        }

        // 24h counters
        $blocked_24h = (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(*) FROM $log_table WHERE event_date >= DATE_SUB(%s, INTERVAL 24 HOUR)",
            current_time( 'mysql' )
        ) );
        $unique_ips_24h = (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(DISTINCT ip) FROM $log_table WHERE event_date >= DATE_SUB(%s, INTERVAL 24 HOUR)",
            current_time( 'mysql' )
        ) );

        // Quarantine stats
        $quarantine_dir = wp_normalize_path( wp_upload_dir()['basedir'] . '/rls-quarantine' );
        $quarantine_count = 0;
        if ( file_exists( $quarantine_dir . '/index_map.json' ) ) {
            $raw = @file_get_contents( $quarantine_dir . '/index_map.json' );
            $data = is_string( $raw ) ? json_decode( $raw, true ) : [];
            if ( is_array( $data ) ) $quarantine_count = count( $data );
        }

        wp_send_json_success( [
            'timeline'     => $timeline,
            'top_ips'      => $top_ips,
            'types'        => $types,
            'countries'    => $countries,
            'blocked_24h'  => $blocked_24h,
            'unique_ips'   => $unique_ips_24h,
            'quarantine'   => $quarantine_count,
        ] );
    }
}
