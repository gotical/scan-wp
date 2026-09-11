<?php
/**
 * Attack Analytics Page — login attempts + attack log statistics.
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Analytics_Page {

    public function init() {
        add_action( 'wp_ajax_rls_get_analytics', [ $this, 'ajax_data' ] );
    }

    public function render_page() {
        if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Access denied' );
        $days = isset( $_GET['rls_days'] ) ? max( 1, min( 90, (int) $_GET['rls_days'] ) ) : 7;
        $summary = class_exists( 'RLS_Login_Attempts' ) ? RLS_Login_Attempts::get_summary( $days ) : [];
        $top_attackers = RLS_Attack_Analytics::get_top_attackers( $days, 10 );
        $top_ips_login = class_exists( 'RLS_Login_Attempts' ) ? RLS_Login_Attempts::get_top_failing_ips( $days, 10 ) : [];
        ?>
        <div class="rls-wrap">
            <div class="rls-page-hero">
                <div class="rls-page-hero-top">
                    <div>
                        <div class="rls-page-kicker">Rybinsk Lab Security</div>
                        <h1 class="rls-page-title">
                            Аналитика атак
                            <span class="rls-page-version">v<?php echo RLS_VERSION; ?></span>
                        </h1>
                        <p class="rls-page-subtitle">Полная статистика отражённых атак, неудачных входов и аномалий. Данные за последние <?php echo intval( $days ); ?> дней.</p>
                    </div>
                    <div class="rls-hero-actions">
                        <select id="rls-analytics-days" style="background: rgba(255,255,255,0.12); color:#fff; border:1px solid rgba(255,255,255,0.18); padding:6px 12px; border-radius:6px;">
                            <option value="1"  <?php selected( $days, 1 ); ?>>24 часа</option>
                            <option value="7"  <?php selected( $days, 7 ); ?>>7 дней</option>
                            <option value="14" <?php selected( $days, 14 ); ?>>14 дней</option>
                            <option value="30" <?php selected( $days, 30 ); ?>>30 дней</option>
                            <option value="90" <?php selected( $days, 90 ); ?>>90 дней</option>
                        </select>
                    </div>
                </div>
            </div>

            <!-- SUMMARY CARDS -->
            <div class="rls-widget-grid">
                <div class="rls-widget-tile is-err">
                    <div class="rls-widget-num rls-counter" data-target="<?php echo intval( $summary['failures'] ?? 0 ); ?>">0</div>
                    <div class="rls-widget-label">Неудачных входов</div>
                </div>
                <div class="rls-widget-tile is-ok">
                    <div class="rls-widget-num rls-counter" data-target="<?php echo intval( $summary['successes'] ?? 0 ); ?>">0</div>
                    <div class="rls-widget-label">Успешных входов</div>
                </div>
                <div class="rls-widget-tile is-warn">
                    <div class="rls-widget-num rls-counter" data-target="<?php echo intval( $summary['unique_ips'] ?? 0 ); ?>">0</div>
                    <div class="rls-widget-label">Уникальных IP</div>
                </div>
                <div class="rls-widget-tile">
                    <div class="rls-widget-num rls-counter" data-target="<?php echo intval( $summary['unique_users'] ?? 0 ); ?>">0</div>
                    <div class="rls-widget-label">Пользователей</div>
                </div>
            </div>

            <!-- CHARTS -->
            <div style="display:grid; grid-template-columns: 2fr 1fr; gap: 18px;">
                <div class="rls-box">
                    <h2><span class="dashicons dashicons-chart-line"></span> Атаки vs. Неудачные входы</h2>
                    <div style="height: 280px;">
                        <canvas id="rls-analytics-timeline"></canvas>
                    </div>
                </div>
                <div class="rls-box">
                    <h2><span class="dashicons dashicons-chart-pie"></span> Типы атак</h2>
                    <div style="height: 280px;">
                        <canvas id="rls-analytics-types"></canvas>
                    </div>
                </div>
            </div>

            <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 18px;">
                <div class="rls-box">
                    <h2><span class="dashicons dashicons-networking"></span> Top-10 атакующих IP</h2>
                    <table class="wp-list-table widefat striped" id="rls-analytics-top-attackers">
                        <thead><tr><th>IP</th><th>Страна</th><th>Атак</th><th>Типов</th></tr></thead>
                        <tbody>
                            <?php foreach ( $top_attackers as $a ) : ?>
                                <tr>
                                    <td><code><?php echo esc_html( $a['ip'] ); ?></code></td>
                                    <td><?php echo esc_html( $a['country_code'] ?: '—' ); ?></td>
                                    <td><strong><?php echo intval( $a['attacks'] ); ?></strong></td>
                                    <td><?php echo intval( $a['types'] ); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <div class="rls-box">
                    <h2><span class="dashicons dashicons-admin-users"></span> Top-10 неудачных логинов</h2>
                    <table class="wp-list-table widefat striped" id="rls-analytics-top-login-ips">
                        <thead><tr><th>IP</th><th>Страна</th><th>Попыток</th><th>Юзеров</th></tr></thead>
                        <tbody>
                            <?php foreach ( $top_ips_login as $a ) : ?>
                                <tr>
                                    <td><code><?php echo esc_html( $a['ip'] ); ?></code></td>
                                    <td><?php echo esc_html( $a['country_code'] ?: '—' ); ?></td>
                                    <td><strong><?php echo intval( $a['failures'] ); ?></strong></td>
                                    <td><?php echo intval( $a['users'] ); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- HEATMAP -->
            <div class="rls-box">
                <h2><span class="dashicons dashicons-chart-area"></span> Heatmap атак (час × день недели)</h2>
                <div id="rls-analytics-heatmap" style="display:grid; grid-template-columns: repeat(24, 1fr); gap:2px; margin-top:12px;"></div>
                <div style="display:flex; justify-content:space-between; margin-top:8px; font-size:11px; color:var(--rls-text-muted);">
                    <span>Пн</span><span>Вт</span><span>Ср</span><span>Чт</span><span>Пт</span><span>Сб</span><span>Вс</span>
                </div>
            </div>

            <!-- EXPORT -->
            <div style="margin-top: 18px;">
                <a class="button button-secondary" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-ajax.php?action=rls_export_attacks' ), 'rls_settings_nonce', 'nonce' ) ); ?>">
                    📥 Экспорт лога атак (JSON)
                </a>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
        <?php
    }

    public function ajax_data() {
        check_ajax_referer( 'rls_monitoring_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error();
        $days = max( 1, min( 90, (int) ( $_POST['days'] ?? 7 ) ) );
        wp_send_json_success( [
            'timeline'        => RLS_Attack_Analytics::get_combined_timeline( $days ),
            'types'           => RLS_Attack_Analytics::get_type_breakdown( $days ),
            'top_attackers'   => RLS_Attack_Analytics::get_top_attackers( $days, 20 ),
            'top_login_ips'   => class_exists( 'RLS_Login_Attempts' ) ? RLS_Login_Attempts::get_top_failing_ips( $days, 20 ) : [],
            'top_logins'      => class_exists( 'RLS_Login_Attempts' ) ? RLS_Login_Attempts::get_top_failing_usernames( $days, 20 ) : [],
            'hour_heatmap'    => RLS_Attack_Analytics::get_hour_heatmap( $days ),
            'country'         => RLS_Attack_Analytics::get_country_breakdown( $days ),
            'login_country'   => class_exists( 'RLS_Login_Attempts' ) ? RLS_Login_Attempts::get_country_distribution( $days ) : [],
            'login_summary'   => class_exists( 'RLS_Login_Attempts' ) ? RLS_Login_Attempts::get_summary( $days ) : [],
            'attack_summary'  => RLS_Attack_Analytics::get_attempts_per_ip( $days ),
            'recent_attacks'  => RLS_Attack_Analytics::get_recent_attacks( 100 ),
            'recent_logins'   => class_exists( 'RLS_Login_Attempts' ) ? RLS_Login_Attempts::get_recent_attempts( 50 ) : [],
        ] );
    }

    /**
     * Export attack log as JSON download.
     */
    public static function ajax_export_attacks() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Access denied' );
        global $wpdb;
        $table = $wpdb->prefix . 'rls_attack_log';
        $rows = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY id DESC LIMIT 10000", ARRAY_A );
        nocache_headers();
        header( 'Content-Type: application/json; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="rls-attacks-' . gmdate( 'Ymd-His' ) . '.json"' );
        echo wp_json_encode( [
            'exported_at' => gmdate( 'c' ),
            'site'        => home_url(),
            'count'       => count( $rows ),
            'attacks'     => $rows,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE );
        exit;
    }
}
