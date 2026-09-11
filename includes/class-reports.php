<?php
/**
 * Scheduled reports.
 * Generates HTML reports for daily/weekly emails and downloadable PDFs (print-ready HTML).
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Reports {

    const OPT_SETTINGS  = 'rls_reports_settings';
    const OPT_LAST_SENT = 'rls_reports_last_sent';
    const CRON_HOOK     = 'rls_cron_send_report';

    public function init() {
        $settings = get_option( self::OPT_SETTINGS, [] );
        if ( ! is_array( $settings ) ) $settings = [];

        add_action( self::CRON_HOOK, [ $this, 'send_scheduled_report' ] );

        if ( ! empty( $settings['enabled'] ) ) {
            add_action( 'rls_cron_daily',  [ $this, 'maybe_send_daily' ] );
            add_action( 'rls_cron_weekly', [ $this, 'maybe_send_weekly' ] );
        }
    }

    /* === Settings === */

    public static function get_settings() {
        $defaults = [
            'enabled'    => 0,
            'frequency'  => 'weekly',       // daily | weekly
            'day_of_week'=> 'monday',
            'hour'       => 9,             // 0-23
            'recipients' => [ get_option( 'admin_email' ) ],
            'sections'   => [
                'summary'      => 1,
                'top_attacks'  => 1,
                'top_ips'      => 1,
                'countries'    => 1,
                'failures'     => 1,
                'recommendations' => 1,
            ],
            'period_days' => ( 'weekly' === 'weekly' ? 7 : 1 ),
        ];
        $stored = get_option( self::OPT_SETTINGS, [] );
        if ( ! is_array( $stored ) ) $stored = [];
        return array_replace_recursive( $defaults, $stored );
    }

    public static function update_settings( $input ) {
        $current = self::get_settings();
        $current['enabled']     = ! empty( $input['enabled'] ) ? 1 : 0;
        $current['frequency']   = in_array( $input['frequency'] ?? 'weekly', [ 'daily', 'weekly' ], true ) ? $input['frequency'] : 'weekly';
        $current['day_of_week'] = sanitize_text_field( $input['day_of_week'] ?? 'monday' );
        $current['hour']        = max( 0, min( 23, (int) ( $input['hour'] ?? 9 ) ) );
        $recipients = (array) ( $input['recipients'] ?? [] );
        $current['recipients']  = array_values( array_filter( array_map( 'sanitize_email', $recipients ) ) );
        if ( empty( $current['recipients'] ) ) {
            $current['recipients'] = [ get_option( 'admin_email' ) ];
        }
        $sections = [];
        foreach ( [ 'summary', 'top_attacks', 'top_ips', 'countries', 'failures', 'recommendations' ] as $s ) {
            $sections[ $s ] = ! empty( $input['sections'][ $s ] ) ? 1 : 0;
        }
        $current['sections'] = $sections;
        $current['period_days'] = 'weekly' === $current['frequency'] ? 7 : 1;
        update_option( self::OPT_SETTINGS, $current );
        return $current;
    }

    public static function is_enabled() {
        $s = self::get_settings();
        return ! empty( $s['enabled'] );
    }

    /* === Report generation === */

    public static function generate_report( $period_days = 7 ) {
        $generated_at = current_time( 'mysql' );
        $data = [
            'period_days'   => $period_days,
            'site_url'      => home_url(),
            'site_name'     => get_bloginfo( 'name' ),
            'generated_at'  => $generated_at,
            'period_from'   => gmdate( 'Y-m-d H:i:s', time() - ( $period_days * 86400 ) ),
            'period_to'     => gmdate( 'Y-m-d H:i:s' ),
        ];

        if ( class_exists( 'RLS_Login_Attempts' ) ) {
            $data['login_summary'] = RLS_Login_Attempts::get_summary( $period_days );
            $data['login_top_ips'] = RLS_Login_Attempts::get_top_failing_ips( $period_days, 10 );
        }
        $data['attack_top_ips']  = RLS_Attack_Analytics::get_top_attackers( $period_days, 10 );
        $data['attack_types']    = RLS_Attack_Analytics::get_type_breakdown( $period_days );
        $data['attack_countries']= RLS_Attack_Analytics::get_country_breakdown( $period_days );
        $data['correlation']     = RLS_Attack_Correlation::get_correlation_summary( $period_days );

        $data['recommendations'] = self::generate_recommendations( $data );

        return $data;
    }

    private static function generate_recommendations( $data ) {
        $recs = [];
        $failures = $data['login_summary']['failures'] ?? 0;
        $attacks  = array_sum( array_column( $data['attack_types'] ?? [], 'attacks' ) );
        $ip_countries = $data['attack_countries'] ?? [];
        $top_country = ! empty( $ip_countries[0] ) ? $ip_countries[0] : null;
        $campaigns = $data['correlation']['ip_campaigns'] ?? 0;

        if ( $failures > 50 ) {
            $recs[] = [
                'severity' => 'high',
                'title'    => 'Много неудачных попыток входа',
                'text'     => sprintf( 'За период зафиксировано %d неудачных входов. Включите обязательную 2FA для администраторов или расширьте blacklist.', $failures ),
            ];
        }
        if ( $campaigns > 0 ) {
            $recs[] = [
                'severity' => 'high',
                'title'    => 'Обнаружены кампании атак',
                'text'     => sprintf( 'Корреляция показала %d активных IP-кампаний. Рекомендуем добавить IP в blacklist или включить geo-блокировку.', $campaigns ),
            ];
        }
        if ( $top_country && (int) $top_country['attacks'] > 100 ) {
            $recs[] = [
                'severity' => 'medium',
                'title'    => 'Концентрация атак из одной страны',
                'text'     => sprintf( '%d атак из %s. Рассмотрите добавление страны в geo-blacklist.', $top_country['attacks'], $top_country['country_code'] ),
            ];
        }
        if ( $attacks > 1000 ) {
            $recs[] = [
                'severity' => 'high',
                'title'    => 'Высокая интенсивность атак',
                'text'     => sprintf( '%d атак за %d дней. Включите rate-limiting и CDN (Cloudflare/Sucuri).', $attacks, $data['period_days'] ),
            ];
        }
        if ( empty( $recs ) ) {
            $recs[] = [
                'severity' => 'low',
                'title'    => 'Аномалий не обнаружено',
                'text'     => 'Защита работает штатно. Продолжайте обновлять плагины и WP ядро.',
            ];
        }
        return $recs;
    }

    /* === HTML rendering (print-ready) === */

    public static function render_html( $data ) {
        $sections = self::get_settings()['sections'] ?? [];
        ob_start();
        ?>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Rybinsk Lab Security Report</title>
<style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #1d2327; margin: 0; padding: 0; background: #f5f7fb; }
    .rls-report { max-width: 760px; margin: 24px auto; background: #fff; box-shadow: 0 4px 20px rgba(0,0,0,0.08); border-radius: 12px; overflow: hidden; }
    .rls-report__header { background: linear-gradient(135deg, #1d3a8a 0%, #1e40af 50%, #0e7490 100%); background-size: 200% 200%; color: #fff; padding: 32px 40px; }
    .rls-report__title { margin: 0; font-size: 24px; font-weight: 700; }
    .rls-report__subtitle { margin: 4px 0 0; opacity: 0.85; font-size: 14px; }
    .rls-report__body { padding: 32px 40px; }
    .rls-report__section { margin-bottom: 32px; }
    .rls-report__section h2 { font-size: 18px; margin: 0 0 12px; color: #1d2327; border-bottom: 2px solid #2271b1; padding-bottom: 6px; }
    .rls-report__stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
    .rls-report__stat { padding: 16px; background: #f8fafc; border-radius: 8px; text-align: center; }
    .rls-report__stat-num { font-size: 24px; font-weight: 700; color: #2271b1; }
    .rls-report__stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: #50575e; margin-top: 4px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { background: #f1f5f9; padding: 8px 12px; text-align: left; font-weight: 600; }
    td { padding: 8px 12px; border-bottom: 1px solid #e4e8ef; }
    .rls-report__footer { padding: 24px 40px; background: #f8fafc; text-align: center; color: #50575e; font-size: 12px; }
    .rls-rec { padding: 12px 16px; border-left: 4px solid; margin-bottom: 10px; border-radius: 6px; background: #f8fafc; }
    .rls-rec--high   { border-color: #dc2626; background: #fee2e2; }
    .rls-rec--medium { border-color: #d97706; background: #fef3c7; }
    .rls-rec--low    { border-color: #16a34a; background: #dcfce7; }
    .rls-rec-title { font-weight: 600; margin-bottom: 4px; }
    @media print {
        body { background: #fff; }
        .rls-report { box-shadow: none; margin: 0; }
        .rls-report__header { background: #1d3a8a !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    }
</style>
</head>
<body>
<div class="rls-report">
    <div class="rls-report__header">
        <h1 class="rls-report__title">🛡️ Отчёт по безопасности</h1>
        <p class="rls-report__subtitle"><?php echo esc_html( $data['site_name'] ); ?> — <?php echo esc_html( $data['site_url'] ); ?></p>
        <p class="rls-report__subtitle" style="margin-top:8px;">Период: <?php echo esc_html( $data['period_from'] ); ?> — <?php echo esc_html( $data['period_to'] ); ?></p>
    </div>
    <div class="rls-report__body">
        <?php if ( ! empty( $sections['summary'] ) ) : ?>
        <div class="rls-report__section">
            <h2>📊 Сводка</h2>
            <div class="rls-report__stat-grid">
                <div class="rls-report__stat">
                    <div class="rls-report__stat-num"><?php echo intval( $data['login_summary']['failures'] ?? 0 ); ?></div>
                    <div class="rls-report__stat-label">Неудачных входов</div>
                </div>
                <div class="rls-report__stat">
                    <div class="rls-report__stat-num"><?php echo intval( $data['login_summary']['successes'] ?? 0 ); ?></div>
                    <div class="rls-report__stat-label">Успешных входов</div>
                </div>
                <div class="rls-report__stat">
                    <div class="rls-report__stat-num"><?php echo intval( $data['login_summary']['unique_ips'] ?? 0 ); ?></div>
                    <div class="rls-report__stat-label">Уникальных IP</div>
                </div>
                <div class="rls-report__stat">
                    <div class="rls-report__stat-num"><?php echo intval( $data['correlation']['ip_campaigns'] ?? 0 ); ?></div>
                    <div class="rls-report__stat-label">Кампаний</div>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <?php if ( ! empty( $sections['top_attacks'] ) && ! empty( $data['attack_types'] ) ) : ?>
        <div class="rls-report__section">
            <h2>🎯 Распределение по типам</h2>
            <table>
                <thead><tr><th>Тип</th><th>Количество</th><th>%</th></tr></thead>
                <tbody>
                <?php
                $total = array_sum( array_column( $data['attack_types'], 'attacks' ) );
                foreach ( $data['attack_types'] as $t ) :
                    $pct = $total > 0 ? round( ( $t['attacks'] / $total ) * 100, 1 ) : 0;
                    $label = RLS_Attack_Types::get_label( $t['type'] );
                    ?>
                    <tr>
                        <td><?php echo esc_html( $label ); ?></td>
                        <td><?php echo intval( $t['attacks'] ); ?></td>
                        <td><?php echo esc_html( $pct . '%' ); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>

        <?php if ( ! empty( $sections['top_ips'] ) && ! empty( $data['attack_top_ips'] ) ) : ?>
        <div class="rls-report__section">
            <h2>🌐 Top-10 атакующих IP</h2>
            <table>
                <thead><tr><th>IP</th><th>Страна</th><th>Атак</th><th>Типов</th></tr></thead>
                <tbody>
                <?php foreach ( $data['attack_top_ips'] as $a ) : ?>
                    <tr>
                        <td><code><?php echo esc_html( $a['ip'] ); ?></code></td>
                        <td><?php echo esc_html( $a['country_code'] ?: '—' ); ?></td>
                        <td><?php echo intval( $a['attacks'] ); ?></td>
                        <td><?php echo intval( $a['types'] ); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>

        <?php if ( ! empty( $sections['countries'] ) && ! empty( $data['attack_countries'] ) ) : ?>
        <div class="rls-report__section">
            <h2>🗺 Распределение по странам</h2>
            <table>
                <thead><tr><th>Страна</th><th>Атак</th><th>IP</th></tr></thead>
                <tbody>
                <?php foreach ( array_slice( $data['attack_countries'], 0, 10 ) as $c ) : ?>
                    <tr>
                        <td><?php echo esc_html( $c['country_code'] ); ?></td>
                        <td><?php echo intval( $c['attacks'] ); ?></td>
                        <td><?php echo intval( $c['unique_ips'] ); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>

        <?php if ( ! empty( $sections['failures'] ) && ! empty( $data['login_top_ips'] ) ) : ?>
        <div class="rls-report__section">
            <h2>🔐 Неудачные входы (Top-10 IP)</h2>
            <table>
                <thead><tr><th>IP</th><th>Страна</th><th>Попыток</th><th>Юзеров</th></tr></thead>
                <tbody>
                <?php foreach ( $data['login_top_ips'] as $a ) : ?>
                    <tr>
                        <td><code><?php echo esc_html( $a['ip'] ); ?></code></td>
                        <td><?php echo esc_html( $a['country_code'] ?: '—' ); ?></td>
                        <td><?php echo intval( $a['failures'] ); ?></td>
                        <td><?php echo intval( $a['users'] ); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>

        <?php if ( ! empty( $sections['recommendations'] ) && ! empty( $data['recommendations'] ) ) : ?>
        <div class="rls-report__section">
            <h2>💡 Рекомендации</h2>
            <?php foreach ( $data['recommendations'] as $rec ) : ?>
                <div class="rls-rec rls-rec--<?php echo esc_attr( $rec['severity'] ); ?>">
                    <div class="rls-rec-title"><?php echo esc_html( $rec['title'] ); ?></div>
                    <div><?php echo esc_html( $rec['text'] ); ?></div>
                </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
    </div>
    <div class="rls-report__footer">
        <p>Сгенерировано плагином <strong>Rybinsk Lab Security</strong> v<?php echo esc_html( defined( 'RLS_VERSION' ) ? RLS_VERSION : '' ); ?></p>
        <p><?php echo esc_html( $data['generated_at'] ); ?> · <a href="<?php echo esc_url( admin_url( 'admin.php?page=rls-reports' ) ); ?>">Открыть в админке</a></p>
    </div>
</div>
</body>
</html>
        <?php
        return ob_get_clean();
    }

    /* === Sending === */

    public function maybe_send_daily() {
        $settings = self::get_settings();
        if ( 'daily' !== $settings['frequency'] ) return;
        $this->send( 1 );
    }

    public function maybe_send_weekly() {
        $settings = self::get_settings();
        if ( 'weekly' !== $settings['frequency'] ) return;
        $this->send( 7 );
    }

    public function send_scheduled_report() {
        $settings = self::get_settings();
        $this->send( $settings['period_days'] ?? 7 );
    }

    public function send( $period_days = 7 ) {
        $settings = self::get_settings();
        $data = self::generate_report( $period_days );
        $html = self::render_html( $data );

        $site_name = get_bloginfo( 'name' );
        $subject = sprintf( '🛡️ [%s] Отчёт по безопасности: %s атак, %s неудачных входов',
            $site_name,
            number_format_i18n( array_sum( array_column( $data['attack_types'] ?? [], 'attacks' ) ) ),
            number_format_i18n( $data['login_summary']['failures'] ?? 0 )
        );

        $headers = [ 'Content-Type: text/html; charset=UTF-8' ];
        $sent = false;
        foreach ( (array) $settings['recipients'] as $to ) {
            if ( is_email( $to ) ) {
                $result = wp_mail( $to, $subject, $html, $headers );
                if ( $result ) $sent = true;
            }
        }
        update_option( self::OPT_LAST_SENT, current_time( 'mysql' ) );
        return $sent;
    }

    /* === AJAX for preview + manual send === */

    public static function ajax_preview() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error();
        $days = max( 1, min( 30, (int) ( $_POST['days'] ?? 7 ) ) );
        $data = self::generate_report( $days );
        $html = self::render_html( $data );
        wp_send_json_success( [ 'html' => $html ] );
    }

    public static function ajax_send_now() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error();
        $instance = new self();
        $result = $instance->send( 7 );
        if ( $result ) {
            wp_send_json_success( 'Отчёт отправлен получателям.' );
        }
        wp_send_json_error( 'Не удалось отправить. Проверьте WP mail() и настройки.' );
    }

    public static function ajax_download_html() {
        check_ajax_referer( 'rls_settings_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Access denied' );
        $days = isset( $_GET['days'] ) ? max( 1, min( 30, (int) $_GET['days'] ) ) : 7;
        $data = self::generate_report( $days );
        $html = self::render_html( $data );
        nocache_headers();
        header( 'Content-Type: text/html; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="security-report-' . gmdate( 'Ymd-His' ) . '.html"' );
        echo $html; // phpcs:ignore WordPress.Security.EscapeOutput
        exit;
    }
}
