<?php
/**
 * Виджет консоли WordPress.
 * Версия 2.3.0
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class RLS_Dashboard_Widget {

    public function init() {
        add_action( 'wp_dashboard_setup', [ $this, 'register_widget' ] );
    }
    
    public function register_widget() {
        if ( current_user_can( 'manage_options' ) ) {
            wp_add_dashboard_widget(
                'rls_security_dashboard_widget',
                'Rybinsk Lab Security',
                [ $this, 'render_widget_content' ]
            );
        }
    }
    
    public function render_widget_content() {
        $stats = get_option( 'rls_stats', [] );

        $firewall = intval( $stats['firewall_blocked'] ?? 0 );
        $login    = intval( $stats['login_attempts_blocked'] ?? 0 );
        $viruses  = intval( $stats['viruses_found'] ?? 0 );
        $total    = $firewall + $login;

        $license_ui = function_exists( 'rls_get_license_ui_state' ) ? rls_get_license_ui_state() : [];
        $mode_ui = function_exists( 'rls_get_protection_mode_ui_state' ) ? rls_get_protection_mode_ui_state() : [];
        $is_prem = ! empty( $license_ui['is_premium'] );
        $mode_background = $mode_ui['badge_background'] ?? '#198754';
        $mode_color = $mode_ui['badge_color'] ?? '#ffffff';
        $mode_short = $mode_ui['short_label'] ?? 'Полная';
        $protection_is_enabled = empty( $mode_ui['mode'] ) || $mode_ui['mode'] !== 'scanner_only';
        $status_color = $protection_is_enabled ? '#16a34a' : '#dc2626';
        $status_text = $protection_is_enabled ? 'Защита активна' : 'Защита отключена';

        // Security score (0..100) based on enabled features.
        $score = $this->calculate_security_score();
        $score_color = $score >= 80 ? '#16a34a' : ( $score >= 50 ? '#d97706' : '#dc2626' );
        ?>
        <div class="rls-widget-container">
            <div class="rls-header" style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                <span style="color: <?php echo esc_attr( $status_color ); ?>; font-weight:600;">
                    <span class="dashicons dashicons-shield-alt"></span> <?php echo esc_html( $status_text ); ?>
                </span>
                <div style="display:flex; gap:6px;">
                    <span class="rls-badge-log <?php echo $is_prem ? 'green' : 'gray'; ?>">
                        <?php echo esc_html( $license_ui['badge_text'] ?? ( $is_prem ? 'PREMIUM' : 'FREE' ) ); ?>
                    </span>
                    <span class="rls-badge-log blue">
                        <?php echo esc_html( $mode_short ); ?>
                    </span>
                </div>
            </div>

            <div class="rls-score-card">
                <div class="rls-score-ring" style="background: conic-gradient(<?php echo esc_attr( $score_color ); ?> <?php echo $score * 3.6; ?>deg, #e4e8ef 0deg);">
                    <span><?php echo intval( $score ); ?></span>
                </div>
                <div class="rls-score-info">
                    <h3>Security Score</h3>
                    <p>
                        <?php if ( $score >= 80 ) : ?>
                            <span class="rls-status-pill is-on">Отличный уровень</span>
                        <?php elseif ( $score >= 50 ) : ?>
                            <span class="rls-status-pill is-warn">Требуется внимание</span>
                        <?php else : ?>
                            <span class="rls-status-pill is-err">Критические пробелы</span>
                        <?php endif; ?>
                    </p>
                    <p style="margin:0; font-size:12px;"><a href="<?php echo admin_url( 'admin.php?page=rls-hardening' ); ?>">Улучшить →</a></p>
                </div>
            </div>

            <div class="rls-widget-grid">
                <div class="rls-widget-tile is-ok">
                    <div class="rls-widget-num"><?php echo number_format_i18n( $total ); ?></div>
                    <div class="rls-widget-label">Атак отражено</div>
                </div>
                <div class="rls-widget-tile <?php echo $viruses > 0 ? 'is-err' : 'is-ok'; ?>">
                    <div class="rls-widget-num"><?php echo number_format_i18n( $viruses ); ?></div>
                    <div class="rls-widget-label">Вирусов</div>
                </div>
                <div class="rls-widget-tile">
                    <div class="rls-widget-num"><?php echo intval( $stats['ai_requests'] ?? 0 ); ?></div>
                    <div class="rls-widget-label">AI-проверок</div>
                </div>
            </div>

            <div style="border-top:1px solid var(--rls-border); padding-top:10px; margin-top:8px; font-size:12px; display:flex; justify-content:space-between; gap:8px; flex-wrap:wrap;">
                <a href="<?php echo admin_url('admin.php?page=rls-settings&tab=tab-logs'); ?>">Журнал атак</a>
                <a href="<?php echo admin_url('admin.php?page=rls-hardening'); ?>">Hardening</a>
                <a href="<?php echo admin_url('admin.php?page=rls-2fa'); ?>">2FA</a>
                <a href="<?php echo admin_url('admin.php?page=rls-settings'); ?>">Настройки</a>
            </div>
        </div>
        <?php
    }

    /**
     * Lightweight security score (0..100) based on enabled features.
     */
    private function calculate_security_score() {
        $score = 0;
        $settings = get_option( 'rls_settings', [] );
        if ( ! is_array( $settings ) ) $settings = [];

        // WAF (25 pts)
        if ( ! empty( $settings['enable_firewall'] ) ) $score += 25;
        // Hardening (20 pts)
        if ( ! empty( $settings['hardening_enabled'] ) ) $score += 20;
        // Login security (15 pts)
        if ( ! empty( $settings['enable_login_security'] ) ) $score += 15;
        // 2FA (15 pts)
        if ( ! empty( $settings['2fa_required_admin'] ) ) $score += 15;
        // SSL verify API (10 pts)
        if ( ! empty( $settings['ssl_verify_api'] ) ) $score += 10;
        // GeoIP (5 pts)
        if ( ! empty( $settings['geo_blocking_enabled'] ) ) $score += 5;
        // Captcha (5 pts)
        if ( ! empty( $settings['captcha_enabled_admin'] ) || ! empty( $settings['captcha_enabled_users'] ) ) $score += 5;
        // Hotlink (5 pts bonus)
        if ( ! empty( $settings['hotlink_protection'] ) ) $score += 5;

        return min( 100, max( 0, $score ) );
    }
}


