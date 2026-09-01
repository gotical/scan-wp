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
        $status_color = $protection_is_enabled ? '#46b450' : '#d63638';
        $status_text = $protection_is_enabled ? 'Защита активна' : 'Защита отключена';
        
        ?>
        <div class="rls-widget-container">
            <div class="rls-header" style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                <span class="rls-status" style="color: <?php echo esc_attr( $status_color ); ?>; font-weight:600;">
                    <span class="dashicons dashicons-shield-alt"></span> <?php echo esc_html( $status_text ); ?>
                </span>
                <span class="rls-badge" style="background:<?php echo esc_attr( $license_ui['badge_background'] ?? ( $is_prem ? '#f0ad4e' : '#e5e5e5' ) ); ?>; color:<?php echo esc_attr( $license_ui['badge_color'] ?? ( $is_prem ? '#fff' : '#333' ) ); ?>; padding:2px 6px; border-radius:4px; font-size:10px; text-transform:uppercase;">
                    <?php echo esc_html( $license_ui['badge_text'] ?? ( $is_prem ? 'PREMIUM' : 'FREE' ) ); ?>
                </span>
                <span class="rls-badge" style="background:<?php echo esc_attr( $mode_background ); ?>; color:<?php echo esc_attr( $mode_color ); ?>; padding:2px 6px; border-radius:4px; font-size:10px;">
                    <?php echo esc_html( $mode_short ); ?>
                </span>
            </div>

            <div style="margin:0 0 12px; padding:10px 12px; background:#f6f7f7; border:1px solid #dcdcde; border-radius:6px;">
                <?php if ( ! empty( $mode_ui['status_text'] ) ) : ?>
                    <div style="font-weight:600; color:#1d2327; margin-bottom:6px;">
                        <?php echo esc_html( $mode_ui['status_text'] ); ?>
                    </div>
                <?php endif; ?>
                <div style="font-weight:600; color:#1d2327;">
                    <?php echo esc_html( $license_ui['status_text'] ?? 'Бесплатная версия активна' ); ?>
                </div>
                <?php if ( ! empty( $license_ui['remaining_text'] ) ) : ?>
                    <div style="margin-top:4px; color:#2271b1;">
                        <?php echo esc_html( $license_ui['remaining_text'] ); ?>
                    </div>
                <?php endif; ?>
                <?php if ( ! empty( $license_ui['expires_text'] ) ) : ?>
                    <div style="margin-top:4px; color:#50575e;">
                        <?php echo esc_html( $license_ui['expires_text'] ); ?>
                    </div>
                <?php endif; ?>
                <?php if ( ! empty( $license_ui['domains_text'] ) ) : ?>
                    <div style="margin-top:4px; color:#50575e;">
                        <?php echo esc_html( $license_ui['domains_text'] ); ?>
                    </div>
                <?php endif; ?>
            </div>

            <div class="rls-stats-grid" style="display:flex; gap:10px; margin:15px 0;">
                <div class="rls-stat-box" style="flex:1; text-align:center; padding:10px; background:#f8f9fa; border:1px solid #ddd; border-radius:4px;">
                    <div style="font-size:20px; font-weight:bold; color:#2271b1;"><?php echo number_format_i18n($total); ?></div>
                    <div style="font-size:11px; color:#666;">Атак отражено</div>
                </div>
                <div class="rls-stat-box" style="flex:1; text-align:center; padding:10px; background:<?php echo $viruses>0 ? '#fbeaea' : '#f8f9fa'; ?>; border:1px solid <?php echo $viruses>0 ? '#dc3545' : '#ddd'; ?>; border-radius:4px;">
                    <div style="font-size:20px; font-weight:bold; color:<?php echo $viruses>0 ? '#dc3545' : '#46b450'; ?>;"><?php echo number_format_i18n($viruses); ?></div>
                    <div style="font-size:11px; color:#666;">Вирусов</div>
                </div>
            </div>

            <div class="rls-footer" style="border-top:1px solid #eee; padding-top:10px; font-size:12px; display:flex; justify-content:space-between;">
                <a href="<?php echo admin_url('admin.php?page=rls-settings#tab-logs'); ?>">Журнал атак</a>
                <a href="<?php echo admin_url('admin.php?page=rls-settings'); ?>">Настройки</a>
            </div>
        </div>
        <?php
    }
}


