<?php
/**
 * Класс RLS_Dashboard_Widget
 * Создает виджет со статистикой безопасности на главной странице консоли WordPress.
 * Автор: Усачёв Денис (https://rybinsklab.ru)
 */

// Прямой доступ запрещен
if (!defined('WPINC')) {
    die;
}

class RLS_Dashboard_Widget {

    /**
     * Инициализатор. Регистрирует хук для добавления виджета.
     */
    public function init() {
        add_action('wp_dashboard_setup', [$this, 'register_widget']);
    }
    
    /**
     * Регистрирует наш виджет в системе WordPress.
     */
    public function register_widget() {
        if (current_user_can('manage_options')) {
            wp_add_dashboard_widget(
                'rls_security_dashboard_widget',
                'Статистика Rybinsk Lab Security',
                [$this, 'render_widget_content']
            );
        }
    }
    
    /**
     * Отображает HTML-содержимое виджета.
     */
    public function render_widget_content() {
        $stats = get_option('rls_stats', []);
        $firewall_blocked = $stats['firewall_blocked'] ?? 0;
        
        $last_scan_results = get_option('rls_last_scan_results', []);
        $viruses_found = count($last_scan_results);
        $last_scan_time = get_option('rls_last_scan_time');
        
        ?>
        <div class="rls-widget">
            <div class="stat-item">
                <span class="stat-number"><?php echo number_format_i18n($firewall_blocked); ?></span>
                <span class="stat-label">Атак отражено фаерволом</span>
            </div>
            <div class="stat-item <?php echo $viruses_found > 0 ? 'has-threats' : 'is-clean'; ?>">
                <span class="stat-number"><?php echo number_format_i18n($viruses_found); ?></span>
                <span class="stat-label">Угроз найдено при последнем сканировании</span>
            </div>
            <hr>
            <div class="last-scan-info">
                <?php if ($last_scan_time): ?>
                    <p>Последняя проверка: <strong><?php echo date_i18n('d.m.Y в H:i', $last_scan_time); ?></strong></p>
                <?php else: ?>
                    <p>Сканирование еще не проводилось.</p>
                <?php endif; ?>
            </div>
            <div class="widget-footer">
                <a href="<?php echo admin_url('admin.php?page=rls-scanner'); ?>" class="button button-primary">Перейти к сканеру</a>
                <p class="author-info">Автор плагина: <a href="https://rybinsklab.ru" target="_blank">Усачёв Денис</a></p>
            </div>
        </div>
        <style>
            .rls-widget .stat-item { text-align: center; padding: 10px; }
            .rls-widget .stat-number { display: block; font-size: 2.5em; font-weight: bold; line-height: 1.1; }
            .rls-widget .stat-label { color: #777; }
            .rls-widget .stat-item.is-clean .stat-number { color: #46b450; }
            .rls-widget .stat-item.has-threats .stat-number { color: #dc3232; }
            .rls-widget .last-scan-info { text-align: center; color: #555; }
            .rls-widget .widget-footer { text-align: center; margin-top: 15px; border-top: 1px solid #eee; padding-top: 15px;}
            .rls-widget .author-info { margin-top: 10px; font-size: 0.9em; color: #999; }
        </style>
        <?php
    }
}