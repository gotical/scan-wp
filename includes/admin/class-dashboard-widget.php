<?php
/**
 * Класс RLS_Dashboard_Widget
 * Создает виджет со статистикой безопасности на главной странице консоли WordPress.
 * Обновлено: Объединена статистика атак и улучшен дизайн.
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
                'Состояние защиты (Rybinsk Lab)',
                [$this, 'render_widget_content']
            );
        }
    }
    
    /**
     * Отображает HTML-содержимое виджета.
     */
    public function render_widget_content() {
        // Получаем статистику
        $stats = get_option('rls_stats', []);
        
        // 1. СУММИРУЕМ ВСЕ ТИПЫ АТАК
        $firewall_blocked = intval($stats['firewall_blocked'] ?? 0);
        $bad_bots = intval($stats['bad_bots_blocked'] ?? 0);
        $login_attempts = intval($stats['login_attempts_blocked'] ?? 0);
        
        $total_attacks_blocked = $firewall_blocked + $bad_bots + $login_attempts;
        
        // 2. ПОЛУЧАЕМ ДАННЫЕ О ВИРУСАХ
        // Берем накопительный счетчик из stats, так как он обновляется при сканировании
        $viruses_found = intval($stats['viruses_found'] ?? 0);
        
        // Данные о последнем сканировании
        $last_scan_time = get_option('rls_last_scan_time');
        
        // Статус лицензии для галочки
        $license_status = get_option('rls_license_status');
        $status_color = ($license_status === 'valid') ? '#46b450' : '#f0ad4e';
        $status_text = ($license_status === 'valid') ? 'Премиум активен' : 'Базовая защита';
        ?>
        
        <div class="rls-widget-container">
            
            <!-- Верхняя панель статуса -->
            <div class="rls-header">
                <span class="rls-badge" style="background-color: <?php echo $status_color; ?>;">
                    <?php echo esc_html($status_text); ?>
                </span>
                <span class="rls-protection-status">
                    <span class="dashicons dashicons-shield-alt"></span> Мониторинг работает
                </span>
            </div>

            <!-- Сетка статистики -->
            <div class="rls-stats-grid">
                
                <!-- Блок 1: Атаки -->
                <div class="rls-stat-box">
                    <div class="rls-icon-wrap attack">
                        <span class="dashicons dashicons-shield"></span>
                    </div>
                    <div class="rls-stat-content">
                        <span class="rls-number"><?php echo number_format_i18n($total_attacks_blocked); ?></span>
                        <span class="rls-label">Отражено атак</span>
                        <div class="rls-tooltip">
                            WAF: <?php echo $firewall_blocked; ?>, Боты: <?php echo $bad_bots; ?>, Вход: <?php echo $login_attempts; ?>
                        </div>
                    </div>
                </div>

                <!-- Блок 2: Вирусы -->
                <div class="rls-stat-box <?php echo $viruses_found > 0 ? 'danger' : ''; ?>">
                    <div class="rls-icon-wrap virus">
                        <span class="dashicons dashicons-bug"></span>
                    </div>
                    <div class="rls-stat-content">
                        <span class="rls-number"><?php echo number_format_i18n($viruses_found); ?></span>
                        <span class="rls-label">Обнаружено угроз</span>
                    </div>
                </div>

            </div>

            <!-- Нижняя панель -->
            <div class="rls-footer">
                <div class="rls-scan-info">
                    <?php if ($last_scan_time): ?>
                        Последняя проверка: <strong><?php echo date_i18n('j F H:i', $last_scan_time); ?></strong>
                    <?php else: ?>
                        Проверка еще не выполнялась
                    <?php endif; ?>
                </div>
                <a href="<?php echo admin_url('admin.php?page=rls-scanner'); ?>" class="button button-primary rls-scan-btn">
                    Открыть сканер
                </a>
            </div>
        </div>

        <style>
            .rls-widget-container { margin-top: -10px; }
            
            /* Header */
            .rls-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid #eee; font-size: 12px; }
            .rls-badge { color: #fff; padding: 2px 8px; border-radius: 10px; font-weight: 600; font-size: 10px; text-transform: uppercase; }
            .rls-protection-status { color: #46b450; font-weight: 500; display: flex; align-items: center; gap: 4px; }
            
            /* Grid */
            .rls-stats-grid { display: flex; gap: 15px; margin-bottom: 20px; }
            .rls-stat-box { flex: 1; background: #f9f9f9; border: 1px solid #e5e5e5; border-radius: 6px; padding: 15px; display: flex; flex-direction: column; align-items: center; text-align: center; position: relative; transition: all 0.2s; }
            .rls-stat-box:hover { background: #fff; border-color: #ccc; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }
            .rls-stat-box.danger { background: #fff5f5; border-color: #ffccd5; }
            .rls-stat-box.danger .rls-number { color: #dc3232; }

            /* Icons & Numbers */
            .rls-icon-wrap { margin-bottom: 5px; }
            .rls-icon-wrap .dashicons { font-size: 24px; width: 24px; height: 24px; }
            .rls-icon-wrap.attack { color: #007bff; }
            .rls-icon-wrap.virus { color: #6c757d; }
            .rls-stat-box.danger .rls-icon-wrap.virus { color: #dc3232; }
            
            .rls-number { display: block; font-size: 28px; font-weight: 700; line-height: 1.2; color: #1d2327; }
            .rls-label { font-size: 12px; color: #646970; }
            
            /* Tooltip on hover */
            .rls-tooltip { display: none; position: absolute; bottom: -30px; left: 50%; transform: translateX(-50%); background: #333; color: #fff; padding: 4px 8px; border-radius: 4px; font-size: 10px; white-space: nowrap; z-index: 10; }
            .rls-stat-box:hover .rls-tooltip { display: block; }

            /* Footer */
            .rls-footer { display: flex; align-items: center; justify-content: space-between; font-size: 12px; color: #646970; }
            .rls-scan-btn { font-size: 12px !important; padding: 0 10px !important; height: 28px !important; line-height: 26px !important; }
        </style>
        <?php
    }
}