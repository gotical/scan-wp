<?php
/**
 * HTML-шаблон для страницы сканера с вкладками и новой таблицей результатов.
 * Автор: Усачёв Денис (https://rybinsklab.ru)
 */

if (!defined('WPINC')) die;

// Получаем информацию о последнем снимке для кнопки "Сравнить"
$snapshot_time = get_option('rls_snapshot_time', 0);
?>

<div class="wrap rls-wrap">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

    <div class="rls-container">
        <div class="rls-main-content">
            <div class="rls-box">
                <!-- ВКЛАДКИ ДЛЯ ПЕРЕКЛЮЧЕНИЯ РЕЖИМОВ -->
                <div class="nav-tab-wrapper">
                    <a href="#malware-scanner" class="nav-tab nav-tab-active" data-tab="malware-scanner">Сканер вирусов</a>
                    <a href="#snapshot-scanner" class="nav-tab" data-tab="snapshot-scanner">Сканер изменений (Снимки)</a>
                </div>

                <!-- ПАНЕЛЬ СКАНЕРА ВИРУСОВ -->
                <div id="malware-scanner" class="rls-tab-panel active">
                    <p>Плагин просканирует все файлы вашего сайта на наличие вредоносного кода на основе вирусных сигнатур.</p>
                    <div class="rls-scan-controls">
                        <button id="rls-start-scan-button" class="button button-primary button-hero">Начать сканирование вирусов</button>
                    </div>
                </div>

                <!-- ПАНЕЛЬ СКАНЕРА ИЗМЕНЕНИЙ -->
                <div id="snapshot-scanner" class="rls-tab-panel">
                    <p>Создайте "снимок" текущего состояния файлов, чтобы позже сравнить и выявить новые, измененные или удаленные файлы.</p>
                     <div class="snapshot-info">
                        <?php if ($snapshot_time): ?>
                            Последний снимок создан: <strong><?php echo date_i18n('d.m.Y в H:i', $snapshot_time); ?></strong>
                        <?php else: ?>
                            Снимок еще не создан.
                        <?php endif; ?>
                    </div>
                    <div class="rls-scan-controls">
                        <button id="rls-create-snapshot-button" class="button button-secondary">Создать / Обновить снимок</button>
                        <button id="rls-compare-snapshot-button" class="button button-primary" <?php disabled(!$snapshot_time); ?>>Сравнить со снимком</button>
                    </div>
                </div>

                <!-- ОБЩИЕ ЭЛЕМЕНТЫ УПРАВЛЕНИЯ И ОТОБРАЖЕНИЯ -->
                <div class="rls-scan-progress-area">
                    <span class="spinner"></span>
                    <div id="rls-scan-progress-container">
                        <div id="rls-scan-progress-bar">0%</div>
                    </div>
                    <div id="rls-scan-status">Готов к работе...</div>
                </div>
            </div>

            <!-- БЛОК ДЛЯ ВЫВОДА РЕЗУЛЬТАТОВ -->
            <div id="rls-scan-results" class="rls-box">
                <h3 class="results-title">Результаты</h3>
                <div id="rls-results-content">
                    <p>Здесь появятся результаты после завершения сканирования.</p>
                </div>
            </div>
        </div>
        
        <div class="rls-sidebar">
             <div class="rls-box author-box">
                <h3>Автор плагина</h3>
                <p><strong>Усачёв Денис</strong></p>
                <p>Благодарим за использование нашего плагина для защиты вашего сайта.</p>
                <a href="https://rybinsklab.ru/scan-wp/" target="_blank" class="button-secondary">Страница плагина</a>
                <?php if (get_option('rls_license_status') !== 'valid'): ?>
                    <a href="<?php echo admin_url('admin.php?page=rls-settings'); ?>" class="button-primary">Получить авто-обновления</a>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>