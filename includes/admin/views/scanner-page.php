<?php
/**
 * HTML-шаблон для страницы сканера.
 * Версия 1.6.0 (Complete with Quarantine Tab)
 *
 * @package RybinskLabSecurity
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

$snapshot_time = get_option( 'rls_snapshot_time', 0 );
$scan_history  = class_exists( 'RLS_Scan_History' ) ? RLS_Scan_History::get_history( 20 ) : [];

// Подгружаем данные карантина
$quarantined_files = [];
if(class_exists('RLS_Quarantine')) {
    $q_obj = new RLS_Quarantine();
    $quarantined_files = $q_obj->get_quarantined_files();
}
?>

<div class="wrap rls-wrap">
    <h1>
        <span class="dashicons dashicons-shield-alt" style="font-size:30px; width:30px; height:30px; color:#2271b1; vertical-align:middle;"></span> 
        Сканер Безопасности
    </h1>

    <div class="rls-container">
        <!-- Левая колонка (Основной контент) -->
        <div class="rls-main-content">
            
            <div class="rls-box">
                <!-- Навигация по вкладкам -->
                <div class="nav-tab-wrapper">
                    <a href="#malware-scanner" class="nav-tab nav-tab-active" data-tab="malware-scanner">Вирусы</a>
                    <a href="#snapshot-scanner" class="nav-tab" data-tab="snapshot-scanner">Контроль изменений</a>
                    <a href="#quarantine" class="nav-tab" data-tab="quarantine">Карантин <?php if(count($quarantined_files) > 0) echo '<span class="update-plugins count-'.count($quarantined_files).'"><span class="plugin-count">'.count($quarantined_files).'</span></span>'; ?></a>
                    <a href="#scan-history" class="nav-tab" data-tab="scan-history">История</a>
                </div>

                <!-- ВКЛАДКА 1: СКАНИРОВАНИЕ НА ВИРУСЫ -->
                <div id="malware-scanner" class="rls-tab-panel active">
                    <div class="rls-header-row">
                        <div class="rls-header-desc">
                            <h3><span class="dashicons dashicons-search"></span> Поиск вредоносного кода</h3>
                            <p class="description">
                                Плагин просканирует файлы ядра, плагинов и тем на наличие шеллов, бэкдоров и известных сигнатур вирусов.
                                Используется локальная база + Premium облако (если активен ключ).
                            </p>
                        </div>
                        <div class="rls-header-actions">
                            <button id="rls-start-scan-button" class="button button-primary button-hero">
                                Начать сканирование
                            </button>
                        </div>
                    </div>
                </div>

                <!-- ВКЛАДКА 2: СНИМОК ФАЙЛОВОЙ СИСТЕМЫ -->
                <div id="snapshot-scanner" class="rls-tab-panel">
                    <div class="rls-header-row">
                        <div class="rls-header-desc">
                            <h3><span class="dashicons dashicons-camera"></span> Снимок файловой системы</h3>
                            <p class="description">
                                Создайте эталонный снимок (Snapshot) ваших файлов. Это позволяет отслеживать любые изменения: 
                                новые файлы, измененные или удаленные. Идеально для обнаружения скрытых вирусов.
                            </p>
                            
                            <div class="rls-snapshot-status <?php echo $snapshot_time ? 'exists' : 'empty'; ?>">
                                <?php if ( $snapshot_time ): ?>
                                    <span class="dashicons dashicons-yes"></span> 
                                    Последний снимок создан: <strong><?php echo date_i18n( 'd.m.Y H:i', $snapshot_time ); ?></strong>
                                <?php else: ?>
                                    <span class="dashicons dashicons-warning"></span> 
                                    Снимок еще не создан. Рекомендуется создать его прямо сейчас.
                                <?php endif; ?>
                            </div>
                        </div>
                        
                        <div class="rls-header-actions">
                            <?php if ( $snapshot_time ): ?>
                                <button id="rls-compare-snapshot-button" class="button button-primary button-hero">
                                    Сравнить файлы
                                </button>
                            <?php endif; ?>
                            
                            <button id="rls-create-snapshot-button" class="button <?php echo $snapshot_time ? 'button-secondary' : 'button-primary button-hero'; ?>">
                                <?php echo $snapshot_time ? 'Обновить снимок' : 'Создать снимок'; ?>
                            </button>
                        </div>
                    </div>
                </div>
                
                <!-- ВКЛАДКА 3: КАРАНТИН (НОВОЕ) -->
                <div id="quarantine" class="rls-tab-panel">
                    <h3>☣️ Карантин (Изолированные файлы)</h3>
                    <p class="description">Файлы перемещены в безопасную папку и переименованы. Они не могут нанести вред сайту.</p>
                    
                    <?php if ( empty( $quarantined_files ) ) : ?>
                        <div class="rls-results-clean" style="padding:20px; background:#f0f6fc; border:1px solid #cce5ff; border-radius:5px; color:#004085; text-align:center;">
                            <span class="dashicons dashicons-shield" style="font-size:40px; width:40px; height:40px; display:block; margin:0 auto 10px;"></span> 
                            <strong>Карантин пуст.</strong><br>Все чисто.
                        </div>
                    <?php else : ?>
                        <table class="wp-list-table widefat fixed striped">
                            <thead>
                                <tr>
                                    <th>Оригинальный путь</th>
                                    <th>Имя файла</th>
                                    <th>Дата изоляции</th>
                                    <th>Действия</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ( $quarantined_files as $id => $file ) : ?>
                                    <tr id="q-row-<?php echo esc_attr($id); ?>">
                                        <td><code><?php echo esc_html( $file['original_path'] ); ?></code></td>
                                        <td><?php echo esc_html( $file['filename'] ); ?></td>
                                        <td><?php echo esc_html( $file['quarantined_at'] ); ?></td>
                                        <td>
                                            <button class="button button-primary rls-restore-btn" data-id="<?php echo esc_attr($id); ?>">Восстановить</button>
                                            <button class="button button-link-delete rls-delete-q-btn" data-id="<?php echo esc_attr($id); ?>">Удалить навсегда</button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>

                <!-- ВКЛАДКА 4: ИСТОРИЯ -->
                <div id="scan-history" class="rls-tab-panel">
                    <p class="description">Журнал последних 20 проверок системы (Ручные и Автоматические).</p>
                    
                    <table class="wp-list-table widefat fixed striped table-view-list">
                        <thead>
                            <tr>
                                <th style="width: 25%;">Дата</th>
                                <th style="width: 15%;">Тип</th>
                                <th style="width: 20%;">Статус</th>
                                <th>Результат</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if ( empty( $scan_history ) ) : ?>
                                <tr>
                                    <td colspan="4">История проверок пуста.</td>
                                </tr>
                            <?php else : foreach ( $scan_history as $entry ) : 
                                $is_infected = ( $entry['scan_status'] === 'infected' );
                                $status_text = $is_infected ? 'УГРОЗА' : 'ЧИСТО';
                                $type_label  = ( $entry['scan_type'] === 'auto' ) ? 'Авто (Cron)' : 'Ручной';
                            ?>
                                <tr>
                                    <td>
                                        <?php echo date_i18n( 'd.m.Y H:i', strtotime( $entry['scan_date'] ) ); ?>
                                    </td>
                                    <td>
                                        <?php echo esc_html( $type_label ); ?>
                                    </td>
                                    <td>
                                        <?php if ( $is_infected ): ?>
                                            <span class="rls-badge red" style="background:#dc3545; color:#fff; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:11px;">УГРОЗА</span>
                                        <?php else: ?>
                                            <span class="rls-badge green" style="background:#46b450; color:#fff; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:11px;">ЧИСТО</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php 
                                        if ( $is_infected ) {
                                            echo 'Найдено файлов: <strong>' . intval( $entry['threats_count'] ) . '</strong>';
                                        } else {
                                            echo 'Угроз не обнаружено.';
                                        }
                                        
                                        if ( ! empty( $entry['duration'] ) ) {
                                            echo ' <span class="description" style="font-size:11px;">(' . intval( $entry['duration'] ) . ' сек)</span>';
                                        }
                                        ?>
                                    </td>
                                </tr>
                            <?php endforeach; endif; ?>
                        </tbody>
                    </table>
                </div>

                <!-- ОБЛАСТЬ ПРОГРЕССА (СКРЫТА ПО УМОЛЧАНИЮ) -->
                <div class="rls-scan-progress-area" style="display:none; margin-top:20px; padding:15px; background:#f9f9f9; border:1px solid #ddd; border-radius:5px;">
                    <div style="display:flex; justify-content:space-between; margin-bottom:5px;">
                        <div style="display:flex; align-items:center; gap:10px;">
                            <span class="spinner is-active" style="float:none; margin:0;"></span>
                            <strong id="rls-scan-status-title">Выполняется операция...</strong>
                        </div>
                        <div id="rls-scan-status">0 / 0</div>
                    </div>
                    <div id="rls-scan-progress-container" style="background-color:#e0e0e0; border-radius:10px; overflow:hidden; height: 20px; width: 100%;">
                        <div id="rls-scan-progress-bar" style="width:0; height:100%; background-color:#2271b1; text-align:center; line-height:20px; color:#fff; font-size: 11px; transition:width 0.2s ease;"></div>
                    </div>
                </div>
            </div>

            <!-- БЛОК РЕЗУЛЬТАТОВ -->
            <div id="rls-scan-results" class="rls-box">
                <h3 class="results-title" style="margin-top:0; border-bottom:1px solid #eee; padding-bottom:10px;">Результаты операции</h3>
                <div id="rls-results-content">
                    <!-- Сюда JS вставит результаты -->
                    <div class="rls-empty-state" style="text-align:center; padding:40px 20px; color:#a0a5aa;">
                        <span class="dashicons dashicons-search" style="font-size:40px; width:40px; height:40px; margin-bottom:10px;"></span>
                        <p>Нажмите кнопку запуска, чтобы увидеть результаты здесь.</p>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Правая колонка (Сайдбар) -->
        <div class="rls-sidebar">
             <div class="rls-box author-box">
                <h3>Rybinsk Lab Security</h3>
                <p>Версия: <strong><?php echo RLS_VERSION; ?></strong></p>
                <hr>
                <p class="description">Регулярно обновляйте снимок системы после установки новых плагинов или обновлений WordPress, чтобы избежать ложных срабатываний.</p>
                <p>
                    <a href="https://rybinsklab.ru/scan-wp/" target="_blank" class="button button-secondary" style="width:100%; text-align:center;">
                        Документация и Поддержка
                    </a>
                </p>
            </div>
        </div>
    </div>
</div>