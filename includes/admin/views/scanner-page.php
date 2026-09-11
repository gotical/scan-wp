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
$license_ui = function_exists( 'rls_get_license_ui_state' ) ? rls_get_license_ui_state() : [];
$mode_ui = function_exists( 'rls_get_protection_mode_ui_state' ) ? rls_get_protection_mode_ui_state() : [];

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
        <span style="font-size: 13px; color: <?php echo esc_attr( $license_ui['badge_color'] ?? '#333333' ); ?>; font-weight:600; background:<?php echo esc_attr( $license_ui['badge_background'] ?? '#e5e5e5' ); ?>; padding:2px 8px; border-radius:999px; margin-left:8px; vertical-align:middle;"><?php echo esc_html( $license_ui['headline'] ?? 'Бесплатная версия' ); ?></span>
        <span style="font-size: 13px; color: <?php echo esc_attr( $mode_ui['badge_color'] ?? '#ffffff' ); ?>; font-weight:600; background:<?php echo esc_attr( $mode_ui['badge_background'] ?? '#198754' ); ?>; padding:2px 8px; border-radius:999px; margin-left:8px; vertical-align:middle;"><?php echo esc_html( $mode_ui['short_label'] ?? 'Полная' ); ?></span>
    </h1>

    <?php if ( ! empty( $mode_ui['warning_text'] ) ) : ?>
        <div class="notice notice-warning" style="margin:12px 0 16px; padding:10px 12px;">
            <p style="margin:0;"><strong><?php echo esc_html( $mode_ui['label'] ?? 'Защита отключена' ); ?>:</strong> <?php echo esc_html( $mode_ui['warning_text'] ); ?></p>
        </div>
    <?php endif; ?>

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
                                Быстрое сканирование проверяет PHP и JS на типичные угрозы.
                                Полное сканирование дольше, но проходит по всем файлам, включая изображения и неизвестные расширения.
                            </p>
                        </div>
                        <div class="rls-header-actions rls-scan-controls" style="display:flex; gap:10px; flex-wrap:wrap;">
                            <button id="rls-start-scan-button" class="button button-primary button-hero">
                                Начать сканирование
                            </button>
                            <button id="rls-start-full-scan-button" class="button button-secondary button-hero" type="button" title="Проверить все расширения, включая изображения и неизвестные типы файлов">
                                Полное сканирование
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
                        
                        <div class="rls-header-actions rls-scan-controls" style="display:flex; gap:10px; flex-wrap:wrap;">
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
                
                <!-- ВКЛАДКА 3: КАРАНТИН -->
                <div id="quarantine" class="rls-tab-panel">
                    <h3>☣️ Карантин (Изолированные файлы)</h3>
                    <p class="description">Файлы перемещены в безопасную папку и переименованы. Они не могут нанести вред сайту.</p>

                    <?php if ( empty( $quarantined_files ) ) : ?>
                        <div class="rls-empty-state">
                            <img src="<?php echo esc_url( plugin_dir_url( RLS_PLUGIN_FILE ) . 'assets/images/shield-empty.svg' ); ?>" alt="Пусто" width="180" />
                            <h3>Карантин пуст</h3>
                            <p>Все чисто — ни один файл не был помещён в карантин.</p>
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

                <!-- ВКЛАДКА 4: ИСТОРИЯ + DIFF -->
                <div id="scan-history" class="rls-tab-panel">
                    <p class="description">Журнал последних 20 проверок системы (Ручные и Автоматические).</p>

                    <!-- Diff between scans -->
                    <div class="rls-diff-controls">
                        <select id="rls-diff-scan-a" class="regular-text" style="max-width:280px;">
                            <option value="">— Скан A —</option>
                            <?php foreach ( $scan_history as $entry ) : ?>
                                <option value="<?php echo (int) $entry['id']; ?>">
                                    #<?php echo (int) $entry['id']; ?> — <?php echo esc_html( date_i18n( 'd.m.Y H:i', strtotime( $entry['scan_date'] ) ) ); ?>
                                    (<?php echo (int) $entry['threats_count']; ?> угроз)
                                </option>
                            <?php endforeach; ?>
                        </select>
                        <select id="rls-diff-scan-b" class="regular-text" style="max-width:280px;">
                            <option value="">— Скан B —</option>
                            <?php foreach ( $scan_history as $entry ) : ?>
                                <option value="<?php echo (int) $entry['id']; ?>">
                                    #<?php echo (int) $entry['id']; ?> — <?php echo esc_html( date_i18n( 'd.m.Y H:i', strtotime( $entry['scan_date'] ) ) ); ?>
                                    (<?php echo (int) $entry['threats_count']; ?> угроз)
                                </option>
                            <?php endforeach; ?>
                        </select>
                        <button type="button" class="button" id="rls-run-diff">Сравнить</button>
                    </div>
                    <div id="rls-diff-result" style="display:none;"></div>

                    <!-- Export buttons -->
                    <div style="margin-top:14px; display:flex; gap:8px; flex-wrap:wrap;">
                        <?php if ( ! empty( $scan_history ) ) :
                            $latest_id = (int) $scan_history[0]['id'];
                            ?>
                            <a class="button button-secondary" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-ajax.php?action=rls_export_scan&format=json&scan_id=' . $latest_id ), 'rls_settings_nonce', 'nonce' ) ); ?>" target="_blank">
                                📥 Экспорт последнего скана (JSON)
                            </a>
                            <a class="button button-secondary" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-ajax.php?action=rls_export_scan&format=csv&scan_id=' . $latest_id ), 'rls_settings_nonce', 'nonce' ) ); ?>" target="_blank">
                                📊 Экспорт (CSV)
                            </a>
                        <?php endif; ?>
                        <button type="button" class="button button-secondary" id="rls-run-db-scan">🗄 Сканировать БД</button>
                        <button type="button" class="button button-secondary" id="rls-run-checksums-scan">🔍 Проверить WP.org checksums</button>
                        <?php if ( ! empty( $scan_history[0]['scan_details'] ) ) : ?>
                            <button type="button" class="button button-primary" id="rls-auto-quarantine" style="margin-left:auto;">🚨 Auto-quarantine critical</button>
                        <?php endif; ?>
                    </div>

                    <hr style="margin: 18px 0;">

                    <?php if ( empty( $scan_history ) ) : ?>
                        <div class="rls-empty-state">
                            <img src="<?php echo esc_url( plugin_dir_url( RLS_PLUGIN_FILE ) . 'assets/images/scan-empty.svg' ); ?>" alt="Нет истории" width="180" />
                            <h3>История сканирований пуста</h3>
                            <p>Запустите первое сканирование, чтобы увидеть результаты здесь.</p>
                        </div>
                    <?php else : ?>

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
                    <?php endif; ?>
                </div>

                <!-- ОБЛАСТЬ ПРОГРЕССА + REAL-TIME -->
                <div class="rls-scan-progress-area" style="display:none; margin-top:20px; padding:18px; background:#f9f9f9; border:1px solid #ddd; border-radius:5px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                        <div style="display:flex; align-items:center; gap:10px;">
                            <span class="spinner is-active" style="float:none; margin:0;"></span>
                            <strong id="rls-scan-status-title">Выполняется сканирование…</strong>
                        </div>
                        <div>
                            <span style="font-size:12px; color:#666;">ETA:</span>
                            <strong id="rls-scan-eta">--:--</strong>
                        </div>
                    </div>
                    <div class="rls-scan-progress-bar">
                        <div class="rls-scan-progress-fill" id="rls-scan-progress-fill"></div>
                    </div>
                    <div class="rls-scan-stats-grid">
                        <div class="rls-scan-stat">
                            <span class="rls-scan-stat__num" id="rls-scan-stat-total">0</span>
                            <span class="rls-scan-stat__label">Всего</span>
                        </div>
                        <div class="rls-scan-stat">
                            <span class="rls-scan-stat__num" id="rls-scan-stat-scanned">0</span>
                            <span class="rls-scan-stat__label">Проверено</span>
                        </div>
                        <div class="rls-scan-stat">
                            <span class="rls-scan-stat__num" id="rls-scan-stat-skipped">0</span>
                            <span class="rls-scan-stat__label">Пропущено</span>
                        </div>
                        <div class="rls-scan-stat">
                            <span class="rls-scan-stat__num" id="rls-scan-stat-threats" style="color: var(--rls-danger);">0</span>
                            <span class="rls-scan-stat__label">Угроз</span>
                        </div>
                    </div>
                    <div class="rls-scan-current-file" id="rls-scan-current-file">
                        Ожидание…
                    </div>
                </div>

                <!-- THREAT DETAILS MODAL -->
                <div id="rls-threat-modal" style="display:none; position:fixed; inset:0; background:rgba(15,23,42,0.6); backdrop-filter:blur(4px); z-index:100000; align-items:center; justify-content:center;">
                    <div style="background:#fff; border-radius:14px; width:90%; max-width:640px; max-height:85vh; overflow:hidden; display:flex; flex-direction:column; box-shadow:0 25px 50px rgba(0,0,0,0.3);">
                        <div style="padding:18px 24px; border-bottom:1px solid var(--rls-border); display:flex; justify-content:space-between; align-items:center;">
                            <h2 style="margin:0;">Детали угрозы</h2>
                            <button type="button" class="button" id="rls-threat-modal-close">Закрыть</button>
                        </div>
                        <div style="padding:24px; overflow-y:auto;" class="rls-modal-body"></div>
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
