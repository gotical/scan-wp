/**
 * JavaScript для СТРАНИЦЫ СКАНЕРА (Scanner Page).
 * Управляет вкладками, процессом сканирования, снимками и обезвреживанием.
 */
jQuery(function($) {
    
    // --- 1. Элементы интерфейса ---
    const startScanBtn = $('#rls-start-scan-button');
    const createSnapshotBtn = $('#rls-create-snapshot-button');
    const compareSnapshotBtn = $('#rls-compare-snapshot-button');
    
    const progressBarContainer = $('#rls-scan-progress-container');
    const progressBar = $('#rls-scan-progress-bar');
    const statusText = $('#rls-scan-status');
    const resultsContainer = $('#rls-results-content');
    const spinner = $('.rls-scan-progress-area .spinner');
    
    // --- 2. Переменные состояния ---
    let totalFiles = 0;
    let processedFiles = 0;
    let foundThreats = [];
    let snapshotData = {}; 
    let comparisonChanges = { added: [], modified: [], deleted: [] };
    
    let isWorking = false; // Флаг, идет ли процесс
    let currentProcess = null; // 'malware', 'snapshot', 'compare'

    // --- 3. Логика вкладок (Tabs) ---
    $('.nav-tab-wrapper .nav-tab').on('click', function(e) {
        e.preventDefault(); 
        
        // Если идет сканирование, не даем переключать
        if (isWorking) return;

        // Управление классами
        $('.nav-tab-wrapper .nav-tab').removeClass('nav-tab-active');
        $(this).addClass('nav-tab-active');

        // Переключение панелей
        const targetTab = $(this).data('tab');
        $('.rls-tab-panel').hide();
        $('#' + targetTab).show();

        // Очистка результатов при смене вкладки
        resultsContainer.html('<p>Здесь появятся результаты после завершения сканирования.</p>');
    });

    // --- 4. Обработчики кнопок запуска ---
    
    // Запуск сканера вирусов
    startScanBtn.on('click', function() { 
        if (!isWorking) { 
            currentProcess = 'malware'; 
            startFileDiscovery(); 
        } 
    });

    // Создание снимка
    createSnapshotBtn.on('click', function() { 
        if (!isWorking) { 
            currentProcess = 'snapshot'; 
            startFileDiscovery(); 
        } 
    });

    // Сравнение со снимком
    compareSnapshotBtn.on('click', function() { 
        if (!isWorking) { 
            currentProcess = 'compare'; 
            startFileDiscovery(); 
        } 
    });

    // --- 5. ФАЗА 1: ПОИСК ФАЙЛОВ (Discovery) ---
    function startFileDiscovery() { 
        isWorking = true; 
        updateUI('discovery_start'); 
        
        $.post(rls_scanner_data.ajax_url, { 
            action: 'rls_start_file_discovery', 
            nonce: rls_scanner_data.nonce 
        })
        .done(function(res) { 
            if (res.success) {
                discoverFilesStep(); 
            } else {
                updateUI('error', res.data);
            }
        })
        .fail(function() { updateUI('error', 'Ошибка сервера при запуске поиска.'); }); 
    }

    function discoverFilesStep() { 
        $.post(rls_scanner_data.ajax_url, { 
            action: 'rls_discover_files_step', 
            nonce: rls_scanner_data.nonce 
        })
        .done(function(res) { 
            if (res.success) { 
                updateUI('discovering', res.data); 
                
                if (!res.data.done) { 
                    // Продолжаем поиск
                    discoverFilesStep(); 
                } else { 
                    // Поиск завершен, переходим к фазе 2
                    totalFiles = res.data.files_found; 
                    startPhase2(); 
                } 
            } else { 
                updateUI('error', res.data); 
            } 
        })
        .fail(function() { updateUI('error', 'Ошибка сервера на шаге поиска.'); }); 
    }

    // --- 6. ФАЗА 2: ОБРАБОТКА (Scan / Snapshot / Compare) ---
    function startPhase2() { 
        processedFiles = 0; 
        
        if (totalFiles === 0) { 
            finalizeProcess(); 
            return; 
        } 
        
        switch(currentProcess) { 
            case 'malware': 
                foundThreats = []; 
                performScanStep(); 
                break; 
            case 'snapshot': 
                snapshotData = {}; 
                createSnapshotStep(); 
                break; 
            case 'compare': 
                comparisonChanges = { added: [], modified: [], deleted: [] }; 
                compareSnapshotStep(); 
                break; 
        } 
    }

    // Шаг сканирования на вирусы
    function performScanStep() { 
        if (processedFiles >= totalFiles) { finalizeProcess(); return; } 
        
        $.post(rls_scanner_data.ajax_url, { 
            action: 'rls_perform_scan_step', 
            nonce: rls_scanner_data.nonce, 
            offset: processedFiles 
        })
        .done(function(res) { 
            if (res.success) { 
                processedFiles += res.data.scanned_count; 
                if (res.data.found_threats.length > 0) {
                    foundThreats = foundThreats.concat(res.data.found_threats);
                }
                updateUI('working'); 
                performScanStep(); 
            } else { 
                updateUI('error', res.data); 
            } 
        })
        .fail(function() { updateUI('error', 'Ошибка шага сканирования.'); }); 
    }

    // Шаг создания снимка
    function createSnapshotStep() { 
        if (processedFiles >= totalFiles) { finalizeProcess(); return; } 
        
        $.post(rls_scanner_data.ajax_url, { 
            action: 'rls_create_snapshot_step', 
            nonce: rls_scanner_data.nonce, 
            offset: processedFiles 
        })
        .done(function(res) { 
            if (res.success) { 
                processedFiles += res.data.processed_count; 
                $.extend(snapshotData, res.data.snapshot_part); 
                updateUI('working'); 
                createSnapshotStep(); 
            } else { 
                updateUI('error', res.data); 
            } 
        })
        .fail(function() { updateUI('error', 'Ошибка шага создания снимка.'); }); 
    }

    // Шаг сравнения
    function compareSnapshotStep() { 
        if (processedFiles >= totalFiles) { finalizeProcess(); return; } 
        
        $.post(rls_scanner_data.ajax_url, { 
            action: 'rls_compare_snapshot_step', 
            nonce: rls_scanner_data.nonce, 
            offset: processedFiles 
        })
        .done(function(res) { 
            if (res.success) { 
                processedFiles += res.data.processed_count; 
                if(res.data.changes.added.length > 0) comparisonChanges.added = comparisonChanges.added.concat(res.data.changes.added); 
                if(res.data.changes.modified.length > 0) comparisonChanges.modified = comparisonChanges.modified.concat(res.data.changes.modified); 
                updateUI('working'); 
                compareSnapshotStep(); 
            } else { 
                updateUI('error', res.data); 
            } 
        })
        .fail(function() { updateUI('error', 'Ошибка шага сравнения.'); }); 
    }

    // --- 7. ЗАВЕРШЕНИЕ И ВЫВОД РЕЗУЛЬТАТОВ ---
    function finalizeProcess() { 
        let finalAction, finalData = {}; 
        
        switch(currentProcess) { 
            case 'malware': 
                finalAction = 'rls_finalize_scan'; 
                finalData = { threats: JSON.stringify(foundThreats) }; 
                break; 
            case 'snapshot': 
                finalAction = 'rls_finalize_snapshot'; 
                finalData = { snapshot: JSON.stringify(snapshotData) }; 
                break; 
            case 'compare': 
                finalAction = 'rls_finalize_comparison'; 
                finalData = { changes: JSON.stringify(comparisonChanges) }; 
                break; 
        } 
        
        finalData.action = finalAction; 
        finalData.nonce = rls_scanner_data.nonce; 
        
        $.post(rls_scanner_data.ajax_url, finalData)
        .done(function(res) { 
            if (res.success) {
                updateUI('finish', res.data); 
            } else {
                updateUI('error', res.data);
            }
        })
        .fail(function() { updateUI('error', 'Ошибка при завершении.'); }); 
    }

    // --- 8. ОБНОВЛЕНИЕ UI ---
    function updateUI(state, data = {}) { 
        let percentage = 0; 
        
        // Блокируем кнопки во время работы
        $('.rls-scan-controls button').prop('disabled', true); 
        spinner.css('visibility', 'visible'); 
        
        switch(state) { 
            case 'discovery_start': 
                progressBarContainer.show(); 
                progressBar.css('width', '0%').text('0%'); 
                statusText.text('Фаза 1: Поиск файлов...'); 
                resultsContainer.html('<p>Процесс запущен, собираем список файлов для анализа...</p>'); 
                break; 
            
            case 'discovering': 
                // Эвристический прогресс для поиска
                percentage = Math.min(10, Math.round((data.files_found / (data.files_found + data.dirs_left * 10)) * 10)); 
                progressBar.css('width', percentage + '%').text(percentage + '%'); 
                statusText.text(`Поиск... Найдено: ${data.files_found}. Директория: ${data.last_dir}`); 
                break; 
            
            case 'working': 
                // Реальный прогресс обработки
                if (totalFiles > 0) {
                    percentage = Math.min(100, 10 + Math.round((processedFiles / totalFiles) * 90)); 
                } else {
                    percentage = 100;
                }
                progressBar.css('width', percentage + '%').text(percentage + '%'); 
                
                let actionText = '';
                if (currentProcess === 'malware') actionText = 'Сканирование...';
                else if (currentProcess === 'snapshot') actionText = 'Создание снимка...';
                else actionText = 'Сравнение...';
                
                statusText.text(`Фаза 2: ${actionText} (${processedFiles} / ${totalFiles})`); 
                break; 
            
            case 'finish': 
                isWorking = false; 
                $('.rls-scan-controls button').prop('disabled', false); 
                
                // Обновляем состояние кнопки "Сравнить"
                rls_scanner_data.snapshot_exists = (currentProcess === 'snapshot' || rls_scanner_data.snapshot_exists); 
                compareSnapshotBtn.prop('disabled', !rls_scanner_data.snapshot_exists); 
                
                spinner.css('visibility', 'hidden'); 
                progressBar.css('width', '100%').text('Завершено'); 
                statusText.text('Процесс успешно завершен.'); 
                displayResults(data); 
                break; 
            
            case 'error': 
                isWorking = false; 
                $('.rls-scan-controls button').prop('disabled', false); 
                compareSnapshotBtn.prop('disabled', !rls_scanner_data.snapshot_exists); 
                spinner.css('visibility', 'hidden'); 
                progressBarContainer.hide(); 
                statusText.html(`<strong style="color:red;">Ошибка:</strong> ${data}`); 
                break; 
        } 
    }
    
    // Вспомогательная функция экранирования
    function escapeHtml(text) { 
        if(typeof text !== 'string') return ''; 
        return $('<div>').text(text).html(); 
    }

    // Вывод таблицы результатов
    function displayResults(msg) {
        let html = '';
        if (currentProcess === 'malware') {
            if (foundThreats.length === 0) { 
                html = '<p class="rls-results-clean" style="color:green; font-size:1.2em;"><strong><span class="dashicons dashicons-yes-alt"></span> Подозрительных файлов не найдено! Ваш сайт чист.</strong></p>'; 
            } else {
                html = `<p><strong>Обнаружено угроз: ${foundThreats.length}</strong></p>
                <table class="wp-list-table widefat striped">
                    <thead>
                        <tr>
                            <th style="width:50%;">Файл</th>
                            <th style="width:25%;">Обнаруженная сигнатура</th>
                            <th style="width:15%;">Статус</th>
                            <th style="width:10%;">Действие</th>
                        </tr>
                    </thead>
                    <tbody>`;
                
                foundThreats.forEach(threat => { 
                    const fileHtml = escapeHtml(threat.file); 
                    const sigHtml = escapeHtml(threat.signature); 
                    html += `
                    <tr data-filepath="${fileHtml}" data-signature="${sigHtml}">
                        <td class="filepath"><code>${fileHtml}</code></td>
                        <td><code>${sigHtml}</code></td>
                        <td class="status-cell" style="color: red; font-weight: bold;">Подозрительный</td>
                        <td class="action-cell"><button class="button-secondary rls-neutralize-button">Обезвредить (AI)</button></td>
                    </tr>`; 
                });
                html += '</tbody></table>';
            }
        } else if (currentProcess === 'snapshot') {
            html = `<p class="rls-results-clean"><strong>Снимок успешно создан/обновлен.</strong> Найдено ${totalFiles} файлов.</p>`;
        } else if (currentProcess === 'compare') {
            const { added, modified, deleted } = comparisonChanges; 
            const allChanges = (added?.length || 0) + (modified?.length || 0) + (deleted?.length || 0);
            
            if (allChanges === 0) { 
                html = '<p class="rls-results-clean"><strong>Изменений не найдено. Файлы соответствуют снимку.</strong></p>'; 
            } else {
                html = `<p><strong>Обнаружено изменений: ${allChanges}</strong></p><ul>`;
                (added || []).forEach(f => html += `<li class="added" style="color:green;"><span class="dashicons dashicons-plus"></span> Добавлен: ${escapeHtml(f)}</li>`);
                (modified || []).forEach(f => html += `<li class="modified" style="color:orange;"><span class="dashicons dashicons-edit"></span> Изменен: ${escapeHtml(f)}</li>`);
                (deleted || []).forEach(f => html += `<li class="deleted" style="color:red; text-decoration:line-through;"><span class="dashicons dashicons-trash"></span> Удален: ${escapeHtml(f)}</li>`);
                html += '</ul>';
            }
        }
        resultsContainer.html(html);
    }

    // --- 9. КНОПКА "ОБЕЗВРЕДИТЬ (AI)" ---
    resultsContainer.on('click', '.rls-neutralize-button', function() {
        const button = $(this);
        const row = button.closest('tr');
        const filepath = row.data('filepath');
        const signature = row.data('signature');
        const statusCell = row.find('.status-cell');
        
        button.prop('disabled', true);
        statusCell.html('<span class="spinner is-active" style="float:none; vertical-align:middle; visibility:visible;"></span> Проверка AI...');

        $.post(rls_scanner_data.ajax_url, { 
            action: 'rls_neutralize_file', 
            nonce: rls_scanner_data.nonce, 
            filepath: filepath, 
            signature: signature 
        })
        .done(function(res) {
            if (res.success) {
                switch(res.data.result) {
                    case 'whitelisted':
                        row.addClass('is-clean').css('background-color', '#e7f7e8');
                        statusCell.html('<span class="status-whitelisted" style="color:green;">Файл ядра (ОК)</span>');
                        button.remove();
                        break;
                    case 'ai_legitimate':
                        row.addClass('is-clean').css('background-color', '#e7f7e8');
                        statusCell.html('<span class="status-ai-legitimate" style="color:blue;">Безопасен (AI)</span>');
                        button.remove();
                        break;
                    case 'ai_virus':
                        row.addClass('is-danger').css('background-color', '#fbeaea');
                        statusCell.html('<span class="status-ai-virus" style="color:red;">Вирус (AI)</span>');
                        button.remove();
                        // Добавляем строку с кодом вируса
                        if (res.data.snippet) {
                            row.after(`<tr><td colspan="4"><div class="virus-snippet" style="background:#fff8e5; padding:10px; font-family:monospace; white-space:pre-wrap;">${escapeHtml(res.data.snippet)}</div></td></tr>`);
                        }
                        break;
                }
            } else {
                statusCell.html(`<span style="color:red;">Ошибка</span>`);
                alert('Ошибка: ' + (res.data || 'Неизвестная ошибка.'));
                button.prop('disabled', false);
            }
        })
        .fail(function() {
            statusCell.html(`<span style="color:red;">Сбой сети</span>`);
            button.prop('disabled', false);
        });
    });
});