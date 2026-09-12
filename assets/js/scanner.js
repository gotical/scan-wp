/**
 * JavaScript для Сканера (Rybinsk Lab Security).
 * Версия: 1.6.1 (Complete: Scan + AI + Quarantine + Full Scan)
 */

jQuery(function($) {
    
// Элементы UI
    const startScanBtn        = $('#rls-start-scan-button');
    const fullScanBtn         = $('#rls-start-full-scan-button');
    const createSnapshotBtn   = $('#rls-create-snapshot-button');
    const compareSnapshotBtn  = $('#rls-compare-snapshot-button');
    const progressBarArea     = $('#rls-scan-progress-area');
    const progressFill        = $('#rls-scan-progress-fill');
    const progressStatTotal   = $('#rls-scan-stat-total');
    const progressStatScanned = $('#rls-scan-stat-scanned');
    const progressStatSkipped = $('#rls-scan-stat-skipped');
    const progressStatThreats = $('#rls-scan-stat-threats');
    const progressEta         = $('#rls-scan-eta');
    const progressCurrent     = $('#rls-scan-current-file');
    const progressPctEl       = $('#rls-scan-progress-pct');
    const statusText          = $('#rls-scan-status');
    const statusTitle         = $('#rls-scan-status-title');
    const resultsContainer    = $('#rls-results-content');
    const spinner             = $('.rls-scan-progress-area .spinner');
    const consoleEl           = $('#rls-scan-console');

    // Переменные состояния
    let totalFiles = 0;
    let processedFiles = 0;
    let foundThreats = [];
    let snapshotData = {}; 
    let comparisonChanges = { added: [], modified: [], deleted: [] };
    
let isWorking = false;
    let currentProcess = null;
    let currentScanMode = 'important';
    let scanStartedAt = 0;
    let retryCount = 0;

    // --- TABS (Вкладки) ---
    $('.nav-tab-wrapper .nav-tab').on('click', function(e) {
        e.preventDefault();
        
        if (isWorking) {
            alert('Пожалуйста, дождитесь завершения текущего процесса.');
            return;
        }

        // Переключение классов
        $('.nav-tab-wrapper .nav-tab').removeClass('nav-tab-active');
        $(this).addClass('nav-tab-active');
        
        // Переключение видимости блоков
        const targetTab = $(this).data('tab');
        $('.rls-tab-panel').hide();
        $('#' + targetTab).show();

        // Если перешли не на историю и не на карантин, очищаем результаты (визуально)
        if (targetTab !== 'scan-history' && targetTab !== 'quarantine') {
             resultsContainer.html('<div class="rls-empty-state" style="text-align:center; padding:40px 20px; color:#a0a5aa;"><span class="dashicons dashicons-search" style="font-size:40px; width:40px; height:40px; margin-bottom:10px;"></span><p>Нажмите кнопку запуска, чтобы увидеть результаты здесь.</p></div>');
             progressBarArea.hide();
        }
    });

    // --- ОБРАБОТЧИКИ КНОПОК ---
    startScanBtn.on('click', function() { 
        if (!isWorking) { currentProcess = 'malware'; currentScanMode = 'important'; startProcess(); } 
    });

    fullScanBtn.on('click', function() { 
        if (!isWorking) { currentProcess = 'malware'; currentScanMode = 'full'; startProcess(); } 
    });

    createSnapshotBtn.on('click', function() { 
        if (!isWorking) { currentProcess = 'snapshot'; currentScanMode = 'important'; startProcess(); } 
    });

    compareSnapshotBtn.on('click', function() { 
        if (!isWorking) { currentProcess = 'compare'; currentScanMode = 'important'; startProcess(); } 
    });

    // --- ЛОГИКА ПРОЦЕССА ---

    function startProcess() { 
        isWorking = true;
        scanStartedAt = Date.now();
        retryCount = 0;
        updateUI('discovery_start'); 
        
        // Сброс данных
        foundThreats = [];
        snapshotData = {};
        comparisonChanges = { added: [], modified: [], deleted: [] };
        
        ajaxCall('rls_start_file_discovery', { mode: currentScanMode }, function(res) {
            if (res.success) {
                // Небольшая задержка перед стартом цикла
                setTimeout(discoverFilesStep, 500); 
            } else {
                updateUI('error', res.data);
            }
        });
    }

    function discoverFilesStep() { 
        if (!isWorking) return; 

        ajaxCall('rls_discover_files_step', {}, function(res) {
            if (res.success) { 
                updateUI('discovering', res.data); 
                
                if (!res.data.done) { 
                    // Рекурсия
                    setTimeout(discoverFilesStep, 100); 
                } else { 
                    totalFiles = res.data.files_found; 
                    setTimeout(startPhase2, 500); 
                } 
            } else { 
                updateUI('error', res.data); 
            } 
        });
    }

    function startPhase2() { 
        processedFiles = 0; 
        
        if (totalFiles === 0) { 
            finalizeProcess(); 
            return; 
        } 
        
        nextStep();
    }

    function nextStep() {
        if (!isWorking) return;
        if (processedFiles >= totalFiles) { finalizeProcess(); return; }

        let action = '';
        if(currentProcess === 'malware') action = 'rls_perform_scan_step';
        else if(currentProcess === 'snapshot') action = 'rls_create_snapshot_step';
        else action = 'rls_compare_snapshot_step';

        ajaxCall(action, { offset: processedFiles }, function(res) {
            if (res.success) {
                // Обновляем прогресс
                let count = res.data.processed_count || res.data.scanned_count || 0;
                if (count === 0) count = 1;
                processedFiles += count;

                // Сколько пропущено (большие файлы).
                if (res.data.skipped) {
                    cumulativeSkipped = (cumulativeSkipped || 0) + res.data.skipped;
                }

                // Текущий файл — для консоли.
                if (res.data.last_file) {
                    currentScanningFile = res.data.last_file;
                }

                // Собираем данные
                if(currentProcess==='malware' && res.data.found_threats) {
                    foundThreats = foundThreats.concat(res.data.found_threats);
                    if (res.data.found_threats.length > 0) {
                        res.data.found_threats.forEach(t => {
                            const name = (t.file || '').split('/').pop();
                            logConsole('⚠ Угроза', name + ': ' + (t.rule_name || t.signature || '?'), 'warning');
                        });
                    }
                }
                if(currentProcess==='snapshot' && res.data.snapshot_part) {
                    $.extend(snapshotData, res.data.snapshot_part);
                }
                if(currentProcess==='compare' && res.data.changes) {
                    if(res.data.changes.added) comparisonChanges.added = comparisonChanges.added.concat(res.data.changes.added);
                    if(res.data.changes.modified) comparisonChanges.modified = comparisonChanges.modified.concat(res.data.changes.modified);
                }

                updateUI('working');

                // Следующий шаг
                setTimeout(nextStep, 50);
            } else {
                updateUI('error', res.data); 
            } 
        });
    }

    function finalizeProcess() { 
        let action = '', data = {}; 
        
        if(currentProcess === 'malware') { 
            action = 'rls_finalize_scan'; 
            data.threats = JSON.stringify(foundThreats); 
        }
        else if(currentProcess === 'snapshot') { 
            action = 'rls_finalize_snapshot'; 
            data.snapshot = JSON.stringify(snapshotData); 
        }
        else { 
            action = 'rls_finalize_comparison'; 
            data.changes = JSON.stringify(comparisonChanges); 
        }
        
        ajaxCall(action, data, function(res) {
            if (res.success) {
                updateUI('finish', res.data); 
            } else {
                updateUI('error', res.data);
            }
        });
    }

    // --- HELPER: AJAX WITH RETRY ---
    function ajaxCall(action, data, successCallback) {
        data.action = action;
        data.nonce = rls_scanner_data.nonce;

        function normalizeJsonResponse(payload) {
            if (typeof payload === 'string') {
                // Убираем UTF BOM / zero-width chars, которые ломают JSON.parse в некоторых окружениях.
                const cleaned = payload.replace(/^[\uFEFF\u200B\u200C\u200D]+/, '').trim();
                return JSON.parse(cleaned);
            }
            return payload;
        }
        
        $.ajax({
            url: rls_scanner_data.ajax_url,
            type: 'POST',
            data: data,
            dataType: 'text',
            timeout: 120000, // 2 минуты тайм-аут (достаточно для большинства хостингов)
            success: function(response) {
                retryCount = 0; // Сброс счетчика ошибок при успехе
                try {
                    successCallback(normalizeJsonResponse(response));
                } catch (e) {
                    updateUI('error', 'Некорректный формат ответа сервера.');
                }
            },
            error: function(xhr, status, error) {
                if (status === 'abort') return; // Игнорируем ручную отмену

                // Частый кейс: parsererror из-за BOM, но JSON в responseText валидный.
                if (status === 'parsererror' && xhr && xhr.responseText) {
                    try {
                        const recovered = normalizeJsonResponse(xhr.responseText);
                        retryCount = 0;
                        successCallback(recovered);
                        return;
                    } catch (e) {}
                }
                
                // Если ошибка сети или тайм-аут, пробуем снова
                if (retryCount < 5) { 
                    retryCount++;
                    let details = '';
                    if (xhr && xhr.status) {
                        details = ` (HTTP ${xhr.status})`;
                    } else if (status) {
                        details = ` (${status})`;
                    }
                    statusText.text(`Сбой сети${details}. Повтор ${retryCount}/5...`);
                    
                    setTimeout(function() { 
                        ajaxCall(action, data, successCallback); 
                    }, 3000);
                } else {
                    const responseHint = (xhr && xhr.responseText) ? String(xhr.responseText).substring(0, 200) : '';
                    updateUI('error', `Сервер не отвечает (${status}). ${responseHint}`);
                }
            }
        });
    }

    // --- UI UPDATER ---
    function updateUI(state, data = {}) { 
        $('.rls-scan-controls button').prop('disabled', true); 
        progressBarArea.show();
        spinner.css('visibility', 'visible'); 
        
        switch(state) { 
case 'discovery_start':
                progressFill.css('width', '0%');
                if (progressPctEl) progressPctEl.text('0%');
                if (progressStatTotal) progressStatTotal.text('0');
                if (progressStatScanned) progressStatScanned.text('0');
                if (progressStatSkipped) progressStatSkipped.text('0');
                if (progressStatThreats) progressStatThreats.text('0');
                if (progressEta) progressEta.text('--:--');
                if (progressCurrent) progressCurrent.text('Ожидание…');
                clearConsole();
                statusTitle.text(currentProcess === 'malware' && currentScanMode === 'full' ? 'Полное сканирование...' : 'Индексация файлов...');
                statusText.text('Подготовка...');
                resultsContainer.html('<div class="rls-empty-state" style="text-align:center; padding:40px 20px; color:#a0a5aa;"><span class="spinner is-active" style="float:none;"></span><p>Составляем список файлов...</p></div>');
                break;

            case 'discovering':
                let est = data.files_found + (data.dirs_left * 10);
                // Показываем до 15% прогресса на этапе поиска
                let pct = Math.min(15, Math.round((data.files_found / (est || 1)) * 15));
                progressFill.css('width', pct + '%');
                if (progressPctEl) progressPctEl.text(pct + '%');
                statusText.text(`Найдено: ${data.files_found} файлов`);
                logConsole('Индексация', 'Найдено файлов: ' + data.files_found);
                break;

            case 'working':
                // Прогресс от 15% до 99%
                let wpct = 0;
                if (totalFiles > 0) {
                    wpct = 15 + Math.round((processedFiles / totalFiles) * 84);
                } else {
                    wpct = 99;
                }
                wpct = Math.min(99, Math.max(15, wpct));

                progressFill.css('width', wpct + '%');
                if (progressPctEl) progressPctEl.text(wpct + '%');

                let actionName = 'Обработка';
                if (currentProcess === 'malware') actionName = (currentScanMode === 'full') ? 'Полное сканирование' : 'Поиск вирусов';
                if (currentProcess === 'snapshot') actionName = 'Создание снимка';
                if (currentProcess === 'compare') actionName = 'Сравнение';

                statusTitle.text(actionName + '...');
                statusText.text(`${processedFiles} / ${totalFiles}`);

                if (progressStatTotal) progressStatTotal.text(totalFiles);
                if (progressStatScanned) progressStatScanned.text(processedFiles);
                if (progressStatSkipped) progressStatSkipped.text(data.skipped || 0);
                if (progressStatThreats) progressStatThreats.text(foundThreats.length);

                // Console log with rate limiting (every ~5%).
                if (consoleEl && consoleEl.length && (processedFiles % 25 === 0 || processedFiles === totalFiles)) {
                    const lastFile = (data.last_file || '').replace(/\/var\/www\/html\/wp-content\//, '.../');
                    const logType = foundThreats.length > 0 ? 'warning' : 'info';
                    logConsole(
                        actionName,
                        'Проверено ' + processedFiles + ' / ' + totalFiles +
                        (lastFile ? ' · ' + lastFile : ''),
                        logType
                    );
                }

                // ETA.
                if (progressEta && processedFiles > 0) {
                    const elapsed = (Date.now() - scanStartedAt) / 1000;
                    const perFile = elapsed / processedFiles;
                    const remaining = Math.max(0, totalFiles - processedFiles);
                    const etaSec = Math.round(perFile * remaining);
                    const mm = Math.floor(etaSec / 60);
                    const ss = etaSec % 60;
                    progressEta.text(mm + ':' + String(ss).padStart(2, '0'));
                }
                break;

            case 'finish':
                isWorking = false;
                $('.rls-scan-controls button').prop('disabled', false);

                if (currentProcess === 'snapshot') {
                    rls_scanner_data.snapshot_exists = true;
                }
                compareSnapshotBtn.prop('disabled', !rls_scanner_data.snapshot_exists);

                spinner.css('visibility', 'hidden');
                progressFill.css('width', '100%');
                if (progressPctEl) progressPctEl.text('100%');
                statusTitle.text('Завершено успешно');
                statusText.text('Готово');
                logConsole('Готово', 'Сканирование завершено успешно');

                displayResults(data);
                break;

            case 'error':
                isWorking = false;
                $('.rls-scan-controls button').prop('disabled', false);
                compareSnapshotBtn.prop('disabled', !rls_scanner_data.snapshot_exists);

                spinner.css('visibility', 'hidden');
                progressFill.css('background', '#dc2626');
                statusTitle.html('<span style="color:#dc2626;">⚠ Ошибка!</span>');
                statusText.text('Остановлено');
                logConsole('Ошибка', data, 'error');
                resultsContainer.html('<div class="rls-notice is-danger" style="margin-top:14px;"><p><strong>Произошла ошибка:</strong> ' + data + '</p><p>Попробуйте обновить страницу и запустить снова.</p></div>');
                break;
        } 
    }

    function logConsole( level, message, type ) {
        if ( ! consoleEl || ! consoleEl.length ) return;
        type = type || 'info';
        const ts = new Date().toLocaleTimeString();
        const li = $('<div class="rls-console-line rls-console-' + type + '">' +
            '<span class="rls-console-ts">[' + ts + ']</span>' +
            '<span class="rls-console-level">' + level + '</span>' +
            '<span class="rls-console-msg">' + esc(message) + '</span>' +
        '</div>');
        consoleEl.append(li);
        consoleEl.scrollTop( consoleEl[0].scrollHeight );
    }

    function clearConsole() {
        if ( consoleEl && consoleEl.length ) consoleEl.empty();
    }

    function displayResults(msg) {
        
        if (currentProcess === 'malware') {
            if (foundThreats.length === 0) { 
                html = '<div class="rls-results-clean" style="padding:20px; background:#e7f7e8; border:1px solid #c3e6cb; border-radius:5px; color:#155724; text-align:center;"><span class="dashicons dashicons-yes-alt" style="font-size:40px; width:40px; height:40px; color:#46b450; display:block; margin:0 auto 10px;"></span> <strong>Чисто!</strong><br>Вредоносного кода не найдено.</div>'; 
            } else {
                html = `<div class="rls-alert-danger" style="padding:10px; background:#fbeaea; border-left:4px solid #dc3545; margin-bottom:15px;"><strong style="color:#d63638;">Найдено угроз: ${foundThreats.length}</strong></div>
                        <table class="wp-list-table widefat striped rls-scan-table">
                            <thead><tr><th>Файл</th><th>Сигнатура</th><th>Действие</th></tr></thead>
                            <tbody>`;
                
                foundThreats.forEach(t => { 
                    html += `<tr data-f="${esc(t.file)}" data-s="${esc(t.signature)}">
                                <td class="filepath"><code>${esc(t.file)}</code></td>
                                <td><span class="rls-badge red" style="background:#dc3545; color:#fff; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:11px;">ВИРУС</span> <span style="font-size:11px; color:#666;">${esc(t.signature)}</span></td>
                                <td class="action-cell">
                                    <button class="button button-small rls-neutralize-button">AI-анализ</button>
                                    <button class="button button-small rls-quarantine-button" style="color:#d63638; border-color:#d63638; margin-left:5px;">В карантин</button>
                                </td>
                             </tr>`; 
                });
                html += '</tbody></table>';
            }
            
        } else if (currentProcess === 'snapshot') {
            html = `<div class="rls-results-clean" style="padding:20px; background:#e7f7e8; border:1px solid #c3e6cb; border-radius:5px; color:#155724; text-align:center;"><span class="dashicons dashicons-camera" style="font-size:40px; width:40px; height:40px; color:#46b450; display:block; margin:0 auto 10px;"></span> <strong>Снимок успешно создан!</strong><br>Проиндексировано файлов: ${totalFiles}</div>`;
            
        } else if (currentProcess === 'compare') {
            const allChanges = (comparisonChanges.added?.length || 0) + (comparisonChanges.modified?.length || 0) + (comparisonChanges.deleted?.length || 0);
            
            if (allChanges === 0) { 
                html = `<div class="rls-results-clean" style="padding:20px; background:#e7f7e8; border:1px solid #c3e6cb; border-radius:5px; color:#155724; text-align:center;"><span class="dashicons dashicons-yes-alt" style="font-size:40px; width:40px; height:40px; color:#46b450; display:block; margin:0 auto 10px;"></span> <strong>Файлы не изменялись.</strong><br>Система соответствует эталонному снимку.</div>`; 
            } else {
                html = `<div class="rls-alert-warning" style="padding:10px; background:#fff8e5; border-left:4px solid #ffba00; margin-bottom:15px;"><strong>Обнаружено изменений: ${allChanges}</strong></div>
                        <table class="wp-list-table widefat striped rls-scan-table">
                            <thead><tr><th>Тип</th><th>Файл</th><th>Действие</th></tr></thead>
                            <tbody>`;
                
                (comparisonChanges.modified || []).forEach(f => {
                    html += `<tr data-f="${esc(f)}" data-s="">
                                <td><span class="rls-badge orange" style="background:#f0ad4e; color:#fff; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:11px;">ИЗМЕНЕН</span></td>
                                <td class="filepath"><code>${esc(f)}</code></td>
                                <td>
                                    <button class="button button-small rls-neutralize-button">Проверить (AI)</button>
                                    <button class="button button-small rls-quarantine-button" style="color:#d63638; border-color:#d63638; margin-left:5px;">В карантин</button>
                                </td>
                             </tr>`;
                });
                (comparisonChanges.added || []).forEach(f => {
                    html += `<tr data-f="${esc(f)}" data-s="">
                                <td><span class="rls-badge green" style="background:#46b450; color:#fff; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:11px;">НОВЫЙ</span></td>
                                <td class="filepath"><code>${esc(f)}</code></td>
                                <td>
                                    <button class="button button-small rls-neutralize-button">Проверить (AI)</button>
                                    <button class="button button-small rls-quarantine-button" style="color:#d63638; border-color:#d63638; margin-left:5px;">В карантин</button>
                                </td>
                             </tr>`;
                });
                (comparisonChanges.deleted || []).forEach(f => {
                    html += `<tr>
                                <td><span class="rls-badge red" style="background:#dc3545; color:#fff; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:11px;">УДАЛЕН</span></td>
                                <td class="filepath" colspan="2"><code>${esc(f)}</code></td>
                             </tr>`;
                });
                html += '</tbody></table>';
            }
        }
        
        resultsContainer.html(html);
    }

    // --- AI ANALYSIS BUTTON HANDLER ---
    resultsContainer.on('click', '.rls-neutralize-button', function() {
        const button = $(this);
        const row = button.closest('tr');
        const filepath = row.data('f');
        const signature = row.data('s');
        
        button.prop('disabled', true).html('<span class="spinner is-active" style="float:none; margin:0;"></span>');
        
        $.post(rls_scanner_data.ajax_url, { 
            action: 'rls_neutralize_file', 
            nonce: rls_scanner_data.nonce, 
            filepath: filepath, 
            signature: signature 
        })
        .done(function(res) {
            if (res.success) {
                if (res.data.result === 'whitelisted') {
                    row.css('background-color', '#f0f6fc');
                    button.replaceWith('<span style="color:green; font-weight:bold;"><span class="dashicons dashicons-shield"></span> Ядро WP (ОК)</span>');
                } else if (res.data.result === 'ai_legitimate') {
                    row.css('background-color', '#f0f6fc');
                    button.replaceWith('<span style="color:blue; font-weight:bold;"><span class="dashicons dashicons-yes"></span> Безопасен (AI)</span>');
                } else if (res.data.result === 'ai_virus') {
                    row.css('background-color', '#ffe6e6');
                    const actionCell = button.closest('.action-cell');
                    if (actionCell.length) {
                        actionCell.find('.rls-neutralize-button').remove();
                        if (!actionCell.find('.rls-ai-virus-label').length) {
                            actionCell.prepend('<span class="rls-ai-virus-label" style="color:red; font-weight:bold; margin-right:8px;">⚠️ ВИРУС (AI)</span>');
                        }
                    }
                    
                    if (res.data.snippet) {
                        row.after(`<tr><td colspan="3"><div class="rls-virus-snippet" style="background:#2c3338; color:#f0f0f1; padding:15px; border-radius:5px; margin-top:10px; font-size:11px; overflow-x:auto;"><strong>Фрагмент кода:</strong><pre>${esc(res.data.snippet)}</pre></div></td></tr>`);
                    }
                } else if (res.data.result === 'too_large') {
                    button.replaceWith('<span style="color:#666; font-size:12px;">Файл слишком велик для AI-анализа</span>');
                }
            } else {
                alert('Ошибка: ' + res.data);
                button.prop('disabled', false).text('Повторить');
            }
        })
        .fail(function() {
            alert('Ошибка сети.');
            button.prop('disabled', false).text('Повторить');
        });
    });

    // --- QUARANTINE BUTTON HANDLER ---
    resultsContainer.on('click', '.rls-quarantine-button', function() {
        const button = $(this);
        const row = button.closest('tr');
        const filepath = row.data('f');
        
        if(!confirm('Переместить файл в карантин? Он будет удален из текущей папки и перестанет работать.')) return;

        button.prop('disabled', true).text('Moving...');

        $.post(rls_scanner_data.ajax_url, {
            action: 'rls_quarantine_file',
            nonce: rls_scanner_data.nonce,
            filepath: filepath
        }, function(response) {
            if (response.success) {
                row.fadeOut().remove();
                // Можно добавить уведомление
            } else {
                alert('Error: ' + response.data);
                button.prop('disabled', false).text('В карантин');
            }
        });
    });

    // --- QUARANTINE RESTORE / DELETE (HANDLERS FOR TAB) ---
    // Эти кнопки находятся во вкладке Карантин
    $('.rls-restore-btn').click(function() {
        var btn = $(this);
        var id = btn.data('id');
        btn.prop('disabled', true);
        
        $.post(rls_scanner_data.ajax_url, { 
            action: 'rls_restore_file', 
            nonce: rls_scanner_data.nonce, 
            id: id 
        }, function(res) {
            if(res.success) { 
                alert(res.data.message); 
                $('#q-row-'+id).fadeOut(); 
            } else { 
                alert(res.data); 
                btn.prop('disabled', false);
            }
        });
    });

    $('.rls-delete-q-btn').click(function() {
        if(!confirm('Удалить файл безвозвратно?')) return;
        var btn = $(this);
        var id = btn.data('id');
        btn.prop('disabled', true);
        
        $.post(rls_scanner_data.ajax_url, { 
            action: 'rls_delete_quarantine', 
            nonce: rls_scanner_data.nonce, 
            id: id 
        }, function(res) {
            if(res.success) { 
                $('#q-row-'+id).fadeOut(); 
            } else {
                alert(res.data);
                btn.prop('disabled', false);
            }
        });
    });

    function esc(text) { 
        if(typeof text !== 'string') return ''; 
        return $('<div>').text(text).html(); 
    }
});


