/**
 * JavaScript для управления двухфазным процессом сканирования и "умным обезвреживанием".
 * Финальная версия.
 * Автор: Усачёв Денис (https://rybinsklab.ru)
 */
jQuery(function($) {
    // --- Элементы UI ---
    const startScanBtn = $('#rls-start-scan-button'),
          createSnapshotBtn = $('#rls-create-snapshot-button'),
          compareSnapshotBtn = $('#rls-compare-snapshot-button'),
          progressBarContainer = $('#rls-scan-progress-container'),
          progressBar = $('#rls-scan-progress-bar'),
          statusText = $('#rls-scan-status'),
          resultsContainer = $('#rls-results-content'),
          spinner = $('.rls-scan-progress-area .spinner');
    
    // --- Переменные состояния ---
    let totalFiles = 0, processedFiles = 0, foundThreats = [], snapshotData = {}, 
        comparisonChanges = { added: [], modified: [], deleted: [] },
        isWorking = false, currentProcess = null;

    // --- Логика вкладок ---
    $('.nav-tab-wrapper .nav-tab').on('click', function(e) {
        e.preventDefault(); if (isWorking) return;
        $('.nav-tab-wrapper .nav-tab').removeClass('nav-tab-active');
        $(this).addClass('nav-tab-active');
        $('.rls-tab-panel').hide();
        $('#' + $(this).data('tab')).show();
        resultsContainer.html('<p>Здесь появятся результаты после завершения сканирования.</p>');
    });

    // --- Обработчики кнопок ---
    startScanBtn.on('click', function() { if (!isWorking) { currentProcess = 'malware'; startFileDiscovery(); } });
    createSnapshotBtn.on('click', function() { if (!isWorking) { currentProcess = 'snapshot'; startFileDiscovery(); } });
    compareSnapshotBtn.on('click', function() { if (!isWorking) { currentProcess = 'compare'; startFileDiscovery(); } });

    // --- ОБРАБОТЧИК КНОПКИ "ОБЕЗВРЕДИТЬ" ---
    resultsContainer.on('click', '.rls-neutralize-button', function() {
        const button = $(this), row = button.closest('tr'), filepath = row.data('filepath'), signature = row.data('signature'), statusCell = row.find('.status-cell');
        button.prop('disabled', true);
        statusCell.html('<span class="spinner is-active" style="float:none; vertical-align:middle;"></span> Проверка...');

        $.post(rls_scanner_data.ajax_url, { action: 'rls_neutralize_file', nonce: rls_scanner_data.nonce, filepath: filepath, signature: signature })
        .done(res => {
            if (res.success) {
                switch(res.data.result) {
                    case 'whitelisted':
                        row.addClass('is-clean');
                        statusCell.html('<span class="status-whitelisted">Обезврежено (Файл ядра)</span>');
                        button.remove();
                        break;
                    case 'ai_legitimate':
                        row.addClass('is-clean');
                        statusCell.html('<span class="status-ai-legitimate">Безопасен (Проверено AI)</span>');
                        button.remove();
                        break;
                    case 'ai_virus':
                        row.addClass('is-danger');
                        statusCell.html(`<span class="status-ai-virus">Вирус (AI)</span>`);
                        button.remove();
                        row.after(`<tr><td colspan="4"><div class="virus-snippet"><pre>${escapeHtml(res.data.snippet)}</pre></div></td></tr>`);
                        break;
                }
            } else {
                statusCell.html(`<span style="color:red;">Ошибка</span>`);
                alert('Ошибка: ' + (res.data || 'Неизвестная ошибка.'));
                button.prop('disabled', false);
            }
        })
        .fail(() => {
            statusCell.html(`<span style="color:red;">Ошибка сервера</span>`);
            button.prop('disabled', false);
        });
    });

    // --- ФАЗА 1: ПОИСК ФАЙЛОВ ---
    function startFileDiscovery() { isWorking = true; updateUI('discovery_start'); $.post(rls_scanner_data.ajax_url, { action: 'rls_start_file_discovery', nonce: rls_scanner_data.nonce }).done(res => res.success ? discoverFilesStep() : updateUI('error', res.data)).fail(() => updateUI('error', 'Ошибка сервера при запуске поиска.')); }
    function discoverFilesStep() { $.post(rls_scanner_data.ajax_url, { action: 'rls_discover_files_step', nonce: rls_scanner_data.nonce }).done(res => { if (res.success) { updateUI('discovering', res.data); if (!res.data.done) { discoverFilesStep(); } else { totalFiles = res.data.files_found; startPhase2(); } } else { updateUI('error', res.data); } }).fail(() => updateUI('error', 'Ошибка сервера на шаге поиска.')); }

    // --- ФАЗА 2: ВЫПОЛНЕНИЕ ЗАДАЧИ ---
    function startPhase2() { processedFiles = 0; if (totalFiles === 0) { finalizeProcess(); return; } switch(currentProcess) { case 'malware': foundThreats = []; performScanStep(); break; case 'snapshot': snapshotData = {}; createSnapshotStep(); break; case 'compare': comparisonChanges = { added: [], modified: [], deleted: [] }; compareSnapshotStep(); break; } }
    function performScanStep() { if (processedFiles >= totalFiles) { finalizeProcess(); return; } $.post(rls_scanner_data.ajax_url, { action: 'rls_perform_scan_step', nonce: rls_scanner_data.nonce, offset: processedFiles }).done(res => { if (res.success) { processedFiles += res.data.scanned_count; if (res.data.found_threats.length > 0) foundThreats = foundThreats.concat(res.data.found_threats); updateUI('working'); performScanStep(); } else { updateUI('error', res.data); } }).fail(() => updateUI('error', 'Ошибка шага сканирования.')); }
    function createSnapshotStep() { if (processedFiles >= totalFiles) { finalizeProcess(); return; } $.post(rls_scanner_data.ajax_url, { action: 'rls_create_snapshot_step', nonce: rls_scanner_data.nonce, offset: processedFiles }).done(res => { if (res.success) { processedFiles += res.data.processed_count; $.extend(snapshotData, res.data.snapshot_part); updateUI('working'); createSnapshotStep(); } else { updateUI('error', res.data); } }).fail(() => updateUI('error', 'Ошибка шага создания снимка.')); }
    function compareSnapshotStep() { if (processedFiles >= totalFiles) { finalizeProcess(); return; } $.post(rls_scanner_data.ajax_url, { action: 'rls_compare_snapshot_step', nonce: rls_scanner_data.nonce, offset: processedFiles }).done(res => { if (res.success) { processedFiles += res.data.processed_count; if(res.data.changes.added.length > 0) comparisonChanges.added = comparisonChanges.added.concat(res.data.changes.added); if(res.data.changes.modified.length > 0) comparisonChanges.modified = comparisonChanges.modified.concat(res.data.changes.modified); updateUI('working'); compareSnapshotStep(); } else { updateUI('error', res.data); } }).fail(() => updateUI('error', 'Ошибка шага сравнения.')); }
    function finalizeProcess() { let finalAction, finalData = {}; switch(currentProcess) { case 'malware': finalAction = 'rls_finalize_scan'; finalData = { threats: JSON.stringify(foundThreats) }; break; case 'snapshot': finalAction = 'rls_finalize_snapshot'; finalData = { snapshot: JSON.stringify(snapshotData) }; break; case 'compare': finalAction = 'rls_finalize_comparison'; finalData = { changes: JSON.stringify(comparisonChanges) }; break; } finalData.action = finalAction; finalData.nonce = rls_scanner_data.nonce; $.post(rls_scanner_data.ajax_url, finalData).done(res => res.success ? updateUI('finish', res.data) : updateUI('error', res.data)).fail(() => updateUI('error', 'Ошибка при завершении.')); }

    // --- Управление UI ---
    function updateUI(state, data = {}) { let percentage = 0; $('.rls-scan-controls button').prop('disabled', true); spinner.css('visibility', 'visible'); switch(state) { case 'discovery_start': progressBarContainer.show(); progressBar.css('width', '0%').text('0%'); statusText.text('Фаза 1: Поиск файлов...'); resultsContainer.html('<p>Процесс запущен, собираем список файлов для анализа...</p>'); break; case 'discovering': percentage = Math.min(10, Math.round((data.files_found / (data.files_found + data.dirs_left * 10)) * 10)); progressBar.css('width', percentage + '%').text(percentage + '%'); statusText.text(`Поиск... Найдено: ${data.files_found}. Директория: ${data.last_dir}`); break; case 'working': percentage = Math.min(100, 10 + Math.round((processedFiles / totalFiles) * 90)); progressBar.css('width', percentage + '%').text(percentage + '%'); let actionText = (currentProcess === 'malware') ? 'Сканирование...' : (currentProcess === 'snapshot') ? 'Создание снимка...' : 'Сравнение...'; statusText.text(`Фаза 2: ${actionText} (${processedFiles} / ${totalFiles})`); break; case 'finish': isWorking = false; $('.rls-scan-controls button').prop('disabled', false); rls_scanner_data.snapshot_exists = (currentProcess === 'snapshot' || rls_scanner_data.snapshot_exists); compareSnapshotBtn.prop('disabled', !rls_scanner_data.snapshot_exists); spinner.css('visibility', 'hidden'); progressBar.css('width', '100%').text('Завершено'); statusText.text('Процесс успешно завершен.'); displayResults(data); break; case 'error': isWorking = false; $('.rls-scan-controls button').prop('disabled', false); compareSnapshotBtn.prop('disabled', !rls_scanner_data.snapshot_exists); spinner.css('visibility', 'hidden'); progressBarContainer.hide(); statusText.html(`<strong style="color:red;">Ошибка:</strong> ${data}`); break; } }
    
    function escapeHtml(text) { if(typeof text !== 'string') return ''; return $('<div>').text(text).html(); }

    function displayResults(msg) {
        let html = '';
        if (currentProcess === 'malware') {
            if (foundThreats.length === 0) { html = '<p class="rls-results-clean"><strong>Подозрительных файлов не найдено!</strong></p>'; } else {
                html = `<p><strong>Обнаружено угроз: ${foundThreats.length}</strong></p><table class="wp-list-table widefat striped"><thead><tr><th style="width:50%;">Файл</th><th style="width:25%;">Обнаруженная сигнатура</th><th style="width:15%;">Статус</th><th style="width:10%;">Действие</th></tr></thead><tbody>`;
                foundThreats.forEach(threat => { const fileHtml = escapeHtml(threat.file); const sigHtml = escapeHtml(threat.signature); html += `<tr data-filepath="${fileHtml}" data-signature="${sigHtml}"><td class="filepath"><code>${fileHtml}</code></td><td><code>${sigHtml}</code></td><td class="status-cell">Подозрительный</td><td class="action-cell"><button class="button-secondary rls-neutralize-button">Обезвредить</button></td></tr>`; });
                html += '</tbody></table>';
            }
        } else if (currentProcess === 'snapshot') {
            html = `<p class="rls-results-clean"><strong>Снимок успешно создан/обновлен.</strong> Найдено ${totalFiles} файлов.</p>`;
        } else if (currentProcess === 'compare') {
            const { added, modified, deleted } = comparisonChanges; const allChanges = (added?.length || 0) + (modified?.length || 0) + (deleted?.length || 0);
            if (allChanges === 0) { html = '<p class="rls-results-clean"><strong>Изменений не найдено. Файлы соответствуют снимку.</strong></p>'; } else {
                html = `<p><strong>Обнаружено изменений: ${allChanges}</strong></p><ul>`;
                (added || []).forEach(f => html += `<li class="added"><i class="bi bi-plus-circle-fill"></i> ${escapeHtml(f)}</li>`);
                (modified || []).forEach(f => html += `<li class="modified"><i class="bi bi-exclamation-triangle-fill"></i> ${escapeHtml(f)}</li>`);
                (deleted || []).forEach(f => html += `<li class="deleted"><i class="bi bi-trash-fill"></i> ${escapeHtml(f)}</li>`);
                html += '</ul>';
            }
        }
        resultsContainer.html(html);
    }
});