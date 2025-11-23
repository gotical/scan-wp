/**
 * JavaScript для СТРАНИЦЫ НАСТРОЕК (Settings Page).
 * Обрабатывает добавление/удаление вопросов, сигнатур и переключение опций.
 * 
 * Файл: assets/js/admin.js
 */
jQuery(function($) {
    
    // =======================================================
    // 1. ЛОГИКА ЗАЩИТЫ ВХОДА (Переключение видимости)
    // =======================================================
    const loginSecurityCheckbox = $('#rls_enable_login_security_cb');
    const loginQuestionsRows = $('.login-questions-settings-row');

    function toggleLoginSettings() {
        if (loginSecurityCheckbox.is(':checked')) {
            loginQuestionsRows.show();
        } else {
            loginQuestionsRows.hide();
        }
    }

    // Слушаем изменения чекбокса
    loginSecurityCheckbox.on('change', toggleLoginSettings);
    
    // Запускаем при загрузке страницы, чтобы установить правильное состояние
    toggleLoginSettings();


    // =======================================================
    // 2. УПРАВЛЕНИЕ КОНТРОЛЬНЫМИ ВОПРОСАМИ
    // =======================================================

    // --- Добавление вопроса ---
    $('#rls-add-login-question-button').on('click', function(e) {
        e.preventDefault();
        
        const btn = $(this);
        const spinner = btn.siblings('.spinner');
        const questionInput = $('#rls-new-login-question');
        const answerInput = $('#rls-new-login-answer');
        
        const question = questionInput.val().trim();
        const answer = answerInput.val().trim();

        if (!question || !answer) {
            alert('Вопрос и ответ не могут быть пустыми.');
            return;
        }

        // Блокируем интерфейс
        spinner.css('visibility', 'visible');
        btn.prop('disabled', true);

        // Отправляем запрос
        $.post(rls_admin_data.ajax_url, {
            action: 'rls_add_login_question',
            nonce: rls_admin_data.questions_nonce, // Используем nonce из локализации
            question: question,
            answer: answer
        })
        .done(function(res) {
            if (res.success) {
                // Добавляем новую строку в таблицу
                $('#rls-login-questions-tbody').append(
                    `<tr data-key="${res.data.key}">
                        <td>${escapeHtml(res.data.question)}</td>
                        <td><button class="button-link-delete rls-delete-login-question-button">Удалить</button></td>
                    </tr>`
                );
                
                // Очищаем поля
                questionInput.val('');
                answerInput.val('');
                
                // Удаляем сообщение "Нет вопросов", если оно было
                $('.no-items', '#rls-login-questions-tbody').remove();
            } else {
                alert('Ошибка: ' + (res.data || 'Неизвестная ошибка'));
            }
        })
        .fail(function() {
            alert('Ошибка сервера. Попробуйте обновить страницу.');
        })
        .always(function() {
            spinner.css('visibility', 'hidden');
            btn.prop('disabled', false);
        });
    });

    // --- Удаление вопроса ---
    // Используем делегирование (on click), так как элементы могут быть добавлены динамически
    $('#rls-login-questions-tbody').on('click', '.rls-delete-login-question-button', function(e) {
        e.preventDefault();
        
        if (!confirm('Вы уверены, что хотите удалить этот вопрос?')) return;

        const btn = $(this);
        const row = btn.closest('tr');
        const key = row.data('key');

        btn.text('Удаление...');
        btn.prop('disabled', true);

        $.post(rls_admin_data.ajax_url, {
            action: 'rls_delete_login_question',
            nonce: rls_admin_data.questions_nonce,
            key: key
        })
        .done(function(res) {
            if (res.success) {
                row.fadeOut(300, function() { 
                    $(this).remove(); 
                    // Если удалили последний элемент, можно показать заглушку (опционально)
                    if ($('#rls-login-questions-tbody tr').length === 0) {
                       $('#rls-login-questions-tbody').html('<tr class="no-items"><td colspan="2">Список вопросов пуст.</td></tr>');
                    }
                });
            } else {
                alert('Ошибка: ' + res.data);
                btn.text('Удалить');
                btn.prop('disabled', false);
            }
        })
        .fail(function() {
            alert('Ошибка сервера.');
            btn.text('Удалить');
            btn.prop('disabled', false);
        });
    });


    // =======================================================
    // 3. УПРАВЛЕНИЕ СИГНАТУРАМИ (База вирусов)
    // =======================================================

    // --- Добавление сигнатуры ---
    $('#rls-add-signature-button').on('click', function(e) {
        e.preventDefault();
        
        const btn = $(this);
        const input = $('#rls-new-signature-input');
        const spinner = btn.siblings('.spinner');
        const sig = input.val().trim();

        if (!sig) {
            input.css('border-color', 'red');
            return;
        }
        
        input.css('border-color', '');
        spinner.css('visibility', 'visible');
        btn.prop('disabled', true);

        $.post(rls_admin_data.ajax_url, {
            action: 'rls_add_signature',
            nonce: rls_admin_data.signatures_nonce, // Используем nonce из локализации
            signature: sig
        })
        .done(function(res) {
            if (res.success) {
                // Добавляем строку в таблицу
                $('#rls-signatures-table-body').append(
                    `<tr data-signature="${escapeHtml(res.data.signature)}">
                        <td class="signature-code"><code>${escapeHtml(res.data.signature)}</code></td>
                        <td><span class="sig-source sig-source-пользовательская">Пользовательская</span></td>
                        <td><button class="button-link-delete rls-delete-signature-button">Удалить</button></td>
                    </tr>`
                );
                
                input.val('');
                $('.no-items', '#rls-signatures-table-body').remove();
            } else {
                alert('Ошибка: ' + res.data);
            }
        })
        .fail(function() {
            alert('Ошибка сервера.');
        })
        .always(function() {
            spinner.css('visibility', 'hidden');
            btn.prop('disabled', false);
        });
    });

    // --- Удаление сигнатуры ---
    $('#rls-signatures-table-body').on('click', '.rls-delete-signature-button', function(e) {
        e.preventDefault();
        
        if (!confirm('Вы уверены, что хотите удалить эту сигнатуру?')) return;

        const btn = $(this);
        const row = btn.closest('tr');
        const signature = row.data('signature');

        btn.text('Удаление...');
        btn.prop('disabled', true);

        $.post(rls_admin_data.ajax_url, {
            action: 'rls_delete_signature',
            nonce: rls_admin_data.signatures_nonce,
            signature: signature
        })
        .done(function(res) {
            if (res.success) {
                row.fadeOut(300, function() { $(this).remove(); });
            } else {
                alert('Ошибка: ' + res.data);
                btn.text('Удалить');
                btn.prop('disabled', false);
            }
        })
        .fail(function() {
            alert('Ошибка сервера.');
            btn.text('Удалить');
            btn.prop('disabled', false);
        });
    });

    // Вспомогательная функция для безопасности (XSS prevention)
    function escapeHtml(text) {
        if (text === null || typeof text === 'undefined') return '';
        return String(text)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

});