/**
 * JavaScript для страницы настроек и модального окна деактивации.
 * Rybinsk Lab Security v1.5.3
 */
jQuery(function($) {
    
    // =======================================================
    // 1. УПРАВЛЕНИЕ ВКЛАДКАМИ (TABS)
    // =======================================================
    
    $('.rls-nav-tabs a').on('click', function(e) {
        e.preventDefault();
        
        // Убираем активность
        $('.rls-nav-tabs a').removeClass('nav-tab-active');
        $(this).addClass('nav-tab-active');
        
        // Скрываем все вкладки
        $('.rls-tab-content').hide();
        
        // Показываем нужную
        const target = $(this).attr('href');
        $(target).show();
        
        // Сохраняем состояние в URL
        window.location.hash = target;
    });

    // Открытие вкладки по хешу в URL
    if (window.location.hash) {
        const hash = window.location.hash;
        if ($(hash).length > 0) {
            $('.rls-nav-tabs a[href="' + hash + '"]').click();
        }
    }

    // =======================================================
    // 2. МОДАЛЬНОЕ ОКНО ДЕАКТИВАЦИИ
    // =======================================================
    
    const deactivateLink = $('tr[data-slug="rybinsklab-security"] .deactivate a');
    const modal = $('#rls-deactivation-modal');
    
    if (deactivateLink.length > 0 && modal.length > 0) {
        let finalDeactivationUrl = deactivateLink.attr('href');

        // Перехват клика
        deactivateLink.on('click', function(e) {
            e.preventDefault();
            modal.fadeIn(200);
        });

        // Отмена
        $('.rls-cancel-btn').on('click', function() {
            modal.fadeOut(200);
        });

        // Продолжить (Шаг 1)
        $('.rls-next-btn').on('click', function() {
            const choice = $('input[name="rls_wipe_choice"]:checked').val();
            
            if (choice === 'keep') {
                savePrefAndRedirect(false); // Сохраняем данные
            } else {
                // Переход к шагу 2
                $('#rls-step-1').hide();
                $('#rls-step-2').fadeIn(200);
            }
        });

        // Удалить окончательно (Шаг 2)
        $('.rls-final-deactivate-btn').on('click', function() {
            const btn = $(this);
            btn.text('Очистка данных...').prop('disabled', true);
            savePrefAndRedirect(true); // Удаляем данные
        });

        function savePrefAndRedirect(wipeData) {
            $.post(ajaxurl, {
                action: 'rls_save_uninstall_pref',
                wipe: wipeData
            }).always(function() {
                window.location.href = finalDeactivationUrl;
            });
        }
    }

    // =======================================================
    // 3. UI ИНТЕРАКТИВ
    // =======================================================

    // Показ/скрытие настроек вопросов
    const loginCb = $('#rls_enable_login_security_cb');
    const loginRows = $('.login-questions-settings-row');
    function toggleLoginSettings() {
        if (loginCb.is(':checked')) loginRows.slideDown(200);
        else loginRows.slideUp(200);
    }
    loginCb.on('change', toggleLoginSettings);
    toggleLoginSettings();

    // =======================================================
    // 4. AJAX: УПРАВЛЕНИЕ СПИСКАМИ IP
    // =======================================================

    // Добавление IP
    $('.rls-add-ip-btn').on('click', function(e) {
        e.preventDefault();
        
        const btn = $(this);
        const listType = btn.data('list'); // 'white' or 'black'
        const input = (listType === 'white') ? $('#rls-new-white-ip') : $('#rls-new-black-ip');
        const ip = input.val().trim();
        const listUl = (listType === 'white') ? $('#rls-white-list') : $('#rls-black-list');

        if (!ip) {
            input.css('border-color', 'red');
            return;
        }

        btn.prop('disabled', true).text('...');

        $.post(rls_admin_data.ajax_url, {
            action: 'rls_add_ip_list',
            nonce: rls_admin_data.settings_nonce,
            ip: ip,
            list: listType
        })
        .done(function(res) {
            if (res.success) {
                input.val('').css('border-color', '');
                listUl.append(
                    `<li>
                        <span>${escapeHtml(res.data.ip)}</span> 
                        <a href="#" class="rls-del-ip" data-ip="${escapeHtml(res.data.ip)}" data-list="${listType}">&times;</a>
                    </li>`
                );
            } else {
                alert('Ошибка: ' + (res.data || 'Неверный IP'));
            }
        })
        .always(function() {
            btn.prop('disabled', false).text(listType === 'black' ? 'Забанить' : 'Добавить');
        });
    });

    // Удаление IP
    $(document).on('click', '.rls-del-ip', function(e) {
        e.preventDefault();
        if (!confirm('Удалить IP из списка?')) return;

        const link = $(this);
        const li = link.closest('li');
        
        $.post(rls_admin_data.ajax_url, {
            action: 'rls_delete_ip_list',
            nonce: rls_admin_data.settings_nonce,
            ip: link.data('ip'),
            list: link.data('list')
        })
        .done(function(res) {
            if (res.success) {
                li.fadeOut(200, function(){ $(this).remove(); });
            }
        });
    });

    // =======================================================
    // 5. AJAX: ВОПРОСЫ И СИГНАТУРЫ
    // =======================================================

    // Добавление вопроса
    $('#rls-add-login-question-button').on('click', function(e) {
        e.preventDefault();
        const btn = $(this);
        const qInput = $('#rls-new-login-question');
        const aInput = $('#rls-new-login-answer');
        const q = qInput.val().trim();
        const a = aInput.val().trim();

        if (!q || !a) return;
        btn.prop('disabled', true);

        $.post(rls_admin_data.ajax_url, {
            action: 'rls_add_login_question',
            nonce: rls_admin_data.questions_nonce,
            question: q,
            answer: a
        }).done(function(res) {
            if (res.success) {
                $('#rls-login-questions-tbody').append(
                    `<tr data-key="${res.data.key}">
                        <td>${escapeHtml(res.data.q)}</td>
                        <td><button class="button-link-delete rls-delete-login-question-button">Удалить</button></td>
                    </tr>`
                );
                qInput.val(''); aInput.val('');
                $('.no-items', '#rls-login-questions-tbody').remove();
            }
        }).always(function(){ btn.prop('disabled', false); });
    });

    // Удаление вопроса
    $(document).on('click', '.rls-delete-login-question-button', function(e) {
        e.preventDefault();
        if(!confirm('Удалить вопрос?')) return;
        const btn = $(this);
        const row = btn.closest('tr');
        
        $.post(rls_admin_data.ajax_url, {
            action: 'rls_delete_login_question',
            nonce: rls_admin_data.questions_nonce,
            key: row.data('key')
        }).done(function(res){ if(res.success) row.remove(); });
    });

    // Добавление сигнатуры
    $('#rls-add-signature-button').on('click', function(e) {
        e.preventDefault();
        const btn = $(this);
        const input = $('#rls-new-signature-input');
        const sig = input.val().trim();

        if (!sig) return;
        btn.prop('disabled', true);

        $.post(rls_admin_data.ajax_url, {
            action: 'rls_add_signature',
            nonce: rls_admin_data.signatures_nonce,
            signature: sig
        }).done(function(res) {
            if (res.success) {
                $('#rls-signatures-table-body').append(
                    `<tr data-signature="${escapeHtml(res.data.signature)}">
                        <td><code>${escapeHtml(res.data.signature)}</code></td>
                        <td><button class="button-link-delete rls-delete-signature-button">Удалить</button></td>
                    </tr>`
                );
                input.val('');
                $('.no-items', '#rls-signatures-table-body').remove();
            }
        }).always(function(){ btn.prop('disabled', false); });
    });

    // Удаление сигнатуры
    $(document).on('click', '.rls-delete-signature-button', function(e) {
        e.preventDefault();
        if(!confirm('Удалить сигнатуру?')) return;
        const btn = $(this);
        const row = btn.closest('tr');
        
        $.post(rls_admin_data.ajax_url, {
            action: 'rls_delete_signature',
            nonce: rls_admin_data.signatures_nonce,
            signature: row.data('signature')
        }).done(function(res){ if(res.success) row.remove(); });
    });

    // Хелпер для экранирования HTML
    function escapeHtml(text) {
        if (!text) return text;
        return text.replace(/&/g, "&amp;")
                   .replace(/</g, "&lt;")
                   .replace(/>/g, "&gt;")
                   .replace(/"/g, "&quot;")
                   .replace(/'/g, "&#039;");
    }
});