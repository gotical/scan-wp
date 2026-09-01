/**
 * JavaScript для страницы настроек и модального окна деактивации.
 * Rybinsk Lab Security v2.3.0
 */
jQuery(function($) {
    const settingsWrap = $('.rls-wrap').first();
    const forcedSection = String(settingsWrap.data('rls-section') || '');
    const forcedInitialTab = String(settingsWrap.data('rls-initial-tab') || '');
    
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
    const initialTab = (function() {
        if (window.location.hash) {
            return window.location.hash;
        }

        const params = new URLSearchParams(window.location.search);
        const tab = params.get('tab');
        if (tab && tab.charAt(0) === '#') {
            return tab;
        }
        if (tab) {
            return '#' + tab;
        }
        return forcedInitialTab ? '#' + forcedInitialTab.replace(/^#/, '') : '';
    })();

    if (initialTab && $(initialTab).length > 0) {
        $('.rls-nav-tabs a[href="' + initialTab + '"]').click();
    }

    if (forcedSection) {
        $('[data-rls-section-box]').each(function() {
            const section = String($(this).data('rls-section-box') || '');
            $(this).toggle(section === forcedSection);
        });
    }

    const licenseKeyInput = document.querySelector('input[name="rls_settings[license_key]"]');
    const licenseRefreshBtn = document.getElementById('rls-license-refresh-button');
    const licenseDeleteBtn = document.getElementById('rls-license-delete-button');

    if (licenseKeyInput) {
        licenseKeyInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                saveLicenseKey();
            }
        });
    }

    if (licenseRefreshBtn && licenseKeyInput) {
        licenseRefreshBtn.addEventListener('click', function() {
            saveLicenseKey();
        });
    }

    if (licenseDeleteBtn && licenseKeyInput) {
        licenseDeleteBtn.addEventListener('click', function() {
            if (!confirm('Удалить ключ и переключить плагин на бесплатную версию?')) {
                return;
            }
            deleteLicenseKey();
        });
    }

    function saveLicenseKey() {
        if (!licenseKeyInput) return;

        const key = licenseKeyInput.value.trim();
        if (licenseRefreshBtn) {
            licenseRefreshBtn.disabled = true;
            licenseRefreshBtn.dataset.originalText = licenseRefreshBtn.textContent;
            licenseRefreshBtn.textContent = 'Проверяем...';
        }

        $.post(rls_admin_data.ajax_url, {
            action: 'rls_save_license_key',
            nonce: rls_admin_data.settings_nonce,
            license_key: key
        })
        .done(function(res) {
            if (res && res.success) {
                window.location.reload();
                return;
            }
            const msg = (res && res.data) ? res.data : 'Не удалось сохранить лицензию.';
            alert(typeof msg === 'string' ? msg : 'Не удалось сохранить лицензию.');
        })
        .fail(function() {
            alert('Не удалось сохранить лицензию.');
        })
        .always(function() {
            if (licenseRefreshBtn) {
                licenseRefreshBtn.disabled = false;
                licenseRefreshBtn.textContent = licenseRefreshBtn.dataset.originalText || 'Обновить статус лицензии';
            }
        });
    }

    function deleteLicenseKey() {
        if (!licenseKeyInput) return;

        if (licenseDeleteBtn) {
            licenseDeleteBtn.disabled = true;
            licenseDeleteBtn.dataset.originalText = licenseDeleteBtn.textContent;
            licenseDeleteBtn.textContent = 'Удаляем...';
        }

        $.post(rls_admin_data.ajax_url, {
            action: 'rls_delete_license_key',
            nonce: rls_admin_data.settings_nonce
        })
        .done(function(res) {
            if (res && res.success) {
                licenseKeyInput.value = '';
                window.location.reload();
                return;
            }
            const msg = (res && res.data) ? res.data : 'Не удалось удалить ключ.';
            alert(typeof msg === 'string' ? msg : 'Не удалось удалить ключ.');
        })
        .fail(function() {
            alert('Не удалось удалить ключ.');
        })
        .always(function() {
            if (licenseDeleteBtn) {
                licenseDeleteBtn.disabled = false;
                licenseDeleteBtn.textContent = licenseDeleteBtn.dataset.originalText || 'Удалить ключ';
            }
        });
    }

    const logFilterButton = document.getElementById('rls-apply-log-filter');
    const logTypeFilter = document.getElementById('rls-log-type-filter');
    if (logFilterButton && logTypeFilter) {
        logFilterButton.addEventListener('click', function() {
            const url = new URL(window.location.href);
            url.searchParams.set('page', 'rls-settings');
            url.searchParams.set('tab', 'tab-logs');
            url.searchParams.set('rls_log_type', logTypeFilter.value || 'all');

            const currentView = url.searchParams.get('rls_logs_view');
            if (currentView !== 'all' && currentView !== 'recent') {
                url.searchParams.set('rls_logs_view', 'recent');
            }

            window.location.href = url.toString();
        });
    }

    function getProtectionMode() {
        const selected = $('input[name="rls_settings[protection_mode]"]:checked').val();
        return selected || 'full';
    }

    function modeAllows($el, mode) {
        const raw = String($el.data('rls-visible-modes') || '').trim();
        if (!raw) return true;
        return raw.split(',').map(function(item) {
            return item.trim();
        }).indexOf(mode) !== -1;
    }

    let previousProtectionMode = getProtectionMode();

    function applyProtectionModeUI() {
        const mode = getProtectionMode();
        const $globalBlacklistToggle = $('[data-rls-global-blacklist-toggle]');
        const $globalBlacklistHint = $globalBlacklistToggle.closest('label').next('.description');

        $('[data-rls-visible-modes]').each(function() {
            const $el = $(this);
            $el.toggle(modeAllows($el, mode));
        });

        $('[data-rls-mode-notice]').each(function() {
            const $el = $(this);
            $el.toggle(String($el.data('rls-mode-notice')) === mode);
        });

        $('.rls-mode-card').each(function() {
            const $card = $(this);
            const checked = $card.find('input[type="radio"]').is(':checked');
            $card.toggleClass('is-selected', checked);
        });

        const activeTab = $('.rls-nav-tabs a.nav-tab-active');
        if (activeTab.length && !activeTab.is(':visible')) {
            const fallbackTab = $('.rls-nav-tabs a:visible').first();
            if (fallbackTab.length) {
                fallbackTab.trigger('click');
            }
        }

        if ($globalBlacklistToggle.length) {
            $globalBlacklistToggle.each(function() {
                const $toggle = $(this);
                const isPremium = String($toggle.data('premiumAvailable') || '0') === '1';

                if (!isPremium) {
                    $toggle.prop('checked', false).prop('disabled', true);
                    return;
                }

                if (mode === 'full') {
                    $toggle.prop('checked', true).prop('disabled', true);
                    return;
                }

                if (mode === 'light') {
                    if (previousProtectionMode !== 'light') {
                        $toggle.prop('checked', false);
                    }
                    $toggle.prop('disabled', false);
                    return;
                }

                $toggle.prop('checked', false).prop('disabled', true);
            });
        }

        if ($globalBlacklistHint.length) {
            if (!$globalBlacklistToggle.length || String($globalBlacklistToggle.first().data('premiumAvailable') || '0') !== '1') {
                $globalBlacklistHint.text('Этот пункт доступен только для премиум пользователей с активированной лицензией.');
            } else if (mode === 'full') {
                $globalBlacklistHint.text('В полной защите облачный blacklist включается автоматически.');
            } else if (mode === 'light') {
                $globalBlacklistHint.text('В легкой защите облачный blacklist выключен по умолчанию и может быть включен вручную.');
            } else {
                $globalBlacklistHint.text('В режиме только сканер облачный blacklist не применяется.');
            }
        }

        if (typeof toggleLoginSettings === 'function') {
            toggleLoginSettings();
        }

        previousProtectionMode = mode;
    }

    $(document).on('change', 'input[name="rls_settings[protection_mode]"]', applyProtectionModeUI);

    $('.rls-bot-select-btn').on('click', function() {
        const mode = String($(this).data('mode') || '');
        const botChecks = $('.rls-bot-toggle');
        if (!botChecks.length) return;

        botChecks.each(function() {
            if (mode === 'all') {
                this.checked = true;
                return;
            }
            if (mode === 'none') {
                this.checked = false;
                return;
            }
            if (mode === 'recommended') {
                this.checked = String($(this).data('bot-recommended') || '0') === '1';
            }
        });
    });

    // =======================================================
    // 2. МОДАЛЬНОЕ ОКНО ДЕАКТИВАЦИИ
    // =======================================================
    
    const deactivateLink = $('tr[data-slug="rybinsklab-security"] .deactivate a');
    const modal = $('#rls-deactivation-modal');
    
    if (deactivateLink.length > 0 && modal.length > 0) {
        let finalDeactivationUrl = deactivateLink.attr('href');

        function resetDeactivationModal() {
            $('#rls-step-1').show();
            $('#rls-step-2').hide();
            $('input[name="rls_wipe_choice"][value="keep"]').prop('checked', true);
            $('.rls-final-deactivate-btn').text('Отключить плагин').prop('disabled', false);
        }

        deactivateLink.on('click', function(e) {
            e.preventDefault();
            resetDeactivationModal();
            modal.fadeIn(200);
        });

        $('.rls-cancel-btn').on('click', function() {
            modal.fadeOut(200);
        });

        $('.rls-next-btn').on('click', function() {
            $('#rls-step-1').hide();
            $('#rls-step-2').fadeIn(200);
        });

        $('.rls-back-btn').on('click', function() {
            $('#rls-step-2').hide();
            $('#rls-step-1').fadeIn(200);
        });

        $('.rls-final-deactivate-btn').on('click', function() {
            const btn = $(this);
            const wipeData = $('input[name="rls_wipe_choice"]:checked').val() === 'wipe';
            btn.text('Подготовка...').prop('disabled', true);
            savePrefAndRedirect(wipeData);
        });

        function savePrefAndRedirect(wipeData) {
            $.post(rls_admin_data.ajax_url || ajaxurl, {
                action: 'rls_save_uninstall_pref',
                nonce: rls_admin_data.settings_nonce,
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
        if (getProtectionMode() === 'scanner_only') {
            loginRows.hide();
            return;
        }

        if (loginCb.is(':checked')) loginRows.slideDown(200);
        else loginRows.slideUp(200);
    }
    loginCb.on('change', toggleLoginSettings);
    toggleLoginSettings();
    applyProtectionModeUI();

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
    $('#rls-clear-attack-logs-button').on('click', function(e) {
        e.preventDefault();
        if (!confirm('Очистить историю атак? Количество удаленных записей будет отправлено на сервер статистики.')) {
            return;
        }

        const btn = $(this);
        btn.prop('disabled', true).text('Очистка...');

        $.post(rls_admin_data.ajax_url, {
            action: 'rls_clear_attack_logs',
            nonce: rls_admin_data.settings_nonce
        }).done(function(res) {
            if (!res.success) {
                alert('Ошибка очистки журнала');
                return;
            }

            const deleted = (res.data && res.data.deleted_count) ? parseInt(res.data.deleted_count, 10) : 0;
            $('#rls-logs-total').text('0');
            $('#rls-attack-logs-tbody').html('<tr><td colspan=\"4\">Журнал очищен. Удалено записей: ' + deleted + '.</td></tr>');
        }).always(function() {
            btn.prop('disabled', false).text('Очистить историю атак');
        });
    });

    // Снять временную блокировку IP (WAF/Brute lockout)
    $(document).on('click', '.rls-unblock-ip', function(e) {
        e.preventDefault();
        if (!confirm('Снять временную блокировку для этого IP?')) return;

        const btn = $(this);
        const ip = btn.data('ip');
        const li = btn.closest('li');
        btn.prop('disabled', true).text('...');

        $.post(rls_admin_data.ajax_url, {
            action: 'rls_unblock_ip',
            nonce: rls_admin_data.settings_nonce,
            ip: ip
        }).done(function(res) {
            if (res.success) {
                li.fadeOut(200, function(){ $(this).remove(); });
            } else {
                alert('Ошибка: ' + (res.data || 'Не удалось снять блок'));
                btn.prop('disabled', false).text('Снять блок');
            }
        }).fail(function() {
            alert('Ошибка сети.');
            btn.prop('disabled', false).text('Снять блок');
        });
    });

    // Добавить временно заблокированный IP в черный список
    $(document).on('click', '.rls-move-blocked-to-black', function(e) {
        e.preventDefault();
        const btn = $(this);
        const ip = btn.data('ip');
        const li = btn.closest('li');
        btn.prop('disabled', true).text('...');

        $.post(rls_admin_data.ajax_url, {
            action: 'rls_add_ip_list',
            nonce: rls_admin_data.settings_nonce,
            ip: ip,
            list: 'black'
        }).done(function(res) {
            if (res.success) {
                const listUl = $('#rls-black-list');
                listUl.append(
                    `<li>
                        <span>${escapeHtml(ip)}</span>
                        <a href="#" class="rls-del-ip" data-ip="${escapeHtml(ip)}" data-list="black">&times;</a>
                    </li>`
                );

                $.post(rls_admin_data.ajax_url, {
                    action: 'rls_unblock_ip',
                    nonce: rls_admin_data.settings_nonce,
                    ip: ip
                }).always(function() {
                    li.fadeOut(200, function(){ $(this).remove(); });
                });
            } else {
                alert('Ошибка: ' + (res.data || 'Не удалось добавить в черный список'));
                btn.prop('disabled', false).text('В черный');
            }
        }).fail(function() {
            alert('Ошибка сети.');
            btn.prop('disabled', false).text('В черный');
        });
    });

    // Добавить временно заблокированный IP в белый список
    $(document).on('click', '.rls-move-blocked-to-white', function(e) {
        e.preventDefault();
        const btn = $(this);
        const ip = btn.data('ip');
        const li = btn.closest('li');
        btn.prop('disabled', true).text('...');

        $.post(rls_admin_data.ajax_url, {
            action: 'rls_add_ip_list',
            nonce: rls_admin_data.settings_nonce,
            ip: ip,
            list: 'white'
        }).done(function(res) {
            if (res.success) {
                const listUl = $('#rls-white-list');
                listUl.append(
                    `<li>
                        <span>${escapeHtml(ip)}</span>
                        <a href="#" class="rls-del-ip" data-ip="${escapeHtml(ip)}" data-list="white">&times;</a>
                    </li>`
                );

                $.post(rls_admin_data.ajax_url, {
                    action: 'rls_unblock_ip',
                    nonce: rls_admin_data.settings_nonce,
                    ip: ip
                }).always(function() {
                    li.fadeOut(200, function(){ $(this).remove(); });
                });
            } else {
                alert('Ошибка: ' + (res.data || 'Не удалось добавить в белый список'));
                btn.prop('disabled', false).text('В белый');
            }
        }).fail(function() {
            alert('Ошибка сети.');
            btn.prop('disabled', false).text('В белый');
        });
    });

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


