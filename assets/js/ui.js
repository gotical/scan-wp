/**
 * RybinskLabSecurity UI: animations, interactions, charts.
 * v2.5.0 — toast, modal, palette, counters, drag-drop, Chart.js.
 */
(function ($, undefined) {
    'use strict';

    /* =================================================================
     * 1. TOAST NOTIFICATIONS
     * ================================================================= */
    const Toast = {
        container: null,
        ensure() {
            if (this.container) return;
            this.container = document.createElement('div');
            this.container.className = 'rls-toast-container';
            this.container.setAttribute('aria-live', 'polite');
            this.container.setAttribute('aria-atomic', 'true');
            document.body.appendChild(this.container);
        },
        show(opts) {
            this.ensure();
            const settings = Object.assign({
                type: 'info',
                title: '',
                message: '',
                duration: 4500,
            }, opts || {});

            const icons = { success: '✓', warning: '!', danger: '✕', info: 'i' };
            const toast = document.createElement('div');
            toast.className = 'rls-toast is-' + settings.type;
            toast.innerHTML =
                '<div class="rls-toast-icon">' + (icons[ settings.type ] || 'i') + '</div>' +
                '<div class="rls-toast-body">' +
                    (settings.title ? '<div class="rls-toast-title"></div>' : '') +
                    '<div class="rls-toast-message"></div>' +
                '</div>' +
                '<button type="button" class="rls-toast-close" aria-label="Закрыть">×</button>';
            if (settings.title) toast.querySelector('.rls-toast-title').textContent = settings.title;
            toast.querySelector('.rls-toast-message').textContent = settings.message;
            this.container.appendChild(toast);

            const dismiss = () => {
                toast.classList.add('is-leaving');
                setTimeout(() => toast.remove(), 250);
            };
            toast.querySelector('.rls-toast-close').addEventListener('click', dismiss);
            if (settings.duration > 0) {
                setTimeout(dismiss, settings.duration);
            }
            return dismiss;
        },
        success(message, title) { this.show({ type: 'success', message, title }); },
        warning(message, title) { this.show({ type: 'warning', message, title }); },
        danger(message, title)  { this.show({ type: 'danger', message, title }); },
        info(message, title)    { this.show({ type: 'info', message, title }); }
    };
    window.RLS_Toast = Toast;

    /* =================================================================
     * 2. CONFIRM DIALOG (replaces native confirm())
     * ================================================================= */
    const Confirm = {
        show(opts) {
            return new Promise((resolve) => {
                const settings = Object.assign({
                    title: 'Подтверждение',
                    message: 'Вы уверены?',
                    type: 'warning',
                    confirmText: 'Подтвердить',
                    cancelText: 'Отмена',
                    danger: false,
                }, opts || {});

                const backdrop = document.createElement('div');
                backdrop.className = 'rls-modal-backdrop';
                const modal = document.createElement('div');
                modal.className = 'rls-modal is-' + settings.type;
                const icons = { warning: '!', danger: '✕', info: 'i', success: '✓' };
                modal.innerHTML =
                    '<div class="rls-modal-header">' +
                        '<div class="rls-modal-icon">' + (icons[ settings.type ] || '!') + '</div>' +
                        '<h3 class="rls-modal-title"></h3>' +
                    '</div>' +
                    '<div class="rls-modal-body"></div>' +
                    '<div class="rls-modal-footer">' +
                        '<button type="button" class="button rls-modal-cancel"></button>' +
                        '<button type="button" class="button button-primary rls-modal-confirm"></button>' +
                    '</div>';
                modal.querySelector('.rls-modal-title').textContent = settings.title;
                modal.querySelector('.rls-modal-body').textContent = settings.message;
                modal.querySelector('.rls-modal-cancel').textContent = settings.cancelText;
                const confirmBtn = modal.querySelector('.rls-modal-confirm');
                confirmBtn.textContent = settings.confirmText;
                if (settings.danger || settings.type === 'danger') {
                    confirmBtn.classList.remove('button-primary');
                    confirmBtn.classList.add('button-danger');
                    confirmBtn.style.background = 'var(--rls-danger)';
                    confirmBtn.style.borderColor = 'var(--rls-danger)';
                }
                backdrop.appendChild(modal);
                document.body.appendChild(backdrop);

                const close = (result) => {
                    backdrop.style.animation = 'rls-fade-in 0.15s ease-out reverse';
                    modal.style.animation = 'rls-scale-in 0.15s ease-out reverse';
                    setTimeout(() => {
                        backdrop.remove();
                        resolve(result);
                    }, 150);
                };
                modal.querySelector('.rls-modal-cancel').addEventListener('click', () => close(false));
                confirmBtn.addEventListener('click', () => close(true));
                backdrop.addEventListener('click', (e) => {
                    if (e.target === backdrop) close(false);
                });
                const escHandler = (e) => {
                    if (e.key === 'Escape') {
                        document.removeEventListener('keydown', escHandler);
                        close(false);
                    }
                };
                document.addEventListener('keydown', escHandler);
                setTimeout(() => confirmBtn.focus(), 50);
            });
        }
    };
    window.RLS_Confirm = Confirm;

    /* =================================================================
     * 3. ANIMATED NUMBER COUNTER
     * ================================================================= */
    function animateCounter(el, finalValue, duration) {
        duration = duration || 1200;
        const start = parseInt(el.dataset.rlsStart || '0', 10);
        const target = parseInt(finalValue, 10) || 0;
        const startTime = performance.now();
        const easeOut = (t) => 1 - Math.pow(1 - t, 3);
        function step(now) {
            const t = Math.min(1, (now - startTime) / duration);
            const eased = easeOut(t);
            const current = Math.round(start + (target - start) * eased);
            el.textContent = current.toLocaleString();
            if (t < 1) requestAnimationFrame(step);
        }
        requestAnimationFrame(step);
    }
    window.RLS_animateCounter = animateCounter;

    /* =================================================================
     * 4. COMMAND PALETTE (Ctrl/Cmd+K)
     * ================================================================= */
    const Palette = {
        isOpen: false,
        items: [],
        activeIndex: 0,

        register(items) { this.items = items || []; },

        open() {
            if (this.isOpen) return;
            this.isOpen = true;
            const backdrop = document.createElement('div');
            backdrop.className = 'rls-palette-backdrop';
            backdrop.innerHTML =
                '<div class="rls-palette">' +
                    '<input type="text" class="rls-palette-search" placeholder="Поиск настроек, разделов, действий…" />' +
                    '<div class="rls-palette-results"></div>' +
                    '<div class="rls-palette-footer">' +
                        '<span><kbd>↑</kbd><kbd>↓</kbd> навигация</span>' +
                        '<span><kbd>Enter</kbd> выбрать</span>' +
                        '<span><kbd>Esc</kbd> закрыть</span>' +
                    '</div>' +
                '</div>';
            document.body.appendChild(backdrop);
            this.element = backdrop;
            this.searchInput = backdrop.querySelector('.rls-palette-search');
            this.resultsEl = backdrop.querySelector('.rls-palette-results');

            this.render('');

            const onKey = (e) => {
                if (e.key === 'Escape') { this.close(); return; }
                if (e.key === 'ArrowDown') { e.preventDefault(); this.move(1); }
                if (e.key === 'ArrowUp')   { e.preventDefault(); this.move(-1); }
                if (e.key === 'Enter')     { e.preventDefault(); this.activate(); }
            };
            this._keyHandler = onKey;
            document.addEventListener('keydown', onKey);

            this.searchInput.addEventListener('input', () => this.render(this.searchInput.value));
            setTimeout(() => this.searchInput.focus(), 50);

            backdrop.addEventListener('click', (e) => {
                if (e.target === backdrop) this.close();
            });
        },

        close() {
            if (!this.isOpen) return;
            this.isOpen = false;
            if (this._keyHandler) document.removeEventListener('keydown', this._keyHandler);
            if (this.element) this.element.remove();
            this.element = null;
        },

        move(delta) {
            const items = this.resultsEl.querySelectorAll('.rls-palette-item');
            if (!items.length) return;
            this.activeIndex = (this.activeIndex + delta + items.length) % items.length;
            items.forEach((el, i) => el.classList.toggle('is-active', i === this.activeIndex));
            items[ this.activeIndex ].scrollIntoView({ block: 'nearest' });
        },

        activate() {
            const items = this.resultsEl.querySelectorAll('.rls-palette-item');
            const active = items[ this.activeIndex ];
            if (active) active.click();
        },

        render(query) {
            const q = (query || '').toLowerCase().trim();
            const matches = this.items.filter((item) => {
                if (!q) return true;
                const text = (item.title + ' ' + (item.subtitle || '') + ' ' + (item.keywords || '').join(' ')).toLowerCase();
                return text.indexOf(q) !== -1;
            });
            if (!matches.length) {
                this.resultsEl.innerHTML = '<div class="rls-palette-empty">Ничего не найдено</div>';
                return;
            }
            this.activeIndex = 0;
            this.resultsEl.innerHTML = matches.map((item, i) => (
                '<div class="rls-palette-item' + (i === 0 ? ' is-active' : '') + '" data-i="' + i + '">' +
                    '<span class="dashicons ' + (item.icon || 'dashicons-admin-generic') + '"></span>' +
                    '<div style="flex:1;">' +
                        '<div style="font-weight:500;"></div>' +
                        (item.subtitle ? '<div style="font-size:12px; color:var(--rls-text-muted);"></div>' : '') +
                    '</div>' +
                '</div>'
            ).join(''));
            matches.forEach((item, i) => {
                const el = this.resultsEl.children[i];
                el.querySelector('div > div:first-child').textContent = item.title;
                if (item.subtitle) el.querySelector('div > div:last-child').textContent = item.subtitle;
                el.addEventListener('click', () => {
                    if (typeof item.action === 'function') item.action();
                    if (item.href) window.location.href = item.href;
                    this.close();
                });
            });
        }
    };
    window.RLS_Palette = Palette;

    /* =================================================================
     * 5. DRAG-AND-DROP for lists
     * ================================================================= */
    function enableDragSort(container, onReorder) {
        if (!container) return;
        let dragItem = null;
        const items = container.querySelectorAll('li');
        items.forEach((li, i) => {
            li.setAttribute('draggable', 'true');
            li.dataset.rlsIndex = i;
            li.addEventListener('dragstart', (e) => {
                dragItem = li;
                li.classList.add('rls-dragging');
                e.dataTransfer.effectAllowed = 'move';
                try { e.dataTransfer.setData('text/plain', String(i)); } catch (err) {}
            });
            li.addEventListener('dragend', () => {
                li.classList.remove('rls-dragging');
                container.querySelectorAll('li').forEach((el) => el.classList.remove('rls-drop-target'));
                dragItem = null;
            });
            li.addEventListener('dragover', (e) => {
                e.preventDefault();
                if (li !== dragItem) li.classList.add('rls-drop-target');
            });
            li.addEventListener('dragleave', () => {
                li.classList.remove('rls-drop-target');
            });
            li.addEventListener('drop', (e) => {
                e.preventDefault();
                if (!dragItem || dragItem === li) return;
                const rect = li.getBoundingClientRect();
                const after = (e.clientY - rect.top) > (rect.height / 2);
                if (after) li.parentNode.insertBefore(dragItem, li.nextSibling);
                else li.parentNode.insertBefore(dragItem, li);
                if (typeof onReorder === 'function') onReorder(container);
            });
        });
    }
    window.RLS_enableDragSort = enableDragSort;

    /* =================================================================
     * 6. CHART.JS SETUP (monitoring dashboard)
     * ================================================================= */
    function setupMonitoringCharts(data) {
        if (typeof Chart === 'undefined') return;

        Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
        Chart.defaults.font.size = 12;
        Chart.defaults.color = '#50575e';

        // 1. Timeline (line chart)
        const ctx1 = document.getElementById('rls-chart-attacks');
        if (ctx1 && data.timeline) {
            const labels = data.timeline.map(r => r.day);
            const values = data.timeline.map(r => parseInt(r.total, 10));
            new Chart(ctx1, {
                type: 'line',
                data: {
                    labels,
                    datasets: [{
                        label: 'Атаки',
                        data: values,
                        borderColor: '#2271b1',
                        backgroundColor: 'rgba(34,113,177,0.10)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2,
                        pointRadius: 4,
                        pointHoverRadius: 7,
                        pointBackgroundColor: '#fff',
                        pointBorderColor: '#2271b1',
                        pointBorderWidth: 2,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: { duration: 1200, easing: 'easeOutQuart' },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: 'rgba(15,23,42,0.95)',
                            padding: 12,
                            cornerRadius: 8,
                            displayColors: false,
                            callbacks: {
                                label: (ctx) => ctx.parsed.y + ' событий'
                            }
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            grid: { color: 'rgba(0,0,0,0.05)' },
                            ticks: { precision: 0 }
                        },
                        x: {
                            grid: { display: false }
                        }
                    }
                }
            });
        }

        // 2. Types (doughnut chart)
        const ctx2 = document.getElementById('rls-chart-types');
        if (ctx2 && data.types) {
            const labels = data.types.map(t => t.type.toUpperCase());
            const values = data.types.map(t => parseInt(t.total, 10));
            const colors = ['#dc2626', '#d97706', '#2271b1', '#7c3aed', '#16a34a', '#0284c7', '#64748b'];
            new Chart(ctx2, {
                type: 'doughnut',
                data: {
                    labels,
                    datasets: [{
                        data: values,
                        backgroundColor: colors.slice(0, values.length),
                        borderColor: '#fff',
                        borderWidth: 3,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '65%',
                    animation: { duration: 1200, animateRotate: true, animateScale: true },
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: { padding: 12, usePointStyle: true, pointStyle: 'circle' }
                        }
                    }
                }
            });
        }
    }
    window.RLS_setupCharts = setupMonitoringCharts;

    /* =================================================================
     * 7. COPY-TO-CLIPBOARD with feedback
     * ================================================================= */
    document.addEventListener('click', (e) => {
        const target = e.target.closest('.rls-2fa-secret, [data-rls-copy]');
        if (!target) return;
        const text = target.dataset.rlsCopy || target.textContent.trim();
        if (!text) return;
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(() => {
                Toast.success('Скопировано в буфер обмена');
            });
        } else {
            // Fallback
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand('copy'); Toast.success('Скопировано'); } catch (err) { Toast.danger('Не удалось скопировать'); }
            ta.remove();
        }
    });

    /* =================================================================
     * 8. GLOBAL KEYBOARD SHORTCUTS
     * ================================================================= */
    document.addEventListener('keydown', (e) => {
        // Ctrl+K or Cmd+K — open command palette
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            Palette.open();
        }
    });

    /* =================================================================
     * 9. AUTO-WIRE existing UI
     * ================================================================= */
    $(function() {
        // Wire drag-and-drop on signature/IP lists if marked.
        $('.rls-draggable').each(function() {
            enableDragSort(this, (container) => {
                Toast.info('Порядок сохранён', 'Готово');
                // Could post to server here.
            });
        });

        // Wire health refresh / export buttons if present.
        const healthRefresh = document.getElementById('rls-health-refresh');
        if (healthRefresh) {
            healthRefresh.addEventListener('click', async () => {
                const ring = document.getElementById('rls-health-ring');
                ring.style.opacity = '0.5';
                try {
                    const res = await fetch(rls_admin_data.ajax_url + '?action=rls_health_check&nonce=' + rls_admin_data.health_nonce);
                    const json = await res.json();
                    if (json.success) {
                        updateHealth(json.data.checks);
                        Toast.success('Диагностика обновлена');
                    }
                } catch (err) {
                    Toast.danger('Не удалось получить данные');
                }
                ring.style.opacity = '1';
            });
        }
        const healthExport = document.getElementById('rls-health-export');
        if (healthExport) {
            healthExport.addEventListener('click', () => {
                Toast.info('Генерация отчёта…');
                window.location.href = rls_admin_data.ajax_url + '?action=rls_health_export&nonce=' + rls_admin_data.health_nonce;
            });
        }

        // Wire details modal link
        const detailsLink = document.getElementById('rls-health-details-link');
        const modal = document.getElementById('rls-health-modal');
        if (detailsLink && modal) {
            detailsLink.addEventListener('click', (e) => {
                e.preventDefault();
                modal.style.display = 'flex';
            });
            const closeBtn = document.getElementById('rls-health-close');
            if (closeBtn) closeBtn.addEventListener('click', () => { modal.style.display = 'none'; });
            modal.addEventListener('click', (e) => {
                if (e.target === modal) modal.style.display = 'none';
            });
        }

        // Populate palette items from existing nav links + actions.
        if (window.RLS_Palette && window.rls_admin_data) {
            const items = [];
            document.querySelectorAll('.rls-section-link').forEach((el) => {
                items.push({
                    title: el.textContent.trim(),
                    subtitle: 'Раздел настроек',
                    icon: (el.querySelector('.dashicons') || {}).className || 'dashicons-admin-generic',
                    href: el.href,
                });
            });
            document.querySelectorAll('.rls-hero-actions .button').forEach((el) => {
                items.push({
                    title: el.textContent.trim(),
                    subtitle: 'Действие',
                    icon: 'dashicons-controls-play',
                    action: () => el.click(),
                });
            });
            items.push({ title: 'Мониторинг', subtitle: 'Графики и аналитика', icon: 'dashicons-chart-line', href: (window.rls_admin_data.ajax_url || '').replace('admin-ajax.php', 'admin.php?page=rls-monitoring') });
            items.push({ title: 'Диагностика', subtitle: 'Проверка системы', icon: 'dashicons-heart', href: (window.rls_admin_data.ajax_url || '').replace('admin-ajax.php', 'admin.php?page=rls-health') });
            items.push({ title: '2FA', subtitle: 'Двухфакторная аутентификация', icon: 'dashicons-smartphone', href: (window.rls_admin_data.ajax_url || '').replace('admin-ajax.php', 'admin.php?page=rls-2fa') });
            items.push({ title: 'Hardening', subtitle: 'Защита wp-config, CSP, REST', icon: 'dashicons-shield-alt', href: (window.rls_admin_data.ajax_url || '').replace('admin-ajax.php', 'admin.php?page=rls-hardening') });
            window.RLS_Palette.register(items);
        }

        // Animated counters: any .rls-counter with data-target
        document.querySelectorAll('.rls-counter').forEach((el) => {
            const target = el.dataset.target || el.textContent;
            animateCounter(el, target, 1400);
        });

        // Wire 2FA secret copy
        document.querySelectorAll('.rls-2fa-secret').forEach((el) => {
            el.style.cursor = 'pointer';
            el.title = 'Кликните, чтобы скопировать';
        });
    });

    function updateHealth(checks) {
        const ok = checks.filter(c => c.status === 'ok').length;
        const total = checks.length;
        const pct = Math.round((ok / total) * 100);
        const ring = document.getElementById('rls-health-ring');
        const percentEl = document.getElementById('rls-health-percent');
        const pill = document.getElementById('rls-health-pill');
        if (!ring || !percentEl || !pill) return;
        const color = pct >= 80 ? '#16a34a' : (pct >= 50 ? '#d97706' : '#dc2626');
        ring.style.background = `conic-gradient(${color} ${pct * 3.6}deg, #e4e8ef 0deg)`;
        animateCounter(percentEl, pct, 900);
        pill.className = 'rls-status-pill ' + (pct >= 80 ? 'is-on' : (pct >= 50 ? 'is-warn' : 'is-err'));
        pill.textContent = pct >= 80 ? 'Отличный уровень' : (pct >= 50 ? 'Требует внимания' : 'Критично');
    }

})(jQuery);

/* =================================================================
 * 10. PROTECTION MODE UI
 * ================================================================= */
(function($) {
    $(function() {
        const applyMode = (profile, preset, button) => {
            const $btn = $(button).prop('disabled', true).text('Применение…');
            const data = { action: 'rls_apply_protection_mode', nonce: rls_admin_data.settings_nonce, profile };
            if (preset) data.preset = preset;
            $.post(rls_admin_data.ajax_url, data)
                .done((res) => {
                    if (res && res.success) {
                        if (window.RLS_Toast) RLS_Toast.success(res.data.message || 'Профиль применён');
                        setTimeout(() => location.reload(), 600);
                    } else {
                        if (window.RLS_Toast) RLS_Toast.danger((res && res.data) || 'Ошибка применения.');
                        $btn.prop('disabled', false).text('Применить');
                    }
                })
                .fail(() => {
                    if (window.RLS_Toast) RLS_Toast.danger('Сетевая ошибка');
                    $btn.prop('disabled', false).text('Применить');
                });
        };

        $(document).on('click', '.rls-mode-apply', function(e) {
            e.preventDefault();
            e.stopPropagation();
            const profile = $(this).data('profile');
            applyMode(profile, null, this);
        });

        $(document).on('click', '.rls-mode-apply-preset', function(e) {
            e.preventDefault();
            e.stopPropagation();
            const profile = $(this).data('profile');
            const preset = $(this).data('preset');
            applyMode(profile, preset, this);
        });

        // Impact preview modal.
        let pendingProfile = null, pendingPreset = null;

        $(document).on('click', '.rls-mode-preview', function(e) {
            e.preventDefault();
            e.stopPropagation();
            const profile = $(this).data('profile');
            const preset = $(this).data('preset');
            pendingProfile = profile;
            pendingPreset = preset;

            $('#rls-impact-modal').css('display', 'flex');
            $('#rls-impact-body').html('<div class="rls-skeleton is-card" style="height:200px;"></div>');

            $.post(rls_admin_data.ajax_url, {
                action: 'rls_preview_protection_mode',
                nonce: rls_admin_data.settings_nonce,
                profile,
                preset: preset || ''
            }).done((res) => {
                if (res && res.success) {
                    renderImpact(res.data);
                } else {
                    $('#rls-impact-body').html('<div class="rls-notice is-danger">Ошибка предпросмотра</div>');
                }
            });
        });

        $(document).on('click', '#rls-impact-cancel', () => {
            $('#rls-impact-modal').hide();
            pendingProfile = null; pendingPreset = null;
        });

        $(document).on('click', '#rls-impact-confirm', () => {
            $('#rls-impact-modal').hide();
            if (pendingProfile) {
                applyMode(pendingProfile, pendingPreset, $('<button>').get(0));
            }
        });

        function renderImpact(data) {
            const enable = (data.will_enable || []).map(m => m.name);
            const disable = (data.will_disable || []).map(m => m.name);
            const perf = data.performance || {};
            const score = data.security_score || 0;
            const risks = data.risk_notes || [];

            let html = '<div class="rls-impact-section"><h4>Производительность</h4>';
            html += '<span class="rls-impact-metric"><strong>' + perf.ms + '</strong> на запрос</span>';
            html += '<span class="rls-impact-metric">Нагрузка: <strong>' + perf.label + '</strong></span>';
            html += '<span class="rls-impact-metric"><strong>' + score + '/100</strong> Security Score</span>';
            html += '</div>';

            html += '<div class="rls-impact-section"><h4>Будет включено</h4>';
            if (enable.length === 0) {
                html += '<div class="rls-impact-empty">Ничего нового не будет включено</div>';
            } else {
                html += '<ul class="rls-impact-list">' + enable.map(n => '<li class="is-enable">✓ ' + escapeHtml(n) + '</li>').join('') + '</ul>';
            }
            html += '</div>';

            html += '<div class="rls-impact-section"><h4>Будет выключено</h4>';
            if (disable.length === 0) {
                html += '<div class="rls-impact-empty">Ничего не будет выключено</div>';
            } else {
                html += '<ul class="rls-impact-list">' + disable.map(n => '<li class="is-disable">✕ ' + escapeHtml(n) + '</li>').join('') + '</ul>';
            }
            html += '</div>';

            if (risks.length > 0) {
                html += '<div class="rls-impact-risks"><h4>⚠ Возможные риски</h4><ul>';
                risks.forEach(r => { html += '<li>' + escapeHtml(r) + '</li>'; });
                html += '</ul></div>';
            }
            $('#rls-impact-body').html(html);
        }

        function escapeHtml(text) {
            if (!text) return text;
            return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        }

        // Emergency mode activation.
        $(document).on('click', '.rls-emergency-activate', function(e) {
            e.preventDefault();
            const mode = $(this).data('emergency');
            const duration = $(this).data('duration');
            $('#rls-emergency-modal').data('mode', mode).data('duration', duration).css('display', 'flex');
        });

        $(document).on('click', '#rls-emergency-cancel', () => {
            $('#rls-emergency-modal').hide();
        });

        $(document).on('click', '#rls-emergency-confirm', function() {
            const modal = $('#rls-emergency-modal');
            const mode = modal.data('mode');
            const duration = modal.data('duration');
            modal.hide();
            $.post(rls_admin_data.ajax_url, {
                action: 'rls_activate_emergency_mode',
                nonce: rls_admin_data.settings_nonce,
                mode,
                duration
            }).done((res) => {
                if (res && res.success) {
                    if (window.RLS_Toast) RLS_Toast.warning(res.data.message || 'Аварийный режим активирован');
                    setTimeout(() => location.reload(), 600);
                } else {
                    if (window.RLS_Toast) RLS_Toast.danger((res && res.data) || 'Ошибка');
                }
            });
        });

        $(document).on('click', '#rls-emergency-disable', function(e) {
            e.preventDefault();
            const mode = $(this).data('emergency-mode');
            if (window.RLS_Confirm) {
                RLS_Confirm.show({
                    title: 'Деактивировать аварийный режим?',
                    message: 'Сайт снова станет доступен для обычных посетителей.',
                    confirmText: 'Деактивировать',
                    cancelText: 'Отмена',
                }).then((ok) => {
                    if (ok) {
                        $.post(rls_admin_data.ajax_url, {
                            action: 'rls_deactivate_emergency_mode',
                            nonce: rls_admin_data.settings_nonce
                        }).done(() => location.reload());
                    }
                });
            }
        });
    });
})(jQuery);

/* =================================================================
 * 11. PREMIUM CELEBRATION — confetti on activation
 * ================================================================= */
(function($) {
    $(function() {
        // Detect premium activation (URL has ?premium_activated=1).
        if (window.location.search.indexOf('premium_activated') !== -1 && window.RLS_Toast) {
            RLS_Toast.success('Добро пожаловать в Premium!', '🎉 Premium активирован');
            setTimeout(function() { fireConfetti(); }, 300);
        }
        // Detect deactivation.
        if (window.location.search.indexOf('premium_deactivated') !== -1 && window.RLS_Toast) {
            RLS_Toast.info('Premium деактивирован. Плагин работает в Free-режиме.');
        }

        // Confetti for premium activation.
        function fireConfetti() {
            const container = document.createElement('div');
            container.style.cssText = 'position:fixed; inset:0; pointer-events:none; z-index:9999999; overflow:hidden;';
            document.body.appendChild(container);
            const colors = ['#fde047', '#f59e0b', '#22d3ee', '#a78bfa', '#4ade80', '#f472b6'];
            for (let i = 0; i < 80; i++) {
                const piece = document.createElement('div');
                piece.style.cssText = `
                    position:absolute;
                    top:-10px;
                    left:${Math.random() * 100}%;
                    width:${6 + Math.random() * 8}px;
                    height:${10 + Math.random() * 12}px;
                    background:${colors[Math.floor(Math.random() * colors.length)]};
                    transform:rotate(${Math.random() * 360}deg);
                    border-radius:${Math.random() > 0.5 ? '50%' : '2px'};
                    opacity:0.95;
                `;
                container.appendChild(piece);
                const duration = 1500 + Math.random() * 2000;
                const startX = Math.random() * 100;
                piece.animate([
                    { transform: `translate(0, 0) rotate(0deg)`, opacity: 1 },
                    { transform: `translate(${(Math.random() - 0.5) * 200}px, ${window.innerHeight + 100}px) rotate(${Math.random() * 720}deg)`, opacity: 0 }
                ], { duration, easing: 'cubic-bezier(0.4, 0, 0.6, 1)' });
                setTimeout(() => piece.remove(), duration);
            }
            setTimeout(() => container.remove(), 4000);
        }
        window.RLS_fireConfetti = fireConfetti;

        // Premium page: click on feature to scroll to comparison table.
        $(document).on('click', '.rls-premium-feature', function() {
            $(this).toggleClass('is-expanded');
        });
    });
})(jQuery);

/* =================================================================
 * 12. SCANNER v2.6.0 — real-time progress, diff, exports, FP report
 * ================================================================= */
(function($) {
    $(function() {
        // Real-time progress polling.
        const progressBar = document.getElementById('rls-scan-progress-fill');
        const progressStatTotal = document.getElementById('rls-scan-stat-total');
        const progressStatScanned = document.getElementById('rls-scan-stat-scanned');
        const progressStatThreats = document.getElementById('rls-scan-stat-threats');
        const progressStatSkipped = document.getElementById('rls-scan-stat-skipped');
        const progressCurrent = document.getElementById('rls-scan-current-file');
        const progressEta = document.getElementById('rls-scan-eta');

        if (progressBar) {
            let pollInterval = null;
            function pollProgress() {
                $.post(rls_admin_data.ajax_url, {
                    action: 'rls_get_scan_progress',
                    nonce: rls_admin_data.settings_nonce
                }).done((res) => {
                    if ( ! res || ! res.success ) return;
                    const p = res.data || {};
                    const total = parseInt(p.total, 10) || 0;
                    const scanned = parseInt(p.scanned, 10) || 0;
                    const threats = parseInt(p.threats, 10) || 0;
                    const skipped = parseInt(p.skipped, 10) || 0;
                    const pct = total > 0 ? ( scanned / total * 100 ) : 0;
                    progressBar.style.width = pct + '%';
                    if (progressStatTotal) progressStatTotal.textContent = total;
                    if (progressStatScanned) progressStatScanned.textContent = scanned;
                    if (progressStatThreats) progressStatThreats.textContent = threats;
                    if (progressStatSkipped) progressStatSkipped.textContent = skipped;
                    if (progressCurrent && p.current) progressCurrent.textContent = '📄 ' + p.current;
                    if (progressEta && p.eta_seconds) {
                        const mm = Math.floor(p.eta_seconds / 60);
                        const ss = p.eta_seconds % 60;
                        progressEta.textContent = mm + ':' + String(ss).padStart(2, '0');
                    }
                    if (p.finished) {
                        if (pollInterval) clearInterval(pollInterval);
                        if (window.RLS_Toast) {
                            RLS_Toast.success('Сканирование завершено', 'Сканер');
                            setTimeout(() => location.reload(), 800);
                        }
                    }
                });
            }
            pollProgress();
            pollInterval = setInterval(pollProgress, 1500);
        }

        // DB scan + Checksums + Diff + Export.
        $('#rls-run-db-scan').on('click', function() {
            const btn = $(this).prop('disabled', true).text('Сканирование...');
            $.post(rls_admin_data.ajax_url, {
                action: 'rls_db_scan',
                nonce: rls_admin_data.settings_nonce
            }).done((res) => {
                if (res && res.success) {
                    if (window.RLS_Toast) RLS_Toast.info(res.data.message || 'DB scan done');
                } else if (window.RLS_Toast) RLS_Toast.danger((res && res.data) || 'Error');
                location.reload();
            });
        });
        $('#rls-run-checksums-scan').on('click', function() {
            const btn = $(this).prop('disabled', true).text('Проверка...');
            $.post(rls_admin_data.ajax_url, {
                action: 'rls_checksums_scan',
                nonce: rls_admin_data.settings_nonce
            }).done((res) => {
                if (res && res.success) {
                    if (window.RLS_Toast) RLS_Toast.info(res.data.message || 'Checksums done');
                } else if (window.RLS_Toast) RLS_Toast.danger((res && res.data) || 'Error');
                location.reload();
            });
        });
        $('#rls-auto-quarantine').on('click', function() {
            if (window.RLS_Confirm) {
                RLS_Confirm.show({
                    title: 'Авто-карантин critical угроз',
                    message: 'Все файлы с risk_score ≥ 90 будут перемещены в карантин с backup. Продолжить?',
                    type: 'danger',
                    confirmText: 'Карантин',
                }).then((ok) => {
                    if (ok) {
                        $.post(rls_admin_data.ajax_url, {
                            action: 'rls_auto_quarantine_critical',
                            nonce: rls_admin_data.settings_nonce
                        }).done((res) => {
                            if (window.RLS_Toast) {
                                if (res && res.success) RLS_Toast.success(res.data.message);
                                else RLS_Toast.danger((res && res.data) || 'Error');
                            }
                            location.reload();
                        });
                    }
                });
            }
        });

        // Diff between scans.
        $('#rls-run-diff').on('click', function() {
            const a = $('#rls-diff-scan-a').val();
            const b = $('#rls-diff-scan-b').val();
            if ( ! a || ! b ) { alert('Выберите оба скана для сравнения'); return; }
            $.post(rls_admin_data.ajax_url, {
                action: 'rls_diff_scans',
                nonce: rls_admin_data.settings_nonce,
                scan_a: a,
                scan_b: b
            }).done((res) => {
                if (res && res.success) {
                    renderDiff(res.data);
                } else if (window.RLS_Toast) RLS_Toast.danger((res && res.data) || 'Error');
            });
        });
        function renderDiff(d) {
            const root = $('#rls-diff-result');
            if ( ! root.length ) return;
            const renderList = (arr) => arr.map(p => '<li>' + escapeHtml(p) + '</li>').join('') || '<li style="color:var(--rls-text-subtle);">Нет</li>';
            root.html(
                '<div class="rls-diff-grid">' +
                    '<div class="rls-diff-col is-new"><h4>🆕 Новые (' + d.new.length + ')</h4><ul class="rls-diff-list">' + renderList(d.new) + '</ul></div>' +
                    '<div class="rls-diff-col is-fixed"><h4>✓ Исправленные (' + d.fixed.length + ')</h4><ul class="rls-diff-list">' + renderList(d.fixed) + '</ul></div>' +
                    '<div class="rls-diff-col is-persistent"><h4>⚠ Остались (' + d.persistent.length + ')</h4><ul class="rls-diff-list">' + renderList(d.persistent) + '</ul></div>' +
                '</div>'
            );
            root.show();
        }

        // False Positive report.
        $(document).on('click', '.rls-report-fp', function(e) {
            e.preventDefault();
            const file = $(this).data('file');
            const rule = $(this).data('rule') || '';
            $.post(rls_admin_data.ajax_url, {
                action: 'rls_report_false_positive',
                nonce: rls_admin_data.settings_nonce,
                file,
                rule
            }).done((res) => {
                if (window.RLS_Toast) {
                    if (res && res.success) RLS_Toast.success('Добавлено в whitelist');
                    else RLS_Toast.danger((res && res.data) || 'Error');
                }
            });
        });

        // Threat details modal.
        $(document).on('click', '.rls-threat-row', function() {
            const file = $(this).data('file');
            const line = $(this).data('line') || 0;
            const snippet = $(this).data('snippet') || '';
            const rule = $(this).data('rule') || '';
            const tags = ($(this).data('tags') || '').split(',').filter(Boolean);
            const risk = $(this).data('risk') || 0;

            const modal = $('#rls-threat-modal');
            if ( ! modal.length ) return;
            modal.find('.rls-modal-title').text('Детали угрозы');
            let body = '<div class="rls-threat-detail">';
            body += '<p><strong>Файл:</strong> <code>' + escapeHtml(file) + '</code></p>';
            body += '<p><strong>Строка:</strong> ' + line + '</p>';
            body += '<p><strong>Правило:</strong> ' + escapeHtml(rule) + '</p>';
            body += '<p><strong>Risk Score:</strong> <span class="rls-risk-badge rls-risk-' + (risk >= 90 ? 'critical' : risk >= 70 ? 'high' : risk >= 40 ? 'medium' : 'low') + '">' + risk + '</span></p>';
            if (tags.length) {
                body += '<div class="rls-threat-tags">' + tags.map(t => '<span class="rls-threat-tag">' + escapeHtml(t) + '</span>').join('') + '</div>';
            }
            if (snippet) {
                body += '<pre class="rls-threat-snippet">' + escapeHtml(snippet) + '</pre>';
            }
            body += '<div style="display:flex; gap:8px; margin-top:14px;">';
            body += '<button class="button button-link-delete rls-report-fp" data-file="' + escapeHtml(file) + '" data-rule="' + escapeHtml(rule) + '">Это не угроза</button>';
            body += '<a class="button" href="?page=rls-scanner&action=quarantine&file=' + encodeURIComponent(file) + '" style="margin-left:auto;">В карантин →</a>';
            body += '</div>';
            body += '</div>';
            modal.find('.rls-modal-body').html(body);
            modal.css('display', 'flex');
        });
        $(document).on('click', '#rls-threat-modal-close', () => $('#rls-threat-modal').hide());
        $(document).on('click', '#rls-threat-modal', (e) => { if (e.target.id === 'rls-threat-modal') $('#rls-threat-modal').hide(); });

        function escapeHtml(text) {
            if (!text) return '';
            return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }
    });
})(jQuery);
