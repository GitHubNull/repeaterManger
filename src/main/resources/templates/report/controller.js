/**
 * 越权测试报告交互控制器
 * 功能: 用户信息卡片构建 / 端点折叠展开 / 截图灯箱 / 会话分布表排序
 */
(function() {
    'use strict';

    var currentSort = { column: 0, asc: true };

    /**
     * 构建用户信息卡片区域
     */
    function buildUserInfoSection() {
        var data = window.REPORT_DATA;
        if (!data || !data.userInfoEntries || data.userInfoEntries.length === 0) {
            return;
        }

        var container = document.getElementById('user-info-section');
        if (!container) return;

        var html = '<h2>用户信息</h2><div class="user-info-cards">';
        data.userInfoEntries.forEach(function(entry) {
            var displayName = entry.isAnonymous ? '匿名用户' : (entry.username || entry.sessionName);
            var roleText = entry.role || (entry.isAnonymous ? '匿名' : '-');
            html += '<div class="user-info-card">';
            html += '<div class="user-info-header">';
            html += '<span class="user-session-name">' + escapeHtml(entry.sessionName) + '</span>';
            if (entry.isAnonymous) {
                html += '<span class="badge anonymous">匿名</span>';
            }
            html += '</div>';
            html += '<div class="user-info-fields">';
            html += '<div class="info-field"><span class="field-label">角色:</span><span>' + escapeHtml(roleText) + '</span></div>';
            html += '<div class="info-field"><span class="field-label">用户名:</span><span>' + escapeHtml(displayName) + '</span></div>';
            html += '</div>';

            // 截图
            if (entry.screenshotFilenames && entry.screenshotFilenames.length > 0) {
                html += '<div class="screenshot-gallery">';
                entry.screenshotFilenames.forEach(function(filename) {
                    html += '<img src="screenshots/' + encodeURIComponent(filename) + '" ';
                    html += 'class="screenshot-thumb" onclick="openLightbox(this.src)" ';
                    html += 'alt="' + escapeHtml(filename) + '" loading="lazy">';
                });
                html += '</div>';
            }

            html += '</div>';
        });
        html += '</div>';
        container.innerHTML = html;
    }

    /**
     * 打开截图灯箱
     */
    window.openLightbox = function(src) {
        var overlay = document.createElement('div');
        overlay.className = 'lightbox-overlay';
        overlay.onclick = function() { document.body.removeChild(overlay); };

        var img = document.createElement('img');
        img.src = src;
        img.className = 'lightbox-image';

        var closeBtn = document.createElement('span');
        closeBtn.className = 'lightbox-close';
        closeBtn.textContent = '\u00D7';
        closeBtn.onclick = function(e) { e.stopPropagation(); document.body.removeChild(overlay); };

        overlay.appendChild(closeBtn);
        overlay.appendChild(img);
        document.body.appendChild(overlay);
    };

    /**
     * 排序会话分布表
     */
    function sortSessionTable(columnIndex) {
        var table = document.getElementById('session-table');
        if (!table) return;
        var tbody = table.querySelector('tbody');
        var rows = Array.from(tbody.querySelectorAll('tr'));

        if (currentSort.column === columnIndex) {
            currentSort.asc = !currentSort.asc;
        } else {
            currentSort.column = columnIndex;
            currentSort.asc = true;
        }

        rows.sort(function(a, b) {
            var aVal = a.cells[columnIndex].textContent.trim();
            var bVal = b.cells[columnIndex].textContent.trim();
            // 尝试数字比较
            var aNum = parseFloat(aVal);
            var bNum = parseFloat(bVal);
            if (!isNaN(aNum) && !isNaN(bNum)) {
                return currentSort.asc ? aNum - bNum : bNum - aNum;
            }
            return currentSort.asc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
        });

        rows.forEach(function(row) { tbody.appendChild(row); });

        // 更新表头指示器
        table.querySelectorAll('th').forEach(function(th, i) {
            th.classList.remove('sort-asc', 'sort-desc');
            if (i === columnIndex) {
                th.classList.add(currentSort.asc ? 'sort-asc' : 'sort-desc');
            }
        });
    }

    /**
     * 为会话分布表绑定排序
     */
    function bindTableSort() {
        var table = document.getElementById('session-table');
        if (!table) return;
        var headers = table.querySelectorAll('th');
        headers.forEach(function(th, i) {
            th.style.cursor = 'pointer';
            th.title = '点击排序';
            th.onclick = function() { sortSessionTable(i); };
        });
    }

    /**
     * 端点报文区域折叠/展开
     */
    function bindEndpointToggle() {
        document.querySelectorAll('.session-header').forEach(function(header) {
            header.style.cursor = 'pointer';
            header.title = '点击折叠/展开';
            header.addEventListener('click', function() {
                var content = this.nextElementSibling;
                if (content) {
                    var isHidden = content.style.display === 'none';
                    content.style.display = isHidden ? '' : 'none';
                    var indicator = this.querySelector('.toggle-indicator');
                    if (indicator) {
                        indicator.textContent = isHidden ? '\u25BC' : '\u25B6';
                    }
                }
            });
        });
    }

    function escapeHtml(text) {
        if (!text) return '';
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // DOM 就绪后执行
    document.addEventListener('DOMContentLoaded', function() {
        buildUserInfoSection();
        bindEndpointToggle();
        bindTableSort();
    });
})();
