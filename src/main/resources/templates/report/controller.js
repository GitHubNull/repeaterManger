/**
 * 越权测试报告交互控制器
 * 功能: 用户信息卡片构建 / 端点折叠展开 / 截图灯箱 / 会话分布表排序
 */
(function() {
    'use strict';

    var currentSort = { column: 0, asc: true };

    /**
     * 构建测试信息配置区域
     */
    function buildTestInfoSection() {
        var data = window.REPORT_DATA;
        if (!data || !data.testInfoConfig) {
            return;
        }

        var container = document.getElementById('test-info-section');
        if (!container) return;

        var config = data.testInfoConfig;
        var html = '<h2>测试信息配置</h2><div class="test-info-config"><table class="test-info-table">';

        if (config.targetName) {
            html += '<tr><td class="test-info-label">目标名称</td><td>' + escapeHtml(config.targetName) + '</td></tr>';
        }
        if (config.targetEntry) {
            html += '<tr><td class="test-info-label">目标入口</td><td><a href="' + sanitizeUrl(config.targetEntry)
                + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(config.targetEntry) + '</a></td></tr>';
        }
        if (config.testTimeRange) {
            html += '<tr><td class="test-info-label">测试时间段</td><td>' + escapeHtml(config.testTimeRange) + '</td></tr>';
        }
        if (config.testPersonnel) {
            html += '<tr><td class="test-info-label">测试人员</td><td>' + escapeHtml(config.testPersonnel) + '</td></tr>';
        }

        html += '</table>';

        // 截图
        if (config.screenshotFilenames && config.screenshotFilenames.length > 0) {
            html += '<div class="screenshot-gallery">';
            config.screenshotFilenames.forEach(function(filename) {
                html += '<img src="screenshots/' + encodeURIComponent(filename) + '" ';
                html += 'class="screenshot-thumb" onclick="openLightbox(this.src)" ';
                html += 'alt="' + escapeHtml(filename) + '" loading="lazy">';
            });
            html += '</div>';
        }

        html += '</div>';
        container.innerHTML = html;
    }

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
     * 打开截图灯箱（支持缩放与拖拽）
     */
    window.openLightbox = function(src) {
        var scale = 1;
        var minScale = 0.2;
        var maxScale = 5;
        var translateX = 0;
        var translateY = 0;
        var isDragging = false;
        var dragStartX = 0;
        var dragStartY = 0;
        var dragTranslateStartX = 0;
        var dragTranslateStartY = 0;

        // 遮罩层
        var overlay = document.createElement('div');
        overlay.className = 'lightbox-overlay';

        // 容器（85vw x 85vh）
        var container = document.createElement('div');
        container.className = 'lightbox-container';

        // 工具栏
        var toolbar = document.createElement('div');
        toolbar.className = 'lightbox-toolbar';

        var zoomOutBtn = document.createElement('button');
        zoomOutBtn.className = 'lightbox-btn';
        zoomOutBtn.textContent = '\u2212';
        zoomOutBtn.title = '缩小';

        var zoomLevel = document.createElement('span');
        zoomLevel.className = 'lightbox-zoom-level';
        zoomLevel.textContent = '100%';

        var zoomInBtn = document.createElement('button');
        zoomInBtn.className = 'lightbox-btn';
        zoomInBtn.textContent = '+';
        zoomInBtn.title = '放大';

        var resetBtn = document.createElement('button');
        resetBtn.className = 'lightbox-btn';
        resetBtn.textContent = '\u21BA';
        resetBtn.title = '重置';

        var closeBtn = document.createElement('button');
        closeBtn.className = 'lightbox-btn lightbox-close-btn';
        closeBtn.textContent = '\u00D7';
        closeBtn.title = '关闭 (Esc)';

        toolbar.appendChild(zoomOutBtn);
        toolbar.appendChild(zoomLevel);
        toolbar.appendChild(zoomInBtn);
        toolbar.appendChild(resetBtn);
        toolbar.appendChild(closeBtn);

        // 图片容器（支持拖拽）
        var imgWrap = document.createElement('div');
        imgWrap.className = 'lightbox-img-wrap';

        var img = document.createElement('img');
        img.src = src;
        img.className = 'lightbox-image';
        img.draggable = false;

        imgWrap.appendChild(img);
        container.appendChild(toolbar);
        container.appendChild(imgWrap);
        overlay.appendChild(container);
        document.body.appendChild(overlay);

        // 应用缩放与平移
        function applyTransform() {
            img.style.transform = 'translate(' + translateX + 'px, ' + translateY + 'px) scale(' + scale + ')';
            zoomLevel.textContent = Math.round(scale * 100) + '%';
        }

        // 设置缩放
        function setScale(newScale, centerX, centerY) {
            var oldScale = scale;
            scale = Math.max(minScale, Math.min(maxScale, newScale));
            if (scale === oldScale) return;

            // 以鼠标位置为中心缩放
            if (centerX !== undefined && centerY !== undefined) {
                var ratio = scale / oldScale;
                translateX = centerX - ratio * (centerX - translateX);
                translateY = centerY - ratio * (centerY - translateY);
            }
            applyTransform();
        }

        // 缩放按钮
        zoomInBtn.onclick = function(e) {
            e.stopPropagation();
            var rect = imgWrap.getBoundingClientRect();
            setScale(scale * 1.2, rect.left + rect.width / 2, rect.top + rect.height / 2);
        };

        zoomOutBtn.onclick = function(e) {
            e.stopPropagation();
            var rect = imgWrap.getBoundingClientRect();
            setScale(scale / 1.2, rect.left + rect.width / 2, rect.top + rect.height / 2);
        };

        resetBtn.onclick = function(e) {
            e.stopPropagation();
            scale = 1;
            translateX = 0;
            translateY = 0;
            applyTransform();
        };

        // 鼠标滚轮缩放
        imgWrap.addEventListener('wheel', function(e) {
            e.preventDefault();
            var rect = imgWrap.getBoundingClientRect();
            var mouseX = e.clientX - rect.left;
            var mouseY = e.clientY - rect.top;
            var delta = e.deltaY > 0 ? 0.9 : 1.1;
            setScale(scale * delta, mouseX, mouseY);
        }, { passive: false });

        // 鼠标拖拽平移
        function onMouseMove(e) {
            if (!isDragging) return;
            translateX = dragTranslateStartX + (e.clientX - dragStartX);
            translateY = dragTranslateStartY + (e.clientY - dragStartY);
            applyTransform();
        }

        function onMouseUp() {
            if (isDragging) {
                isDragging = false;
                imgWrap.style.cursor = scale > 1 ? 'grab' : 'default';
            }
        }

        imgWrap.addEventListener('mousedown', function(e) {
            if (e.button !== 0) return;
            isDragging = true;
            dragStartX = e.clientX;
            dragStartY = e.clientY;
            dragTranslateStartX = translateX;
            dragTranslateStartY = translateY;
            imgWrap.style.cursor = 'grabbing';
            e.preventDefault();
        });

        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);

        // 光标样式随缩放变化
        var origSetScale = setScale;
        setScale = function(newScale, cx, cy) {
            origSetScale(newScale, cx, cy);
            imgWrap.style.cursor = scale > 1 ? 'grab' : 'default';
        };

        // 关闭函数
        function close() {
            document.body.removeChild(overlay);
            document.removeEventListener('keydown', onKeyDown);
            document.removeEventListener('mousemove', onMouseMove);
            document.removeEventListener('mouseup', onMouseUp);
        }

        // 关闭按钮
        closeBtn.onclick = function(e) { e.stopPropagation(); close(); };

        // 点击遮罩关闭
        overlay.addEventListener('click', function(e) {
            if (e.target === overlay) close();
        });

        // 键盘快捷键
        function onKeyDown(e) {
            switch (e.key) {
                case 'Escape': close(); break;
                case '+': case '=':
                    var rect = imgWrap.getBoundingClientRect();
                    setScale(scale * 1.2, rect.left + rect.width / 2, rect.top + rect.height / 2);
                    break;
                case '-':
                    var rect2 = imgWrap.getBoundingClientRect();
                    setScale(scale / 1.2, rect2.left + rect2.width / 2, rect2.top + rect2.height / 2);
                    break;
                case '0':
                    scale = 1; translateX = 0; translateY = 0;
                    applyTransform();
                    imgWrap.style.cursor = 'default';
                    break;
            }
        }
        document.addEventListener('keydown', onKeyDown);

        // 初始应用
        applyTransform();
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

    /**
     * URL 安全处理：过滤危险协议、自动补全 https://
     */
    function sanitizeUrl(url) {
        if (!url) return '#';
        // 过滤危险协议
        if (/^\s*(javascript|data|vbscript):/i.test(url)) return '#';
        // 已有合法协议前缀，直接返回
        if (/^https?:\/\//i.test(url)) return url;
        // 自动补全 https://
        return 'https://' + url;
    }

    // DOM 就绪后执行
    document.addEventListener('DOMContentLoaded', function() {
        buildTestInfoSection();
        buildUserInfoSection();
        bindEndpointToggle();
        bindTableSort();
    });
})();
