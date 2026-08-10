/**
 * 越权测试报告交互控制器
 * 功能: 用户信息卡片构建 / 端点折叠展开 / 截图灯箱 / 会话分布表排序
 */
(function() {
    'use strict';

    var currentSort = { column: 0, asc: true };

    // 灯箱截图分组存储：key=组ID, value=图片URL数组
    window._lightboxGroups = {};

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
            var groupId = 'testInfoConfig';
            window._lightboxGroups[groupId] = [];
            html += '<div class="screenshot-gallery">';
            config.screenshotFilenames.forEach(function(filename) {
                var imgSrc = 'screenshots/' + encodeURIComponent(filename);
                window._lightboxGroups[groupId].push(imgSrc);
                html += '<img src="' + imgSrc + '" ';
                html += 'class="screenshot-thumb" onclick="openLightbox(this.src, \'' + groupId + '\')" ';
                html += 'alt="' + escapeHtml(filename) + '" loading="lazy" data-group="' + groupId + '">';
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
                var groupId = 'userInfo_' + entry.sessionName;
                window._lightboxGroups[groupId] = [];
                html += '<div class="screenshot-gallery">';
                entry.screenshotFilenames.forEach(function(filename) {
                    var imgSrc = 'screenshots/' + encodeURIComponent(filename);
                    window._lightboxGroups[groupId].push(imgSrc);
                    html += '<img src="' + imgSrc + '" ';
                    html += 'class="screenshot-thumb" onclick="openLightbox(this.src, \'' + groupId + '\')" ';
                    html += 'alt="' + escapeHtml(filename) + '" loading="lazy" data-group="' + groupId + '">';
                });
                html += '</div>';
            }

            html += '</div>';
        });
        html += '</div>';
        container.innerHTML = html;
    }

    /**
     * 打开截图灯箱（支持缩放、拖拽、轮播、键盘快捷键）
     * @param {string} src - 图片URL
     * @param {string} [groupId] - 截图分组ID，提供时启用轮播模式
     */
    window.openLightbox = function(src, groupId) {
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

        // 轮播状态
        var images = [];
        var currentIndex = 0;
        if (groupId && window._lightboxGroups[groupId] && window._lightboxGroups[groupId].length > 1) {
            images = window._lightboxGroups[groupId];
            currentIndex = images.indexOf(src);
            if (currentIndex < 0) currentIndex = 0;
        } else {
            images = [src];
            currentIndex = 0;
        }
        var isCarousel = images.length > 1;

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

        // 图片计数（仅轮播模式显示）
        var counter = null;
        if (isCarousel) {
            counter = document.createElement('span');
            counter.className = 'lightbox-counter';
            counter.textContent = '第' + (currentIndex + 1) + '张，共' + images.length + '张';
        }

        var closeBtn = document.createElement('button');
        closeBtn.className = 'lightbox-btn lightbox-close-btn';
        closeBtn.textContent = '\u00D7';
        closeBtn.title = '关闭 (Esc)';

        toolbar.appendChild(zoomOutBtn);
        toolbar.appendChild(zoomLevel);
        toolbar.appendChild(zoomInBtn);
        toolbar.appendChild(resetBtn);
        if (counter) toolbar.appendChild(counter);
        toolbar.appendChild(closeBtn);

        // 图片容器（支持拖拽）
        var imgWrap = document.createElement('div');
        imgWrap.className = 'lightbox-img-wrap';

        // 加载指示器
        var loading = document.createElement('div');
        loading.className = 'lightbox-loading';
        loading.style.display = 'none';

        var img = document.createElement('img');
        img.src = src;
        img.className = 'lightbox-image';
        img.draggable = false;

        imgWrap.appendChild(loading);
        imgWrap.appendChild(img);

        // 左右导航箭头（仅轮播模式）
        var prevBtn = null;
        var nextBtn = null;
        if (isCarousel) {
            prevBtn = document.createElement('button');
            prevBtn.className = 'lightbox-nav-btn lightbox-nav-prev';
            prevBtn.innerHTML = '\u2039';
            prevBtn.title = '上一张 (\u2190)';

            nextBtn = document.createElement('button');
            nextBtn.className = 'lightbox-nav-btn lightbox-nav-next';
            nextBtn.innerHTML = '\u203A';
            nextBtn.title = '下一张 (\u2192)';

            container.appendChild(prevBtn);
            container.appendChild(nextBtn);
        }

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

        // 重置缩放和平移
        function resetTransform() {
            scale = 1;
            translateX = 0;
            translateY = 0;
            applyTransform();
            imgWrap.style.cursor = 'default';
        }

        // 切换图片
        function showImage(index) {
            if (index < 0) index = images.length - 1;
            if (index >= images.length) index = 0;
            currentIndex = index;
            resetTransform();
            loading.style.display = 'flex';
            img.style.opacity = '0';
            img.src = images[currentIndex];
            if (counter) {
                counter.textContent = '第' + (currentIndex + 1) + '张，共' + images.length + '张';
            }
        }

        img.onload = function() {
            loading.style.display = 'none';
            img.style.opacity = '1';
        };

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
            resetTransform();
        };

        // 导航按钮
        if (prevBtn) {
            prevBtn.onclick = function(e) { e.stopPropagation(); showImage(currentIndex - 1); };
        }
        if (nextBtn) {
            nextBtn.onclick = function(e) { e.stopPropagation(); showImage(currentIndex + 1); };
        }

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
                case 'ArrowLeft':
                    if (isCarousel) { e.preventDefault(); showImage(currentIndex - 1); }
                    break;
                case 'ArrowRight':
                    if (isCarousel) { e.preventDefault(); showImage(currentIndex + 1); }
                    break;
                case '+': case '=':
                    var rect = imgWrap.getBoundingClientRect();
                    setScale(scale * 1.2, rect.left + rect.width / 2, rect.top + rect.height / 2);
                    break;
                case '-':
                    var rect2 = imgWrap.getBoundingClientRect();
                    setScale(scale / 1.2, rect2.left + rect2.width / 2, rect2.top + rect2.height / 2);
                    break;
                case '0':
                    resetTransform();
                    break;
            }
        }
        document.addEventListener('keydown', onKeyDown);

        // 初始应用
        applyTransform();
    };

    /**
     * 构建摘要卡片区域
     */
    function buildSummarySection() {
        var data = window.REPORT_DATA;
        var container = document.getElementById('summary-section');
        if (!data || !data.summary || !container) {
            return;
        }
        var s = data.summary;
        var html = '<h2>摘要</h2><div class="summary-cards">';
        html += '<div class="card total"><div class="number">' + s.totalTests + '</div><div class="label">测试总数</div></div>';
        html += '<div class="card escalated"><div class="number">' + s.escalatedCount + '</div><div class="label">\u26A0 越权</div></div>';
        html += '<div class="card safe"><div class="number">' + s.safeCount + '</div><div class="label">\u2714 安全</div></div>';
        html += '<div class="card error"><div class="number">' + s.errorCount + '</div><div class="label">\u2716 错误</div></div>';
        html += '<div class="card" style="border-top:4px solid #1565C0"><div class="number" style="color:#1565C0">'
            + s.baselineCount + '</div><div class="label">基线</div></div>';
        html += '</div>';
        container.innerHTML = html;
    }

    /**
     * 构建会话分布表（保留 id="session-table" 与 tbody 结构以兼容排序逻辑）
     */
    function buildSessionBreakdownSection() {
        var data = window.REPORT_DATA;
        var container = document.getElementById('session-breakdown-section');
        if (!data || !data.sessionBreakdown || data.sessionBreakdown.length === 0 || !container) {
            return;
        }
        var html = '<h2>会话分布</h2><table id="session-table">';
        html += '<thead><tr><th>会话</th><th>越权</th><th>安全</th><th>错误</th><th>总计</th></tr></thead>';
        html += '<tbody>';
        data.sessionBreakdown.forEach(function(sb) {
            html += '<tr>';
            html += '<td>' + escapeHtml(sb.sessionName) + '</td>';
            html += '<td>' + sb.escalatedCount + '</td>';
            html += '<td>' + sb.safeCount + '</td>';
            html += '<td>' + sb.errorCount + '</td>';
            html += '<td>' + sb.totalTests + '</td>';
            html += '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
    }

    /**
     * 构建接口请求行列表（越权/报错(存疑)/安全通用）
     */
    function buildEndpointListSection(containerId, title, lines, listClass, itemClass) {
        var container = document.getElementById(containerId);
        if (!lines || lines.length === 0 || !container) {
            return;
        }
        var html = '<h2>' + title + '</h2>';
        html += '<div class="endpoint-list ' + listClass + '"><ol>';
        lines.forEach(function(line) {
            html += '<li class="' + itemClass + '">' + escapeHtml(line) + '</li>';
        });
        html += '</ol></div>';
        container.innerHTML = html;
    }

    /**
     * 构建端点报文详情区域（基线报文 + 各用户会话报文）
     */
    function buildEndpointsSection() {
        var data = window.REPORT_DATA;
        var container = document.getElementById('endpoints-section');
        if (!data || !data.endpoints || data.endpoints.length === 0 || !container) {
            return;
        }
        var html = '<h2>报文详情</h2>';
        data.endpoints.forEach(function(ep) {
            var totalTests = ep.escalatedCount + ep.safeCount + ep.errorCount;
            var indexText = String(ep.endpointIndex).padStart(2, '0');
            html += '<div class="endpoint-section">';
            html += '<div class="endpoint-header"><div>';
            html += '<h3>api_' + indexText + ' <span class="method">' + escapeHtml(ep.method) + '</span> ' + escapeHtml(ep.url) + '</h3>';
            html += '</div><div class="meta-info">';
            if (ep.baselineCount > 0) {
                html += '基线: ' + ep.baselineCount + ' | ';
            }
            html += '测试: ' + totalTests;
            if (ep.escalatedCount > 0) {
                html += ' | <span style="color:#d32f2f;font-weight:600">\u26A0 ' + ep.escalatedCount + ' 越权</span>';
            }
            html += ' | \u2714 ' + ep.safeCount + ' 安全';
            html += '</div></div>';

            // 基线报文块
            if (ep.baselineData) {
                var bd = ep.baselineData;
                html += '<div class="session-block baseline-block">';
                html += '<div class="session-header baseline-header">';
                html += '<span>原始基准 HTTP 数据 — 参考对照标准</span>';
                html += '<span class="badge baseline">基线</span>';
                html += '</div><div class="session-content">';
                html += '<p class="baseline-note">基准报文是参考用户的原始请求与响应，用于与各会话重放结果对比分析，判断是否存在越权。</p>';
                html += '<div class="section-title">请求</div>';
                html += bd.requestHtml || '';
                html += '<div class="section-title">响应 — HTTP ' + bd.statusCode
                    + ' (' + bd.responseLength + ' bytes, ' + bd.responseTime + 'ms)</div>';
                html += bd.responseHtml || '';
                html += '</div></div>';
            }

            // 用户会话报文块
            (ep.userSessions || []).forEach(function(us) {
                var badgeClass;
                var badgeIcon;
                if (us.judgment === 'ESCALATED') {
                    badgeClass = 'escalated';
                    badgeIcon = '\u26A0 ';
                } else if (us.judgment === 'NOT_ESCALATED') {
                    badgeClass = 'safe';
                    badgeIcon = '\u2714 ';
                } else {
                    badgeClass = 'error';
                    badgeIcon = '\u2716 ';
                }
                html += '<div class="session-block">';
                html += '<div class="session-header">';
                html += '<span>' + escapeHtml(us.sessionName) + ' HTTP 数据</span>';
                html += '<span class="badge ' + badgeClass + '">' + badgeIcon + escapeHtml(us.judgmentDisplayName) + '</span>';
                html += '</div><div class="session-content">';
                if (us.matchedRuleName) {
                    html += '<div>规则: <strong>' + escapeHtml(us.matchedRuleName) + '</strong></div>';
                }
                html += '<div class="meta-info">相似度: ' + escapeHtml(us.similarityDisplay) + '</div>';

                html += '<div class="section-title">请求</div>';
                html += us.requestHtml || '';

                html += '<div class="section-title">响应 — HTTP ' + us.statusCode
                    + ' (' + us.responseLength + ' bytes, ' + us.responseTime + 'ms)</div>';
                html += us.responseHtml || '';

                html += '<div class="section-title">复现命令 — cURL</div>';
                html += '<pre class="curl-block">' + escapeHtml(us.curlCommand) + '</pre>';

                html += '<div class="section-title">复现导入 — Postman</div>';
                html += '<pre class="postman-block">' + escapeHtml(us.postmanSnippet) + '</pre>';

                html += '</div></div>';
            });

            html += '</div>';
        });
        container.innerHTML = html;
    }

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
        var data = window.REPORT_DATA || {};
        buildTestInfoSection();
        buildUserInfoSection();
        buildSummarySection();
        buildSessionBreakdownSection();
        buildEndpointListSection('escalated-list-section', '越权接口列表',
            data.escalatedEndpoints, 'escalated-list', 'escalated-item');
        buildEndpointListSection('error-list-section', '报错(存疑)接口列表',
            data.errorEndpoints, 'error-list', 'error-item');
        buildEndpointListSection('safe-list-section', '安全接口列表',
            data.safeEndpoints, 'safe-list', 'safe-item');
        buildEndpointsSection();
        bindEndpointToggle();
        bindTableSort();
    });
})();
