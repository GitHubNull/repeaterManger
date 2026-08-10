<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${title}</title>
<#if inlineMode?? && inlineMode>
<#include "html_css.ftl">
<#else>
<link rel="stylesheet" href="style.css">
</#if>
</head>
<body>

<#-- Header -->
<div class="header">
  <h1>${title}</h1>
  <#if subtitle?? && subtitle != "">
  <h2 class="report-subtitle">${subtitle}</h2>
  </#if>
  <p class="meta">生成时间: ${generatedAt} | Repeater Manager v${pluginVersion}<#if !(inlineMode?? && inlineMode)> | <a href="test_cases.html" target="_blank">查看越权测试用例参考</a></#if></p>
</div>

<#if inlineMode?? && inlineMode>

<#-- Test Info Config Section -->
<#if testInfoConfig?? && testInfoConfig.hasAnyData()>
<h2>测试信息配置</h2>
<div class="test-info-config">
  <table class="test-info-table">
    <#if testInfoConfig.targetName?? && testInfoConfig.targetName != "">
    <tr><td class="test-info-label">目标名称</td><td>${testInfoConfig.targetName}</td></tr>
    </#if>
    <#if testInfoConfig.targetEntry?? && testInfoConfig.targetEntry != "">
    <tr><td class="test-info-label">目标入口</td><td><a href="${testInfoConfig.targetEntry?replace('"', '&quot;')}" target="_blank" rel="noopener noreferrer">${testInfoConfig.targetEntry}</a></td></tr>
    </#if>
    <#if testInfoConfig.testTimeRange?? && testInfoConfig.testTimeRange != "">
    <tr><td class="test-info-label">测试时间段</td><td>${testInfoConfig.testTimeRange}</td></tr>
    </#if>
    <#if testInfoConfig.testPersonnel?? && testInfoConfig.testPersonnel != "">
    <tr><td class="test-info-label">测试人员</td><td>${testInfoConfig.testPersonnel}</td></tr>
    </#if>
  </table>
  <#if testInfoConfigScreenshots?? && testInfoConfigScreenshots?size gt 0>
  <div class="screenshot-gallery">
    <#list testInfoConfigScreenshots as img>
    <img src="${img}" class="screenshot-thumb" onclick="openLightbox(this.src, 'testInfoConfig')" alt="测试目标截图" loading="lazy" data-group="testInfoConfig">
    </#list>
  </div>
  </#if>
</div>
</#if>

<#-- User Info Section -->
<#if userInfoEntries?? && userInfoEntries?size gt 0>
<h2>用户信息</h2>
<div class="user-info-cards">
<#list userInfoEntries as entry>
<div class="user-info-card">
  <div class="user-info-header">
    <span class="user-session-name">${entry.sessionName}</span>
    <#if entry.anonymous><span class="badge anonymous">匿名</span></#if>
  </div>
  <div class="user-info-fields">
    <div class="info-field"><span class="field-label">角色:</span><span><#if entry.role?? && entry.role != "">${entry.role}<#elseif entry.anonymous>匿名<#else>-</#if></span></div>
    <div class="info-field"><span class="field-label">用户名:</span><span><#if entry.username?? && entry.username != "">${entry.username}<#elseif entry.anonymous>匿名用户<#else>${entry.sessionName}</#if></span></div>
  </div>
  <#if entry.screenshotFilenames?? && entry.screenshotFilenames?size gt 0>
  <div class="screenshot-gallery">
    <#list entry.screenshotFilenames as fn>
    <span class="screenshot-thumb-placeholder">[截图: ${fn}]</span>
    </#list>
  </div>
  </#if>
</div>
</#list>
</div>
</#if>

<#-- Summary -->
<h2>摘要</h2>
<div class="summary-cards">
  <div class="card total"><div class="number">${summary.totalTests}</div><div class="label">测试总数</div></div>
  <div class="card escalated"><div class="number">${summary.escalatedCount}</div><div class="label">&#9888; 越权</div></div>
  <div class="card safe"><div class="number">${summary.safeCount}</div><div class="label">&#10004; 安全</div></div>
  <div class="card error"><div class="number">${summary.errorCount}</div><div class="label">&#10007; 错误</div></div>
  <div class="card" style="border-top:4px solid #1565C0"><div class="number" style="color:#1565C0">${summary.baselineCount}</div><div class="label">基线</div></div>
</div>

<#-- Session Breakdown -->
<#if sessionBreakdown?? && sessionBreakdown?size gt 0>
<h2>会话分布</h2>
<table id="session-table">
  <tr><th>会话</th><th>越权</th><th>安全</th><th>错误</th><th>总计</th></tr>
  <#list sessionBreakdown as sb>
  <tr>
    <td>${sb.sessionName}</td>
    <td>${sb.escalatedCount}</td>
    <td>${sb.safeCount}</td>
    <td>${sb.errorCount}</td>
    <td>${sb.totalTests}</td>
  </tr>
  </#list>
</table>
</#if>

<#-- Escalated Endpoints List -->
<#if escalatedEndpoints?? && escalatedEndpoints?size gt 0>
<h2>越权接口列表</h2>
<div class="endpoint-list escalated-list">
  <ol>
    <#list escalatedEndpoints as ep>
    <li class="escalated-item">${ep.requestLine}</li>
    </#list>
  </ol>
</div>
</#if>

<#-- Safe Endpoints List -->
<#if safeEndpoints?? && safeEndpoints?size gt 0>
<h2>安全接口列表</h2>
<div class="endpoint-list safe-list">
  <ol>
    <#list safeEndpoints as ep>
    <li class="safe-item">${ep.requestLine}</li>
    </#list>
  </ol>
</div>
</#if>

<#-- Findings by Endpoint -->
<h2>报文详情</h2>
<#list endpoints as ep>
<div class="endpoint-section">
  <div class="endpoint-header">
    <div>
      <h3>api_${ep.endpointIndex?string("00")} <span class="method">${ep.method}</span> ${ep.url}</h3>
    </div>
    <div class="meta-info">
      <#if ep.baselineCount gt 0>基线: ${ep.baselineCount} | </#if>
      测试: ${ep.totalTests}
      <#if ep.escalatedCount gt 0> | <span style="color:#d32f2f;font-weight:600">&#9888; ${ep.escalatedCount} 越权</span></#if>
      | &#10004; ${ep.safeCount} 安全
    </div>
  </div>

  <#-- Baseline (orin) -->
  <#if ep.baselineData??>
  <div class="session-block baseline-block">
    <div class="session-header baseline-header">
      <span>原始基准 HTTP 数据 — 参考对照标准</span>
      <span class="badge baseline">基线</span>
    </div>
    <div class="session-content">
      <p class="baseline-note">基准报文是参考用户的原始请求与响应，用于与各会话重放结果对比分析，判断是否存在越权。</p>
      <div class="section-title">请求</div>
      ${ep.baselineData.requestHtml?no_esc}
      <div class="section-title">响应 — HTTP ${ep.baselineData.record.statusCode} (${ep.baselineData.record.responseLength} bytes, ${ep.baselineData.record.responseTime}ms)</div>
      ${ep.baselineData.responseHtml?no_esc}
    </div>
  </div>
  </#if>

  <#-- User sessions -->
  <#list ep.userSessions as us>
  <div class="session-block">
    <div class="session-header">
      <span>${us.sessionName} HTTP 数据</span>
      <span class="badge <#if us.judgment == 'ESCALATED'>escalated<#elseif us.judgment == 'NOT_ESCALATED'>safe<#else>error</#if>">
        <#if us.judgment == 'ESCALATED'>&#9888; 越权<#elseif us.judgment == 'NOT_ESCALATED'>&#10004; 安全<#else>&#10007; 错误</#if>
      </span>
    </div>
    <div class="session-content">
      <#if us.matchedRuleName??>
      <div>规则: <strong>${us.matchedRuleName}</strong></div>
      </#if>
      <div class="meta-info">相似度: ${us.similarityDisplay}</div>

      <#-- Request -->
      <div class="section-title">请求</div>
      ${us.requestHtml?no_esc}

      <#-- Response -->
      <div class="section-title">响应 — HTTP ${us.record.statusCode} (${us.record.responseLength} bytes, ${us.record.responseTime}ms)</div>
      ${us.responseHtml?no_esc}

      <#-- cURL -->
      <div class="section-title">复现命令 — cURL</div>
      <pre class="curl-block">${us.curlCommand}</pre>

      <#-- Postman -->
      <div class="section-title">复现导入 — Postman</div>
      <pre class="postman-block">${us.postmanSnippet}</pre>
    </div>
  </div>
  </#list>
</div>
</#list>

<#else>
<#-- 多文件分离模式：仅输出占位容器，全部内容由 controller.js 读取 data.js 动态渲染 -->
<div id="test-info-section"></div>
<div id="user-info-section"></div>
<div id="summary-section"></div>
<div id="session-breakdown-section"></div>
<div id="escalated-list-section"></div>
<div id="error-list-section"></div>
<div id="safe-list-section"></div>
<div id="endpoints-section"></div>
</#if>

<#if inlineMode?? && inlineMode>
<#-- 单文件模式：在页面底部嵌入越权测试用例参考 -->
<h2>越权测试用例参考</h2>
<p style="margin-bottom:16px;color:#555;">以下为越权测试的典型用例参考，涵盖未授权访问、垂直越权和水平越权三种主要越权类型。</p>
<#include "test_cases_content.ftl">

<#-- 单文件模式：内联灯箱脚本（不依赖 REPORT_DATA） -->
<script>
(function() {
    'use strict';
    var currentSort = { column: 0, asc: true };

    window._lightboxGroups = {};

    // 收集页面中所有带 data-group 的截图，按组归类
    function collectLightboxGroups() {
        var thumbs = document.querySelectorAll('.screenshot-thumb[data-group]');
        thumbs.forEach(function(thumb) {
            var group = thumb.getAttribute('data-group');
            if (!window._lightboxGroups[group]) {
                window._lightboxGroups[group] = [];
            }
            window._lightboxGroups[group].push(thumb.src);
        });
    }

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

    // DOM 就绪后收集截图分组
    document.addEventListener('DOMContentLoaded', function() {
        collectLightboxGroups();
    });
})();
</script>
</#if>

<#if !(inlineMode?? && inlineMode)>
<script src="data.js"></script>
<script src="controller.js"></script>
</#if>
</body>
</html>
