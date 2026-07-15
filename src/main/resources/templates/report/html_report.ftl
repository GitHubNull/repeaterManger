<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${title}</title>
<#include "html_css.ftl">
</head>
<body>

<#-- Header -->
<div class="header">
  <h1>${title}</h1>
  <p class="meta">生成时间: ${generatedAt} | Repeater Manager v${pluginVersion}</p>
</div>

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
<table>
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

</body>
</html>
