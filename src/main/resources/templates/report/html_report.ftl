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
  <p class="meta">Generated: ${generatedAt} | Repeater Manager v${pluginVersion}</p>
</div>

<#-- Summary -->
<h2>Summary</h2>
<div class="summary-cards">
  <div class="card total"><div class="number">${summary.totalTests}</div><div class="label">Total Tests</div></div>
  <div class="card escalated"><div class="number">${summary.escalatedCount}</div><div class="label">&#9888; Escalated</div></div>
  <div class="card safe"><div class="number">${summary.safeCount}</div><div class="label">&#10004; Safe</div></div>
  <div class="card error"><div class="number">${summary.errorCount}</div><div class="label">&#10007; Errors</div></div>
  <div class="card" style="border-top:4px solid #1565C0"><div class="number" style="color:#1565C0">${summary.baselineCount}</div><div class="label">Baseline</div></div>
</div>

<#-- Session Breakdown -->
<#if sessionBreakdown?? && sessionBreakdown?size gt 0>
<h2>Session Breakdown</h2>
<table>
  <tr><th>Session</th><th>Escalated</th><th>Safe</th><th>Errors</th><th>Total</th></tr>
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

<#-- Findings by Endpoint -->
<h2>Findings by Endpoint</h2>
<#list endpoints as ep>
<div class="endpoint-section">
  <div class="endpoint-header">
    <div>
      <h3>api_${ep.endpointIndex?string("00")} <span class="method">${ep.method}</span> ${ep.url}</h3>
    </div>
    <div class="meta-info">
      <#if ep.baselineCount gt 0>Baseline: ${ep.baselineCount} | </#if>
      Tests: ${ep.totalTests}
      <#if ep.escalatedCount gt 0> | <span style="color:#d32f2f;font-weight:600">&#9888; ${ep.escalatedCount} Escalated</span></#if>
      | &#10004; ${ep.safeCount} Safe
    </div>
  </div>

  <#-- Baseline (orin) -->
  <#if ep.baselineData??>
  <div class="session-block baseline-block">
    <div class="session-header baseline-header">
      <span>orin http data</span>
      <span class="badge baseline">BASELINE</span>
    </div>
    <div class="session-content">
      <div class="section-title">Request</div>
      ${ep.baselineData.requestHtml?no_esc}
      <div class="section-title">Response — HTTP ${ep.baselineData.record.statusCode} (${ep.baselineData.record.responseLength} bytes, ${ep.baselineData.record.responseTime}ms)</div>
      ${ep.baselineData.responseHtml?no_esc}
    </div>
  </div>
  </#if>

  <#-- User sessions -->
  <#list ep.userSessions as us>
  <div class="session-block">
    <div class="session-header">
      <span>${us.sessionName} http data</span>
      <span class="badge <#if us.judgment == 'ESCALATED'>escalated<#elseif us.judgment == 'NOT_ESCALATED'>safe<#else>error</#if>">
        <#if us.judgment == 'ESCALATED'>&#9888; 越权<#elseif us.judgment == 'NOT_ESCALATED'>&#10004; 安全<#else>&#10007; 错误</#if>
      </span>
    </div>
    <div class="session-content">
      <#if us.matchedRuleName??>
      <div>Rule: <strong>${us.matchedRuleName}</strong></div>
      </#if>
      <div class="meta-info">Similarity: ${us.similarity?string["0.00"]}</div>

      <#-- Request -->
      <div class="section-title">Request</div>
      ${us.requestHtml?no_esc}

      <#-- Response -->
      <div class="section-title">Response — HTTP ${us.record.statusCode} (${us.record.responseLength} bytes, ${us.record.responseTime}ms)</div>
      ${us.responseHtml?no_esc}

      <#-- cURL -->
      <div class="section-title">Reproduction — cURL</div>
      <pre class="curl-block">${us.curlCommand}</pre>

      <#-- Postman -->
      <div class="section-title">Reproduction — Postman Import</div>
      <pre class="postman-block">${us.postmanSnippet}</pre>
    </div>
  </div>
  </#list>
</div>
</#list>

</body>
</html>
