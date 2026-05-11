# ${title}

> Generated: ${generatedAt} | Repeater Manager v${pluginVersion}

## Summary

| Metric | Count |
|--------|-------|
| Total Tests | ${summary.totalTests} |
| Escalated (&#9888;) | ${summary.escalatedCount} |
| Safe (&#10004;) | ${summary.safeCount} |
| Errors (&#10007;) | ${summary.errorCount} |
| Baseline | ${summary.baselineCount} |
| Unique Endpoints | ${summary.endpointsTested} |

<#if sessionBreakdown?? && sessionBreakdown?size gt 0>
## Session Breakdown

| Session | Escalated | Safe | Errors | Total |
|---------|-----------|------|--------|-------|
<#list sessionBreakdown as sb>
| ${sb.sessionName} | ${sb.escalatedCount} | ${sb.safeCount} | ${sb.errorCount} | ${sb.totalTests} |
</#list>

</#if>
## Findings by Endpoint

<#list endpoints as ep>
### api_${ep.endpointIndex?string("00")} ${ep.method} ${ep.url}

**<#if ep.baselineCount gt 0>Baseline: ${ep.baselineCount} | </#if>Tests: ${ep.totalTests} | Escalated: ${ep.escalatedCount} | Safe: ${ep.safeCount}**

<#-- Baseline (orin) -->
<#if ep.baselineData??>
#### orin http data BASELINE

##### Request

${ep.baselineData.requestMd}

##### Response — HTTP ${ep.baselineData.record.statusCode} (${ep.baselineData.record.responseLength} bytes, ${ep.baselineData.record.responseTime}ms)

${ep.baselineData.responseMd}

---

</#if>

<#-- User sessions -->
<#list ep.userSessions as us>
#### ${us.sessionName} http data <#if us.judgment == 'ESCALATED'>&#9888; ESCALATED<#elseif us.judgment == 'NOT_ESCALATED'>&#10004; SAFE<#else>&#10007; ERROR</#if>

<#if us.matchedRuleName??>
- **Rule**: ${us.matchedRuleName}
</#if>
- **Similarity**: ${us.similarity?string["0.00"]}
- **Status**: HTTP ${us.record.statusCode} | ${us.record.responseLength} bytes | ${us.record.responseTime}ms

##### Request

${us.requestMd}

##### Response — HTTP ${us.record.statusCode} (${us.record.responseLength} bytes, ${us.record.responseTime}ms)

${us.responseMd}

**Reproduction (cURL):**

```bash
${us.curlCommand}
```

**Reproduction (Postman):**

```json
${us.postmanSnippet}
```

---

</#list>
</#list>
