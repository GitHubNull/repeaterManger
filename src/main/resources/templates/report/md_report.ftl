# ${title}

> 生成时间: ${generatedAt} | Repeater Manager v${pluginVersion}

## 摘要

| 指标 | 数量 |
|--------|-------|
| 测试总数 | ${summary.totalTests} |
| 越权 (&#9888;) | ${summary.escalatedCount} |
| 安全 (&#10004;) | ${summary.safeCount} |
| 错误 (&#10007;) | ${summary.errorCount} |
| 基线 | ${summary.baselineCount} |
| 唯一端点 | ${summary.endpointsTested} |

<#if sessionBreakdown?? && sessionBreakdown?size gt 0>
## 会话分布

| 会话 | 越权 | 安全 | 错误 | 总计 |
|---------|-----------|------|--------|-------|
<#list sessionBreakdown as sb>
| ${sb.sessionName} | ${sb.escalatedCount} | ${sb.safeCount} | ${sb.errorCount} | ${sb.totalTests} |
</#list>

</#if>
## 端点发现详情

<#list endpoints as ep>
### api_${ep.endpointIndex?string("00")} ${ep.method} ${ep.url}

**<#if ep.baselineCount gt 0>基线: ${ep.baselineCount} | </#if>测试: ${ep.totalTests} | 越权: ${ep.escalatedCount} | 安全: ${ep.safeCount}**

<#-- Baseline (orin) -->
<#if ep.baselineData??>
#### 原始基准 HTTP 数据 — 参考对照标准

> 基准报文是参考用户的原始请求与响应，用于与各会话重放结果对比分析，判断是否存在越权。

##### 请求

${ep.baselineData.requestMd}

##### 响应 — HTTP ${ep.baselineData.record.statusCode} (${ep.baselineData.record.responseLength} bytes, ${ep.baselineData.record.responseTime}ms)

${ep.baselineData.responseMd}

---

</#if>

<#-- User sessions -->
<#list ep.userSessions as us>
#### ${us.sessionName} HTTP 数据 <#if us.judgment == 'ESCALATED'>&#9888; 越权<#elseif us.judgment == 'NOT_ESCALATED'>&#10004; 安全<#else>&#10007; 错误</#if>

<#if us.matchedRuleName??>
- **规则**: ${us.matchedRuleName}
</#if>
- **相似度**: ${us.similarityDisplay}
- **状态**: HTTP ${us.record.statusCode} | ${us.record.responseLength} bytes | ${us.record.responseTime}ms

##### 请求

${us.requestMd}

##### 响应 — HTTP ${us.record.statusCode} (${us.record.responseLength} bytes, ${us.record.responseTime}ms)

${us.responseMd}

**复现命令 (cURL):**

```bash
${us.curlCommand}
```

**复现导入 (Postman):**

```json
${us.postmanSnippet}
```

---

</#list>
</#list>
