package oxff.top.privilege.report;

import oxff.top.db.history.HistoryReadDAO;
import oxff.top.http.RequestResponseRecord;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * 报告生成器抽象基类
 */
public abstract class ReportGenerator {

    protected final HistoryReadDAO historyReadDAO;
    protected final BinaryContentRenderer binaryRenderer = new BinaryContentRenderer();

    protected ReportGenerator() {
        this.historyReadDAO = new HistoryReadDAO();
    }

    /**
     * 收集报告数据
     */
    public ReportData collectData() {
        ReportData data = new ReportData();

        // 获取所有越权测试结果
        List<RequestResponseRecord> records = historyReadDAO.getPrivilegeTestResults();

        // 获取统计
        Map<String, Integer> stats = historyReadDAO.getPrivilegeTestStats();
        List<Map<String, Object>> sessionStats = historyReadDAO.getPrivilegeTestStatsBySession();

        // 汇总统计
        ReportData.ReportSummary summary = new ReportData.ReportSummary();
        int escalated = stats.getOrDefault("ESCALATED", 0);
        int safe = stats.getOrDefault("NOT_ESCALATED", 0);
        int errors = stats.getOrDefault("ERROR", 0);
        summary.setTotalTests(escalated + safe + errors);
        summary.setEscalatedCount(escalated);
        summary.setSafeCount(safe);
        summary.setErrorCount(errors);

        // 按端点分组
        Map<String, ReportData.EndpointSummary> endpointMap = new LinkedHashMap<>();
        Set<String> uniqueEndpoints = new HashSet<>();
        for (RequestResponseRecord record : records) {
            String key = record.getMethod() + " " + record.getDomain() + record.getPath();
            uniqueEndpoints.add(key);

            ReportData.EndpointSummary es = endpointMap.computeIfAbsent(key, k -> {
                ReportData.EndpointSummary e = new ReportData.EndpointSummary();
                e.setMethod(record.getMethod());
                e.setUrl(record.getProtocol() + "://" + record.getDomain() + record.getPath());
                return e;
            });

            ReportData.Finding finding = new ReportData.Finding();
            finding.setUserSessionName(record.getUserSessionName());
            finding.setJudgment(record.getJudgment());
            finding.setSimilarity(record.getSimilarity());
            finding.setRecord(record);
            finding.setCurlCommand(CurlBuilder.build(record));
            finding.setPostmanSnippet(PostmanSnippetBuilder.build(record));

            // 尝试获取匹配规则名（从注释提取或留空）
            String comment = record.getComment();
            if (comment != null && !comment.isEmpty()) {
                finding.setMatchedRuleName(extractRuleName(comment));
            }

            es.getFindings().add(finding);

            // 统计
            String judgment = record.getJudgment();
            if ("ESCALATED".equalsIgnoreCase(judgment)) {
                es.setEscalatedCount(es.getEscalatedCount() + 1);
            } else if ("NOT_ESCALATED".equalsIgnoreCase(judgment)) {
                es.setSafeCount(es.getSafeCount() + 1);
            } else {
                es.setErrorCount(es.getErrorCount() + 1);
            }
        }

        summary.setEndpointsTested(uniqueEndpoints.size());
        data.setSummary(summary);
        data.setEndpoints(new ArrayList<>(endpointMap.values()));

        Map<String, ReportData.SessionBreakdown> sessionMap = new LinkedHashMap<>();
        for (Map<String, Object> row : sessionStats) {
            String sessionName = (String) row.get("user_session_name");
            String judgment = (String) row.get("judgment");
            int cnt = (Integer) row.get("cnt");

            ReportData.SessionBreakdown sb = sessionMap.computeIfAbsent(sessionName, k -> {
                ReportData.SessionBreakdown b = new ReportData.SessionBreakdown();
                b.setSessionName(sessionName);
                return b;
            });

            if ("ESCALATED".equalsIgnoreCase(judgment)) {
                sb.setEscalatedCount(cnt);
            } else if ("NOT_ESCALATED".equalsIgnoreCase(judgment)) {
                sb.setSafeCount(cnt);
            } else if ("ERROR".equalsIgnoreCase(judgment)) {
                sb.setErrorCount(cnt);
            }
        }
        data.setSessionBreakdown(new ArrayList<>(sessionMap.values()));

        return data;
    }

    /**
     * 生成报告内容（由子类实现）
     */
    public abstract String generate(ReportData data);

    /**
     * 获取文件扩展名
     */
    public abstract String getFileExtension();

    /**
     * 检测是否为二进制 body
     */
    protected boolean isBinaryBody(byte[] data) {
        if (data == null || data.length == 0) return false;
        int nonPrintable = 0;
        int checkLen = Math.min(data.length, 1024);
        for (int i = 0; i < checkLen; i++) {
            byte b = data[i];
            if (b < 0x09 || (b > 0x0D && b < 0x20) || b == 0x7F) {
                nonPrintable++;
            }
        }
        return (double) nonPrintable / checkLen > 0.3;
    }

    /**
     * 安全处理 body 用于显示
     */
    protected String sanitizeBody(byte[] body) {
        if (body == null || body.length == 0) return "[Empty]";
        if (isBinaryBody(body)) return "[Binary data — " + body.length + " bytes]";
        String text = new String(body, StandardCharsets.UTF_8);
        if (text.length() > 50000) {
            text = text.substring(0, 50000) + "\n\n... [Truncated — total " + body.length + " bytes]";
        }
        return text;
    }

    /**
     * 智能渲染 body 内容：检测二进制，返回分级渲染数据
     *
     * @param body              原始 body 字节
     * @param contentTypeHeader Content-Type header 值（可为 null）
     * @return 分级渲染内容，若为文本则 TieredRenderContent.tier == null
     */
    protected BinaryContentRenderer.TieredRenderContent renderBinaryBody(byte[] body, String contentTypeHeader) {
        if (body == null || body.length == 0) {
            // 空 body，返回文本标记
            return new BinaryContentRenderer.TieredRenderContent(null, "", "", null, null,
                    "text/plain", "text", "0 bytes");
        }

        BinaryContentRenderer.BinaryAnalysisResult analysis = binaryRenderer.analyzeBody(body, contentTypeHeader);
        if (!analysis.isBinary) {
            // 文本内容，返回标记为非二进制
            return new BinaryContentRenderer.TieredRenderContent(null, "", "", null, null,
                    analysis.contentType, "text", analysis.humanSize);
        }

        return binaryRenderer.createTieredContent(analysis);
    }

    /**
     * 从 HTTP 响应数据中提取 Content-Type
     */
    protected String extractResponseContentType(byte[] responseData) {
        return BinaryContentRenderer.extractContentTypeFromResponse(responseData);
    }

    /**
     * 从 HTTP 请求数据中提取 Content-Type
     */
    protected String extractRequestContentType(byte[] requestData) {
        return BinaryContentRenderer.extractContentTypeFromRequest(requestData);
    }

    /**
     * HTML 转义
     */
    protected String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    /**
     * 从注释提取规则名
     */
    private String extractRuleName(String comment) {
        if (comment == null) return null;
        // 尝试匹配 "规则: xxx" 或 "Rule: xxx"
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("(?:规则|Rule):\\s*(.+?)(?:\\s|$)");
        java.util.regex.Matcher m = p.matcher(comment);
        if (m.find()) {
            return m.group(1);
        }
        return null;
    }
}
