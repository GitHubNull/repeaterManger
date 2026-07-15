package org.oxff.repeater.privilege.report;

import org.oxff.repeater.db.RequestDAO;
import org.oxff.repeater.db.history.HistoryReadDAO;
import org.oxff.repeater.http.RequestResponseRecord;
import org.oxff.repeater.logging.LogManager;

import java.util.*;

/**
 * 报告生成器抽象基类
 */
public abstract class ReportGenerator {

    protected final HistoryReadDAO historyReadDAO;
    protected final BodyRenderer bodyRenderer = new BodyRenderer();

    protected ReportGenerator() {
        this.historyReadDAO = new HistoryReadDAO();
    }

    /**
     * 收集报告数据
     * 四阶段：端点分组 → 构建 EndpointSection → 计数修正 → 预渲染 body
     */
    public ReportData collectData() {
        ReportData data = new ReportData();

        // 获取所有越权测试结果
        List<RequestResponseRecord> records = historyReadDAO.getPrivilegeTestResults();

        // ===== 阶段 A：按端点分组，分桶存储 baseline 和 user session =====
        Map<String, List<RequestResponseRecord>> endpointRecordsMap = new LinkedHashMap<>();
        Set<String> uniqueEndpoints = new HashSet<>();
        for (RequestResponseRecord record : records) {
            String key = record.getMethod() + " " + record.getDomain() + record.getPath();
            uniqueEndpoints.add(key);
            endpointRecordsMap.computeIfAbsent(key, k -> new ArrayList<>()).add(record);
        }

        // ===== 阶段 B：构建 EndpointSection（baseline 与 user session 分离） =====
        List<ReportData.EndpointSection> endpointSections = new ArrayList<>();
        int endpointIndex = 1;
        Map<String, ReportData.SessionBreakdown> sessionMap = new LinkedHashMap<>();

        for (List<RequestResponseRecord> epRecords : endpointRecordsMap.values()) {

            ReportData.EndpointSection section = new ReportData.EndpointSection();
            section.setEndpointIndex(endpointIndex++);

            // 从第一条记录提取端点信息
            RequestResponseRecord first = epRecords.get(0);
            section.setMethod(first.getMethod());
            section.setUrl(first.getProtocol() + "://" + first.getDomain() + first.getPath());

            // 分离 baseline 和 user session 记录
            // 优先通过 baselineResponseData 字段识别基准记录（v2.18+），回退到旧逻辑兼容
            RequestResponseRecord baselineRecord = null;
            String baselineSessionName = null;
            List<RequestResponseRecord> userRecords = new ArrayList<>();

            for (RequestResponseRecord record : epRecords) {
                boolean isBaseline = false;
                // 新逻辑：基准记录带有独立的基准响应体字段
                if (record.getBaselineResponseData() != null) {
                    isBaseline = true;
                } else if (record.getSimilarity() == -1 && "NOT_ESCALATED".equalsIgnoreCase(record.getJudgment())) {
                    // 旧逻辑回退：兼容 v2.17 及以下版本的历史数据
                    isBaseline = true;
                }

                if (isBaseline) {
                    baselineRecord = record;
                    baselineSessionName = record.getUserSessionName();
                } else {
                    userRecords.add(record);
                }
            }

            // 构建 BaselineData - 使用 requests 表中的原始请求数据
            if (baselineRecord != null) {
                ReportData.BaselineData baselineData = new ReportData.BaselineData();
                baselineData.setSessionName(baselineSessionName);

                int requestId = baselineRecord.getRequestId();
                if (requestId > 0) {
                    RequestDAO requestDAO = new RequestDAO();
                    Map<String, Object> originalRequest = requestDAO.getRequest(requestId);
                    if (originalRequest != null && originalRequest.containsKey("request_data")) {
                        byte[] originalRequestData = (byte[]) originalRequest.get("request_data");
                        RequestResponseRecord orinRecord = new RequestResponseRecord();
                        orinRecord.setRequestData(originalRequestData);
                        // 优先从 requests 表获取完整的原始 HTTP 响应（含状态行+响应头+响应体）
                        byte[] fullOriginalResponse = requestDAO.getOriginalResponseData(requestId);
                        if (fullOriginalResponse != null && fullOriginalResponse.length > 0) {
                            orinRecord.setResponseData(fullOriginalResponse);
                            orinRecord.setStatusCode(requestDAO.getOriginalResponseStatusCode(requestId));
                            orinRecord.setResponseLength(fullOriginalResponse.length);
                            orinRecord.setResponseTime(baselineRecord.getResponseTime());
                        } else {
                            // 回退兼容：使用历史记录中的响应数据（旧版本数据）
                            byte[] baselineRespData = baselineRecord.getBaselineResponseData();
                            if (baselineRespData != null && baselineRespData.length > 0) {
                                orinRecord.setResponseData(baselineRespData);
                            } else {
                                orinRecord.setResponseData(baselineRecord.getResponseData());
                            }
                            orinRecord.setStatusCode(baselineRecord.getStatusCode());
                            orinRecord.setResponseLength(baselineRecord.getResponseLength());
                            orinRecord.setResponseTime(baselineRecord.getResponseTime());
                        }
                        orinRecord.setMethod((String) originalRequest.get("method"));
                        orinRecord.setProtocol((String) originalRequest.get("protocol"));
                        orinRecord.setDomain((String) originalRequest.get("domain"));
                        orinRecord.setPath((String) originalRequest.get("path"));
                        orinRecord.setQueryParameters((String) originalRequest.get("query"));
                        baselineData.setRecord(orinRecord);
                    } else {
                        LogManager.getInstance().printOutput(
                            "[*] 端点 " + section.getUrl() + " 的基准请求(requestId=" + requestId
                            + ")未在requests表中找到，使用历史记录中的请求数据作为基准");
                        baselineData.setRecord(baselineRecord);
                    }
                } else {
                    LogManager.getInstance().printOutput(
                        "[*] 端点 " + section.getUrl() + " 的基准记录无有效requestId(requestId=" + requestId
                        + ")，使用历史记录中的请求数据作为基准");
                    baselineData.setRecord(baselineRecord);
                }
                section.setBaselineData(baselineData);
            }

            // 构建 SessionFinding 列表（所有用户会话均作为普通会话显示）
            List<ReportData.SessionFinding> sessionFindings = new ArrayList<>();

            // 将 baseline 用户添加为 SessionFinding（显示为 "用户X http data"，使用实际判决结果）
            if (baselineRecord != null) {
                ReportData.SessionFinding baselineFinding = new ReportData.SessionFinding();
                baselineFinding.setSessionName(baselineSessionName);
                baselineFinding.setJudgment(baselineRecord.getJudgment());
                baselineFinding.setSimilarity(baselineRecord.getSimilarity());
                baselineFinding.setRecord(baselineRecord);
                baselineFinding.setBaseline(false);
                baselineFinding.setCurlCommand(CurlBuilder.build(baselineRecord));
                baselineFinding.setPostmanSnippet(PostmanSnippetBuilder.build(baselineRecord));
                sessionFindings.add(baselineFinding);
            }

            // 非基准用户会话
            for (RequestResponseRecord record : userRecords) {
                ReportData.SessionFinding finding = new ReportData.SessionFinding();
                finding.setSessionName(record.getUserSessionName());
                finding.setJudgment(record.getJudgment());
                finding.setSimilarity(record.getSimilarity());
                finding.setRecord(record);
                finding.setCurlCommand(CurlBuilder.build(record));
                finding.setPostmanSnippet(PostmanSnippetBuilder.build(record));

                // 尝试获取匹配规则名（从注释提取）
                String comment = record.getComment();
                if (comment != null && !comment.isEmpty()) {
                    finding.setMatchedRuleName(extractRuleName(comment));
                }

                sessionFindings.add(finding);
            }
            section.setUserSessions(sessionFindings);

            endpointSections.add(section);
        }

        // ===== 阶段 C：计数修正（排除 baseline SessionFinding） =====
        ReportData.ReportSummary summary = new ReportData.ReportSummary();
        int escalated = 0, safe = 0, errors = 0, baselineTotal = 0;

        for (ReportData.EndpointSection section : endpointSections) {
            int epEscalated = 0, epSafe = 0, epError = 0;

            if (section.getBaselineData() != null) {
                baselineTotal++;
            }

            for (ReportData.SessionFinding f : section.getUserSessions()) {
                // baseline 用户的 SessionFinding 不计入测试统计
                if (f.isBaseline()) continue;

                String judgment = f.getJudgment();
                if ("ESCALATED".equalsIgnoreCase(judgment)) {
                    epEscalated++;
                    escalated++;
                } else if ("NOT_ESCALATED".equalsIgnoreCase(judgment)) {
                    epSafe++;
                    safe++;
                } else {
                    epError++;
                    errors++;
                }

                // 按会话统计
                ReportData.SessionBreakdown sb = sessionMap.computeIfAbsent(
                        f.getSessionName(), k -> {
                            ReportData.SessionBreakdown b = new ReportData.SessionBreakdown();
                            b.setSessionName(k);
                            return b;
                        });
                if ("ESCALATED".equalsIgnoreCase(judgment)) {
                    sb.setEscalatedCount(sb.getEscalatedCount() + 1);
                } else if ("NOT_ESCALATED".equalsIgnoreCase(judgment)) {
                    sb.setSafeCount(sb.getSafeCount() + 1);
                } else {
                    sb.setErrorCount(sb.getErrorCount() + 1);
                }
            }

            section.setEscalatedCount(epEscalated);
            section.setSafeCount(epSafe);
            section.setErrorCount(epError);
            section.setBaselineCount(section.getBaselineData() != null ? 1 : 0);
        }

        summary.setTotalTests(escalated + safe + errors);
        summary.setEscalatedCount(escalated);
        summary.setSafeCount(safe);
        summary.setErrorCount(errors);
        summary.setBaselineCount(baselineTotal);
        summary.setEndpointsTested(uniqueEndpoints.size());

        data.setSummary(summary);
        data.setEndpoints(endpointSections);
        data.setSessionBreakdown(new ArrayList<>(sessionMap.values()));

        // ===== 阶段 D：收集三类接口请求行列表 =====
        java.util.Set<String> escalatedSet = new java.util.LinkedHashSet<>();
        java.util.Set<String> errorSet = new java.util.LinkedHashSet<>();
        java.util.Set<String> safeSet = new java.util.LinkedHashSet<>();

        for (ReportData.EndpointSection section : endpointSections) {
            for (ReportData.SessionFinding f : section.getUserSessions()) {
                if (f.isBaseline()) continue;
                String judgment = f.getJudgment();
                String requestLine = buildRequestLine(f.getRecord());
                if (requestLine == null || requestLine.isEmpty()) continue;

                if ("ESCALATED".equalsIgnoreCase(judgment)) {
                    escalatedSet.add(requestLine);
                } else if ("NOT_ESCALATED".equalsIgnoreCase(judgment)) {
                    safeSet.add(requestLine);
                } else {
                    errorSet.add(requestLine);
                }
            }
        }

        List<ReportData.EndpointRequestLine> escalatedList = new ArrayList<>();
        for (String rl : escalatedSet) {
            escalatedList.add(new ReportData.EndpointRequestLine(rl));
        }
        data.setEscalatedEndpoints(escalatedList);

        List<ReportData.EndpointRequestLine> errorList = new ArrayList<>();
        for (String rl : errorSet) {
            errorList.add(new ReportData.EndpointRequestLine(rl));
        }
        data.setErrorEndpoints(errorList);

        List<ReportData.EndpointRequestLine> safeList = new ArrayList<>();
        for (String rl : safeSet) {
            safeList.add(new ReportData.EndpointRequestLine(rl));
        }
        data.setSafeEndpoints(safeList);

        // ===== 阶段 E：预渲染 body 内容 =====
        for (ReportData.EndpointSection section : endpointSections) {
            // 预渲染 baseline body
            if (section.getBaselineData() != null) {
                ReportData.BaselineData bd = section.getBaselineData();
                RequestResponseRecord rec = bd.getRecord();
                bd.setRequestHtml(bodyRenderer.renderBodyHtml(rec.getRequestData(),
                        bodyRenderer.extractRequestContentType(rec.getRequestData())));
                bd.setResponseHtml(bodyRenderer.renderBodyHtml(rec.getResponseData(),
                        bodyRenderer.extractResponseContentType(rec.getResponseData())));
                bd.setRequestMd(bodyRenderer.renderBodyMd(rec.getRequestData(),
                        bodyRenderer.extractRequestContentType(rec.getRequestData())));
                bd.setResponseMd(bodyRenderer.renderBodyMd(rec.getResponseData(),
                        bodyRenderer.extractResponseContentType(rec.getResponseData())));
            }

            // 预渲染 user session body
            for (ReportData.SessionFinding sf : section.getUserSessions()) {
                RequestResponseRecord rec = sf.getRecord();
                sf.setRequestHtml(bodyRenderer.renderBodyHtml(rec.getRequestData(),
                        bodyRenderer.extractRequestContentType(rec.getRequestData())));
                sf.setResponseHtml(bodyRenderer.renderBodyHtml(rec.getResponseData(),
                        bodyRenderer.extractResponseContentType(rec.getResponseData())));
                sf.setRequestMd(bodyRenderer.renderBodyMd(rec.getRequestData(),
                        bodyRenderer.extractRequestContentType(rec.getRequestData())));
                sf.setResponseMd(bodyRenderer.renderBodyMd(rec.getResponseData(),
                        bodyRenderer.extractResponseContentType(rec.getResponseData())));
            }
        }

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
     * 构建请求行，格式为 "METHOD API HTTP/version"
     * API 优先使用 record.getApi()（支持 JSON-RPC 等 body 中隐藏真实接口的场景），
     * 为空时回退到 record.getPath()
     */
    private String buildRequestLine(RequestResponseRecord record) {
        if (record == null) return null;

        String method = record.getMethod();
        String api = record.getApi();
        if (api == null || api.isEmpty()) {
            api = record.getPath();
        }
        if (api == null || api.isEmpty()) {
            return null;
        }

        String httpVersion = extractHttpVersion(record.getRequestData());
        return method + " " + api + " " + httpVersion;
    }

    /**
     * 从原始请求字节中提取 HTTP 版本
     * 解析请求首行（如 "GET /path HTTP/1.1"），返回 "HTTP/1.1"
     */
    private String extractHttpVersion(byte[] requestData) {
        if (requestData == null || requestData.length == 0) {
            return "HTTP/1.1"; // 默认值
        }
        String text = new String(requestData, java.nio.charset.StandardCharsets.UTF_8);
        int firstLineEnd = text.indexOf("\r\n");
        if (firstLineEnd < 0) {
            firstLineEnd = text.indexOf("\n");
        }
        String firstLine = firstLineEnd > 0 ? text.substring(0, firstLineEnd) : text;

        // 从请求行末尾提取 HTTP 版本（如 "HTTP/1.1" 或 "HTTP/2"）
        int lastSpace = firstLine.lastIndexOf(' ');
        if (lastSpace > 0 && lastSpace < firstLine.length() - 1) {
            String version = firstLine.substring(lastSpace + 1).trim();
            if (version.startsWith("HTTP/")) {
                return version;
            }
        }
        return "HTTP/1.1";
    }

    /**
     * 从注释提取规则名
     */
    private String extractRuleName(String comment) {
        if (comment == null) return null;
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("(?:规则|Rule):\\s*(.+?)(?:\\s|$)");
        java.util.regex.Matcher m = p.matcher(comment);
        if (m.find()) {
            return m.group(1);
        }
        return null;
    }
}
