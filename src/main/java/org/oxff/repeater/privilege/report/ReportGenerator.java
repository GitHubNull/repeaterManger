package org.oxff.repeater.privilege.report;

import org.oxff.repeater.db.RequestDAO;
import org.oxff.repeater.db.history.HistoryReadDAO;
import org.oxff.repeater.http.RequestResponseRecord;

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
            RequestResponseRecord baselineRecord = null;
            String baselineSessionName = null;
            List<RequestResponseRecord> userRecords = new ArrayList<>();

            for (RequestResponseRecord record : epRecords) {
                if (record.getSimilarity() == -1 && "NOT_ESCALATED".equalsIgnoreCase(record.getJudgment())) {
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
                        orinRecord.setResponseData(baselineRecord.getResponseData());
                        orinRecord.setStatusCode(baselineRecord.getStatusCode());
                        orinRecord.setResponseLength(baselineRecord.getResponseLength());
                        orinRecord.setResponseTime(baselineRecord.getResponseTime());
                        orinRecord.setMethod((String) originalRequest.get("method"));
                        orinRecord.setProtocol((String) originalRequest.get("protocol"));
                        orinRecord.setDomain((String) originalRequest.get("domain"));
                        orinRecord.setPath((String) originalRequest.get("path"));
                        orinRecord.setQueryParameters((String) originalRequest.get("query"));
                        baselineData.setRecord(orinRecord);
                    } else {
                        baselineData.setRecord(baselineRecord);
                    }
                } else {
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
                baselineFinding.setSimilarity(-1);
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

        // ===== 阶段 D：预渲染 body 内容 =====
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
