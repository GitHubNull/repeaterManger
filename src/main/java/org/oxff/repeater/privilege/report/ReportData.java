package org.oxff.repeater.privilege.report;

import org.oxff.repeater.http.RequestResponseRecord;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * 越权测试报告数据模型
 * 结构：Endpoint → BaselineData（原始报文） → List<SessionFinding>（各用户会话报文）
 */
public class ReportData {

    private String title = "越权测试报告";
    private Date generatedAt = new Date();
    private String pluginVersion = "2.33.1";

    private ReportSummary summary;
    private List<EndpointSection> endpoints = new ArrayList<>();
    private List<SessionBreakdown> sessionBreakdown = new ArrayList<>();
    private List<EndpointRequestLine> escalatedEndpoints = new ArrayList<>();
    private List<EndpointRequestLine> errorEndpoints = new ArrayList<>();
    private List<EndpointRequestLine> safeEndpoints = new ArrayList<>();
    private List<UserInfoEntry> userInfoEntries = new ArrayList<>();

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public Date getGeneratedAt() {
        return generatedAt;
    }

    public void setGeneratedAt(Date generatedAt) {
        this.generatedAt = generatedAt;
    }

    public String getPluginVersion() {
        return pluginVersion;
    }

    public void setPluginVersion(String pluginVersion) {
        this.pluginVersion = pluginVersion;
    }

    public ReportSummary getSummary() {
        return summary;
    }

    public void setSummary(ReportSummary summary) {
        this.summary = summary;
    }

    public List<EndpointSection> getEndpoints() {
        return endpoints;
    }

    public void setEndpoints(List<EndpointSection> endpoints) {
        this.endpoints = endpoints;
    }

    public List<SessionBreakdown> getSessionBreakdown() {
        return sessionBreakdown;
    }

    public void setSessionBreakdown(List<SessionBreakdown> sessionBreakdown) {
        this.sessionBreakdown = sessionBreakdown;
    }

    public List<EndpointRequestLine> getEscalatedEndpoints() {
        return escalatedEndpoints;
    }

    public void setEscalatedEndpoints(List<EndpointRequestLine> escalatedEndpoints) {
        this.escalatedEndpoints = escalatedEndpoints;
    }

    public List<EndpointRequestLine> getErrorEndpoints() {
        return errorEndpoints;
    }

    public void setErrorEndpoints(List<EndpointRequestLine> errorEndpoints) {
        this.errorEndpoints = errorEndpoints;
    }

    public List<EndpointRequestLine> getSafeEndpoints() {
        return safeEndpoints;
    }

    public void setSafeEndpoints(List<EndpointRequestLine> safeEndpoints) {
        this.safeEndpoints = safeEndpoints;
    }

    public List<UserInfoEntry> getUserInfoEntries() {
        return userInfoEntries;
    }

    public void setUserInfoEntries(List<UserInfoEntry> userInfoEntries) {
        this.userInfoEntries = userInfoEntries;
    }

    /**
     * 报告汇总统计
     */
    public static class ReportSummary {
        private int totalTests;
        private int escalatedCount;
        private int safeCount;
        private int errorCount;
        private int baselineCount;
        private int endpointsTested;

        public int getTotalTests() {
            return totalTests;
        }

        public void setTotalTests(int totalTests) {
            this.totalTests = totalTests;
        }

        public int getEscalatedCount() {
            return escalatedCount;
        }

        public void setEscalatedCount(int escalatedCount) {
            this.escalatedCount = escalatedCount;
        }

        public int getSafeCount() {
            return safeCount;
        }

        public void setSafeCount(int safeCount) {
            this.safeCount = safeCount;
        }

        public int getErrorCount() {
            return errorCount;
        }

        public void setErrorCount(int errorCount) {
            this.errorCount = errorCount;
        }

        public int getBaselineCount() {
            return baselineCount;
        }

        public void setBaselineCount(int baselineCount) {
            this.baselineCount = baselineCount;
        }

        public int getEndpointsTested() {
            return endpointsTested;
        }

        public void setEndpointsTested(int endpointsTested) {
            this.endpointsTested = endpointsTested;
        }
    }

    /**
     * 端点区域（按接口分组，含原始报文和用户会话报文）
     */
    public static class EndpointSection {
        private String method;
        private String url;
        private int endpointIndex;
        private int escalatedCount;
        private int safeCount;
        private int errorCount;
        private int baselineCount;
        private BaselineData baselineData;
        private List<SessionFinding> userSessions = new ArrayList<>();

        public String getMethod() {
            return method;
        }

        public void setMethod(String method) {
            this.method = method;
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public int getEndpointIndex() {
            return endpointIndex;
        }

        public void setEndpointIndex(int endpointIndex) {
            this.endpointIndex = endpointIndex;
        }

        public int getEscalatedCount() {
            return escalatedCount;
        }

        public void setEscalatedCount(int escalatedCount) {
            this.escalatedCount = escalatedCount;
        }

        public int getSafeCount() {
            return safeCount;
        }

        public void setSafeCount(int safeCount) {
            this.safeCount = safeCount;
        }

        public int getErrorCount() {
            return errorCount;
        }

        public void setErrorCount(int errorCount) {
            this.errorCount = errorCount;
        }

        public int getBaselineCount() {
            return baselineCount;
        }

        public void setBaselineCount(int baselineCount) {
            this.baselineCount = baselineCount;
        }

        public int getTotalTests() {
            return escalatedCount + safeCount + errorCount;
        }

        public BaselineData getBaselineData() {
            return baselineData;
        }

        public void setBaselineData(BaselineData baselineData) {
            this.baselineData = baselineData;
        }

        public List<SessionFinding> getUserSessions() {
            return userSessions;
        }

        public void setUserSessions(List<SessionFinding> userSessions) {
            this.userSessions = userSessions;
        }
    }

    /**
     * 原始基准报文数据（每个端点最多一个）
     */
    public static class BaselineData {
        private String sessionName;
        private RequestResponseRecord record;
        private String requestHtml;
        private String responseHtml;
        private String requestMd;
        private String responseMd;

        public String getSessionName() {
            return sessionName;
        }

        public void setSessionName(String sessionName) {
            this.sessionName = sessionName;
        }

        public RequestResponseRecord getRecord() {
            return record;
        }

        public void setRecord(RequestResponseRecord record) {
            this.record = record;
        }

        public String getRequestHtml() {
            return requestHtml;
        }

        public void setRequestHtml(String requestHtml) {
            this.requestHtml = requestHtml;
        }

        public String getResponseHtml() {
            return responseHtml;
        }

        public void setResponseHtml(String responseHtml) {
            this.responseHtml = responseHtml;
        }

        public String getRequestMd() {
            return requestMd;
        }

        public void setRequestMd(String requestMd) {
            this.requestMd = requestMd;
        }

        public String getResponseMd() {
            return responseMd;
        }

        public void setResponseMd(String responseMd) {
            this.responseMd = responseMd;
        }
    }

    /**
     * 用户会话发现详情（非基准的测试结果）
     */
    public static class SessionFinding {
        private String sessionName;
        private String judgment;
        private double similarity;
        private String matchedRuleName;
        private RequestResponseRecord record;
        private String curlCommand;
        private String postmanSnippet;
        private boolean baseline;
        private String requestHtml;
        private String responseHtml;
        private String requestMd;
        private String responseMd;

        public String getSessionName() {
            return sessionName;
        }

        public void setSessionName(String sessionName) {
            this.sessionName = sessionName;
        }

        public String getJudgment() {
            return judgment;
        }

        public void setJudgment(String judgment) {
            this.judgment = judgment;
        }

        /**
         * 获取判决结果的中文显示名
         * @return 中文显示名（如 "越权"、"安全"、"错误"、"待判定"）
         */
        public String getJudgmentDisplayName() {
            return org.oxff.repeater.privilege.model.JudgmentResult.toDisplayName(judgment);
        }

        public double getSimilarity() {
            return similarity;
        }

        public void setSimilarity(double similarity) {
            this.similarity = similarity;
        }

        /**
         * 获取相似度的展示文本，对哨兵值 -1 做语义化处理。
         * @return 正常值返回 "X.XX"，未计算值返回 "N/A"
         */
        public String getSimilarityDisplay() {
            if (similarity < 0) {
                return "N/A";
            }
            return String.format("%.2f", similarity);
        }

        public String getMatchedRuleName() {
            return matchedRuleName;
        }

        public void setMatchedRuleName(String matchedRuleName) {
            this.matchedRuleName = matchedRuleName;
        }

        public RequestResponseRecord getRecord() {
            return record;
        }

        public void setRecord(RequestResponseRecord record) {
            this.record = record;
        }

        public String getCurlCommand() {
            return curlCommand;
        }

        public void setCurlCommand(String curlCommand) {
            this.curlCommand = curlCommand;
        }

        public String getPostmanSnippet() {
            return postmanSnippet;
        }

        public void setPostmanSnippet(String postmanSnippet) {
            this.postmanSnippet = postmanSnippet;
        }

        public boolean isBaseline() {
            return baseline;
        }

        public void setBaseline(boolean baseline) {
            this.baseline = baseline;
        }

        public String getRequestHtml() {
            return requestHtml;
        }

        public void setRequestHtml(String requestHtml) {
            this.requestHtml = requestHtml;
        }

        public String getResponseHtml() {
            return responseHtml;
        }

        public void setResponseHtml(String responseHtml) {
            this.responseHtml = responseHtml;
        }

        public String getRequestMd() {
            return requestMd;
        }

        public void setRequestMd(String requestMd) {
            this.requestMd = requestMd;
        }

        public String getResponseMd() {
            return responseMd;
        }

        public void setResponseMd(String responseMd) {
            this.responseMd = responseMd;
        }
    }

    /**
     * 按会话分布统计
     */
    public static class SessionBreakdown {
        private String sessionName;
        private int escalatedCount;
        private int safeCount;
        private int errorCount;

        public String getSessionName() {
            return sessionName;
        }

        public void setSessionName(String sessionName) {
            this.sessionName = sessionName;
        }

        public int getEscalatedCount() {
            return escalatedCount;
        }

        public void setEscalatedCount(int escalatedCount) {
            this.escalatedCount = escalatedCount;
        }

        public int getSafeCount() {
            return safeCount;
        }

        public void setSafeCount(int safeCount) {
            this.safeCount = safeCount;
        }

        public int getErrorCount() {
            return errorCount;
        }

        public void setErrorCount(int errorCount) {
            this.errorCount = errorCount;
        }

        public int getTotalTests() {
            return escalatedCount + safeCount + errorCount;
        }
    }

    /**
     * 接口请求行信息
     * 用于越权接口列表、报错(存疑)接口列表、安全接口列表中的条目展示
     */
    public static class EndpointRequestLine {
        private String requestLine;

        public EndpointRequestLine() {
        }

        public EndpointRequestLine(String requestLine) {
            this.requestLine = requestLine;
        }

        public String getRequestLine() {
            return requestLine;
        }

        public void setRequestLine(String requestLine) {
            this.requestLine = requestLine;
        }
    }

    /**
     * 用户信息条目（报告头部展示）
     */
    public static class UserInfoEntry {
        private String sessionName;
        private String role;
        private String username;
        private boolean isAnonymous;
        /** Base64 编码的截图数据 URI 列表（用于 PDF/MD 嵌入），与 screenshotFilenames 一一对应 */
        private List<String> screenshotsBase64;
        /** 截图文件名列表（用于 HTML 文件引用），与 screenshotsBase64 一一对应 */
        private List<String> screenshotFilenames;

        public UserInfoEntry() {
            this.screenshotsBase64 = new ArrayList<>();
            this.screenshotFilenames = new ArrayList<>();
        }

        public String getSessionName() {
            return sessionName;
        }

        public void setSessionName(String sessionName) {
            this.sessionName = sessionName;
        }

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public boolean isAnonymous() {
            return isAnonymous;
        }

        public void setAnonymous(boolean anonymous) {
            isAnonymous = anonymous;
        }

        public List<String> getScreenshotsBase64() {
            return screenshotsBase64;
        }

        public List<String> getScreenshotFilenames() {
            return screenshotFilenames;
        }

        /**
         * 同时设置截图 base64 数据和文件名，确保两者一一对应
         * @throws IllegalArgumentException 如果两个列表大小不一致
         */
        public void setScreenshots(List<String> base64List, List<String> filenameList) {
            if (base64List == null || filenameList == null) {
                this.screenshotsBase64 = base64List != null ? base64List : new ArrayList<>();
                this.screenshotFilenames = filenameList != null ? filenameList : new ArrayList<>();
                return;
            }
            if (base64List.size() != filenameList.size()) {
                throw new IllegalArgumentException(
                    "截图base64列表和文件名列表大小不一致: " + base64List.size() + " vs " + filenameList.size());
            }
            this.screenshotsBase64 = base64List;
            this.screenshotFilenames = filenameList;
        }
    }
}
