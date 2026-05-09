package oxff.top.privilege.report;

import oxff.top.http.RequestResponseRecord;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * 越权测试报告数据模型
 */
public class ReportData {

    private String title = "Privilege Escalation Test Report";
    private Date generatedAt = new Date();
    private String pluginVersion = "2.6.0";

    private ReportSummary summary;
    private List<EndpointSummary> endpoints = new ArrayList<>();
    private List<SessionBreakdown> sessionBreakdown = new ArrayList<>();

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

    public List<EndpointSummary> getEndpoints() {
        return endpoints;
    }

    public void setEndpoints(List<EndpointSummary> endpoints) {
        this.endpoints = endpoints;
    }

    public List<SessionBreakdown> getSessionBreakdown() {
        return sessionBreakdown;
    }

    public void setSessionBreakdown(List<SessionBreakdown> sessionBreakdown) {
        this.sessionBreakdown = sessionBreakdown;
    }

    /**
     * 报告汇总统计
     */
    public static class ReportSummary {
        private int totalTests;
        private int escalatedCount;
        private int safeCount;
        private int errorCount;
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

        public int getEndpointsTested() {
            return endpointsTested;
        }

        public void setEndpointsTested(int endpointsTested) {
            this.endpointsTested = endpointsTested;
        }
    }

    /**
     * 端点汇总（按 URL 分组）
     */
    public static class EndpointSummary {
        private String method;
        private String url;
        private int escalatedCount;
        private int safeCount;
        private int errorCount;
        private List<Finding> findings = new ArrayList<>();

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

        public List<Finding> getFindings() {
            return findings;
        }

        public void setFindings(List<Finding> findings) {
            this.findings = findings;
        }
    }

    /**
     * 单条发现详情
     */
    public static class Finding {
        private String userSessionName;
        private String judgment;
        private double similarity;
        private String matchedRuleName;
        private RequestResponseRecord record;
        private String curlCommand;
        private String postmanSnippet;

        public String getUserSessionName() {
            return userSessionName;
        }

        public void setUserSessionName(String userSessionName) {
            this.userSessionName = userSessionName;
        }

        public String getJudgment() {
            return judgment;
        }

        public void setJudgment(String judgment) {
            this.judgment = judgment;
        }

        public double getSimilarity() {
            return similarity;
        }

        public void setSimilarity(double similarity) {
            this.similarity = similarity;
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
}
