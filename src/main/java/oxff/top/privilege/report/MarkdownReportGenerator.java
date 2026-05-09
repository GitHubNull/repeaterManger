package oxff.top.privilege.report;

import java.text.SimpleDateFormat;
import java.util.List;

/**
 * Markdown 格式报告生成器
 * 生成 GitHub-Flavored Markdown 报告
 */
public class MarkdownReportGenerator extends ReportGenerator {

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    @Override
    public String getFileExtension() {
        return "md";
    }

    @Override
    public String generate(ReportData data) {
        StringBuilder md = new StringBuilder();

        // Header
        md.append("# ").append(data.getTitle()).append("\n\n");
        md.append("> Generated: ").append(DATE_FORMAT.format(data.getGeneratedAt()))
                .append(" | Repeater Manager v").append(data.getPluginVersion()).append("\n\n");

        // Summary
        md.append(buildSummary(data.getSummary()));

        // Session Breakdown
        md.append(buildSessionBreakdown(data.getSessionBreakdown()));

        // Endpoints
        md.append("## Findings by Endpoint\n\n");
        for (ReportData.EndpointSummary endpoint : data.getEndpoints()) {
            md.append(buildEndpointSection(endpoint));
        }

        return md.toString();
    }

    private String buildSummary(ReportData.ReportSummary s) {
        StringBuilder sb = new StringBuilder();
        sb.append("## Summary\n\n");
        sb.append("| Metric | Count |\n");
        sb.append("|--------|-------|\n");
        sb.append("| Total Tests | ").append(s.getTotalTests()).append(" |\n");
        sb.append("| Escalated (&#9888;) | ").append(s.getEscalatedCount()).append(" |\n");
        sb.append("| Safe (&#10004;) | ").append(s.getSafeCount()).append(" |\n");
        sb.append("| Errors (&#10007;) | ").append(s.getErrorCount()).append(" |\n");
        sb.append("| Unique Endpoints | ").append(s.getEndpointsTested()).append(" |\n\n");
        return sb.toString();
    }

    private String buildSessionBreakdown(List<ReportData.SessionBreakdown> sessions) {
        if (sessions.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("## Session Breakdown\n\n");
        sb.append("| Session | Escalated | Safe | Errors | Total |\n");
        sb.append("|---------|-----------|------|--------|-------|\n");
        for (ReportData.SessionBreakdown s : sessions) {
            sb.append("| ").append(escapeMd(s.getSessionName()))
                    .append(" | ").append(s.getEscalatedCount())
                    .append(" | ").append(s.getSafeCount())
                    .append(" | ").append(s.getErrorCount())
                    .append(" | ").append(s.getTotalTests()).append(" |\n");
        }
        sb.append("\n");
        return sb.toString();
    }

    private String buildEndpointSection(ReportData.EndpointSummary endpoint) {
        StringBuilder sb = new StringBuilder();
        sb.append("### ").append(endpoint.getMethod()).append(" ").append(endpoint.getUrl()).append("\n\n");
        sb.append("**Tests: ").append(endpoint.getTotalTests()).append(" | ");
        sb.append("Escalated: ").append(endpoint.getEscalatedCount()).append(" | ");
        sb.append("Safe: ").append(endpoint.getSafeCount()).append("**\n\n");

        for (ReportData.Finding finding : endpoint.getFindings()) {
            sb.append(buildFinding(finding));
        }
        return sb.toString();
    }

    private String buildFinding(ReportData.Finding finding) {
        StringBuilder sb = new StringBuilder();
        String judgmentIcon = "ESCALATED".equalsIgnoreCase(finding.getJudgment()) ? "&#9888; ESCALATED"
                : "NOT_ESCALATED".equalsIgnoreCase(finding.getJudgment()) ? "&#10004; SAFE"
                : "&#10007; ERROR";

        sb.append("#### Finding: ").append(judgmentIcon).append(" — Session \"").append(escapeMd(finding.getUserSessionName())).append("\"\n\n");

        if (finding.getMatchedRuleName() != null) {
            sb.append("- **Rule**: ").append(escapeMd(finding.getMatchedRuleName())).append("\n");
        }
        sb.append("- **Similarity**: ").append(String.format("%.2f", finding.getSimilarity())).append("\n");
        sb.append("- **Status**: HTTP ").append(finding.getRecord().getStatusCode())
                .append(" | ").append(finding.getRecord().getResponseLength()).append(" bytes | ")
                .append(finding.getRecord().getResponseTime()).append("ms\n\n");

        // Request
        sb.append("**Request:**\n\n```http\n")
                .append(sanitizeBody(finding.getRecord().getRequestData())).append("\n```\n\n");

        // Response
        sb.append("**Response:**\n\n```\n")
                .append(sanitizeBody(finding.getRecord().getResponseData())).append("\n```\n\n");

        // cURL
        sb.append("**Reproduction (cURL):**\n\n```bash\n")
                .append(finding.getCurlCommand()).append("\n```\n\n");

        // Postman
        sb.append("**Reproduction (Postman):**\n\n```json\n")
                .append(finding.getPostmanSnippet()).append("\n```\n\n");

        sb.append("---\n\n");
        return sb.toString();
    }

    private String escapeMd(String s) {
        if (s == null) return "";
        return s.replace("|", "\\|").replace("\n", " ");
    }
}
