package oxff.top.privilege.report;

import java.text.SimpleDateFormat;
import java.util.List;

/**
 * HTML 格式报告生成器
 * 生成自包含的 HTML 报告（内联 CSS）
 */
public class HtmlReportGenerator extends ReportGenerator {

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    @Override
    public String getFileExtension() {
        return "html";
    }

    @Override
    public String generate(ReportData data) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n");
        html.append("<meta charset=\"UTF-8\">\n");
        html.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.append("<title>").append(escapeHtml(data.getTitle())).append("</title>\n");
        html.append(getCss());
        html.append("</head>\n<body>\n");

        // Header
        html.append("<div class=\"header\">\n");
        html.append("  <h1>").append(escapeHtml(data.getTitle())).append("</h1>\n");
        html.append("  <p class=\"meta\">Generated: ").append(DATE_FORMAT.format(data.getGeneratedAt()))
                .append(" | Repeater Manager v").append(escapeHtml(data.getPluginVersion())).append("</p>\n");
        html.append("</div>\n");

        // Summary
        html.append(buildSummarySection(data.getSummary()));

        // Session Breakdown
        html.append(buildSessionBreakdown(data.getSessionBreakdown()));

        // Endpoints
        html.append("<h2>Findings by Endpoint</h2>\n");
        for (ReportData.EndpointSummary endpoint : data.getEndpoints()) {
            html.append(buildEndpointSection(endpoint));
        }

        html.append("</body>\n</html>");
        return html.toString();
    }

    private String getCss() {
        return "<style>\n" +
                "  * { margin: 0; padding: 0; box-sizing: border-box; }\n" +
                "  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; " +
                "    font-size: 14px; color: #333; line-height: 1.6; max-width: 1100px; margin: 0 auto; " +
                "    padding: 20px; background: #f5f5f5; }\n" +
                "  .header { background: #1a237e; color: white; padding: 30px; border-radius: 8px; margin-bottom: 24px; }\n" +
                "  .header h1 { font-size: 24px; margin-bottom: 8px; }\n" +
                "  .header .meta { font-size: 13px; opacity: 0.85; }\n" +
                "  h2 { font-size: 20px; margin: 28px 0 16px; color: #1a237e; border-bottom: 2px solid #1a237e; padding-bottom: 8px; }\n" +
                "  h3 { font-size: 16px; margin: 16px 0 10px; color: #283593; }\n" +
                "  .summary-cards { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }\n" +
                "  .card { flex: 1; min-width: 140px; background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }\n" +
                "  .card .number { font-size: 32px; font-weight: 700; }\n" +
                "  .card .label { font-size: 13px; color: #666; margin-top: 4px; }\n" +
                "  .card.total { border-top: 4px solid #1a237e; }\n" +
                "  .card.escalated { border-top: 4px solid #d32f2f; }\n" +
                "  .card.escalated .number { color: #d32f2f; }\n" +
                "  .card.safe { border-top: 4px solid #2e7d32; }\n" +
                "  .card.safe .number { color: #2e7d32; }\n" +
                "  .card.error { border-top: 4px solid #f57c00; }\n" +
                "  .card.error .number { color: #f57c00; }\n" +
                "  table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; " +
                "    overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 16px; }\n" +
                "  th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #e0e0e0; }\n" +
                "  th { background: #1a237e; color: white; font-weight: 600; font-size: 13px; }\n" +
                "  tr:hover td { background: #f5f5f5; }\n" +
                "  .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; color: white; }\n" +
                "  .badge.escalated { background: #d32f2f; }\n" +
                "  .badge.safe { background: #2e7d32; }\n" +
                "  .badge.error { background: #f57c00; }\n" +
                "  .endpoint-section { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; " +
                "    box-shadow: 0 1px 3px rgba(0,0,0,0.1); }\n" +
                "  .endpoint-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }\n" +
                "  .endpoint-header .method { font-weight: 700; color: #1a237e; }\n" +
                "  .finding { border: 1px solid #e0e0e0; border-radius: 6px; margin-bottom: 10px; overflow: hidden; }\n" +
                "  .finding summary { padding: 10px 14px; background: #fafafa; cursor: pointer; font-weight: 600; " +
                "    display: flex; justify-content: space-between; align-items: center; }\n" +
                "  .finding-content { padding: 14px; }\n" +
                "  .finding-content .section-title { font-weight: 600; color: #555; margin: 10px 0 6px; font-size: 13px; }\n" +
                "  pre { background: #263238; color: #eeffff; padding: 12px 16px; border-radius: 4px; overflow-x: auto; " +
                "    font-size: 12px; line-height: 1.5; max-height: 400px; overflow-y: auto; margin: 6px 0; }\n" +
                "  .curl-block { background: #1e1e1e; color: #d4d4d4; }\n" +
                "  .postman-block { background: #263238; color: #eeffff; max-height: 200px; }\n" +
                "  .meta-info { font-size: 12px; color: #888; margin-bottom: 6px; }\n" +
                "  .meta-info span { margin-right: 16px; }\n" +
                "  @media print { body { background: white; padding: 0; } .card { box-shadow: none; border: 1px solid #ddd; } }\n" +
                "</style>\n";
    }

    private String buildSummarySection(ReportData.ReportSummary s) {
        StringBuilder sb = new StringBuilder();
        sb.append("<h2>Summary</h2>\n");
        sb.append("<div class=\"summary-cards\">\n");
        sb.append("  <div class=\"card total\"><div class=\"number\">").append(s.getTotalTests())
                .append("</div><div class=\"label\">Total Tests</div></div>\n");
        sb.append("  <div class=\"card escalated\"><div class=\"number\">").append(s.getEscalatedCount())
                .append("</div><div class=\"label\">&#9888; Escalated</div></div>\n");
        sb.append("  <div class=\"card safe\"><div class=\"number\">").append(s.getSafeCount())
                .append("</div><div class=\"label\">&#10004; Safe</div></div>\n");
        sb.append("  <div class=\"card error\"><div class=\"number\">").append(s.getErrorCount())
                .append("</div><div class=\"label\">&#10007; Errors</div></div>\n");
        sb.append("</div>\n");
        return sb.toString();
    }

    private String buildSessionBreakdown(List<ReportData.SessionBreakdown> sessions) {
        if (sessions.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("<h2>Session Breakdown</h2>\n");
        sb.append("<table><tr><th>Session</th><th>Escalated</th><th>Safe</th><th>Errors</th><th>Total</th></tr>\n");
        for (ReportData.SessionBreakdown s : sessions) {
            sb.append("<tr><td>").append(escapeHtml(s.getSessionName())).append("</td>");
            sb.append("<td>").append(s.getEscalatedCount()).append("</td>");
            sb.append("<td>").append(s.getSafeCount()).append("</td>");
            sb.append("<td>").append(s.getErrorCount()).append("</td>");
            sb.append("<td>").append(s.getTotalTests()).append("</td></tr>\n");
        }
        sb.append("</table>\n");
        return sb.toString();
    }

    private String buildEndpointSection(ReportData.EndpointSummary endpoint) {
        StringBuilder sb = new StringBuilder();
        sb.append("<div class=\"endpoint-section\">\n");
        sb.append("  <div class=\"endpoint-header\">\n");
        sb.append("    <div><span class=\"method\">").append(escapeHtml(endpoint.getMethod()))
                .append("</span> ").append(escapeHtml(endpoint.getUrl())).append("</div>\n");
        sb.append("    <div class=\"meta-info\">\n");
        sb.append("      Tests: ").append(endpoint.getTotalTests());
        if (endpoint.getEscalatedCount() > 0) {
            sb.append(" | <span style=\"color:#d32f2f;font-weight:600\">&#9888; ")
                    .append(endpoint.getEscalatedCount()).append(" Escalated</span>");
        }
        sb.append(" | &#10004; ").append(endpoint.getSafeCount()).append(" Safe");
        sb.append("    </div>\n");
        sb.append("  </div>\n");

        for (ReportData.Finding finding : endpoint.getFindings()) {
            sb.append(buildFinding(finding));
        }
        sb.append("</div>\n");
        return sb.toString();
    }

    private String buildFinding(ReportData.Finding finding) {
        StringBuilder sb = new StringBuilder();
        String badgeClass = "ESCALATED".equalsIgnoreCase(finding.getJudgment()) ? "escalated"
                : "NOT_ESCALATED".equalsIgnoreCase(finding.getJudgment()) ? "safe" : "error";
        String judgmentLabel = "ESCALATED".equalsIgnoreCase(finding.getJudgment()) ? "ESCALATED"
                : "NOT_ESCALATED".equalsIgnoreCase(finding.getJudgment()) ? "SAFE" : "ERROR";

        sb.append("<details class=\"finding\">\n");
        sb.append("  <summary>\n");
        sb.append("    <span>Session: <strong>").append(escapeHtml(finding.getUserSessionName()))
                .append("</strong></span>\n");
        sb.append("    <span class=\"badge ").append(badgeClass).append("\">").append(judgmentLabel).append("</span>\n");
        sb.append("  </summary>\n");
        sb.append("  <div class=\"finding-content\">\n");

        if (finding.getMatchedRuleName() != null) {
            sb.append("    <div>Rule: <strong>").append(escapeHtml(finding.getMatchedRuleName()))
                    .append("</strong></div>\n");
        }
        sb.append("    <div class=\"meta-info\">Similarity: ")
                .append(String.format("%.2f", finding.getSimilarity())).append("</div>\n");

        // Request
        sb.append("    <div class=\"section-title\">Request</div>\n");
        sb.append("    <pre>").append(escapeHtml(sanitizeBody(finding.getRecord().getRequestData())))
                .append("</pre>\n");

        // Response
        sb.append("    <div class=\"section-title\">Response — HTTP ")
                .append(finding.getRecord().getStatusCode()).append(" (")
                .append(finding.getRecord().getResponseLength()).append(" bytes, ")
                .append(finding.getRecord().getResponseTime()).append("ms)</div>\n");
        sb.append("    <pre>").append(escapeHtml(sanitizeBody(finding.getRecord().getResponseData())))
                .append("</pre>\n");

        // cURL
        sb.append("    <div class=\"section-title\">Reproduction — cURL</div>\n");
        sb.append("    <pre class=\"curl-block\">").append(escapeHtml(finding.getCurlCommand()))
                .append("</pre>\n");

        // Postman snippet
        sb.append("    <div class=\"section-title\">Reproduction — Postman Import</div>\n");
        sb.append("    <pre class=\"postman-block\">").append(escapeHtml(finding.getPostmanSnippet()))
                .append("</pre>\n");

        sb.append("  </div>\n");
        sb.append("</details>\n");
        return sb.toString();
    }
}
