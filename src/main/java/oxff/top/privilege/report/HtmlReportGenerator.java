package oxff.top.privilege.report;

import java.text.SimpleDateFormat;
import java.util.List;

/**
 * HTML 格式报告生成器
 * 生成自包含的 HTML 报告（内联 CSS），支持二进制内容智能渲染
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
                // === 二进制内容渲染 CSS ===
                "  .binary-card { border: 1px solid #b0bec5; border-radius: 6px; margin: 6px 0; overflow: hidden; }\n" +
                "  .binary-card .card-header { background: #eceff1; padding: 8px 14px; font-weight: 600; font-size: 13px; color: #37474f; " +
                "    border-bottom: 1px solid #cfd8dc; }\n" +
                "  .binary-card .meta-row { padding: 4px 14px; font-size: 12px; display: flex; }\n" +
                "  .binary-card .meta-key { font-weight: 600; color: #546e7a; min-width: 130px; flex-shrink: 0; }\n" +
                "  .binary-card .meta-value { font-family: 'Courier New', monospace; color: #263238; word-break: break-all; }\n" +
                "  .binary-card pre.hex-dump { background: #1a1a2e; color: #a8d8ea; font-size: 11px; max-height: 300px; border-radius: 0 0 4px 4px; }\n" +
                "  .binary-card details.base64-section summary { padding: 6px 14px; background: #e8eaf6; cursor: pointer; font-size: 12px; font-weight: 600; color: #283593; }\n" +
                "  .binary-card details.base64-section pre { border-radius: 0; max-height: 200px; }\n" +
                "  .multipart-part { border: 1px dashed #90a4ae; border-radius: 4px; margin: 6px 14px; }\n" +
                "  .multipart-part .part-header { padding: 4px 10px; background: #f5f5f5; font-size: 12px; font-weight: 600; color: #546e7a; }\n" +
                "  .multipart-part pre { border-radius: 0 0 4px 4px; margin: 0; }\n" +
                "  .multipart-binary-part { background: #fff8e1; border-color: #ffb74d; }\n" +
                "  .multipart-binary-part .part-header { background: #fff3e0; color: #e65100; }\n" +
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

        // Request — 智能渲染
        sb.append("    <div class=\"section-title\">Request</div>\n");
        sb.append(renderBodyHtml(finding.getRecord().getRequestData(),
                extractRequestContentType(finding.getRecord().getRequestData())));

        // Response — 智能渲染
        sb.append("    <div class=\"section-title\">Response — HTTP ")
                .append(finding.getRecord().getStatusCode()).append(" (")
                .append(finding.getRecord().getResponseLength()).append(" bytes, ")
                .append(finding.getRecord().getResponseTime()).append("ms)</div>\n");
        sb.append(renderBodyHtml(finding.getRecord().getResponseData(),
                extractResponseContentType(finding.getRecord().getResponseData())));

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

    /**
     * 智能渲染 body：二进制内容展示为元数据卡+hex预览，文本保持原样
     */
    private String renderBodyHtml(byte[] body, String contentType) {
        if (body == null || body.length == 0) {
            return "<pre>[Empty]</pre>\n";
        }

        BinaryContentRenderer.TieredRenderContent content = renderBinaryBody(body, contentType);

        // 文本内容: 保持原有渲染
        if (content.tier == null) {
            return "<pre>" + escapeHtml(sanitizeBody(body)) + "</pre>\n";
        }

        // 二进制内容: 渲染为 binary-card
        return buildBinaryContentHtml(content);
    }

    /**
     * 构建二进制内容 HTML 卡片
     */
    private String buildBinaryContentHtml(BinaryContentRenderer.TieredRenderContent content) {
        StringBuilder sb = new StringBuilder();
        sb.append("<div class=\"binary-card\">\n");

        // 卡片标题
        sb.append("  <div class=\"card-header\">Binary Content (").append(escapeHtml(content.contentCategory))
                .append(" — ").append(escapeHtml(content.humanSize)).append(")</div>\n");

        // 元数据行
        sb.append("  <div class=\"meta-row\"><span class=\"meta-key\">Content-Type:</span> ")
                .append("<span class=\"meta-value\">").append(escapeHtml(content.contentType)).append("</span></div>\n");
        sb.append("  <div class=\"meta-row\"><span class=\"meta-key\">Size:</span> ")
                .append("<span class=\"meta-value\">").append(escapeHtml(content.humanSize)).append("</span></div>\n");

        // SHA-256 (仅显示前32字符 + ...)
        if (content.metadataCardText != null && content.metadataCardText.contains("SHA-256:")) {
            String shaLine = extractShaFromMetadata(content.metadataCardText);
            sb.append("  <div class=\"meta-row\"><span class=\"meta-key\">SHA-256:</span> ")
                    .append("<span class=\"meta-value\">").append(escapeHtml(shaLine)).append("</span></div>\n");
        }

        // Multipart 部分
        if (content.multipartParts != null && !content.multipartParts.isEmpty()) {
            sb.append("  <div class=\"meta-row\"><span class=\"meta-key\">Multipart Parts:</span> ")
                    .append("<span class=\"meta-value\">").append(content.multipartParts.size()).append("</span></div>\n");
            for (BinaryContentRenderer.MultipartPartInfo part : content.multipartParts) {
                sb.append(buildMultipartPartHtml(part));
            }
        }

        // Hex dump 预览 (SMALL / MEDIUM)
        if (content.hexDumpPreview != null && !content.hexDumpPreview.isEmpty()) {
            sb.append("  <pre class=\"hex-dump\">").append(escapeHtml(content.hexDumpPreview)).append("</pre>\n");
        }

        // Base64 折叠 (仅 SMALL)
        if (content.base64Content != null && !content.base64Content.isEmpty()) {
            sb.append("  <details class=\"base64-section\"><summary>Base64 (")
                    .append(content.base64Content.length()).append(" chars)</summary>\n");
            sb.append("    <pre>").append(escapeHtml(content.base64Content)).append("</pre>\n");
            sb.append("  </details>\n");
        }

        sb.append("</div>\n");
        return sb.toString();
    }

    /**
     * 构建 multipart 单 part HTML
     */
    private String buildMultipartPartHtml(BinaryContentRenderer.MultipartPartInfo part) {
        StringBuilder sb = new StringBuilder();
        String partClass = part.isText ? "multipart-part" : "multipart-part multipart-binary-part";

        sb.append("  <div class=\"").append(partClass).append("\">\n");
        sb.append("    <div class=\"part-header\">");
        if (part.name != null) sb.append("Field: ").append(escapeHtml(part.name));
        if (part.fileName != null) sb.append(" | File: ").append(escapeHtml(part.fileName));
        sb.append(" | Type: ").append(escapeHtml(part.partContentType));
        sb.append(" | ").append(BinaryContentRenderer.formatHumanSize(part.partSize));
        sb.append("</div>\n");

        if (part.isText) {
            sb.append("    <pre>").append(escapeHtml(part.textContent)).append("</pre>\n");
        } else {
            // 二进制 part: hex 预览
            if (part.binaryPreview != null && part.binaryPreview.length > 0) {
                String hexDump = BinaryContentRenderer.generateHexDump(part.binaryPreview, part.binaryPreview.length);
                sb.append("    <pre class=\"hex-dump\">").append(escapeHtml(hexDump)).append("</pre>\n");
            }
        }

        sb.append("  </div>\n");
        return sb.toString();
    }

    /**
     * 从元数据卡文本中提取 SHA-256 行
     */
    private String extractShaFromMetadata(String metadata) {
        for (String line : metadata.split("\n")) {
            if (line.startsWith("SHA-256:")) {
                return line.substring("SHA-256:".length()).trim();
            }
        }
        return "";
    }
}
