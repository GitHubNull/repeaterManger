package oxff.top.privilege.report;

import oxff.top.http.RequestResponseRecord;

import java.text.SimpleDateFormat;
import java.util.List;

/**
 * Markdown 格式报告生成器
 * 生成 GitHub-Flavored Markdown 报告，支持二进制内容智能渲染
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
        sb.append("| Baseline | ").append(s.getBaselineCount()).append(" |\n");
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
        sb.append("**");
        if (endpoint.getBaselineCount() > 0) {
            sb.append("Baseline: ").append(endpoint.getBaselineCount()).append(" | ");
        }
        sb.append("Tests: ").append(endpoint.getTotalTests()).append(" | ");
        sb.append("Escalated: ").append(endpoint.getEscalatedCount()).append(" | ");
        sb.append("Safe: ").append(endpoint.getSafeCount()).append("**\n\n");

        for (ReportData.Finding finding : endpoint.getFindings()) {
            sb.append(buildFinding(finding));
        }
        return sb.toString();
    }

    private String buildFinding(ReportData.Finding finding) {
        StringBuilder sb = new StringBuilder();
        String judgmentIcon;
        if (finding.isBaseline()) {
            judgmentIcon = "BASELINE";
        } else if ("ESCALATED".equalsIgnoreCase(finding.getJudgment())) {
            judgmentIcon = "&#9888; ESCALATED";
        } else if ("NOT_ESCALATED".equalsIgnoreCase(finding.getJudgment())) {
            judgmentIcon = "&#10004; SAFE";
        } else {
            judgmentIcon = "&#10007; ERROR";
        }

        sb.append("#### Finding: ").append(judgmentIcon).append(" — Session \"").append(escapeMd(finding.getUserSessionName())).append("\"\n\n");

        if (finding.getMatchedRuleName() != null) {
            sb.append("- **Rule**: ").append(escapeMd(finding.getMatchedRuleName())).append("\n");
        }
        if (finding.isBaseline()) {
            sb.append("- **Similarity**: N/A (baseline)\n");
        } else {
            sb.append("- **Similarity**: ").append(String.format("%.2f", finding.getSimilarity())).append("\n");
        }
        sb.append("- **Status**: HTTP ").append(finding.getRecord().getStatusCode())
                .append(" | ").append(finding.getRecord().getResponseLength()).append(" bytes | ")
                .append(finding.getRecord().getResponseTime()).append("ms\n\n");

        // 非基准 Finding：在当前报文前展示基准报文（折叠）
        if (!finding.isBaseline() && finding.getBaselineRecord() != null) {
            RequestResponseRecord baselineRec = finding.getBaselineRecord();
            sb.append("<details><summary>Baseline Request — Session: ")
                    .append(escapeMd(finding.getBaselineSessionName())).append("</summary>\n\n");
            sb.append(renderBodyMd(baselineRec.getRequestData(),
                    extractRequestContentType(baselineRec.getRequestData())));
            sb.append("</details>\n\n");

            sb.append("<details><summary>Baseline Response — HTTP ").append(baselineRec.getStatusCode())
                    .append(" (").append(baselineRec.getResponseLength()).append(" bytes, ")
                    .append(baselineRec.getResponseTime()).append("ms) — Session: ")
                    .append(escapeMd(finding.getBaselineSessionName())).append("</summary>\n\n");
            sb.append(renderBodyMd(baselineRec.getResponseData(),
                    extractResponseContentType(baselineRec.getResponseData())));
            sb.append("</details>\n\n");
        }

        // Request — 智能渲染
        sb.append("**Request:**\n\n");
        sb.append(renderBodyMd(finding.getRecord().getRequestData(),
                extractRequestContentType(finding.getRecord().getRequestData())));

        // Response — 智能渲染
        sb.append("**Response:**\n\n");
        sb.append(renderBodyMd(finding.getRecord().getResponseData(),
                extractResponseContentType(finding.getRecord().getResponseData())));

        // cURL
        sb.append("**Reproduction (cURL):**\n\n```bash\n")
                .append(finding.getCurlCommand()).append("\n```\n\n");

        // Postman
        sb.append("**Reproduction (Postman):**\n\n```json\n")
                .append(finding.getPostmanSnippet()).append("\n```\n\n");

        sb.append("---\n\n");
        return sb.toString();
    }

    /**
     * 智能渲染 body: 二进制内容展示为元数据表+hex预览，文本保持原样
     */
    private String renderBodyMd(byte[] body, String contentType) {
        if (body == null || body.length == 0) {
            return "```\n[Empty]\n```\n\n";
        }

        BinaryContentRenderer.TieredRenderContent content = renderBinaryBody(body, contentType);

        // 文本内容: 保持原有渲染
        if (content.tier == null) {
            return "```http\n" + sanitizeBody(body) + "\n```\n\n";
        }

        // 二进制内容
        return buildBinaryContentMd(content);
    }

    /**
     * 构建二进制内容 Markdown
     */
    private String buildBinaryContentMd(BinaryContentRenderer.TieredRenderContent content) {
        StringBuilder sb = new StringBuilder();

        sb.append("**Binary Content (").append(content.contentCategory)
                .append(" — ").append(content.humanSize).append(")**\n\n");

        // 元数据表
        sb.append("| Property | Value |\n");
        sb.append("|----------|-------|\n");
        sb.append("| Content-Type | ").append(escapeMd(content.contentType)).append(" |\n");
        sb.append("| Size | ").append(escapeMd(content.humanSize)).append(" |\n");
        if (content.metadataCardText != null) {
            String sha = extractShaFromMetadata(content.metadataCardText);
            if (!sha.isEmpty()) {
                sb.append("| SHA-256 | `").append(sha).append("` |\n");
            }
        }
        if (content.multipartParts != null && !content.multipartParts.isEmpty()) {
            sb.append("| Multipart Parts | ").append(content.multipartParts.size()).append(" |\n");
        }
        sb.append("\n");

        // Multipart 部分
        if (content.multipartParts != null) {
            for (BinaryContentRenderer.MultipartPartInfo part : content.multipartParts) {
                sb.append(buildMultipartPartMd(part));
            }
        }

        // Hex dump 预览
        if (content.hexDumpPreview != null && !content.hexDumpPreview.isEmpty()) {
            sb.append("```hex\n").append(content.hexDumpPreview).append("```\n\n");
        }

        // Base64 折叠 (GFM 兼容)
        if (content.base64Content != null && !content.base64Content.isEmpty()) {
            sb.append("<details><summary>Base64 (").append(content.base64Content.length())
                    .append(" chars)</summary>\n\n");
            sb.append("```base64\n").append(content.base64Content).append("\n```\n\n");
            sb.append("</details>\n\n");
        }

        return sb.toString();
    }

    /**
     * 构建 multipart 单 part Markdown
     */
    private String buildMultipartPartMd(BinaryContentRenderer.MultipartPartInfo part) {
        StringBuilder sb = new StringBuilder();

        sb.append("##### Part: ");
        if (part.name != null) sb.append(part.name);
        if (part.fileName != null) sb.append(" (").append(part.fileName).append(")");
        sb.append(" — ").append(part.partContentType)
                .append(" — ").append(BinaryContentRenderer.formatHumanSize(part.partSize));
        sb.append("\n\n");

        if (part.isText) {
            sb.append("```http\n").append(part.textContent).append("\n```\n\n");
        } else {
            // 二进制 part: hex 预览
            if (part.binaryPreview != null && part.binaryPreview.length > 0) {
                String hexDump = BinaryContentRenderer.generateHexDump(part.binaryPreview, part.binaryPreview.length);
                sb.append("```hex\n").append(hexDump).append("```\n\n");
            }
        }

        return sb.toString();
    }

    /**
     * 从元数据卡文本中提取 SHA-256 值
     */
    private String extractShaFromMetadata(String metadata) {
        for (String line : metadata.split("\n")) {
            if (line.startsWith("SHA-256:")) {
                return line.substring("SHA-256:".length()).trim();
            }
        }
        return "";
    }

    private String escapeMd(String s) {
        if (s == null) return "";
        return s.replace("|", "\\|").replace("\n", " ");
    }
}
