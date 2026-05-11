package oxff.top.privilege.report;

/**
 * 报告 body 预渲染器
 * 将请求/响应体预渲染为 HTML/Markdown 字符串，供模板引擎直接输出
 */
public class BodyRenderer {

    private final BinaryContentRenderer binaryRenderer = new BinaryContentRenderer();

    /**
     * 预渲染 body 为 HTML 字符串
     */
    public String renderBodyHtml(byte[] body, String contentType) {
        if (body == null || body.length == 0) {
            return "<pre>[Empty]</pre>\n";
        }

        BinaryContentRenderer.TieredRenderContent content = renderBinaryBody(body, contentType);

        if (content.tier == null) {
            return "<pre>" + escapeHtml(sanitizeBody(body, contentType)) + "</pre>\n";
        }

        return buildBinaryContentHtml(content);
    }

    /**
     * 预渲染 body 为 Markdown 字符串
     */
    public String renderBodyMd(byte[] body, String contentType) {
        if (body == null || body.length == 0) {
            return "```\n[Empty]\n```\n\n";
        }

        BinaryContentRenderer.TieredRenderContent content = renderBinaryBody(body, contentType);

        if (content.tier == null) {
            return "```http\n" + sanitizeBody(body, contentType) + "\n```\n\n";
        }

        return buildBinaryContentMd(content);
    }

    // ========== HTML 渲染 ==========

    private String buildBinaryContentHtml(BinaryContentRenderer.TieredRenderContent content) {
        StringBuilder sb = new StringBuilder();
        sb.append("<div class=\"binary-card\">\n");

        sb.append("  <div class=\"card-header\">Binary Content (").append(escapeHtml(content.contentCategory))
                .append(" — ").append(escapeHtml(content.humanSize)).append(")</div>\n");

        sb.append("  <div class=\"meta-row\"><span class=\"meta-key\">Content-Type:</span> ")
                .append("<span class=\"meta-value\">").append(escapeHtml(content.contentType)).append("</span></div>\n");
        sb.append("  <div class=\"meta-row\"><span class=\"meta-key\">Size:</span> ")
                .append("<span class=\"meta-value\">").append(escapeHtml(content.humanSize)).append("</span></div>\n");

        if (content.metadataCardText != null && content.metadataCardText.contains("SHA-256:")) {
            String shaLine = extractShaFromMetadata(content.metadataCardText);
            sb.append("  <div class=\"meta-row\"><span class=\"meta-key\">SHA-256:</span> ")
                    .append("<span class=\"meta-value\">").append(escapeHtml(shaLine)).append("</span></div>\n");
        }

        if (content.multipartParts != null && !content.multipartParts.isEmpty()) {
            sb.append("  <div class=\"meta-row\"><span class=\"meta-key\">Multipart Parts:</span> ")
                    .append("<span class=\"meta-value\">").append(content.multipartParts.size()).append("</span></div>\n");
            for (BinaryContentRenderer.MultipartPartInfo part : content.multipartParts) {
                sb.append(buildMultipartPartHtml(part));
            }
        }

        if (content.hexDumpPreview != null && !content.hexDumpPreview.isEmpty()) {
            sb.append("  <pre class=\"hex-dump\">").append(escapeHtml(content.hexDumpPreview)).append("</pre>\n");
        }

        if (content.base64Content != null && !content.base64Content.isEmpty()) {
            sb.append("  <details class=\"base64-section\"><summary>Base64 (")
                    .append(content.base64Content.length()).append(" chars)</summary>\n");
            sb.append("    <pre>").append(escapeHtml(content.base64Content)).append("</pre>\n");
            sb.append("  </details>\n");
        }

        sb.append("</div>\n");
        return sb.toString();
    }

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
            if (part.binaryPreview != null && part.binaryPreview.length > 0) {
                String hexDump = BinaryContentRenderer.generateHexDump(part.binaryPreview, part.binaryPreview.length);
                sb.append("    <pre class=\"hex-dump\">").append(escapeHtml(hexDump)).append("</pre>\n");
            }
        }

        sb.append("  </div>\n");
        return sb.toString();
    }

    // ========== Markdown 渲染 ==========

    private String buildBinaryContentMd(BinaryContentRenderer.TieredRenderContent content) {
        StringBuilder sb = new StringBuilder();

        sb.append("**Binary Content (").append(content.contentCategory)
                .append(" — ").append(content.humanSize).append(")**\n\n");

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

        if (content.multipartParts != null) {
            for (BinaryContentRenderer.MultipartPartInfo part : content.multipartParts) {
                sb.append(buildMultipartPartMd(part));
            }
        }

        if (content.hexDumpPreview != null && !content.hexDumpPreview.isEmpty()) {
            sb.append("```hex\n").append(content.hexDumpPreview).append("```\n\n");
        }

        if (content.base64Content != null && !content.base64Content.isEmpty()) {
            sb.append("<details><summary>Base64 (").append(content.base64Content.length())
                    .append(" chars)</summary>\n\n");
            sb.append("```base64\n").append(content.base64Content).append("\n```\n\n");
            sb.append("</details>\n\n");
        }

        return sb.toString();
    }

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
            if (part.binaryPreview != null && part.binaryPreview.length > 0) {
                String hexDump = BinaryContentRenderer.generateHexDump(part.binaryPreview, part.binaryPreview.length);
                sb.append("```hex\n").append(hexDump).append("```\n\n");
            }
        }

        return sb.toString();
    }

    // ========== 共享工具方法 ==========

    private BinaryContentRenderer.TieredRenderContent renderBinaryBody(byte[] body, String contentTypeHeader) {
        if (body == null || body.length == 0) {
            return new BinaryContentRenderer.TieredRenderContent(null, "", "", null, null,
                    "text/plain", "text", "0 bytes");
        }

        BinaryContentRenderer.BinaryAnalysisResult analysis = binaryRenderer.analyzeBody(body, contentTypeHeader);
        if (!analysis.isBinary) {
            return new BinaryContentRenderer.TieredRenderContent(null, "", "", null, null,
                    analysis.contentType, "text", analysis.humanSize);
        }

        return binaryRenderer.createTieredContent(analysis);
    }

    private boolean isBinaryBody(byte[] data) {
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

    private String sanitizeBody(byte[] body, String contentType) {
        if (body == null || body.length == 0) return "[Empty]";
        if (isBinaryBody(body)) return "[Binary data — " + body.length + " bytes]";
        String text = BinaryContentRenderer.decodeBody(body, contentType);
        if (text.length() > 50000) {
            text = text.substring(0, 50000) + "\n\n... [Truncated — total " + body.length + " bytes]";
        }
        return text;
    }

    private String extractShaFromMetadata(String metadata) {
        for (String line : metadata.split("\n")) {
            if (line.startsWith("SHA-256:")) {
                return line.substring("SHA-256:".length()).trim();
            }
        }
        return "";
    }

    private String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private String escapeMd(String s) {
        if (s == null) return "";
        return s.replace("|", "\\|").replace("\n", " ");
    }

    /**
     * 从 HTTP 响应数据中提取 Content-Type
     */
    public String extractResponseContentType(byte[] responseData) {
        return BinaryContentRenderer.extractContentTypeFromResponse(responseData);
    }

    /**
     * 从 HTTP 请求数据中提取 Content-Type
     */
    public String extractRequestContentType(byte[] requestData) {
        return BinaryContentRenderer.extractContentTypeFromRequest(requestData);
    }
}
