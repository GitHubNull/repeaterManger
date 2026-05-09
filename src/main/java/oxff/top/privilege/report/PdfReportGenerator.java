package oxff.top.privilege.report;

import oxff.top.http.RequestResponseRecord;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;

import java.io.ByteArrayOutputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;

/**
 * PDF 格式报告生成器
 * 使用 Apache PDFBox 直接布局，支持二进制内容智能渲染
 */
public class PdfReportGenerator extends ReportGenerator {

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static final float PAGE_WIDTH = PDRectangle.A4.getWidth();
    private static final float PAGE_HEIGHT = PDRectangle.A4.getHeight();
    private static final float MARGIN = 50;
    private static final float CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN;
    /** PDF 中每个代码块的最大字符数，避免报告过大 */
    private static final int PDF_BODY_LIMIT = 3000;
    /** PDF 中 base64 显示的最大字符数 */
    private static final int PDF_BASE64_LIMIT = 2000;

    @Override
    public String getFileExtension() {
        return "pdf";
    }

    @Override
    public String generate(ReportData data) {
        return "[PDF report — use generateToBytes() for binary output]";
    }

    /**
     * 生成 PDF 到字节数组
     */
    public byte[] generateToBytes(ReportData data) throws Exception {
        try (PDDocument document = new PDDocument()) {
            PDType1Font regularFont = new PDType1Font(Standard14Fonts.FontName.HELVETICA);
            PDType1Font boldFont = new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD);
            PDType1Font monoFont = new PDType1Font(Standard14Fonts.FontName.COURIER);

            InnerWriter writer = new InnerWriter(document, regularFont, boldFont, monoFont);
            writer.beginPage();

            // Title
            writer.drawTitle(data.getTitle(), 20);
            writer.drawText("Generated: " + DATE_FORMAT.format(data.getGeneratedAt())
                    + " | Repeater Manager v" + data.getPluginVersion(), 10);
            writer.drawLine();

            // Summary
            buildSummary(writer, data.getSummary());

            // Session Breakdown
            buildSessionBreakdown(writer, data.getSessionBreakdown());

            // Endpoints
            writer.drawTitle("Findings by Endpoint", 14);
            for (ReportData.EndpointSummary endpoint : data.getEndpoints()) {
                buildEndpoint(writer, endpoint);
            }

            writer.finish();

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            document.save(baos);
            return baos.toByteArray();
        }
    }

    private void buildSummary(InnerWriter writer, ReportData.ReportSummary s) throws Exception {
        writer.drawTitle("Summary", 14);
        String[] headers = {"Metric", "Count"};
        float[] widths = {0.6f, 0.4f};
        List<String[]> rows = new ArrayList<>();
        rows.add(new String[]{"Total Tests", String.valueOf(s.getTotalTests())});
        rows.add(new String[]{"Escalated", String.valueOf(s.getEscalatedCount())});
        rows.add(new String[]{"Safe", String.valueOf(s.getSafeCount())});
        rows.add(new String[]{"Errors", String.valueOf(s.getErrorCount())});
        rows.add(new String[]{"Baseline", String.valueOf(s.getBaselineCount())});
        rows.add(new String[]{"Unique Endpoints", String.valueOf(s.getEndpointsTested())});
        writer.drawTable(headers, rows, widths);
        writer.drawLine();
    }

    private void buildSessionBreakdown(InnerWriter writer,
                                        List<ReportData.SessionBreakdown> sessions) throws Exception {
        if (sessions.isEmpty()) return;
        writer.drawTitle("Session Breakdown", 14);
        String[] headers = {"Session", "Escalated", "Safe", "Errors", "Total"};
        float[] widths = {0.35f, 0.15f, 0.15f, 0.15f, 0.2f};
        List<String[]> rows = new ArrayList<>();
        for (ReportData.SessionBreakdown s : sessions) {
            rows.add(new String[]{
                    trunc(s.getSessionName(), 20),
                    String.valueOf(s.getEscalatedCount()),
                    String.valueOf(s.getSafeCount()),
                    String.valueOf(s.getErrorCount()),
                    String.valueOf(s.getTotalTests())
            });
        }
        writer.drawTable(headers, rows, widths);
        writer.drawLine();
    }

    private void buildEndpoint(InnerWriter writer, ReportData.EndpointSummary endpoint) throws Exception {
        writer.drawTitle(endpoint.getMethod() + " " + endpoint.getUrl(), 11);
        StringBuilder stats = new StringBuilder();
        if (endpoint.getBaselineCount() > 0) {
            stats.append("Baseline: ").append(endpoint.getBaselineCount()).append(" | ");
        }
        stats.append("Tests: ").append(endpoint.getTotalTests())
                .append(" | Escalated: ").append(endpoint.getEscalatedCount())
                .append(" | Safe: ").append(endpoint.getSafeCount())
                .append(" | Errors: ").append(endpoint.getErrorCount());
        writer.drawText(stats.toString(), 9, MARGIN + 15);
        writer.drawLine();

        for (ReportData.Finding finding : endpoint.getFindings()) {
            buildFinding(writer, finding);
        }
    }

    private void buildFinding(InnerWriter writer, ReportData.Finding finding) throws Exception {
        String judgmentLabel;
        if (finding.isBaseline()) {
            judgmentLabel = "BASELINE";
        } else if ("ESCALATED".equalsIgnoreCase(finding.getJudgment())) {
            judgmentLabel = "ESCALATED";
        } else if ("NOT_ESCALATED".equalsIgnoreCase(finding.getJudgment())) {
            judgmentLabel = "SAFE";
        } else {
            judgmentLabel = "ERROR";
        }

        // Finding header
        writer.drawTitle("Session: " + finding.getUserSessionName() + "  |  " + judgmentLabel, 10);

        // Metadata
        StringBuilder meta = new StringBuilder();
        if (finding.isBaseline()) {
            meta.append("Similarity: N/A (baseline)");
        } else {
            meta.append("Similarity: ").append(String.format("%.2f", finding.getSimilarity()));
        }
        meta.append("  |  HTTP ").append(finding.getRecord().getStatusCode());
        meta.append("  |  ").append(finding.getRecord().getResponseLength()).append(" bytes");
        meta.append("  |  ").append(finding.getRecord().getResponseTime()).append("ms");
        writer.drawText(meta.toString(), 9, MARGIN + 15);

        if (finding.getMatchedRuleName() != null) {
            writer.drawText("Rule: " + finding.getMatchedRuleName(), 9, MARGIN + 15);
        }

        writer.drawLine();

        // 非基准 Finding：在当前报文前展示基准报文
        if (!finding.isBaseline() && finding.getBaselineRecord() != null) {
            RequestResponseRecord baselineRec = finding.getBaselineRecord();

            writer.drawSectionTitle("Baseline Request  -  Session: " + finding.getBaselineSessionName());
            renderBodyPdf(writer, baselineRec.getRequestData(),
                    extractRequestContentType(baselineRec.getRequestData()));

            writer.drawSectionTitle("Baseline Response  -  HTTP " + baselineRec.getStatusCode()
                    + " (" + baselineRec.getResponseLength() + " bytes, "
                    + baselineRec.getResponseTime() + "ms)  -  Session: " + finding.getBaselineSessionName());
            renderBodyPdf(writer, baselineRec.getResponseData(),
                    extractResponseContentType(baselineRec.getResponseData()));
        }

        // Request — 智能渲染
        writer.drawSectionTitle("Request:");
        renderBodyPdf(writer, finding.getRecord().getRequestData(),
                extractRequestContentType(finding.getRecord().getRequestData()));

        // Response — 智能渲染
        writer.drawSectionTitle("Response  -  HTTP " + finding.getRecord().getStatusCode()
                + " (" + finding.getRecord().getResponseLength() + " bytes, "
                + finding.getRecord().getResponseTime() + "ms):");
        renderBodyPdf(writer, finding.getRecord().getResponseData(),
                extractResponseContentType(finding.getRecord().getResponseData()));

        // cURL
        writer.drawSectionTitle("Reproduction  -  cURL:");
        writer.drawCodeBlock(truncForPdf(finding.getCurlCommand()));

        // Postman
        writer.drawSectionTitle("Reproduction  -  Postman Import:");
        writer.drawCodeBlock(truncForPdf(finding.getPostmanSnippet()));

        writer.drawLine();
    }

    /**
     * 智能渲染 body: 二进制内容展示为元数据表+hex预览，文本保持原样
     */
    private void renderBodyPdf(InnerWriter writer, byte[] body, String contentType) throws Exception {
        if (body == null || body.length == 0) {
            writer.drawCodeBlock("[Empty]");
            return;
        }

        BinaryContentRenderer.TieredRenderContent content = renderBinaryBody(body, contentType);

        // 文本内容: 保持原有渲染
        if (content.tier == null) {
            writer.drawCodeBlock(sanitizeBodyForPdf(body));
            return;
        }

        // 二进制内容: 渲染元数据表 + hex/base64
        buildBinaryContentPdf(writer, content);
    }

    /**
     * 构建二进制内容 PDF 渲染
     */
    private void buildBinaryContentPdf(InnerWriter writer,
                                        BinaryContentRenderer.TieredRenderContent content) throws Exception {
        // 元数据表
        writer.drawSectionTitle("Binary Content (" + InnerWriter.filter(content.contentCategory)
                + " - " + InnerWriter.filter(content.humanSize) + "):");

        String[] headers = {"Property", "Value"};
        float[] widths = {0.3f, 0.7f};
        List<String[]> rows = new ArrayList<>();
        rows.add(new String[]{"Content-Type", trunc(content.contentType, 50)});
        rows.add(new String[]{"Size", content.humanSize});

        if (content.metadataCardText != null) {
            String sha = extractShaFromMetadata(content.metadataCardText);
            if (!sha.isEmpty()) {
                rows.add(new String[]{"SHA-256", trunc(sha, 50)});
            }
        }

        writer.drawTable(headers, rows, widths);

        // Multipart 部分
        if (content.multipartParts != null) {
            for (BinaryContentRenderer.MultipartPartInfo part : content.multipartParts) {
                buildMultipartPartPdf(writer, part);
            }
        }

        // Hex dump 预览
        if (content.hexDumpPreview != null && !content.hexDumpPreview.isEmpty()) {
            writer.drawSectionTitle("Hex Preview:");
            writer.drawCodeBlock(truncForPdf(content.hexDumpPreview));
        }

        // Base64 (仅 SMALL, 截断显示)
        if (content.base64Content != null && !content.base64Content.isEmpty()) {
            writer.drawSectionTitle("Base64:");
            String base64Display = content.base64Content;
            if (base64Display.length() > PDF_BASE64_LIMIT) {
                base64Display = base64Display.substring(0, PDF_BASE64_LIMIT)
                        + "\n... [Truncated in PDF - see HTML report for full data]";
            }
            writer.drawCodeBlock(base64Display);
        }
    }

    /**
     * 构建 multipart 单 part PDF
     */
    private void buildMultipartPartPdf(InnerWriter writer,
                                        BinaryContentRenderer.MultipartPartInfo part) throws Exception {
        String partTitle = "Part: ";
        if (part.name != null) partTitle += part.name;
        if (part.fileName != null) partTitle += " (" + part.fileName + ")";
        partTitle += " - " + part.partContentType + " - " + BinaryContentRenderer.formatHumanSize(part.partSize);

        writer.drawSectionTitle(partTitle);

        if (part.isText) {
            writer.drawCodeBlock(truncForPdf(part.textContent));
        } else {
            // 二进制 part: hex 预览
            if (part.binaryPreview != null && part.binaryPreview.length > 0) {
                String hexDump = BinaryContentRenderer.generateHexDump(part.binaryPreview, part.binaryPreview.length);
                writer.drawCodeBlock(truncForPdf(hexDump));
            }
        }
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

    private static String trunc(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max - 3) + "..." : s;
    }

    /**
     * 截断文本以适应 PDF 代码块长度限制
     */
    private static String truncForPdf(String s) {
        if (s == null) return "";
        if (s.length() > PDF_BODY_LIMIT) {
            return s.substring(0, PDF_BODY_LIMIT) + "\n... [Truncated in PDF - see HTML report for full data]";
        }
        return s;
    }

    /**
     * 针对PDF显示的body数据清洗，使用更短的限制
     */
    private String sanitizeBodyForPdf(byte[] body) {
        String text = sanitizeBody(body);
        if (text.length() > PDF_BODY_LIMIT) {
            text = text.substring(0, PDF_BODY_LIMIT) + "\n... [Truncated in PDF - see HTML report for full data]";
        }
        return text;
    }

    // ========== 内部 PDF 写入器 ==========

    static class InnerWriter {
        private final PDDocument document;
        private final PDType1Font regularFont;
        private final PDType1Font boldFont;
        private final PDType1Font monoFont;
        private PDPageContentStream cs;
        private float y;

        InnerWriter(PDDocument document, PDType1Font regularFont, PDType1Font boldFont, PDType1Font monoFont) {
            this.document = document;
            this.regularFont = regularFont;
            this.boldFont = boldFont;
            this.monoFont = monoFont;
        }

        void beginPage() throws Exception {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);
            cs = new PDPageContentStream(document, page);
            y = PAGE_HEIGHT - MARGIN;
        }

        void finish() throws Exception {
            if (cs != null) cs.close();
        }

        void drawTitle(String text, float fontSize) throws Exception {
            ensureSpace(fontSize + 12);
            cs.beginText();
            cs.setFont(boldFont, fontSize);
            cs.newLineAtOffset(MARGIN, y);
            cs.showText(filter(text));
            cs.endText();
            y -= fontSize + 10;
        }

        /**
         * 绘制小节标题（如 "Request:"、"Response:" 等）
         */
        void drawSectionTitle(String text) throws Exception {
            ensureSpace(16);
            cs.beginText();
            cs.setFont(boldFont, 9);
            cs.newLineAtOffset(MARGIN + 10, y);
            cs.showText(filter(text));
            cs.endText();
            y -= 14;
        }

        void drawText(String text, float fontSize) throws Exception {
            drawText(text, fontSize, MARGIN);
        }

        void drawText(String text, float fontSize, float x) throws Exception {
            ensureSpace(fontSize + 6);
            cs.beginText();
            cs.setFont(regularFont, fontSize);
            cs.newLineAtOffset(x, y);
            cs.showText(filter(text));
            cs.endText();
            y -= fontSize + 5;
        }

        void drawLine() throws Exception {
            ensureSpace(10);
            cs.setLineWidth(0.5f);
            cs.setStrokingColor(0.7f, 0.7f, 0.7f);
            cs.moveTo(MARGIN, y);
            cs.lineTo(MARGIN + CONTENT_WIDTH, y);
            cs.stroke();
            cs.setStrokingColor(0, 0, 0);
            y -= 8;
        }

        /**
         * 绘制代码块：使用等宽字体、浅灰背景，支持自动换行和分页
         */
        void drawCodeBlock(String content) throws Exception {
            if (content == null || content.isEmpty()) {
                drawText("[Empty]", 8, MARGIN + 12);
                return;
            }

            float codeFontSize = 7;
            float lineHeight = codeFontSize + 3;
            float codeX = MARGIN + 12;
            float codeMaxWidth = CONTENT_WIDTH - 24;
            float charWidth = monoFont.getStringWidth("M") / 1000f * codeFontSize;
            int maxCharsPerLine = Math.max(1, (int) (codeMaxWidth / charWidth));

            // 按换行符拆分，再对超长行按字符宽度折行
            List<String> lines = new ArrayList<>();
            for (String rawLine : content.split("\n", -1)) {
                String line = filterLine(rawLine);
                if (line.isEmpty()) {
                    lines.add("");
                } else {
                    int pos = 0;
                    while (pos < line.length()) {
                        int end = Math.min(pos + maxCharsPerLine, line.length());
                        lines.add(line.substring(pos, end));
                        pos = end;
                    }
                }
            }

            // 逐行渲染，每行画浅灰背景 + 等宽文字
            for (String line : lines) {
                ensureSpace(lineHeight);

                // 浅灰背景
                cs.setNonStrokingColor(0.95f, 0.95f, 0.95f);
                cs.addRect(MARGIN + 8, y - lineHeight + 2, CONTENT_WIDTH - 16, lineHeight);
                cs.fill();
                cs.setNonStrokingColor(0, 0, 0);

                // 文字
                if (!line.isEmpty()) {
                    cs.beginText();
                    cs.setFont(monoFont, codeFontSize);
                    cs.newLineAtOffset(codeX, y);
                    cs.showText(line);
                    cs.endText();
                }

                y -= lineHeight;
            }

            y -= 6; // 代码块后间距
        }

        void drawTable(String[] headers, List<String[]> rows, float[] colWidths) throws Exception {
            float rowHeight = 18;
            float headerHeight = 22;
            float tableWidth = CONTENT_WIDTH;

            ensureSpace(headerHeight + rowHeight);
            cs.setNonStrokingColor(0.102f, 0.137f, 0.494f);
            cs.addRect(MARGIN, y - headerHeight, tableWidth, headerHeight);
            cs.fill();

            float colX = MARGIN + 2;
            cs.setNonStrokingColor(1, 1, 1);
            for (int i = 0; i < headers.length; i++) {
                cs.beginText();
                cs.setFont(boldFont, 9);
                cs.newLineAtOffset(colX, y - headerHeight + 5);
                cs.showText(filter(headers[i]));
                cs.endText();
                colX += tableWidth * colWidths[i];
            }
            cs.setNonStrokingColor(0, 0, 0);
            y -= headerHeight;

            int rowIdx = 0;
            for (String[] row : rows) {
                ensureSpace(rowHeight);
                if (rowIdx % 2 == 1) {
                    cs.setNonStrokingColor(0.96f, 0.96f, 0.96f);
                    cs.addRect(MARGIN, y - rowHeight, tableWidth, rowHeight);
                    cs.fill();
                    cs.setNonStrokingColor(0, 0, 0);
                }
                colX = MARGIN + 2;
                for (int i = 0; i < row.length && i < headers.length; i++) {
                    cs.beginText();
                    cs.setFont(regularFont, 8);
                    cs.newLineAtOffset(colX, y - rowHeight + 4);
                    cs.showText(filter(row[i] != null ? row[i] : ""));
                    cs.endText();
                    colX += tableWidth * colWidths[i];
                }
                y -= rowHeight;
                rowIdx++;
            }
            y -= 4;
        }

        private void ensureSpace(float needed) throws Exception {
            if (y - needed < MARGIN) {
                cs.close();
                PDPage page = new PDPage(PDRectangle.A4);
                document.addPage(page);
                cs = new PDPageContentStream(document, page);
                y = PAGE_HEIGHT - MARGIN;
            }
        }

        /**
         * 过滤单行文本：移除控制字符，替换非 Latin-1 字符为 '?'
         * 用于 drawTitle / drawText 等单行渲染
         */
        static String filter(String s) {
            if (s == null) return "";
            StringBuilder sb = new StringBuilder(s.length());
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '\n': sb.append(' '); break;
                    case '\r': break;
                    case '\t': sb.append("    "); break;
                    case '\f': break;
                    case '\u0000': break;
                    default:
                        if (c <= 0xFF) {
                            sb.append(c);
                        } else {
                            sb.append('?');
                        }
                }
            }
            return sb.toString();
        }

        /**
         * 过滤代码行文本：保留换行（由调用方拆分），替换非 Latin-1 字符为 '?'
         * 用于 drawCodeBlock 中逐行处理
         */
        static String filterLine(String s) {
            if (s == null) return "";
            StringBuilder sb = new StringBuilder(s.length());
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '\r': break;
                    case '\t': sb.append("    "); break;
                    case '\f': break;
                    case '\u0000': break;
                    default:
                        if (c <= 0xFF) {
                            sb.append(c);
                        } else {
                            sb.append('?');
                        }
                }
            }
            return sb.toString();
        }
    }
}
