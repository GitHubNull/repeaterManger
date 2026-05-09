package oxff.top.privilege.report;

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
 * 使用 Apache PDFBox 直接布局
 */
public class PdfReportGenerator extends ReportGenerator {

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static final float PAGE_WIDTH = PDRectangle.A4.getWidth();
    private static final float PAGE_HEIGHT = PDRectangle.A4.getHeight();
    private static final float MARGIN = 50;
    private static final float CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN;
    /** PDF 中每个代码块的最大字符数，避免报告过大 */
    private static final int PDF_BODY_LIMIT = 3000;

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
        writer.drawText("Tests: " + endpoint.getTotalTests()
                + " | Escalated: " + endpoint.getEscalatedCount()
                + " | Safe: " + endpoint.getSafeCount()
                + " | Errors: " + endpoint.getErrorCount(), 9, MARGIN + 15);
        writer.drawLine();

        for (ReportData.Finding finding : endpoint.getFindings()) {
            buildFinding(writer, finding);
        }
    }

    private void buildFinding(InnerWriter writer, ReportData.Finding finding) throws Exception {
        String judgmentLabel = "ESCALATED".equalsIgnoreCase(finding.getJudgment()) ? "ESCALATED"
                : "NOT_ESCALATED".equalsIgnoreCase(finding.getJudgment()) ? "SAFE" : "ERROR";

        // Finding header
        writer.drawTitle("Session: " + finding.getUserSessionName() + "  |  " + judgmentLabel, 10);

        // Metadata
        StringBuilder meta = new StringBuilder();
        meta.append("Similarity: ").append(String.format("%.2f", finding.getSimilarity()));
        meta.append("  |  HTTP ").append(finding.getRecord().getStatusCode());
        meta.append("  |  ").append(finding.getRecord().getResponseLength()).append(" bytes");
        meta.append("  |  ").append(finding.getRecord().getResponseTime()).append("ms");
        writer.drawText(meta.toString(), 9, MARGIN + 15);

        if (finding.getMatchedRuleName() != null) {
            writer.drawText("Rule: " + finding.getMatchedRuleName(), 9, MARGIN + 15);
        }

        writer.drawLine();

        // Request
        writer.drawSectionTitle("Request:");
        writer.drawCodeBlock(sanitizeBodyForPdf(finding.getRecord().getRequestData()));

        // Response
        writer.drawSectionTitle("Response  -  HTTP " + finding.getRecord().getStatusCode()
                + " (" + finding.getRecord().getResponseLength() + " bytes, "
                + finding.getRecord().getResponseTime() + "ms):");
        writer.drawCodeBlock(sanitizeBodyForPdf(finding.getRecord().getResponseData()));

        // cURL
        writer.drawSectionTitle("Reproduction  -  cURL:");
        writer.drawCodeBlock(truncForPdf(finding.getCurlCommand()));

        // Postman
        writer.drawSectionTitle("Reproduction  -  Postman Import:");
        writer.drawCodeBlock(truncForPdf(finding.getPostmanSnippet()));

        writer.drawLine();
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

    private static class InnerWriter {
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
        private static String filter(String s) {
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
        private static String filterLine(String s) {
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
