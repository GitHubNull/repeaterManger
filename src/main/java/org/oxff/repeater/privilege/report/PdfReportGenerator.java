package org.oxff.repeater.privilege.report;

import org.oxff.repeater.http.RequestResponseRecord;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;

import org.apache.fontbox.ttf.TrueTypeCollection;
import org.apache.fontbox.ttf.TrueTypeFont;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;

/**
 * PDF 格式报告生成器
 * 使用 Apache PDFBox 直接布局，适配 EndpointSection 数据模型
 * 优先加载系统 CJK 字体以支持中文渲染
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

    /** CJK 字体候选路径（按优先级排列） */
    private static final String[] CJK_FONT_PATHS = {
            // Windows
            "C:/Windows/Fonts/msyh.ttc",
            "C:/Windows/Fonts/simhei.ttf",
            "C:/Windows/Fonts/simsun.ttc",
            // macOS
            "/System/Library/Fonts/PingFang.ttc",
            "/Library/Fonts/Arial Unicode.ttf",
            "/System/Library/Fonts/STHeiti Light.ttc",
            // Linux
            "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
            "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
    };

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
            // 尝试加载 CJK 字体
            CJKFontHolder cjkFonts = loadCJKFonts(document);

            InnerWriter writer;
            if (cjkFonts != null) {
                writer = new InnerWriter(document, cjkFonts.regular, cjkFonts.bold, cjkFonts.mono, true);
            } else {
                // 回退到标准字体（中文将显示为 ?）
                PDType1Font regularFont = new PDType1Font(Standard14Fonts.FontName.HELVETICA);
                PDType1Font boldFont = new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD);
                PDType1Font monoFont = new PDType1Font(Standard14Fonts.FontName.COURIER);
                writer = new InnerWriter(document, regularFont, boldFont, monoFont, false);
            }

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
            for (ReportData.EndpointSection endpoint : data.getEndpoints()) {
                buildEndpoint(writer, endpoint);
            }

            writer.finish();

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            document.save(baos);
            return baos.toByteArray();
        }
    }

    /**
     * 尝试加载 CJK 字体，返回 null 则回退到标准字体
     */
    private CJKFontHolder loadCJKFonts(PDDocument document) {
        for (String path : CJK_FONT_PATHS) {
            File fontFile = new File(path);
            if (!fontFile.exists()) continue;

            try {
                if (path.endsWith(".ttc")) {
                    // .ttc 是 TrueType Collection
                    TrueTypeCollection ttc = new TrueTypeCollection(fontFile);
                    try {
                        // 用 processAllFonts 收集字体名
                        List<String> fontNames = new ArrayList<>();
                        ttc.processAllFonts(ttf -> fontNames.add(ttf.getName()));

                        for (String name : fontNames) {
                            try {
                                TrueTypeFont ttf = ttc.getFontByName(name);
                                PDType0Font regular = PDType0Font.load(document, ttf, true);
                                if (regular.getStringWidth("\u4e2d") > 0) {
                                    PDType0Font bold = findBoldInTTC(document, ttc, fontNames, name);
                                    return new CJKFontHolder(regular, bold, regular);
                                }
                            } catch (Exception ignored) {
                            }
                        }
                    } finally {
                        ttc.close();
                    }
                } else {
                    // .ttf 单文件字体
                    try (FileInputStream fis = new FileInputStream(fontFile)) {
                        PDType0Font regular = PDType0Font.load(document, fis, true);
                        if (regular.getStringWidth("\u4e2d") > 0) {
                            return new CJKFontHolder(regular, regular, regular);
                        }
                    }
                }
            } catch (Exception e) {
                // 字体加载失败，尝试下一个路径
            }
        }
        return null;
    }

    /**
     * 从 .ttc 中查找 bold 变体，失败则复用 regular
     */
    private PDType0Font findBoldInTTC(PDDocument document, TrueTypeCollection ttc,
                                       List<String> fontNames, String regularName) {
        for (String name : fontNames) {
            if (name.contains("Bold") && !name.equals(regularName)) {
                try {
                    TrueTypeFont ttf = ttc.getFontByName(name);
                    return PDType0Font.load(document, ttf, true);
                } catch (Exception ignored) {
                }
            }
        }
        try {
            TrueTypeFont ttf = ttc.getFontByName(regularName);
            return PDType0Font.load(document, ttf, true);
        } catch (Exception e) {
            return null;
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

    private void buildEndpoint(InnerWriter writer, ReportData.EndpointSection endpoint) throws Exception {
        String epLabel = "api_" + String.format("%02d", endpoint.getEndpointIndex());
        writer.drawTitle(epLabel + "  " + endpoint.getMethod() + " " + endpoint.getUrl(), 11);
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

        // Baseline 区域（orin http data，在端点顶部展示一次）
        if (endpoint.getBaselineData() != null) {
            buildBaselineSection(writer, endpoint.getBaselineData());
        }

        // 用户会话区域（包括 baseline 用户的 SessionFinding）
        for (ReportData.SessionFinding session : endpoint.getUserSessions()) {
            buildUserSessionSection(writer, session);
        }
    }

    /**
     * 渲染基准报文区域（orin http data，每个端点顶部展示一次）
     */
    private void buildBaselineSection(InnerWriter writer, ReportData.BaselineData baseline) throws Exception {
        writer.drawTitle("orin http data  |  BASELINE", 10);

        RequestResponseRecord rec = baseline.getRecord();

        // Request
        writer.drawSectionTitle("Request:");
        writer.drawCodeBlock(sanitizeBodyForPdf(rec.getRequestData()));

        // Response
        writer.drawSectionTitle("Response  -  HTTP " + rec.getStatusCode()
                + " (" + rec.getResponseLength() + " bytes, "
                + rec.getResponseTime() + "ms):");
        writer.drawCodeBlock(sanitizeBodyForPdf(rec.getResponseData()));

        writer.drawSeparatorLine();
    }

    /**
     * 渲染用户会话报文区域（包括 baseline 用户的 SessionFinding）
     */
    private void buildUserSessionSection(InnerWriter writer, ReportData.SessionFinding session) throws Exception {
        if (session.isBaseline()) {
            // baseline 用户的 SessionFinding — 只显示用户名和报文，不显示 cURL/Postman
            writer.drawTitle(session.getSessionName() + " http data  |  BASELINE", 10);

            RequestResponseRecord rec = session.getRecord();
            writer.drawSectionTitle("Request:");
            writer.drawCodeBlock(sanitizeBodyForPdf(rec.getRequestData()));

            writer.drawSectionTitle("Response  -  HTTP " + rec.getStatusCode()
                    + " (" + rec.getResponseLength() + " bytes, "
                    + rec.getResponseTime() + "ms):");
            writer.drawCodeBlock(sanitizeBodyForPdf(rec.getResponseData()));
        } else {
            // 非基准用户会话
            String judgmentLabel;
            if ("ESCALATED".equalsIgnoreCase(session.getJudgment())) {
                judgmentLabel = "ESCALATED";
            } else if ("NOT_ESCALATED".equalsIgnoreCase(session.getJudgment())) {
                judgmentLabel = "SAFE";
            } else {
                judgmentLabel = "ERROR";
            }

            writer.drawTitle(session.getSessionName() + " http data  |  " + judgmentLabel, 10);

            // Metadata
            StringBuilder meta = new StringBuilder();
            meta.append("Similarity: ").append(String.format("%.2f", session.getSimilarity()));
            RequestResponseRecord rec = session.getRecord();
            meta.append("  |  HTTP ").append(rec.getStatusCode());
            meta.append("  |  ").append(rec.getResponseLength()).append(" bytes");
            meta.append("  |  ").append(rec.getResponseTime()).append("ms");
            writer.drawText(meta.toString(), 9, MARGIN + 15);

            if (session.getMatchedRuleName() != null) {
                writer.drawText("Rule: " + session.getMatchedRuleName(), 9, MARGIN + 15);
            }

            writer.drawLine();

            // Request
            writer.drawSectionTitle("Request:");
            writer.drawCodeBlock(sanitizeBodyForPdf(rec.getRequestData()));

            // Response
            writer.drawSectionTitle("Response  -  HTTP " + rec.getStatusCode()
                    + " (" + rec.getResponseLength() + " bytes, "
                    + rec.getResponseTime() + "ms):");
            writer.drawCodeBlock(sanitizeBodyForPdf(rec.getResponseData()));

            // cURL
            writer.drawSectionTitle("Reproduction  -  cURL:");
            writer.drawCodeBlock(truncForPdf(session.getCurlCommand()));

            // Postman
            writer.drawSectionTitle("Reproduction  -  Postman Import:");
            writer.drawCodeBlock(truncForPdf(session.getPostmanSnippet()));
        }

        writer.drawSeparatorLine();
    }

    /**
     * 针对PDF显示的body数据清洗，使用更短的限制
     * 对 base64 长字符串做独立截断，避免 PDF 页面被无意义编码撑满
     */
    private String sanitizeBodyForPdf(byte[] body) {
        if (body == null || body.length == 0) {
            return "[Empty]";
        }
        boolean binary = isBinaryBody(body);
        if (binary) {
            return "[Binary data - " + body.length + " bytes]";
        }
        String str = new String(body, java.nio.charset.StandardCharsets.UTF_8);
        str = truncateBase64InText(str);
        if (str.length() > PDF_BODY_LIMIT) {
            str = str.substring(0, PDF_BODY_LIMIT) + "\n... [Truncated in PDF - see HTML report for full data]";
        }
        return str;
    }

    private static final java.util.regex.Pattern BASE64_PATTERN =
            java.util.regex.Pattern.compile("([A-Za-z0-9+/]{80,}={0,2})");

    /**
     * 检测文本中的 base64 长字符串并截断至 PDF_BASE64_LIMIT
     */
    private String truncateBase64InText(String text) {
        java.util.regex.Matcher matcher = BASE64_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            String b64 = matcher.group(1);
            if (b64.length() > PDF_BASE64_LIMIT) {
                String truncated = b64.substring(0, PDF_BASE64_LIMIT)
                        + "... [Base64 truncated in PDF - " + b64.length() + " chars total]";
                matcher.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(truncated));
            }
        }
        matcher.appendTail(sb);
        return sb.toString();
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

    private static String trunc(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max - 3) + "..." : s;
    }

    private static String truncForPdf(String s) {
        if (s == null) return "";
        if (s.length() > PDF_BODY_LIMIT) {
            return s.substring(0, PDF_BODY_LIMIT) + "\n... [Truncated in PDF - see HTML report for full data]";
        }
        return s;
    }

    // ========== CJK 字体持有者 ==========

    private static class CJKFontHolder {
        final PDFont regular;
        final PDFont bold;
        final PDFont mono;

        CJKFontHolder(PDFont regular, PDFont bold, PDFont mono) {
            this.regular = regular;
            this.bold = bold;
            this.mono = mono;
        }
    }

    // ========== 内部 PDF 写入器 ==========

    static class InnerWriter {
        private final PDDocument document;
        private final PDFont regularFont;
        private final PDFont boldFont;
        private final PDFont monoFont;
        /** 是否使用 CJK 字体（决定 filter 策略） */
        private final boolean cjkEnabled;
        private PDPageContentStream cs;
        private float y;

        InnerWriter(PDDocument document, PDFont regularFont, PDFont boldFont, PDFont monoFont, boolean cjkEnabled) {
            this.document = document;
            this.regularFont = regularFont;
            this.boldFont = boldFont;
            this.monoFont = monoFont;
            this.cjkEnabled = cjkEnabled;
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
            ensureSpace(fontSize * 1.5f + 14);
            cs.beginText();
            cs.setFont(boldFont, fontSize);
            cs.newLineAtOffset(MARGIN, y);
            cs.showText(filter(text));
            cs.endText();
            y -= fontSize * 1.5f + 12;
        }

        void drawSectionTitle(String text) throws Exception {
            ensureSpace(28);
            cs.beginText();
            cs.setFont(boldFont, 9);
            cs.newLineAtOffset(MARGIN + 10, y);
            cs.showText(filter(text));
            cs.endText();
            y -= 22;
        }

        void drawText(String text, float fontSize) throws Exception {
            drawText(text, fontSize, MARGIN);
        }

        void drawText(String text, float fontSize, float x) throws Exception {
            ensureSpace(fontSize + 16);
            cs.beginText();
            cs.setFont(regularFont, fontSize);
            cs.newLineAtOffset(x, y);
            cs.showText(filter(text));
            cs.endText();
            y -= fontSize + 12;
        }

        void drawLine() throws Exception {
            ensureSpace(20);
            cs.setLineWidth(0.5f);
            cs.setStrokingColor(0.7f, 0.7f, 0.7f);
            cs.moveTo(MARGIN, y);
            cs.lineTo(MARGIN + CONTENT_WIDTH, y);
            cs.stroke();
            cs.setStrokingColor(0, 0, 0);
            y -= 18;
        }

        /**
         * 分隔线 — 用于 baseline 与 user session 之间的视觉分隔
         */
        void drawSeparatorLine() throws Exception {
            ensureSpace(34);
            y -= 10;
            cs.setLineWidth(1.5f);
            cs.setStrokingColor(0.56f, 0.64f, 0.74f);
            cs.moveTo(MARGIN, y);
            cs.lineTo(MARGIN + CONTENT_WIDTH, y);
            cs.stroke();
            cs.setStrokingColor(0, 0, 0);
            y -= 22;
        }

        void drawCodeBlock(String content) throws Exception {
            if (content == null || content.isEmpty()) {
                drawText("[Empty]", 8, MARGIN + 12);
                return;
            }

            float codeFontSize = 7;
            float lineHeight = codeFontSize + 3;
            float codeX = MARGIN + 12;
            float codeMaxWidth = CONTENT_WIDTH - 24;

            // 计算 maxCharsPerLine：使用 try-catch 回退策略
            int maxCharsPerLine = 80; // 默认值
            try {
                float charWidth = monoFont.getStringWidth("M") / 1000f * codeFontSize;
                if (charWidth > 0) {
                    maxCharsPerLine = Math.max(1, (int) (codeMaxWidth / charWidth));
                }
            } catch (Exception ignored) {
                // 字体不支持 getStringWidth，使用默认值
            }

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

            for (String line : lines) {
                ensureSpace(lineHeight);

                cs.setNonStrokingColor(0.95f, 0.95f, 0.95f);
                cs.addRect(MARGIN + 8, y - lineHeight + 2, CONTENT_WIDTH - 16, lineHeight);
                cs.fill();
                cs.setNonStrokingColor(0, 0, 0);

                if (!line.isEmpty()) {
                    cs.beginText();
                    cs.setFont(monoFont, codeFontSize);
                    cs.newLineAtOffset(codeX, y);
                    cs.showText(line);
                    cs.endText();
                }

                y -= lineHeight;
            }

            y -= 14;
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
            y -= 12;
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
         * 过滤文本：CJK 字体模式下保留中文，否则替换为 ?
         */
        String filter(String s) {
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
                        if (cjkEnabled) {
                            // CJK 字体支持所有 Unicode 字符，直接保留
                            sb.append(c);
                        } else if (c <= 0xFF) {
                            sb.append(c);
                        } else {
                            sb.append('?');
                        }
                }
            }
            return sb.toString();
        }

        String filterLine(String s) {
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
                        if (cjkEnabled) {
                            sb.append(c);
                        } else if (c <= 0xFF) {
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
