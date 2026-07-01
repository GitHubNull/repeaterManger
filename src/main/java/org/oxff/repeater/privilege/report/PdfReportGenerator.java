package org.oxff.repeater.privilege.report;

import org.oxff.repeater.http.RequestResponseRecord;

import org.apache.pdfbox.pdmodel.PDDocument;
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
    private static final float MARGIN = 50;
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

            PdfReportWriter writer;
            if (cjkFonts != null) {
                writer = new PdfReportWriter(document, cjkFonts.regular, cjkFonts.bold, cjkFonts.mono, true, MARGIN);
            } else {
                // 回退到标准字体（中文将显示为 ?）
                PDType1Font regularFont = new PDType1Font(Standard14Fonts.FontName.HELVETICA);
                PDType1Font boldFont = new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD);
                PDType1Font monoFont = new PDType1Font(Standard14Fonts.FontName.COURIER);
                writer = new PdfReportWriter(document, regularFont, boldFont, monoFont, false, MARGIN);
            }

            writer.beginPage();

            // Title
            writer.drawTitle(data.getTitle(), 20);
            writer.drawText("生成时间: " + DATE_FORMAT.format(data.getGeneratedAt())
                    + " | Repeater Manager v" + data.getPluginVersion(), 10);
            writer.drawLine();

            // Summary
            buildSummary(writer, data.getSummary());

            // Session Breakdown
            buildSessionBreakdown(writer, data.getSessionBreakdown());

            // Endpoints
            writer.drawTitle("端点发现详情", 14);
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

    private void buildSummary(PdfReportWriter writer, ReportData.ReportSummary s) throws Exception {
        writer.drawTitle("摘要", 14);
        String[] headers = {"指标", "数量"};
        float[] widths = {0.6f, 0.4f};
        List<String[]> rows = new ArrayList<>();
        rows.add(new String[]{"测试总数", String.valueOf(s.getTotalTests())});
        rows.add(new String[]{"越权", String.valueOf(s.getEscalatedCount())});
        rows.add(new String[]{"安全", String.valueOf(s.getSafeCount())});
        rows.add(new String[]{"错误", String.valueOf(s.getErrorCount())});
        rows.add(new String[]{"基线", String.valueOf(s.getBaselineCount())});
        rows.add(new String[]{"唯一端点", String.valueOf(s.getEndpointsTested())});
        writer.drawTable(headers, rows, widths);
        writer.drawLine();
    }

    private void buildSessionBreakdown(PdfReportWriter writer,
                                        List<ReportData.SessionBreakdown> sessions) throws Exception {
        if (sessions.isEmpty()) return;
        writer.drawTitle("会话分布", 14);
        String[] headers = {"会话", "越权", "安全", "错误", "总计"};
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

    private void buildEndpoint(PdfReportWriter writer, ReportData.EndpointSection endpoint) throws Exception {
        String epLabel = "api_" + String.format("%02d", endpoint.getEndpointIndex());
        writer.drawTitle(epLabel + "  " + endpoint.getMethod() + " " + endpoint.getUrl(), 11);
        StringBuilder stats = new StringBuilder();
        if (endpoint.getBaselineCount() > 0) {
            stats.append("基线: ").append(endpoint.getBaselineCount()).append(" | ");
        }
        stats.append("测试: ").append(endpoint.getTotalTests())
                .append(" | 越权: ").append(endpoint.getEscalatedCount())
                .append(" | 安全: ").append(endpoint.getSafeCount())
                .append(" | 错误: ").append(endpoint.getErrorCount());
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
    private void buildBaselineSection(PdfReportWriter writer, ReportData.BaselineData baseline) throws Exception {
        writer.drawTitle("原始基准 HTTP 数据（参考对照标准）  |  基线", 10);
        writer.drawText("以下为基准用户的原始请求与响应，用于与各会话重放结果对比分析，判断是否存在越权。", 8, MARGIN + 10);

        RequestResponseRecord rec = baseline.getRecord();

        // 请求
        writer.drawSectionTitle("请求:");
        writer.drawCodeBlock(sanitizeBodyForPdf(rec.getRequestData()));

        // 响应
        writer.drawSectionTitle("响应  -  HTTP " + rec.getStatusCode()
                + " (" + rec.getResponseLength() + " 字节, "
                + rec.getResponseTime() + "ms):");
        writer.drawCodeBlock(sanitizeBodyForPdf(rec.getResponseData()));

        writer.drawSeparatorLine();
    }

    /**
     * 渲染用户会话报文区域（包括 baseline 用户的 SessionFinding）
     */
    private void buildUserSessionSection(PdfReportWriter writer, ReportData.SessionFinding session) throws Exception {
        if (session.isBaseline()) {
            // baseline 用户的 SessionFinding — 只显示用户名和报文，不显示 cURL/Postman
            writer.drawTitle(session.getSessionName() + " HTTP 数据  |  基线", 10);

            RequestResponseRecord rec = session.getRecord();
            writer.drawSectionTitle("请求:");
            writer.drawCodeBlock(sanitizeBodyForPdf(rec.getRequestData()));

            writer.drawSectionTitle("响应  -  HTTP " + rec.getStatusCode()
                    + " (" + rec.getResponseLength() + " 字节, "
                    + rec.getResponseTime() + "ms):");
            writer.drawCodeBlock(sanitizeBodyForPdf(rec.getResponseData()));
        } else {
            // 非基准用户会话
            String judgmentLabel;
            if ("ESCALATED".equalsIgnoreCase(session.getJudgment())) {
                judgmentLabel = "越权";
            } else if ("NOT_ESCALATED".equalsIgnoreCase(session.getJudgment())) {
                judgmentLabel = "安全";
            } else {
                judgmentLabel = "错误";
            }

            writer.drawTitle(session.getSessionName() + " HTTP 数据  |  " + judgmentLabel, 10);

            // 元数据
            StringBuilder meta = new StringBuilder();
            meta.append("相似度: ").append(String.format("%.2f", session.getSimilarity()));
            RequestResponseRecord rec = session.getRecord();
            meta.append("  |  HTTP ").append(rec.getStatusCode());
            meta.append("  |  ").append(rec.getResponseLength()).append(" 字节");
            meta.append("  |  ").append(rec.getResponseTime()).append("ms");
            writer.drawText(meta.toString(), 9, MARGIN + 15);

            if (session.getMatchedRuleName() != null) {
                writer.drawText("规则: " + session.getMatchedRuleName(), 9, MARGIN + 15);
            }

            writer.drawLine();

            // 请求
            writer.drawSectionTitle("请求:");
            writer.drawCodeBlock(sanitizeBodyForPdf(rec.getRequestData()));

            // 响应
            writer.drawSectionTitle("响应  -  HTTP " + rec.getStatusCode()
                    + " (" + rec.getResponseLength() + " 字节, "
                    + rec.getResponseTime() + "ms):");
            writer.drawCodeBlock(sanitizeBodyForPdf(rec.getResponseData()));

            // cURL
            writer.drawSectionTitle("复现命令  -  cURL:");
            writer.drawCodeBlock(truncForPdf(session.getCurlCommand()));

            // Postman
            writer.drawSectionTitle("复现导入  -  Postman:");
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
            return "[空]";
        }
        boolean binary = isBinaryBody(body);
        if (binary) {
            return "[二进制数据 - " + body.length + " 字节]";
        }
        // 使用 UTF-8 解码，对无法解码的字节使用替换字符
        String str = new String(body, java.nio.charset.StandardCharsets.UTF_8);
        // 移除 Unicode 替换字符 (U+FFFD)，这些是二进制数据被误解码的产物
        str = str.replace("\uFFFD", "");
        str = truncateBase64InText(str);
        if (str.length() > PDF_BODY_LIMIT) {
            str = str.substring(0, PDF_BODY_LIMIT) + "\n... [PDF 中已截断 - 完整数据请查看 HTML 报告]";
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
                        + "... [Base64 在 PDF 中已截断 - " + b64.length() + " 字符]";
                matcher.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(truncated));
            }
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    /**
     * 检测 body 是否为二进制数据
     * 采用多层检测策略：魔数检测（头部）+ 非打印字符比例检测
     * 阈值 20%，平衡检测灵敏度与 UTF-8 文本容错性
     */
    private boolean isBinaryBody(byte[] data) {
        if (data == null || data.length == 0) return false;

        // 第1层：魔数检测（常见二进制格式，仅检查数据头部）
        if (hasBinaryMagicBytes(data)) return true;

        // 第2层：非打印字符比例检测（无魔数命中时使用较高阈值避免误判）
        int nonPrintable = 0;
        int checkLen = Math.min(data.length, 1024);
        for (int i = 0; i < checkLen; i++) {
            byte b = data[i];
            // 允许 \t(0x09) \n(0x0A) \r(0x0D)，其他 <0x20 的控制字符和 DEL(0x7F) 为不可打印
            if (b < 0x09 || (b > 0x0D && b < 0x20) || b == 0x7F) {
                nonPrintable++;
            }
        }
        // 阈值 20%：无魔数命中时采用折中阈值，避免 UTF-8 文本误判
        return (double) nonPrintable / checkLen > 0.2;
    }

    /**
     * 检测数据开头是否匹配常见二进制文件魔数
     * 仅检查数据头部，因为真正的二进制文件魔数始终位于文件起始位置
     */
    private boolean hasBinaryMagicBytes(byte[] data) {
        if (data == null || data.length < 4) return false;

        // PDF: %PDF
        if (data[0] == 0x25 && data[1] == 0x50 && data[2] == 0x44 && data[3] == 0x46) return true;
        // PNG: \x89PNG
        if (data[0] == (byte) 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47) return true;
        // GIF: GIF8
        if (data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x38) return true;
        // ZIP: PK\x03\x04
        if (data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04) return true;
        // BMP: BM
        if (data[0] == 0x42 && data[1] == 0x4D) return true;
        // GZIP: \x1F\x8B
        if (data[0] == 0x1F && data[1] == (byte) 0x8B) return true;
        // JPEG: \xFF\xD8\xFF (只需 3 字节)
        if (data.length >= 3 && data[0] == (byte) 0xFF && data[1] == (byte) 0xD8 && data[2] == (byte) 0xFF) return true;
        // WEBP: RIFF....WEBP (需要 12 字节)
        if (data.length >= 12
                && data[0] == 0x52 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x46
                && data[8] == 0x57 && data[9] == 0x45 && data[10] == 0x42 && data[11] == 0x50) return true;

        return false;
    }

    private static String trunc(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max - 3) + "..." : s;
    }

    private static String truncForPdf(String s) {
        if (s == null) return "";
        if (s.length() > PDF_BODY_LIMIT) {
            return s.substring(0, PDF_BODY_LIMIT) + "\n... [PDF 中已截断 - 完整数据请查看 HTML 报告]";
        }
        return s;
    }
}
