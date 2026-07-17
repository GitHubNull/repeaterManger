package org.oxff.repeater.privilege.report;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;

import java.util.ArrayList;
import java.util.List;

import org.oxff.repeater.logging.LogManager;

/**
 * PDF 内容写入器 — 从 PdfReportGenerator 提取出的 PDF 绘制引擎。
 * 负责页面管理、文本绘制、表格绘制、代码块绘制等底层 PDF 操作。
 */
class PdfReportWriter {

    private static final float PAGE_WIDTH = PDRectangle.A4.getWidth();
    private static final float PAGE_HEIGHT = PDRectangle.A4.getHeight();

    private final PDDocument document;
    private final PDFont regularFont;
    private final PDFont boldFont;
    private final PDFont monoFont;
    private final boolean cjkEnabled;
    private final float margin;
    private final float contentWidth;

    private PDPageContentStream cs;
    private float y;

    PdfReportWriter(PDDocument document, PDFont regularFont, PDFont boldFont, PDFont monoFont,
                    boolean cjkEnabled, float margin) {
        this.document = document;
        this.regularFont = regularFont;
        this.boldFont = boldFont;
        this.monoFont = monoFont;
        this.cjkEnabled = cjkEnabled;
        this.margin = margin;
        this.contentWidth = PAGE_WIDTH - 2 * margin;
    }

    void beginPage() throws Exception {
        PDPage page = new PDPage(PDRectangle.A4);
        document.addPage(page);
        cs = new PDPageContentStream(document, page);
        y = PAGE_HEIGHT - margin;
    }

    void finish() throws Exception {
        if (cs != null) cs.close();
    }

    PDDocument getDocument() {
        return document;
    }

    void drawImage(PDImageXObject image, float width, float height) throws Exception {
        ensureSpace(height + 10);
        cs.drawImage(image, margin, y - height, width, height);
        y -= height + 10;
    }

    void drawTitle(String text, float fontSize) throws Exception {
        ensureSpace(fontSize * 1.5f + 14);
        cs.beginText();
        cs.setFont(boldFont, fontSize);
        cs.newLineAtOffset(margin, y);
        showTextSafe(filter(text));
        cs.endText();
        y -= fontSize * 1.5f + 12;
    }

    void drawSectionTitle(String text) throws Exception {
        ensureSpace(28);
        cs.beginText();
        cs.setFont(boldFont, 9);
        cs.newLineAtOffset(margin + 10, y);
        showTextSafe(filter(text));
        cs.endText();
        y -= 22;
    }

    void drawText(String text, float fontSize) throws Exception {
        drawText(text, fontSize, margin);
    }

    void drawText(String text, float fontSize, float x) throws Exception {
        ensureSpace(fontSize + 16);
        cs.beginText();
        cs.setFont(regularFont, fontSize);
        cs.newLineAtOffset(x, y);
        showTextSafe(filter(text));
        cs.endText();
        y -= fontSize + 12;
    }

    void drawLine() throws Exception {
        ensureSpace(20);
        cs.setLineWidth(0.5f);
        cs.setStrokingColor(0.7f, 0.7f, 0.7f);
        cs.moveTo(margin, y);
        cs.lineTo(margin + contentWidth, y);
        cs.stroke();
        cs.setStrokingColor(0, 0, 0);
        y -= 18;
    }

    void drawSeparatorLine() throws Exception {
        ensureSpace(34);
        y -= 10;
        cs.setLineWidth(1.5f);
        cs.setStrokingColor(0.56f, 0.64f, 0.74f);
        cs.moveTo(margin, y);
        cs.lineTo(margin + contentWidth, y);
        cs.stroke();
        cs.setStrokingColor(0, 0, 0);
        y -= 22;
    }

    void drawCodeBlock(String content) throws Exception {
        if (content == null || content.isEmpty()) {
            drawText("[Empty]", 8, margin + 12);
            return;
        }

        float codeFontSize = 7;
        float lineHeight = codeFontSize + 3;
        float codeX = margin + 12;
        float codeMaxWidth = contentWidth - 24;

        int maxCharsPerLine = 80;
        try {
            float charWidth = monoFont.getStringWidth("M") / 1000f * codeFontSize;
            if (charWidth > 0) {
                maxCharsPerLine = Math.max(1, (int) (codeMaxWidth / charWidth));
            }
        } catch (Exception ignored) {
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
            cs.addRect(margin + 8, y - lineHeight + 2, contentWidth - 16, lineHeight);
            cs.fill();
            cs.setNonStrokingColor(0, 0, 0);

            if (!line.isEmpty()) {
                cs.beginText();
                cs.setFont(monoFont, codeFontSize);
                cs.newLineAtOffset(codeX, y);
                showTextSafe(line);
                cs.endText();
            }

            y -= lineHeight;
        }

        y -= 14;
    }

    void drawTable(String[] headers, List<String[]> rows, float[] colWidths) throws Exception {
        float rowHeight = 18;
        float headerHeight = 22;
        float tableWidth = contentWidth;

        ensureSpace(headerHeight + rowHeight);
        cs.setNonStrokingColor(0.102f, 0.137f, 0.494f);
        cs.addRect(margin, y - headerHeight, tableWidth, headerHeight);
        cs.fill();

        float colX = margin + 2;
        cs.setNonStrokingColor(1, 1, 1);
        for (int i = 0; i < headers.length; i++) {
            cs.beginText();
            cs.setFont(boldFont, 9);
            cs.newLineAtOffset(colX, y - headerHeight + 5);
            showTextSafe(filter(headers[i]));
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
                cs.addRect(margin, y - rowHeight, tableWidth, rowHeight);
                cs.fill();
                cs.setNonStrokingColor(0, 0, 0);
            }
            colX = margin + 2;
            for (int i = 0; i < row.length && i < headers.length; i++) {
                cs.beginText();
                cs.setFont(regularFont, 8);
                cs.newLineAtOffset(colX, y - rowHeight + 4);
                showTextSafe(filter(row[i] != null ? row[i] : ""));
                cs.endText();
                colX += tableWidth * colWidths[i];
            }
            y -= rowHeight;
            rowIdx++;
        }
        y -= 12;
    }

    /**
     * 安全的 showText 调用，对每个字符进行字形可用性检查，
     * 过滤掉当前字体中无 glyph 的字符，避免 PDFBox 抛出
     * "could not find the glyphId for the character" 异常导致整个 PDF 生成失败。
     *
     * 采用二级防御策略：
     * 1. 先用 isRenderableChar 预过滤（在 filter/filterLine 中完成）
     * 2. 若 showText 仍失败，回退到 ASCII-only 安全渲染
     */
    private void showTextSafe(String text) throws Exception {
        if (text == null || text.isEmpty()) return;

        try {
            cs.showText(text);
        } catch (Exception e) {
            LogManager.getInstance().debug("PDF showText 降级，使用 ASCII 安全渲染: "
                    + text.substring(0, Math.min(20, text.length()))
                    + "..., 原因: " + e.getMessage());
            // 异常降级：将所有非 ASCII 字符替换为 ?，只保留可安全渲染的 ASCII
            String safeText = toAsciiSafe(text);
            if (!safeText.isEmpty()) {
                try {
                    cs.showText(safeText);
                } catch (Exception ignored) {
                    LogManager.getInstance().debug("PDF showText ASCII 降级也失败: "
                            + text.substring(0, Math.min(20, text.length())) + "...");
                }
            }
        }
    }

    /**
     * 将文本降级为 ASCII 安全形式：
     * 保留 0x20-0x7E 可打印 ASCII，连续非 ASCII 字符压缩为单个 '?'
     */
    private String toAsciiSafe(String text) {
        if (text == null) return "";
        StringBuilder sb = new StringBuilder(text.length());
        boolean lastWasReplacement = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c >= 0x20 && c <= 0x7E) {
                sb.append(c);
                lastWasReplacement = false;
            } else if (!lastWasReplacement) {
                sb.append('?');
                lastWasReplacement = true;
            }
        }
        return sb.toString();
    }

    private void ensureSpace(float needed) throws Exception {
        if (y - needed < margin) {
            cs.close();
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);
            cs = new PDPageContentStream(document, page);
            y = PAGE_HEIGHT - margin;
        }
    }

    /**
     * 检查字符是否可在当前 PDF 字体中渲染
     * 基于常见 CJK 字体的字符覆盖范围进行过滤，
     * 排除私用区、代理对、C0/C1 控制字符等无 glyph 的字符
     */
    private boolean isRenderableChar(char c) {
        // C0 控制字符 (0x00-0x1F): 均不可直接渲染，由 filter/filterLine 单独处理
        if (c < 0x20) {
            return false;
        }
        // DEL (0x7F)
        if (c == 0x7F) return false;
        // C1 控制字符 (0x80-0x9F)
        if (c >= 0x80 && c <= 0x9F) return false;
        // 代理对区域 (0xD800-0xDFFF) — 不应出现在合法 UTF-16 中
        if (c >= 0xD800 && c <= 0xDFFF) return false;
        // 私用区 (0xE000-0xF8FF) — 常见 CJK 字体不覆盖
        if (c >= 0xE000 && c <= 0xF8FF) return false;
        // Unicode 替换字符 (0xFFFD) — 解码错误的标记
        if (c == 0xFFFD) return false;
        // Unicode 特殊区域 (0xFFF0-0xFFFF)
        if (c >= 0xFFF0 && c <= 0xFFFF) return false;

        // CJK 字体主要覆盖:
        // - Basic Latin (0x0020-0x007E)
        // - Latin-1 Supplement (0x00A0-0x00FF)
        // - Latin Extended-A (0x0100-0x017F)
        // - CJK 相关 (0x2000-0x206F, 0x3000-0x303F, 0x4E00-0x9FFF 等)
        // 非 CJK 模式下仅保留 Latin-1
        if (!cjkEnabled && c > 0xFF) {
            return false;
        }

        return true;
    }

    String filter(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            // 控制字符特殊处理（在 isRenderableChar 之前，避免死代码）
            if (c == '\r') continue;           // \r 会导致 PDF showText 异常，必须丢弃
            if (c == '\n') { sb.append(' '); continue; }
            if (c == '\t') { sb.append("    "); continue; }
            // 过滤不可渲染字符
            if (!isRenderableChar(c)) continue;
            sb.append(c);
        }
        return sb.toString();
    }

    String filterLine(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            // 控制字符特殊处理（在 isRenderableChar 之前，避免死代码）
            if (c == '\r') continue;           // \r 会导致 PDF showText 异常，必须丢弃
            if (c == '\t') { sb.append("    "); continue; }
            // 过滤不可渲染字符
            if (!isRenderableChar(c)) continue;
            sb.append(c);
        }
        return sb.toString();
    }
}
