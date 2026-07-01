package org.oxff.repeater.privilege.report;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDFont;

import java.util.ArrayList;
import java.util.List;

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

    void drawTitle(String text, float fontSize) throws Exception {
        ensureSpace(fontSize * 1.5f + 14);
        cs.beginText();
        cs.setFont(boldFont, fontSize);
        cs.newLineAtOffset(margin, y);
        cs.showText(filter(text));
        cs.endText();
        y -= fontSize * 1.5f + 12;
    }

    void drawSectionTitle(String text) throws Exception {
        ensureSpace(28);
        cs.beginText();
        cs.setFont(boldFont, 9);
        cs.newLineAtOffset(margin + 10, y);
        cs.showText(filter(text));
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
        cs.showText(filter(text));
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
                cs.addRect(margin, y - rowHeight, tableWidth, rowHeight);
                cs.fill();
                cs.setNonStrokingColor(0, 0, 0);
            }
            colX = margin + 2;
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
        if (y - needed < margin) {
            cs.close();
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);
            cs = new PDPageContentStream(document, page);
            y = PAGE_HEIGHT - margin;
        }
    }

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
                    if (cjkEnabled || c <= 0xFF) {
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
                    if (cjkEnabled || c <= 0xFF) {
                        sb.append(c);
                    } else {
                        sb.append('?');
                    }
            }
        }
        return sb.toString();
    }
}
