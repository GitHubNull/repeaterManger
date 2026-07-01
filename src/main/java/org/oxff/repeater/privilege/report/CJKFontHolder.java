package org.oxff.repeater.privilege.report;

import org.apache.pdfbox.pdmodel.font.PDFont;

/**
 * CJK 字体持有者，存储 PDF 渲染所需的 regular / bold / mono 字体
 */
public class CJKFontHolder {
    public final PDFont regular;
    public final PDFont bold;
    public final PDFont mono;

    public CJKFontHolder(PDFont regular, PDFont bold, PDFont mono) {
        this.regular = regular;
        this.bold = bold;
        this.mono = mono;
    }
}
