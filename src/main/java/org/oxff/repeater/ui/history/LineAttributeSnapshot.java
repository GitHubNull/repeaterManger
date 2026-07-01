package org.oxff.repeater.ui.history;

import java.awt.Color;

/**
 * 行属性快照 — 记录每行在文档中的偏移和差异背景色
 */
class LineAttributeSnapshot {
    final int startOffset;
    final int length;
    final Color backgroundColor;

    LineAttributeSnapshot(int startOffset, int length, Color backgroundColor) {
        this.startOffset = startOffset;
        this.length = length;
        this.backgroundColor = backgroundColor;
    }
}
