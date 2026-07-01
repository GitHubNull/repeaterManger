package org.oxff.repeater.ui.history;

/**
 * 差异区域 — 记录文档中差异行的偏移位置，用于导航
 */
public class DiffRegion {
    private final int startOffset;
    private final int endOffset;
    private final DiffType diffType;
    private final int lineNumber;

    public DiffRegion(int startOffset, int endOffset, DiffType diffType, int lineNumber) {
        this.startOffset = startOffset;
        this.endOffset = endOffset;
        this.diffType = diffType;
        this.lineNumber = lineNumber;
    }

    public int getStartOffset() { return startOffset; }
    public int getEndOffset() { return endOffset; }
    public DiffType getDiffType() { return diffType; }
    public int getLineNumber() { return lineNumber; }
}
