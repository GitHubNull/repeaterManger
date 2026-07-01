package org.oxff.repeater.ui.history;

/**
 * 行级差异结果
 */
public class DiffLine {
    private final int lineNumber;
    private final String lineText;
    private final DiffType diffType;

    public DiffLine(int lineNumber, String lineText, DiffType diffType) {
        this.lineNumber = lineNumber;
        this.lineText = lineText;
        this.diffType = diffType;
    }

    public int getLineNumber() { return lineNumber; }
    public String getLineText() { return lineText; }
    public DiffType getDiffType() { return diffType; }
}
