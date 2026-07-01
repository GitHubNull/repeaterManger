package org.oxff.repeater.ui.history;

/**
 * 字节级差异结果（hex格式）
 */
public class DiffSegment {
    private final int offset;
    private final String hexData;
    private final String asciiData;
    private final DiffType diffType;

    public DiffSegment(int offset, String hexData, String asciiData, DiffType diffType) {
        this.offset = offset;
        this.hexData = hexData;
        this.asciiData = asciiData;
        this.diffType = diffType;
    }

    public int getOffset() { return offset; }
    public String getHexData() { return hexData; }
    public String getAsciiData() { return asciiData; }
    public DiffType getDiffType() { return diffType; }
}
