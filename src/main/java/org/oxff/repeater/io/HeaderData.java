package org.oxff.repeater.io;

/**
 * 文件头解析结果
 */
public class HeaderData {
    public int formatVersion;
    public int flags;
    public int entryCount;
    public long manifestOffset;
    public int schemaVersion;
    public int headerSize;
    public boolean isEncrypted;
}
