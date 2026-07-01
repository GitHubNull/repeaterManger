package org.oxff.repeater.io;

/**
 * 数据条目头解析结果
 */
public class EntryHeader {
    public String path;
    public int compressionMethod;
    public long compressedSize;
    public long uncompressedSize;
    public long entryCrc;
}
