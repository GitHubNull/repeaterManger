package org.oxff.repeater.privilege.report;

/** Multipart 单 part 信息 */
public class MultipartPartInfo {
    public final String name;
    public final String fileName;
    public final String partContentType;
    public final boolean isText;
    public final String textContent;
    public final byte[] binaryPreview;
    public final long partSize;

    public MultipartPartInfo(String name, String fileName, String partContentType,
                             boolean isText, String textContent, byte[] binaryPreview,
                             long partSize) {
        this.name = name;
        this.fileName = fileName;
        this.partContentType = partContentType;
        this.isText = isText;
        this.textContent = textContent;
        this.binaryPreview = binaryPreview;
        this.partSize = partSize;
    }
}
