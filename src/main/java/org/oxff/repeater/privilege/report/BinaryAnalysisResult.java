package org.oxff.repeater.privilege.report;

import java.util.List;

/** 二进制内容分析结果 */
public class BinaryAnalysisResult {
    public final boolean isBinary;
    public final String contentType;
    public final String contentCategory;
    public final long contentLength;
    public final String sha256Hash;
    public final String humanSize;
    public final byte[] previewBytes;
    public final String base64Data;
    public final List<MultipartPartInfo> multipartParts;

    public BinaryAnalysisResult(boolean isBinary, String contentType, String contentCategory,
                                long contentLength, String sha256Hash, String humanSize,
                                byte[] previewBytes, String base64Data,
                                List<MultipartPartInfo> multipartParts) {
        this.isBinary = isBinary;
        this.contentType = contentType;
        this.contentCategory = contentCategory;
        this.contentLength = contentLength;
        this.sha256Hash = sha256Hash;
        this.humanSize = humanSize;
        this.previewBytes = previewBytes;
        this.base64Data = base64Data;
        this.multipartParts = multipartParts;
    }
}
