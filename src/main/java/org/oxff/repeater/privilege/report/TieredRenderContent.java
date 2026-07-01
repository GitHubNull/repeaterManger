package org.oxff.repeater.privilege.report;

import java.util.List;

/** 分级渲染内容 */
public class TieredRenderContent {
    public final BinarySizeTier tier;
    public final String metadataCardText;
    public final String hexDumpPreview;
    public final String base64Content;
    public final List<MultipartPartInfo> multipartParts;
    public final String contentType;
    public final String contentCategory;
    public final String humanSize;

    public TieredRenderContent(BinarySizeTier tier, String metadataCardText,
                               String hexDumpPreview, String base64Content,
                               List<MultipartPartInfo> multipartParts,
                               String contentType, String contentCategory,
                               String humanSize) {
        this.tier = tier;
        this.metadataCardText = metadataCardText;
        this.hexDumpPreview = hexDumpPreview;
        this.base64Content = base64Content;
        this.multipartParts = multipartParts;
        this.contentType = contentType;
        this.contentCategory = contentCategory;
        this.humanSize = humanSize;
    }
}
