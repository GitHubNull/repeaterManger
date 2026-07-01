package org.oxff.repeater.ui.history;

import java.util.List;

/**
 * 行内差异结果对 — 同时包含原始侧和修改侧的差异段
 */
public class InlineDiffResult {
    private final List<InlineDiffSegment> originalSegments;
    private final List<InlineDiffSegment> modifiedSegments;

    public InlineDiffResult(List<InlineDiffSegment> originalSegments,
                            List<InlineDiffSegment> modifiedSegments) {
        this.originalSegments = originalSegments;
        this.modifiedSegments = modifiedSegments;
    }

    public List<InlineDiffSegment> getOriginalSegments() { return originalSegments; }
    public List<InlineDiffSegment> getModifiedSegments() { return modifiedSegments; }
}
