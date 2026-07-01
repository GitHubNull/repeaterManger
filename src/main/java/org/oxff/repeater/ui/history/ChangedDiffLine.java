package org.oxff.repeater.ui.history;

import java.util.List;

/**
 * 已变更行差异结果 — 携带行内字符级差异。
 * 继承 DiffLine，增加原始侧和修改侧的行内差异段。
 */
public class ChangedDiffLine extends DiffLine {
    private final String pairedText;
    private final List<InlineDiffSegment> originalInlineDiff;
    private final List<InlineDiffSegment> modifiedInlineDiff;

    public ChangedDiffLine(int lineNumber, String originalText, String modifiedText,
                           List<InlineDiffSegment> originalInlineDiff,
                           List<InlineDiffSegment> modifiedInlineDiff) {
        super(lineNumber, originalText, DiffType.CHANGED);
        this.pairedText = modifiedText;
        this.originalInlineDiff = originalInlineDiff;
        this.modifiedInlineDiff = modifiedInlineDiff;
    }

    public String getPairedText() { return pairedText; }
    public List<InlineDiffSegment> getOriginalInlineDiff() { return originalInlineDiff; }
    public List<InlineDiffSegment> getModifiedInlineDiff() { return modifiedInlineDiff; }
}
