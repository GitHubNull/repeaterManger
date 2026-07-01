package org.oxff.repeater.ui.history;

/**
 * 行内差异段 — 表示一行内连续的匹配或不匹配文本
 */
public class InlineDiffSegment {
    private final String text;
    private final InlineDiffType type;

    public InlineDiffSegment(String text, InlineDiffType type) {
        this.text = text;
        this.type = type;
    }

    public String getText() { return text; }
    public InlineDiffType getType() { return type; }
}
