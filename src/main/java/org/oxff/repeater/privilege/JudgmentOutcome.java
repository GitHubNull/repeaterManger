package org.oxff.repeater.privilege;

import org.oxff.repeater.privilege.model.JudgmentResult;
import java.awt.Color;

/**
 * 判决结果持有者
 */
public class JudgmentOutcome {
    public final JudgmentResult result;
    public final Color color;
    public final String note;
    public final double similarity;
    /** 匹配到的规则名称（null表示使用默认判决） */
    public final String matchedRuleName;

    public JudgmentOutcome(JudgmentResult result, Color color, String note,
                           double similarity, String matchedRuleName) {
        this.result = result;
        this.color = color;
        this.note = note;
        this.similarity = similarity;
        this.matchedRuleName = matchedRuleName;
    }
}
