package org.oxff.repeater.privilege;

import org.oxff.repeater.privilege.model.TokenScheme;

/**
 * TokenScheme匹配结果
 * 封装从HTTP报文解析后与某个TokenScheme的匹配程度
 */
public class SchemeMatch {
    private final TokenScheme scheme;
    private final int matchedCount;
    private final int totalCount;

    public SchemeMatch(TokenScheme scheme, int matchedCount, int totalCount) {
        this.scheme = scheme;
        this.matchedCount = matchedCount;
        this.totalCount = totalCount;
    }

    public TokenScheme getScheme() {
        return scheme;
    }

    public int getMatchedCount() {
        return matchedCount;
    }

    public int getTotalCount() {
        return totalCount;
    }

    /**
     * 获取匹配率（0.0 ~ 1.0）
     */
    public double getMatchRate() {
        if (totalCount <= 0) {
            return 0.0;
        }
        return (double) matchedCount / totalCount;
    }

    @Override
    public String toString() {
        return String.format("SchemeMatch{scheme='%s', matched=%d/%d, rate=%.0f%%}",
                scheme != null ? scheme.getName() : "null",
                matchedCount, totalCount, getMatchRate() * 100);
    }
}
