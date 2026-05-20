package oxff.top.privilege;

import java.util.HashSet;
import java.util.Set;

/**
 * Jaccard 相似度计算器 - 无状态工具类
 * 基于 n-gram token 集合的 Jaccard 系数计算文本相似度
 *
 * <p>作为非结构化文本（HTML、纯文本等）的默认相似度算法，
 * 替代 Levenshtein 编辑距离，具有以下优势：
 * <ul>
 *   <li>时间复杂度 O(n+m)，远快于 Levenshtein 的 O(n*m)</li>
 *   <li>无需截断，可处理任意大小的响应</li>
 *   <li>对局部插入/删除比 Levenshtein 更鲁棒</li>
 *   <li>字段顺序变化对相似度影响更小</li>
 * </ul>
 */
public class JaccardSimilarityCalculator {

    /** n-gram 的 n 值，3-gram 在粒度和性能间取得平衡 */
    private static final int NGRAM_SIZE = 3;

    private JaccardSimilarityCalculator() {
    }

    /**
     * 计算两个字符串的 Jaccard 相似度（经过噪声过滤后）
     *
     * @param s1 第一个字符串
     * @param s2 第二个字符串
     * @return 相似度值 0.0~1.0，1.0 表示完全相同，0.0 表示完全不同
     */
    public static double similarity(String s1, String s2) {
        if (s1 == null && s2 == null) return 1.0;
        if (s1 == null || s2 == null) return 0.0;
        if (s1.isEmpty() && s2.isEmpty()) return 1.0;
        if (s1.isEmpty() || s2.isEmpty()) return 0.0;
        if (s1.equals(s2)) return 1.0;

        // 噪声归一化
        String norm1 = NoiseFilter.normalize(s1);
        String norm2 = NoiseFilter.normalize(s2);

        Set<String> set1 = buildNgramSet(norm1);
        Set<String> set2 = buildNgramSet(norm2);

        if (set1.isEmpty() && set2.isEmpty()) return 1.0;
        if (set1.isEmpty() || set2.isEmpty()) return 0.0;

        // 计算交集大小
        Set<String> intersection = new HashSet<>(set1);
        intersection.retainAll(set2);

        // 计算并集大小
        Set<String> union = new HashSet<>(set1);
        union.addAll(set2);

        return (double) intersection.size() / union.size();
    }

    /**
     * 构建文本的 n-gram token 集合
     *
     * @param text 输入文本
     * @return n-gram 集合
     */
    private static Set<String> buildNgramSet(String text) {
        Set<String> ngrams = new HashSet<>();
        // 对短文本降级为字符级匹配
        int n = Math.min(NGRAM_SIZE, text.length());
        if (n <= 0) return ngrams;

        for (int i = 0; i <= text.length() - n; i++) {
            ngrams.add(text.substring(i, i + n));
        }
        return ngrams;
    }
}
