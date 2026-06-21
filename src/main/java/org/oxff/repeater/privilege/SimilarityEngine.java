package org.oxff.repeater.privilege;

/**
 * 相似度引擎 - 无状态工具类
 * 根据响应内容类型自动选择最优相似度算法的混合引擎
 *
 * <p>路由策略：
 * <ul>
 *   <li>JSON → JsonSimilarityCalculator（Tree Diff，字段顺序无关）</li>
 *   <li>XML → XmlSimilarityCalculator（Tree Diff，元素顺序无关）</li>
 *   <li>HTML → JaccardSimilarityCalculator（n-gram，噪声过滤）</li>
 *   <li>TEXT → JaccardSimilarityCalculator（n-gram，噪声过滤）</li>
 *   <li>BINARY → 基于长度的粗略比较</li>
 *   <li>解析失败时自动降级到 Jaccard n-gram</li>
 * </ul>
 *
 * <p>替代原有的 LevenshteinCalculator，作为越权判决和报文比对的一致入口
 */
public class SimilarityEngine {

    private SimilarityEngine() {
    }

    /**
     * 自动检测内容类型并计算相似度
     * 当无 HTTP 头部可用时，从响应体内容推断格式
     *
     * @param s1 第一个字符串
     * @param s2 第二个字符串
     * @return 相似度值 0.0~1.0，1.0 表示完全相同
     */
    public static double similarity(String s1, String s2) {
        if (s1 == null && s2 == null) return 1.0;
        if (s1 == null || s2 == null) return 0.0;
        if (s1.isEmpty() && s2.isEmpty()) return 1.0;
        if (s1.isEmpty() || s2.isEmpty()) return 0.0;
        if (s1.equals(s2)) return 1.0;

        ContentTypeDetector.ContentType type = ContentTypeDetector.detect(s1);
        return computeByType(s1, s2, type);
    }

    /**
     * 显式指定内容类型计算相似度
     * 当有 HTTP Content-Type 头部时优先使用此方法
     *
     * @param s1   第一个字符串
     * @param s2   第二个字符串
     * @param type 已知的内容类型
     * @return 相似度值 0.0~1.0，1.0 表示完全相同
     */
    public static double similarity(String s1, String s2, ContentTypeDetector.ContentType type) {
        if (s1 == null && s2 == null) return 1.0;
        if (s1 == null || s2 == null) return 0.0;
        if (s1.isEmpty() && s2.isEmpty()) return 1.0;
        if (s1.isEmpty() || s2.isEmpty()) return 0.0;
        if (s1.equals(s2)) return 1.0;

        return computeByType(s1, s2, type);
    }

    /**
     * 结合 HTTP 头部检测内容类型并计算相似度
     * 优先使用头部信息，头部无法确定时用内容推断
     *
     * @param s1                第一个字符串
     * @param s2                第二个字符串
     * @param contentTypeHeader HTTP Content-Type 头部值
     * @return 相似度值 0.0~1.0，1.0 表示完全相同
     */
    public static double similarity(String s1, String s2, String contentTypeHeader) {
        if (s1 == null && s2 == null) return 1.0;
        if (s1 == null || s2 == null) return 0.0;
        if (s1.isEmpty() && s2.isEmpty()) return 1.0;
        if (s1.isEmpty() || s2.isEmpty()) return 0.0;
        if (s1.equals(s2)) return 1.0;

        ContentTypeDetector.ContentType type = ContentTypeDetector.detect(contentTypeHeader, s1);
        return computeByType(s1, s2, type);
    }

    /**
     * 按内容类型路由到具体算法
     */
    private static double computeByType(String s1, String s2, ContentTypeDetector.ContentType type) {
        return switch (type) {
            case JSON -> JsonSimilarityCalculator.similarity(s1, s2);
            case XML -> XmlSimilarityCalculator.similarity(s1, s2);
            case HTML, TEXT -> JaccardSimilarityCalculator.similarity(s1, s2);
            case BINARY -> computeBinarySimilarity(s1, s2);
        };
    }

    /**
     * 二进制内容的粗略相似度：基于长度比
     * 对于二进制响应，精确内容比较无意义，仅比较长度差异
     */
    private static double computeBinarySimilarity(String s1, String s2) {
        if (s1.isEmpty() && s2.isEmpty()) return 1.0;

        int len1 = s1.length();
        int len2 = s2.length();
        int maxLen = Math.max(len1, len2);

        if (maxLen == 0) return 1.0;

        int minLen = Math.min(len1, len2);
        return (double) minLen / maxLen;
    }
}
