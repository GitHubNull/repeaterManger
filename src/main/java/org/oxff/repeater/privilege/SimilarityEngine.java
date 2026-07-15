package org.oxff.repeater.privilege;

import org.oxff.repeater.logging.LogManager;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
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
        if (s1 == null || s2 == null) {
            LogManager.getInstance().judgmentDebug("[相似度] 一方为null → 0.0");
            return 0.0;
        }
        if (s1.isEmpty() && s2.isEmpty()) {
            LogManager.getInstance().judgmentDebug("[相似度] 双方均为空字符串 → 1.0");
            return 1.0;
        }
        if (s1.isEmpty() || s2.isEmpty()) {
            LogManager.getInstance().judgmentDebug(String.format(
                    "[相似度] 一方为空(len1=%d,len2=%d) → 0.0", s1.length(), s2.length()));
            return 0.0;
        }
        if (s1.equals(s2)) {
            LogManager.getInstance().judgmentDebug("[相似度] 内容完全相同 → 1.0");
            return 1.0;
        }

        return computeByType(s1, s2, type);
    }

    /**
     * 结合 HTTP 头部检测内容类型并计算相似度（字节数组版本）
     * <p>
     * 对于二进制内容类型，直接使用原始字节长度计算相似度，
     * 避免 UTF-8 字符串解码导致长度失真。
     * 对于文本内容类型，转换为字符串后委托给字符串版本。
     *
     * @param data1             第一个字节数组
     * @param data2             第二个字节数组
     * @param contentTypeHeader HTTP Content-Type 头部值
     * @return 相似度值 0.0~1.0，1.0 表示完全相同
     */
    public static double similarity(byte[] data1, byte[] data2, String contentTypeHeader) {
        if (data1 == null && data2 == null) return 1.0;
        if (data1 == null || data2 == null) {
            LogManager.getInstance().judgmentDebug("[相似度] 一方为null → 0.0");
            return 0.0;
        }
        if (data1.length == 0 && data2.length == 0) {
            LogManager.getInstance().judgmentDebug("[相似度] 双方均为空 → 1.0");
            return 1.0;
        }
        if (data1.length == 0 || data2.length == 0) {
            LogManager.getInstance().judgmentDebug(String.format(
                    "[相似度] 一方为空(len1=%d,len2=%d) → 0.0", data1.length, data2.length));
            return 0.0;
        }
        if (Arrays.equals(data1, data2)) {
            LogManager.getInstance().judgmentDebug("[相似度] 内容完全相同 → 1.0");
            return 1.0;
        }

        ContentTypeDetector.ContentType type = ContentTypeDetector.detect(contentTypeHeader,
                new String(data1, StandardCharsets.UTF_8));
        LogManager.getInstance().judgmentDebug(String.format(
                "[相似度] ContentType=%s, len1=%d, len2=%d", type.name(), data1.length, data2.length));

        if (type == ContentTypeDetector.ContentType.BINARY) {
            return computeBinarySimilarity(data1, data2);
        }

        // 非二进制内容：转换为字符串后委托给字符串版本
        String s1 = new String(data1, StandardCharsets.UTF_8);
        String s2 = new String(data2, StandardCharsets.UTF_8);
        return computeByType(s1, s2, type);
    }

    /**
     * 结合 HTTP 头部检测内容类型并计算相似度（字符串版本）
     * 优先使用头部信息，头部无法确定时用内容推断
     *
     * @param s1                第一个字符串
     * @param s2                第二个字符串
     * @param contentTypeHeader HTTP Content-Type 头部值
     * @return 相似度值 0.0~1.0，1.0 表示完全相同
     */
    public static double similarity(String s1, String s2, String contentTypeHeader) {
        if (s1 == null && s2 == null) return 1.0;
        if (s1 == null || s2 == null) {
            LogManager.getInstance().judgmentDebug("[相似度] 一方为null → 0.0");
            return 0.0;
        }
        if (s1.isEmpty() && s2.isEmpty()) {
            LogManager.getInstance().judgmentDebug("[相似度] 双方均为空字符串 → 1.0");
            return 1.0;
        }
        if (s1.isEmpty() || s2.isEmpty()) {
            LogManager.getInstance().judgmentDebug(String.format(
                    "[相似度] 一方为空(len1=%d,len2=%d) → 0.0", s1.length(), s2.length()));
            return 0.0;
        }
        if (s1.equals(s2)) {
            LogManager.getInstance().judgmentDebug("[相似度] 内容完全相同 → 1.0");
            return 1.0;
        }

        ContentTypeDetector.ContentType type = ContentTypeDetector.detect(contentTypeHeader, s1);
        LogManager.getInstance().judgmentDebug(String.format(
                "[相似度] ContentType=%s, len1=%d, len2=%d", type.name(), s1.length(), s2.length()));
        return computeByType(s1, s2, type);
    }

    /**
     * 按内容类型路由到具体算法
     */
    private static double computeByType(String s1, String s2, ContentTypeDetector.ContentType type) {
        double result = switch (type) {
            case JSON -> JsonSimilarityCalculator.similarity(s1, s2);
            case XML -> XmlSimilarityCalculator.similarity(s1, s2);
            case HTML, TEXT -> JaccardSimilarityCalculator.similarity(s1, s2);
            case BINARY -> computeBinarySimilarity(s1, s2);
        };
        LogManager.getInstance().judgmentDebug(String.format(
                "[相似度] 算法=%s, 结果=%.4f", type.name(), result));
        return result;
    }

    /**
     * 二进制内容的粗略相似度：基于字节长度比
     * 对于二进制响应，精确内容比较无意义，仅比较长度差异。
     * 使用字节数组长度而非字符串长度，避免 UTF-8 解码导致失真。
     */
    private static double computeBinarySimilarity(byte[] data1, byte[] data2) {
        if (data1.length == 0 && data2.length == 0) return 1.0;

        int len1 = data1.length;
        int len2 = data2.length;
        int maxLen = Math.max(len1, len2);

        if (maxLen == 0) return 1.0;

        int minLen = Math.min(len1, len2);
        return (double) minLen / maxLen;
    }

    /**
     * 二进制内容的粗略相似度：基于字符串长度比（已废弃，保留兼容）
     * 使用字节数组版本 {@link #computeBinarySimilarity(byte[], byte[])} 替代
     */
    @Deprecated
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
