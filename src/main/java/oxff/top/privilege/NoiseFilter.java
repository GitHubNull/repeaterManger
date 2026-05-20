package oxff.top.privilege;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 噪声过滤器 - 无状态工具类
 * 将响应体中的动态值（时间戳、UUID、签名等）替换为常量占位符，
 * 使相似度比较只关注结构差异而非动态噪声，降低误报率
 */
public class NoiseFilter {

    /** 噪声替换占位符 */
    public static final String NOISE_PLACEHOLDER = "__NOISE__";

    /** 预定义噪声正则列表 */
    private static final List<Pattern> BUILTIN_PATTERNS = List.of(
            // ISO 8601 时间戳: 2024-01-15T10:30:00Z, 2024-01-15T10:30:00.123+08:00
            Pattern.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})?"),
            // 日期: 2024-01-15, 2024/01/15
            Pattern.compile("\\d{4}[-/]\\d{2}[-/]\\d{2}"),
            // 时间: 10:30:00, 10:30
            Pattern.compile("\\b\\d{2}:\\d{2}(?::\\d{2})?\\b"),
            // Unix epoch 毫秒: 1705312200123
            Pattern.compile("\\b\\d{13}\\b"),
            // Unix epoch 秒: 1705312200
            Pattern.compile("\\b1[6-9]\\d{8}\\b"),
            // UUID: 550e8400-e29b-41d4-a716-446655440000
            Pattern.compile("\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b"),
            // JWT token (三段 base64)
            Pattern.compile("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"),
            // Base64 长串 (>=40字符)
            Pattern.compile("(?:[A-Za-z0-9+/]{4}){10,}={0,2}"),
            // 十六进制哈希/签名 (32/40/64字符)
            Pattern.compile("\\b[0-9a-fA-F]{32}\\b"),
            Pattern.compile("\\b[0-9a-fA-F]{40}\\b"),
            Pattern.compile("\\b[0-9a-fA-F]{64}\\b"),
            // 数字型ID (纯数字，6-19位)
            Pattern.compile("\\b\\d{6,19}\\b")
    );

    /** 自定义扩展噪声正则列表（线程安全） */
    private static final List<Pattern> customPatterns = new ArrayList<>();

    private NoiseFilter() {
    }

    /**
     * 对文本做噪声归一化，将匹配到的动态值替换为占位符
     *
     * @param text 原始文本
     * @return 归一化后的文本
     */
    public static String normalize(String text) {
        if (text == null || text.isEmpty()) return text;

        String result = text;
        // 先应用自定义规则
        for (Pattern p : customPatterns) {
            result = p.matcher(result).replaceAll(NOISE_PLACEHOLDER);
        }
        // 再应用内置规则
        for (Pattern p : BUILTIN_PATTERNS) {
            result = p.matcher(result).replaceAll(NOISE_PLACEHOLDER);
        }
        return result;
    }

    /**
     * 添加自定义噪声正则（运行时扩展）
     *
     * @param regex 正则表达式
     */
    public static synchronized void addPattern(String regex) {
        customPatterns.add(Pattern.compile(regex));
    }

    /**
     * 清除所有自定义噪声正则
     */
    public static synchronized void clearCustomPatterns() {
        customPatterns.clear();
    }
}
