package org.oxff.repeater.privilege;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.util.HashMap;
import java.util.Map;

/**
 * JSON 相似度计算器 - 无状态工具类
 * 基于 JSON Tree Diff 算法，递归展平 JSON 为 key-path → leaf-value 映射后比较
 *
 * <p>优势：
 * <ul>
 *   <li>字段顺序无关 — {"a":1,"b":2} 和 {"b":2,"a":1} 视为相同</li>
 *   <li>噪声过滤 — 时间戳、UUID 等动态值自动归一化</li>
 *   <li>语义级别比较 — 关注数据结构而非字符序列</li>
 *   <li>精确差异定位 — 可扩展为返回差异路径列表</li>
 * </ul>
 */
public class JsonSimilarityCalculator {

    private JsonSimilarityCalculator() {
    }

    /**
     * 计算两个 JSON 字符串的结构相似度
     *
     * @param json1 第一个 JSON 字符串
     * @param json2 第二个 JSON 字符串
     * @return 相似度值 0.0~1.0，1.0 表示完全相同
     */
    public static double similarity(String json1, String json2) {
        if (json1 == null && json2 == null) return 1.0;
        if (json1 == null || json2 == null) return 0.0;
        if (json1.isEmpty() && json2.isEmpty()) return 1.0;
        if (json1.isEmpty() || json2.isEmpty()) return 0.0;
        if (json1.equals(json2)) return 1.0;

        try {
            JsonElement elem1 = JsonParser.parseString(json1);
            JsonElement elem2 = JsonParser.parseString(json2);

            Map<String, String> map1 = flattenJson(elem1, "");
            Map<String, String> map2 = flattenJson(elem2, "");

            return computeMapSimilarity(map1, map2);
        } catch (JsonSyntaxException e) {
            // JSON 解析失败，降级到 Jaccard
            return JaccardSimilarityCalculator.similarity(json1, json2);
        }
    }

    /**
     * 递归展平 JSON 元素为 key-path → leaf-value 映射
     *
     * @param element JSON 元素
     * @param prefix  当前路径前缀
     * @return 展平后的映射
     */
    private static Map<String, String> flattenJson(JsonElement element, String prefix) {
        Map<String, String> result = new HashMap<>();

        if (element == null || element.isJsonNull()) {
            result.put(prefix, "null");
            return result;
        }

        if (element.isJsonPrimitive()) {
            // 叶子节点：归一化后存储
            String value = element.getAsString();
            result.put(prefix, NoiseFilter.normalize(value));
            return result;
        }

        if (element.isJsonArray()) {
            JsonArray array = element.getAsJsonArray();
            if (array.isEmpty()) {
                result.put(prefix + "[]", "[]");
            } else {
                for (int i = 0; i < array.size(); i++) {
                    String childPath = prefix + "[" + i + "]";
                    result.putAll(flattenJson(array.get(i), childPath));
                }
            }
            return result;
        }

        if (element.isJsonObject()) {
            JsonObject obj = element.getAsJsonObject();
            if (obj.isEmpty()) {
                result.put(prefix + "{}", "{}");
            } else {
                for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                    String childPath = prefix.isEmpty()
                            ? entry.getKey()
                            : prefix + "." + entry.getKey();
                    result.putAll(flattenJson(entry.getValue(), childPath));
                }
            }
            return result;
        }

        return result;
    }

    /**
     * 计算两个 key-path 映射的相似度
     * 使用结构分 + 值分加权混合算法：
     * - 结构分：衡量 key 级别的覆盖度（两边共有 key 数 / 总 key 数）
     * - 值分：在共有 key 上衡量值的匹配度
     * - 最终相似度 = 0.5 × 结构分 + 0.5 × 值分
     *
     * 50/50 平衡权重确保对 RESPONSE WRAPPER 中少量用户元数据字段差异
     * 具有足够的鲁棒性，避免将真实水平越权漏报为“安全”。
     */
    private static double computeMapSimilarity(Map<String, String> map1, Map<String, String> map2) {
        if (map1.isEmpty() && map2.isEmpty()) return 1.0;
        if (map1.isEmpty() || map2.isEmpty()) return 0.0;

        // 所有 key 的并集
        java.util.Set<String> allKeys = new java.util.HashSet<>(map1.keySet());
        allKeys.addAll(map2.keySet());

        int totalKeys = allKeys.size();
        double structuralScore = 0.0;  // key 存在即得分
        double valueScore = 0.0;       // 值相同才得分

        for (String key : allKeys) {
            String v1 = map1.get(key);
            String v2 = map2.get(key);

            if (v1 != null && v2 != null) {
                // 两边都有这个 key → 结构分+1
                structuralScore += 1.0;
                if (v1.equals(v2)) {
                    // 值也相同 → 值分+1
                    valueScore += 1.0;
                } else {
                    // 值不同，但可能只有噪声差异，计算值的字符串相似度给部分分
                    double valueSim = computeValueSimilarity(v1, v2);
                    valueScore += valueSim;
                }
            }
            // 单边独有的 key → 两个分数都不加
        }

        double structureSimilarity = totalKeys > 0 ? structuralScore / totalKeys : 0.0;
        double valueSimilarity = structuralScore > 0 ? valueScore / structuralScore : 0.0;

        // 加权混合：结构分权重 0.5，值分权重 0.5
        // 50/50 平衡避免值分权重过高导致包装层少量元数据差异引发漏报
        return 0.5 * structureSimilarity + 0.5 * valueSimilarity;
    }

    /**
     * 计算两个叶子值的相似度（已归一化后）
     * 短字符串（<=50字符）使用 Levenshtein 比率给部分分，
     * 长字符串使用 Jaccard n-gram 给部分分
     */
    private static double computeValueSimilarity(String v1, String v2) {
        if (v1.equals(v2)) return 1.0;

        // 短值（<=50字符）：使用 Levenshtein 比率给部分分
        if (v1.length() <= 50 && v2.length() <= 50) {
            return LevenshteinCalculator.similarity(v1, v2);
        }

        // 长值：用 Jaccard n-gram 给部分分
        return JaccardSimilarityCalculator.similarity(v1, v2);
    }
}
