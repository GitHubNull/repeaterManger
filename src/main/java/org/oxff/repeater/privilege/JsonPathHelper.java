package org.oxff.repeater.privilege;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.util.ArrayList;
import java.util.List;

/**
 * JSON 路径操作工具类
 * 提供 JSONPath 段分割、类型感知的 JSON 值转换、JSON 结构导航等通用工具方法
 */
public class JsonPathHelper {

    private JsonPathHelper() {
        // 工具类，禁止实例化
    }

    /**
     * 分割JSONPath路径段
     * 处理 "field.subfield[0].name" → ["field", "subfield", "[0]", "name"]
     */
    public static String[] splitJsonPath(String path) {
        List<String> segments = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inBracket = false;

        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (c == '[') {
                if (current.length() > 0) {
                    segments.add(current.toString());
                    current = new StringBuilder();
                }
                inBracket = true;
                current.append(c);
            } else if (c == ']') {
                current.append(c);
                segments.add(current.toString());
                current = new StringBuilder();
                inBracket = false;
            } else if (c == '.' && !inBracket) {
                if (current.length() > 0) {
                    segments.add(current.toString());
                    current = new StringBuilder();
                }
            } else {
                current.append(c);
            }
        }
        if (current.length() > 0) {
            segments.add(current.toString());
        }

        return segments.toArray(new String[0]);
    }

    /**
     * 根据原始JSON值类型，将替换字符串转换为对应类型的JsonElement
     * 如果原始值为数字/布尔值，则尝试将替换值转换为相同类型；
     * 如果无法转换，回退为字符串类型
     */
    public static JsonElement coerceJsonValue(JsonElement original, String value) {
        if (original != null && original.isJsonPrimitive()) {
            JsonPrimitive prim = original.getAsJsonPrimitive();
            if (prim.isBoolean()) {
                // 尝试解析为布尔值
                if ("true".equalsIgnoreCase(value) || "false".equalsIgnoreCase(value)) {
                    return new JsonPrimitive(Boolean.parseBoolean(value));
                }
                // 无法转换为布尔值，保持字符串
                return new JsonPrimitive(value);
            } else if (prim.isNumber()) {
                // 尝试解析为数字
                try {
                    if (value.contains(".") || value.contains("e") || value.contains("E")) {
                        return new JsonPrimitive(Double.parseDouble(value));
                    } else {
                        long longVal = Long.parseLong(value);
                        // 如果在 int 范围内，用 int 避免不必要的小数点
                        if (longVal >= Integer.MIN_VALUE && longVal <= Integer.MAX_VALUE) {
                            return new JsonPrimitive((int) longVal);
                        }
                        return new JsonPrimitive(longVal);
                    }
                } catch (NumberFormatException e) {
                    // 无法转换为数字，保持字符串
                    return new JsonPrimitive(value);
                }
            }
        }
        // 默认：原始值为字符串或无原始值，直接使用字符串
        return new JsonPrimitive(value);
    }

    /**
     * 导航到JSON的指定段
     */
    public static JsonElement navigateJsonSegment(JsonElement current, String segment) {
        if (current == null || current.isJsonNull()) return null;

        if (segment.startsWith("[") && segment.endsWith("]")) {
            if (!current.isJsonArray()) return null;
            JsonArray array = current.getAsJsonArray();
            int idx = Integer.parseInt(segment.substring(1, segment.length() - 1));
            if (idx < 0 || idx >= array.size()) return null;
            return array.get(idx);
        } else {
            if (!current.isJsonObject()) return null;
            JsonObject obj = current.getAsJsonObject();
            if (!obj.has(segment)) return null;
            return obj.get(segment);
        }
    }
}
