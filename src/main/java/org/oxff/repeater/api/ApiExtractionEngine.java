package org.oxff.repeater.api;

import burp.BurpExtender;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * API提取引擎 - 无状态工具类
 * 根据配置的提取规则从请求数据中提取API标识符
 *
 * 规则执行策略：首次匹配优先
 * - 按优先级升序执行已启用规则
 * - 第一个匹配成功的规则结果即为API值
 * - 全部未匹配则使用URL路径作为默认值
 */
public class ApiExtractionEngine {

    private static final int MAX_BODY_SIZE_FOR_EXTRACTION = 1024 * 1024; // 1MB

    /**
     * 提取API标识符
     *
     * @param path        URL路径（如 /api/users）
     * @param query       URL查询字符串（如 action=getUser&id=1，可为null）
     * @param headers     请求头列表（每行一个header，如 ["Host: example.com", "Content-Type: application/json"]）
     * @param body        请求体字节数据（可为null）
     * @param contentType Content-Type头值（可为null）
     * @param rules       提取规则列表
     * @return 提取到的API字符串，全部未匹配时返回path
     */
    public static String extractApi(String path, String query, List<String> headers, byte[] body,
                                    String contentType, List<ApiExtractionRule> rules) {
        // 默认值为路径
        String defaultApi = (path != null) ? path : "/";
        if (rules == null || rules.isEmpty()) {
            return defaultApi;
        }

        // 按优先级升序排列已启用规则
        List<ApiExtractionRule> activeRules = new java.util.ArrayList<>();
        for (ApiExtractionRule rule : rules) {
            if (rule.isEnabled() && rule.isValid()) {
                activeRules.add(rule);
            }
        }
        if (activeRules.isEmpty()) {
            return defaultApi;
        }

        Collections.sort(activeRules, new Comparator<ApiExtractionRule>() {
            @Override
            public int compare(ApiExtractionRule r1, ApiExtractionRule r2) {
                return Integer.compare(r1.getPriority(), r2.getPriority());
            }
        });

        // 首次匹配优先
        for (ApiExtractionRule rule : activeRules) {
            try {
                String result = applyRule(path, query, headers, body, contentType, rule);
                if (result != null && !result.trim().isEmpty()) {
                    return result;
                }
            } catch (Exception e) {
                BurpExtender.printError("[!] API提取规则执行异常 (id=" + rule.getId()
                        + ", source=" + rule.getSource() + ", method=" + rule.getMethod()
                        + "): " + e.getMessage());
            }
        }

        return defaultApi;
    }

    /**
     * 应用单条规则
     */
    private static String applyRule(String path, String query, List<String> headers, byte[] body,
                                    String contentType, ApiExtractionRule rule) {
        switch (rule.getSource()) {
            case URL_PATH:
                return applyUrlPathRule(path, rule);
            case URL_QUERY:
                return applyUrlQueryRule(query, rule);
            case HEADER:
                return applyHeaderRule(headers, rule);
            case BODY:
                return applyBodyRule(body, contentType, rule);
            default:
                return null;
        }
    }

    // ========== URL_PATH 规则 ==========

    private static String applyUrlPathRule(String path, ApiExtractionRule rule) {
        if (path == null || path.isEmpty()) return null;
        switch (rule.getMethod()) {
            case REGEX:
                return applyRegex(path, rule.getExpression());
            case SUBSTR:
                return parseSubstrExpression(rule.getExpression(), path);
            default:
                return null;
        }
    }

    // ========== URL_QUERY 规则 ==========

    private static String applyUrlQueryRule(String query, ApiExtractionRule rule) {
        if (query == null || query.isEmpty()) return null;
        switch (rule.getMethod()) {
            case REGEX:
                return applyRegex(query, rule.getExpression());
            case SUBSTR:
                return parseSubstrExpression(rule.getExpression(), query);
            default:
                return null;
        }
    }

    // ========== HEADER 规则 ==========

    private static String applyHeaderRule(List<String> headers, ApiExtractionRule rule) {
        if (headers == null || headers.isEmpty()) return null;
        switch (rule.getMethod()) {
            case REGEX:
                return applyHeaderRegex(headers, rule.getExpression());
            case SUBSTR:
                return applyHeaderSubstr(headers, rule.getExpression());
            default:
                return null;
        }
    }

    /**
     * 对请求头应用正则提取
     * 表达式格式1: "Header-Name: pattern" — 先匹配header行，再从值中提取
     * 表达式格式2: "pattern" — 直接对所有header行应用正则
     */
    private static String applyHeaderRegex(List<String> headers, String expression) {
        if (expression == null || expression.isEmpty()) return null;
        try {
            Pattern pattern = Pattern.compile(expression);
            for (String header : headers) {
                if (header == null) continue;
                Matcher matcher = pattern.matcher(header);
                if (matcher.find()) {
                    // 优先返回捕获组1，否则返回整个匹配
                    if (matcher.groupCount() >= 1) {
                        return matcher.group(1);
                    }
                    return matcher.group(0);
                }
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] Header正则提取失败: " + e.getMessage());
        }
        return null;
    }

    /**
     * 对请求头应用子串截取
     * 格式: "Header-Name,START,END" — 先找到对应header，再对值截取
     * 格式: "START,END" — 对第一个header值截取（一般不推荐）
     */
    private static String applyHeaderSubstr(List<String> headers, String expression) {
        if (expression == null || expression.isEmpty()) return null;

        String[] parts = expression.split(",", 3);
        String headerValue = null;
        String substrExpr;

        if (parts.length == 3) {
            // 格式: "Header-Name,START,END"
            String headerName = parts[0].trim().toLowerCase();
            for (String header : headers) {
                if (header == null) continue;
                int colonIdx = header.indexOf(':');
                if (colonIdx > 0) {
                    String name = header.substring(0, colonIdx).trim().toLowerCase();
                    if (name.equals(headerName)) {
                        headerValue = header.substring(colonIdx + 1).trim();
                        break;
                    }
                }
            }
            substrExpr = parts[1].trim() + "," + parts[2].trim();
        } else if (parts.length == 2) {
            // 格式: "START,END" — 使用第一个header的值
            if (!headers.isEmpty()) {
                String firstHeader = headers.get(0);
                if (firstHeader != null) {
                    int colonIdx = firstHeader.indexOf(':');
                    headerValue = (colonIdx > 0) ? firstHeader.substring(colonIdx + 1).trim() : firstHeader;
                }
            }
            substrExpr = expression;
        } else {
            return null;
        }

        if (headerValue == null) return null;
        return parseSubstrExpression(substrExpr, headerValue);
    }

    // ========== BODY 规则 ==========

    private static String applyBodyRule(byte[] body, String contentType, ApiExtractionRule rule) {
        if (body == null || body.length == 0) return null;
        if (body.length > MAX_BODY_SIZE_FOR_EXTRACTION) return null;

        // 检查body是否为文本类型
        if (!isTextBody(contentType, body)) return null;

        String bodyStr = new String(body, StandardCharsets.UTF_8);

        switch (rule.getMethod()) {
            case REGEX:
                return applyRegex(bodyStr, rule.getExpression());
            case SUBSTR:
                return parseSubstrExpression(rule.getExpression(), bodyStr);
            case JSON_PATH:
                return extractJsonPath(bodyStr, rule.getExpression());
            case XPATH:
                return extractXpath(bodyStr, rule.getExpression());
            default:
                return null;
        }
    }

    // ========== 通用提取方法 ==========

    /**
     * 应用正则表达式提取
     * 优先返回捕获组1，否则返回整个匹配
     */
    static String applyRegex(String input, String expression) {
        if (input == null || expression == null || expression.isEmpty()) return null;
        try {
            Pattern pattern = Pattern.compile(expression);
            Matcher matcher = pattern.matcher(input);
            if (matcher.find()) {
                if (matcher.groupCount() >= 1) {
                    return matcher.group(1);
                }
                return matcher.group(0);
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 正则提取失败: " + e.getMessage());
        }
        return null;
    }

    /**
     * 解析substr表达式并截取字符串
     * 格式: START,END
     * - START: 非负整数，起始索引
     * - END: 正整数（绝对位置exclusive）| 负整数（从末尾倒数）| END关键字（到末尾）
     *
     * 示例:
     *   "0,10"  → 前10个字符
     *   "5,END" → 从索引5到末尾
     *   "4,-3"  → 从索引4到倒数第3个字符
     */
    static String parseSubstrExpression(String expression, String input) {
        if (expression == null || input == null || expression.isEmpty()) return null;

        String[] parts = expression.split(",", 2);
        if (parts.length != 2) return null;

        try {
            int start = Integer.parseInt(parts[0].trim());
            String endPart = parts[1].trim();

            int end;
            if ("END".equalsIgnoreCase(endPart)) {
                end = input.length();
            } else {
                end = Integer.parseInt(endPart);
                if (end < 0) {
                    // 负数表示从末尾倒数
                    end = input.length() + end;
                }
            }

            // 边界检查
            if (start < 0) start = 0;
            if (start >= input.length()) return null;
            if (end > input.length()) end = input.length();
            if (end <= start) return null;

            return input.substring(start, end);
        } catch (NumberFormatException e) {
            BurpExtender.printError("[!] substr表达式格式错误: " + expression);
            return null;
        }
    }

    /**
     * 使用简易JSONPath从JSON数据中提取值
     * 支持:
     *   $.field.subfield       — 点号导航
     *   $.array[0].field       — 数组索引
     *   $.array[*].field       — 通配符（返回第一个匹配）
     */
    static String extractJsonPath(String json, String jsonPath) {
        if (json == null || jsonPath == null || jsonPath.isEmpty()) return null;
        if (!jsonPath.startsWith("$")) {
            jsonPath = "$." + jsonPath;
        }
        // 去掉 $. 前缀
        String path = jsonPath.substring(jsonPath.startsWith("$.") ? 2 : 1);
        if (path.isEmpty()) return null;

        try {
            JsonElement root = JsonParser.parseString(json);
            JsonElement current = root;

            // 按段解析路径
            String[] segments = splitJsonPath(path);
            for (String segment : segments) {
                if (current == null || current.isJsonNull()) return null;

                if (segment.startsWith("[") && segment.endsWith("]")) {
                    // 数组访问
                    String indexStr = segment.substring(1, segment.length() - 1);
                    if (!current.isJsonArray()) return null;
                    JsonArray array = current.getAsJsonArray();
                    if ("*".equals(indexStr)) {
                        // 通配符：取第一个元素继续
                        if (array.size() == 0) return null;
                        current = array.get(0);
                    } else {
                        int idx = Integer.parseInt(indexStr);
                        if (idx < 0 || idx >= array.size()) return null;
                        current = array.get(idx);
                    }
                } else {
                    // 对象字段访问
                    if (!current.isJsonObject()) return null;
                    JsonObject obj = current.getAsJsonObject();
                    if (!obj.has(segment)) return null;
                    current = obj.get(segment);
                }
            }

            if (current == null || current.isJsonNull()) return null;
            if (current.isJsonPrimitive()) {
                return current.getAsString();
            }
            return current.toString();
        } catch (Exception e) {
            BurpExtender.printError("[!] JSON路径提取失败 (path=" + jsonPath + "): " + e.getMessage());
            return null;
        }
    }

    /**
     * 分割JSONPath路径段
     * 处理 "field.subfield[0].name" → ["field", "subfield", "[0]", "name"]
     */
    private static String[] splitJsonPath(String path) {
        java.util.List<String> segments = new java.util.ArrayList<>();
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
     * 使用XPath从XML数据中提取值
     */
    static String extractXpath(String xml, String xpathExpr) {
        if (xml == null || xpathExpr == null || xpathExpr.isEmpty()) return null;
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // 禁用外部实体以防止XXE
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xml)));

            XPath xpath = XPathFactory.newInstance().newXPath();
            String result = (String) xpath.evaluate(xpathExpr, doc, XPathConstants.STRING);
            return (result != null && !result.trim().isEmpty()) ? result.trim() : null;
        } catch (Exception e) {
            BurpExtender.printError("[!] XPath提取失败 (expr=" + xpathExpr + "): " + e.getMessage());
            return null;
        }
    }

    /**
     * 判断body是否为文本类型数据
     *
     * 允许: application/json, application/xml, text/*, application/x-www-form-urlencoded
     * 拒绝: multipart/form-data, application/octet-stream, image/*, video/*, audio/*
     * 无Content-Type时: 启发式检查前512字节是否有null字节
     */
    public static boolean isTextBody(String contentType, byte[] body) {
        if (body == null || body.length == 0) return false;

        if (contentType != null) {
            String ct = contentType.toLowerCase().trim();
            // 移除参数部分（如 charset=utf-8）
            int semiIdx = ct.indexOf(';');
            if (semiIdx > 0) {
                ct = ct.substring(0, semiIdx).trim();
            }

            // 拒绝的类型
            if (ct.startsWith("multipart/") || ct.equals("application/octet-stream")
                    || ct.startsWith("image/") || ct.startsWith("video/")
                    || ct.startsWith("audio/")) {
                return false;
            }

            // 允许的类型
            if (ct.equals("application/json") || ct.equals("application/xml")
                    || ct.startsWith("text/") || ct.equals("application/x-www-form-urlencoded")
                    || ct.endsWith("+xml") || ct.endsWith("+json")) {
                return true;
            }

            // 其他application/*类型，做启发式检查
            if (ct.startsWith("application/")) {
                return isLikelyText(body);
            }

            return false;
        }

        // 无Content-Type，做启发式检查
        return isLikelyText(body);
    }

    /**
     * 启发式检查：扫描前512字节是否存在null字节
     * 如果存在null字节，则认为是二进制数据
     */
    private static boolean isLikelyText(byte[] body) {
        int checkLen = Math.min(body.length, 512);
        for (int i = 0; i < checkLen; i++) {
            if (body[i] == 0) {
                return false;
            }
        }
        return true;
    }
}
