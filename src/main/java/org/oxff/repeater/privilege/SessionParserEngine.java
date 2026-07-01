package org.oxff.repeater.privilege;

import org.oxff.repeater.logging.LogManager;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.oxff.repeater.privilege.model.FieldDefinition;
import org.oxff.repeater.privilege.model.Scheme;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.StringReader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * HTTP报文会话字段解析引擎 - 无状态工具类
 * FieldReplacementEngine的反向操作：从HTTP报文中提取会话字段值
 *
 * 支持6种位置类型：HEADER / JSON_BODY / XML_BODY / FORM_FIELD / MULTIPART_FIELD / URL_PARAM
 */
public class SessionParserEngine {

    /**
     * 解析HTTP报文，提取指定位置的字段值
     *
     * @param httpMessage 原始HTTP请求字节数组
     * @param locations  字段位置列表
     * @return 解析结果封装
     */
    public static SessionParseResult parse(byte[] httpMessage, List<FieldDefinition> locations) {
        if (httpMessage == null || httpMessage.length == 0) {
            return new SessionParseResult("", "", null, new HashMap<>(), new HashMap<>());
        }
        if (locations == null || locations.isEmpty()) {
            return new SessionParseResult("", "", null, new HashMap<>(), new HashMap<>());
        }

        // 分离header和body
        int bodyOffset = findBodyOffset(httpMessage);
        byte[] headerBytes;
        byte[] bodyBytes;

        if (bodyOffset > 0 && bodyOffset < httpMessage.length) {
            headerBytes = new byte[bodyOffset];
            bodyBytes = new byte[httpMessage.length - bodyOffset];
            System.arraycopy(httpMessage, 0, headerBytes, 0, bodyOffset);
            System.arraycopy(httpMessage, bodyOffset, bodyBytes, 0, bodyBytes.length);
        } else {
            headerBytes = httpMessage;
            bodyBytes = new byte[0];
        }

        String headerStr = new String(headerBytes, StandardCharsets.ISO_8859_1);
        String bodyStr = bodyBytes.length > 0 ? new String(bodyBytes, StandardCharsets.UTF_8) : "";

        // 提取Content-Type
        String contentType = extractContentType(headerStr);

        // 构建locationId到FieldDefinition的映射
        Map<Integer, FieldDefinition> locationMap = new HashMap<>();
        for (FieldDefinition loc : locations) {
            locationMap.put(loc.getId(), loc);
        }

        // 提取各位置的值
        Map<Integer, String> extractedValues = new HashMap<>();

        for (FieldDefinition loc : locations) {
            if (!loc.isEnabled()) {
                continue;
            }
            String value = null;
            try {
                switch (loc.getType()) {
                    case HEADER:
                        value = extractHeader(headerStr, loc.getExpression());
                        break;
                    case URL_PARAM:
                        value = extractUrlParam(headerStr, loc.getExpression());
                        break;
                    case JSON_BODY:
                        if (contentType != null && contentType.contains("application/json") && !bodyStr.isEmpty()) {
                            value = extractJsonBody(bodyStr, loc.getExpression());
                        }
                        break;
                    case XML_BODY:
                        if (contentType != null && contentType.contains("xml") && !bodyStr.isEmpty()) {
                            value = extractXmlBody(bodyStr, loc.getExpression());
                        }
                        break;
                    case FORM_FIELD:
                        if (contentType != null && contentType.contains("x-www-form-urlencoded") && !bodyStr.isEmpty()) {
                            value = extractFormField(bodyStr, loc.getExpression());
                        }
                        break;
                    case MULTIPART_FIELD:
                        if (contentType != null && contentType.contains("multipart/form-data") && !bodyStr.isEmpty()) {
                            value = extractMultipartField(bodyStr, contentType, loc.getExpression());
                        }
                        break;
                    default:
                        break;
                }
            } catch (Exception e) {
                LogManager.getInstance().printError("[!] 字段提取失败 (type=" + loc.getType() + ", expression=" + loc.getExpression() + "): " + e.getMessage());
            }
            if (value != null) {
                extractedValues.put(loc.getId(), value);
            }
        }

        return new SessionParseResult(headerStr, bodyStr, contentType, extractedValues, locationMap);
    }

    /**
     * 将解析结果与启用的Scheme进行匹配，返回第一个匹配的方案
     *
     * @param result   解析结果
     * @param schemes  Scheme列表
     * @return 包含第一个匹配SchemeMatch的列表（单元素），无匹配返回空列表
     */
    public static List<SchemeMatch> matchSchemes(SessionParseResult result, List<Scheme> schemes) {
        List<SchemeMatch> matches = new ArrayList<>();
        if (result == null || schemes == null || schemes.isEmpty()) {
            return matches;
        }

        for (Scheme scheme : schemes) {
            if (!scheme.isEnabled()) {
                continue;
            }
            List<Integer> fieldIds = scheme.getFieldIds();
            if (fieldIds == null || fieldIds.isEmpty()) {
                continue;
            }

            int matchedCount = 0;
            for (Integer locId : fieldIds) {
                if (result.getExtractedValue(locId) != null) {
                    matchedCount++;
                }
            }

            // 返回第一个匹配率大于0的方案
            if (matchedCount > 0) {
                matches.add(new SchemeMatch(scheme, matchedCount, fieldIds.size()));
                break;
            }
        }

        return matches;
    }

    // ==================== Header 提取 ====================

    /**
     * 从header字符串中提取指定header的值
     *
     * @param headerStr  header字符串
     * @param headerName header名称
     * @return header值（trim后的冒号后内容），未找到返回null
     */
    private static String extractHeader(String headerStr, String headerName) {
        if (headerStr == null || headerName == null) {
            return null;
        }
        String headerNameLower = headerName.toLowerCase();
        String[] lines = headerStr.split("\r\n");
        for (String line : lines) {
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String currentName = line.substring(0, colonIdx).trim().toLowerCase();
                if (currentName.equals(headerNameLower)) {
                    return line.substring(colonIdx + 1).trim();
                }
            }
        }
        return null;
    }

    // ==================== JSON Body 提取 ====================

    /**
     * 从JSON body中提取指定JSONPath路径的值
     *
     * @param bodyStr  JSON body字符串
     * @param jsonPath JSONPath表达式，如 $.data.token
     * @return 提取的值（字符串形式），未找到返回null
     */
    private static String extractJsonBody(String bodyStr, String jsonPath) {
        if (bodyStr == null || jsonPath == null) {
            return null;
        }
        try {
            // 去掉开头的 $. 或 $
            String path = jsonPath;
            if (path.startsWith("$.")) {
                path = path.substring(2);
            } else if (path.startsWith("$")) {
                path = path.substring(1);
                if (path.startsWith(".")) {
                    path = path.substring(1);
                }
            }

            JsonElement root = JsonParser.parseString(bodyStr);
            if (path.isEmpty()) {
                // 根路径，返回整个JSON字符串
                return root.toString();
            }

            String[] segments = splitJsonPath(path);
            JsonElement current = root;

            for (String segment : segments) {
                current = navigateJsonSegment(current, segment);
                if (current == null || current.isJsonNull()) {
                    return null;
                }
            }

            // 到达目标节点，提取值
            if (current.isJsonPrimitive()) {
                return current.getAsString();
            } else if (current.isJsonObject() || current.isJsonArray()) {
                // 对象或数组，返回JSON字符串表示
                return current.toString();
            }
            return null;
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] JSON body提取失败: " + e.getMessage());
            return null;
        }
    }

    // ==================== XML Body 提取 ====================

    /**
     * 从XML body中提取指定XPath节点的textContent
     *
     * @param bodyStr        XML body字符串
     * @param xpathExpression XPath表达式
     * @return 节点textContent，未找到返回null
     */
    private static String extractXmlBody(String bodyStr, String xpathExpression) {
        if (bodyStr == null || xpathExpression == null) {
            return null;
        }
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // 禁用外部实体，防止XXE
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(bodyStr)));

            XPathFactory xPathFactory = XPathFactory.newInstance();
            XPath xpath = xPathFactory.newXPath();
            Node node = (Node) xpath.evaluate(xpathExpression, doc, XPathConstants.NODE);

            if (node != null) {
                return node.getTextContent();
            }
            return null;
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] XML body提取失败: " + e.getMessage());
            return null;
        }
    }

    // ==================== Form Field 提取 ====================

    /**
     * 从表单编码body中提取指定字段的值
     *
     * @param bodyStr   表单编码body字符串
     * @param fieldName 字段名
     * @return URL解码后的字段值，未找到返回null
     */
    private static String extractFormField(String bodyStr, String fieldName) {
        return extractUrlEncodedPairs(bodyStr, fieldName);
    }

    // ==================== Multipart Field 提取 ====================

    /**
     * 从multipart/form-data body中提取指定字段的值
     *
     * @param bodyStr     multipart body内容
     * @param contentType Content-Type头值（包含boundary参数）
     * @param fieldName   要提取的表单字段名
     * @return 字段值，未找到返回null
     */
    private static String extractMultipartField(String bodyStr, String contentType, String fieldName) {
        String boundary = extractBoundary(contentType);
        if (boundary == null) {
            return null;
        }

        String boundaryDelimiter = "--" + boundary;

        // 按boundary分隔各part
        String[] parts = bodyStr.split(boundaryDelimiter);
        for (String part : parts) {
            String trimmedPart = part.trim();
            if (trimmedPart.isEmpty() || trimmedPart.startsWith("--")) {
                continue;
            }

            // 解析part：子header和子body以\r\n\r\n分隔
            int subBodyOffset = part.indexOf("\r\n\r\n");
            if (subBodyOffset < 0) {
                continue;
            }

            String subHeaders = part.substring(0, subBodyOffset);
            String subBody = part.substring(subBodyOffset + 4);

            // 从Content-Disposition提取name参数
            String partFieldName = extractMultipartFieldName(subHeaders);

            if (partFieldName != null && partFieldName.equals(fieldName)) {
                // 去除尾部可能的\r\n
                if (subBody.endsWith("\r\n")) {
                    subBody = subBody.substring(0, subBody.length() - 2);
                }
                return subBody;
            }
        }
        return null;
    }

    // ==================== URL Parameter 提取 ====================

    /**
     * 从请求行中提取指定URL查询参数的值
     *
     * @param headerStr 包含请求行的完整header字符串
     * @param paramName 查询参数名
     * @return URL解码后的参数值，未找到返回null
     */
    private static String extractUrlParam(String headerStr, String paramName) {
        // 找到请求行（第一行，以\r\n结尾）
        int firstCRLF = headerStr.indexOf("\r\n");
        if (firstCRLF < 0) {
            return null;
        }

        String requestLine = headerStr.substring(0, firstCRLF);

        // 解析请求行：METHOD PATH HTTP_VERSION
        String[] parts = requestLine.split("\\s+");
        if (parts.length < 2) {
            return null;
        }

        String originalPath = parts[1];

        // 分离路径和查询字符串
        int queryIdx = originalPath.indexOf('?');
        if (queryIdx < 0) {
            return null;
        }

        String queryString = originalPath.substring(queryIdx + 1);
        return extractUrlEncodedPairs(queryString, paramName);
    }

    // ==================== 通用键值对提取 ====================

    /**
     * 从URL编码的键值对字符串中提取指定键的值
     * 适用于 URL 查询参数和 x-www-form-urlencoded 表单字段
     *
     * @param pairsStr 键值对字符串（如 "key1=val1&key2=val2"）
     * @param keyName  要提取的键名
     * @return URL解码后的值，未找到返回null
     */
    private static String extractUrlEncodedPairs(String pairsStr, String keyName) {
        if (pairsStr == null || pairsStr.isEmpty() || keyName == null) {
            return null;
        }

        String[] pairs = pairsStr.split("&");
        for (String pair : pairs) {
            int eqIdx = pair.indexOf('=');
            if (eqIdx > 0) {
                String key = URLDecoder.decode(pair.substring(0, eqIdx), StandardCharsets.UTF_8);
                if (key.equals(keyName)) {
                    String value = pair.substring(eqIdx + 1);
                    return URLDecoder.decode(value, StandardCharsets.UTF_8);
                }
            }
        }
        return null;
    }

    // ==================== 工具方法 ====================

    /**
     * 查找请求中body的起始偏移量（\r\n\r\n之后）
     */
    private static int findBodyOffset(byte[] request) {
        for (int i = 0; i < request.length - 3; i++) {
            if (request[i] == '\r' && request[i + 1] == '\n' &&
                    request[i + 2] == '\r' && request[i + 3] == '\n') {
                return i + 4;
            }
        }
        // 尝试 \n\n 分隔
        for (int i = 0; i < request.length - 1; i++) {
            if (request[i] == '\n' && request[i + 1] == '\n') {
                return i + 2;
            }
        }
        return -1; // 没有body
    }

    /**
     * 从header中提取Content-Type值
     */
    private static String extractContentType(String headerStr) {
        String[] lines = headerStr.split("\r\n");
        for (String line : lines) {
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String name = line.substring(0, colonIdx).trim();
                if (name.equalsIgnoreCase("Content-Type")) {
                    return line.substring(colonIdx + 1).trim();
                }
            }
        }
        return null;
    }

    /**
     * 从Content-Type头中提取boundary参数
     * 支持格式: boundary=xxx 或 boundary="xxx"
     */
    private static String extractBoundary(String contentType) {
        if (contentType == null) return null;

        int boundaryIdx = contentType.toLowerCase().indexOf("boundary=");
        if (boundaryIdx < 0) return null;

        String boundaryValue = contentType.substring(boundaryIdx + 9).trim();

        // 去除尾部可能的其他参数（如 ; charset=xxx）
        int semiIdx = boundaryValue.indexOf(';');
        if (semiIdx > 0) {
            boundaryValue = boundaryValue.substring(0, semiIdx).trim();
        }

        // 去除引号包裹
        if (boundaryValue.startsWith("\"") && boundaryValue.endsWith("\"") && boundaryValue.length() > 1) {
            boundaryValue = boundaryValue.substring(1, boundaryValue.length() - 1);
        }

        return boundaryValue.isEmpty() ? null : boundaryValue;
    }

    /**
     * 从multipart part的子header中提取name参数
     * 格式: Content-Disposition: form-data; name="fieldName"
     */
    private static String extractMultipartFieldName(String subHeaders) {
        String[] lines = subHeaders.split("\r\n");
        for (String line : lines) {
            if (line.toLowerCase().startsWith("content-disposition:")) {
                int nameIdx = line.toLowerCase().indexOf("name=");
                if (nameIdx > 0) {
                    String nameValue = line.substring(nameIdx + 5).trim();
                    // 去除尾部可能的其他参数
                    int semiIdx = nameValue.indexOf(';');
                    if (semiIdx > 0) {
                        nameValue = nameValue.substring(0, semiIdx).trim();
                    }
                    // 去除引号包裹
                    if (nameValue.startsWith("\"") && nameValue.endsWith("\"") && nameValue.length() > 1) {
                        nameValue = nameValue.substring(1, nameValue.length() - 1);
                    }
                    return nameValue;
                }
            }
        }
        return null;
    }

    /**
     * 分割JSONPath路径段
     * 处理 "field.subfield[0].name" → ["field", "subfield", "[0]", "name"]
     */
    private static String[] splitJsonPath(String path) {
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
     * 导航到JSON的指定段
     */
    private static JsonElement navigateJsonSegment(JsonElement current, String segment) {
        if (current == null || current.isJsonNull()) return null;

        if (segment.startsWith("[") && segment.endsWith("]")) {
            if (!current.isJsonArray()) return null;
            try {
                int idx = Integer.parseInt(segment.substring(1, segment.length() - 1));
                var array = current.getAsJsonArray();
                if (idx < 0 || idx >= array.size()) return null;
                return array.get(idx);
            } catch (NumberFormatException e) {
                return null;
            }
        } else {
            if (!current.isJsonObject()) return null;
            JsonObject obj = current.getAsJsonObject();
            if (!obj.has(segment)) return null;
            return obj.get(segment);
        }
    }
}
