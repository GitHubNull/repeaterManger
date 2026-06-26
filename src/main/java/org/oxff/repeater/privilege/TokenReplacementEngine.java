package org.oxff.repeater.privilege;

import org.oxff.repeater.logging.LogManager;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import org.oxff.repeater.http.RequestDataHelper;
import org.oxff.repeater.privilege.model.TokenLocation;
import org.oxff.repeater.privilege.model.TokenLocationType;
import org.oxff.repeater.privilege.model.UserSession;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 令牌替换引擎 - 无状态工具类
 * 根据配置的令牌位置和用户会话值，替换HTTP请求中的会话令牌
 *
 * 支持6种位置类型：HEADER / JSON_BODY / XML_BODY / FORM_FIELD / MULTIPART_FIELD / URL_PARAM
 * 替换后自动修正Content-Length
 */
public class TokenReplacementEngine {

    /**
     * 替换请求中的令牌
     *
     * @param originalRequest 原始请求字节数组
     * @param locations       令牌位置列表
     * @param session         用户会话（包含各位置的值）
     * @return 替换后的请求字节数组，如果某项替换失败则跳过该项继续
     */
    public static byte[] replaceTokens(byte[] originalRequest, List<TokenLocation> locations, UserSession session) {
        if (originalRequest == null || originalRequest.length == 0) {
            return originalRequest;
        }
        if (locations == null || locations.isEmpty() || session == null) {
            return originalRequest;
        }

        // 分离header和body
        int bodyOffset = findBodyOffset(originalRequest);
        byte[] headerBytes;
        byte[] bodyBytes;

        if (bodyOffset > 0 && bodyOffset < originalRequest.length) {
            headerBytes = new byte[bodyOffset];
            bodyBytes = new byte[originalRequest.length - bodyOffset];
            System.arraycopy(originalRequest, 0, headerBytes, 0, bodyOffset);
            System.arraycopy(originalRequest, bodyOffset, bodyBytes, 0, bodyBytes.length);
        } else {
            headerBytes = originalRequest;
            bodyBytes = new byte[0];
        }

        String headerStr = new String(headerBytes, StandardCharsets.ISO_8859_1);
        String bodyStr = bodyBytes.length > 0 ? new String(bodyBytes, StandardCharsets.UTF_8) : "";

        // 提取Content-Type
        String contentType = extractContentType(headerStr);

        // 分类处理：URL参数、header类型和body类型的分开
        List<TokenLocation> urlLocations = new ArrayList<>();
        List<TokenLocation> headerLocations = new ArrayList<>();
        List<TokenLocation> bodyLocations = new ArrayList<>();

        for (TokenLocation loc : locations) {
            if (loc.getType() == TokenLocationType.HEADER) {
                headerLocations.add(loc);
            } else if (loc.getType() == TokenLocationType.URL_PARAM) {
                urlLocations.add(loc);
            } else {
                bodyLocations.add(loc);
            }
        }

        // 替换URL参数中的令牌（在header替换之前，因为URL参数在请求行中）
        for (TokenLocation loc : urlLocations) {
            String value = session.getTokenValue(loc.getId());
            // null表示该令牌位置未配置值（如未授权用户），视为空字符串以删除对应token
            if (value == null) {
                value = "";
            }
            value = sanitizeNewlines(value, loc.getExpression());
            try {
                headerStr = replaceUrlParam(headerStr, loc.getExpression(), value);
            } catch (Exception e) {
                LogManager.getInstance().printError("[!] URL参数令牌替换失败 (expression=" + loc.getExpression() + "): " + e.getMessage());
            }
        }

        // 替换Header中的令牌
        for (TokenLocation loc : headerLocations) {
            String value = session.getTokenValue(loc.getId());
            // null表示该令牌位置未配置值（如未授权用户），视为空字符串以删除对应header
            if (value == null) {
                value = "";
            }
            // 安全过滤：将换行符替换为空格，防止HTTP header注入
            value = sanitizeNewlines(value, loc.getExpression());
            try {
                headerStr = replaceHeader(headerStr, loc.getExpression(), value);
            } catch (Exception e) {
                LogManager.getInstance().printError("[!] Header令牌替换失败 (expression=" + loc.getExpression() + "): " + e.getMessage());
            }
        }

        // 替换Body中的令牌
        if (!bodyStr.isEmpty() && !bodyLocations.isEmpty()) {
            for (TokenLocation loc : bodyLocations) {
                String value = session.getTokenValue(loc.getId());
                // null表示该令牌位置未配置值（如未授权用户），视为空字符串以删除对应字段
                if (value == null) {
                    value = "";
                }
                // 安全过滤：将换行符替换为空格，防止JSON/XML/body结构破坏
                value = sanitizeNewlines(value, loc.getExpression());
                try {
                    switch (loc.getType()) {
                        case JSON_BODY:
                            if (contentType != null && contentType.contains("application/json")) {
                                bodyStr = replaceJsonBody(bodyStr, loc.getExpression(), value);
                            }
                            break;
                        case XML_BODY:
                            if (contentType != null && contentType.contains("xml")) {
                                bodyStr = replaceXmlBody(bodyStr, loc.getExpression(), value);
                            }
                            break;
                        case FORM_FIELD:
                            if (contentType != null && contentType.contains("x-www-form-urlencoded")) {
                                bodyStr = replaceFormField(bodyStr, loc.getExpression(), value);
                            }
                            break;
                        case MULTIPART_FIELD:
                            if (contentType != null && contentType.contains("multipart/form-data")) {
                                bodyStr = replaceMultipartField(bodyStr, contentType, loc.getExpression(), value);
                            }
                            break;
                        default:
                            break;
                    }
                } catch (Exception e) {
                    LogManager.getInstance().printError("[!] Body令牌替换失败 (type=" + loc.getType() + ", expression=" + loc.getExpression() + "): " + e.getMessage());
                }
            }
        }

        // 重新组装请求
        byte[] newHeaderBytes = headerStr.getBytes(StandardCharsets.ISO_8859_1);
        byte[] newBodyBytes = bodyStr.getBytes(StandardCharsets.UTF_8);

        byte[] result = new byte[newHeaderBytes.length + newBodyBytes.length];
        System.arraycopy(newHeaderBytes, 0, result, 0, newHeaderBytes.length);
        System.arraycopy(newBodyBytes, 0, result, newHeaderBytes.length, newBodyBytes.length);

        // 修正Content-Length
        result = RequestDataHelper.fixContentLength(result, null);

        return result;
    }

    // ==================== Header 替换 ====================

    /**
     * 替换指定Header的值
     * 如果value为空字符串，则删除该Header行（不留空白行）
     */
    private static String replaceHeader(String headerStr, String headerName, String value) {
        String[] lines = headerStr.split("\r\n", -1);
        List<String> keptLines = new ArrayList<>();
        boolean replaced = false;
        String headerNameLower = headerName.toLowerCase();

        for (String line : lines) {
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String currentName = line.substring(0, colonIdx).trim().toLowerCase();
                if (currentName.equals(headerNameLower)) {
                    replaced = true;
                    if (!value.isEmpty()) {
                        keptLines.add(headerName + ": " + value);
                    }
                    // value为空则删除该header行（不添加到keptLines，不留空白行）
                } else {
                    keptLines.add(line);
                }
            } else {
                // 请求行或其他非header行，直接保留
                keptLines.add(line);
            }
        }

        // 如果目标header不存在且value非空，追加新header（在header/body分隔空行之前）
        if (!replaced && !value.isEmpty()) {
            String newHeaderLine = headerName + ": " + value;
            int emptyLineIdx = -1;
            for (int i = 0; i < keptLines.size(); i++) {
                if (keptLines.get(i).isEmpty()) {
                    emptyLineIdx = i;
                    break;
                }
            }
            if (emptyLineIdx > 0) {
                keptLines.add(emptyLineIdx, newHeaderLine);
            } else {
                keptLines.add(newHeaderLine);
            }
        }

        return String.join("\r\n", keptLines);
    }

    // ==================== JSON Body 替换 ====================

    /**
     * 替换JSON body中指定路径的值
     * 路径格式如 $.data.token 或 $.users[0].sessionId
     * 如果value为空字符串，则移除该属性（未授权测试场景：模拟请求中不存在此参数）
     */
    private static String replaceJsonBody(String bodyStr, String jsonPath, String value) {
        try {
            // 去掉开头的 $. 
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
            if (value.isEmpty()) {
                // 空值表示移除该JSON属性，模拟请求中不存在此参数
                removeJsonValueAtPath(root, path);
            } else {
                setJsonValueAtPath(root, path, value);
            }
            return root.toString();
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] JSON body替换失败: " + e.getMessage());
            return bodyStr;
        }
    }

    /**
     * 在JSON结构中按路径设置值
     * 保留原始值类型：如果原始值是数字或布尔值，替换值会自动转换类型
     */
    private static void setJsonValueAtPath(JsonElement root, String path, String value) {
        String[] segments = splitJsonPath(path);
        if (segments.length == 0) return;

        JsonElement current = root;
        for (int i = 0; i < segments.length - 1; i++) {
            String segment = segments[i];
            current = navigateJsonSegment(current, segment);
            if (current == null) {
                return; // 路径不存在，跳过
            }
        }

        // 设置最后一个段的值
        String lastSegment = segments[segments.length - 1];
        if (lastSegment.startsWith("[") && lastSegment.endsWith("]")) {
            // 数组索引
            if (current.isJsonArray()) {
                JsonArray array = current.getAsJsonArray();
                int idx = Integer.parseInt(lastSegment.substring(1, lastSegment.length() - 1));
                if (idx >= 0 && idx < array.size()) {
                    JsonElement original = array.get(idx);
                    array.set(idx, coerceJsonValue(original, value));
                }
            }
        } else {
            if (current.isJsonObject()) {
                JsonObject obj = current.getAsJsonObject();
                JsonElement original = obj.has(lastSegment) ? obj.get(lastSegment) : null;
                obj.add(lastSegment, coerceJsonValue(original, value));
            }
        }
    }

    /**
     * 在JSON结构中按路径移除属性
     * 用于未授权测试场景：空令牌值时移除对应参数，模拟请求中不存在此字段
     */
    private static void removeJsonValueAtPath(JsonElement root, String path) {
        String[] segments = splitJsonPath(path);
        if (segments.length == 0) return;

        JsonElement current = root;
        for (int i = 0; i < segments.length - 1; i++) {
            String segment = segments[i];
            current = navigateJsonSegment(current, segment);
            if (current == null) return;
        }

        String lastSegment = segments[segments.length - 1];
        if (lastSegment.startsWith("[") && lastSegment.endsWith("]")) {
            // 数组索引：移除该元素
            if (current.isJsonArray()) {
                JsonArray array = current.getAsJsonArray();
                int idx = Integer.parseInt(lastSegment.substring(1, lastSegment.length() - 1));
                if (idx >= 0 && idx < array.size()) {
                    array.remove(idx);
                }
            }
        } else {
            // 对象属性：移除该属性
            if (current.isJsonObject()) {
                current.getAsJsonObject().remove(lastSegment);
            }
        }
    }

    /**
     * 根据原始JSON值类型，将替换字符串转换为对应类型的JsonElement
     * 如果原始值为数字/布尔值，则尝试将替换值转换为相同类型；
     * 如果无法转换，回退为字符串类型
     */
    private static JsonElement coerceJsonValue(JsonElement original, String value) {
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
    private static JsonElement navigateJsonSegment(JsonElement current, String segment) {
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

    // ==================== XML Body 替换 ====================

    /**
     * 替换XML body中指定XPath节点的文本内容
     * 如果value为空字符串，则移除该节点的文本内容（未授权测试场景）
     */
    private static String replaceXmlBody(String bodyStr, String xpathExpression, String value) {
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
                if (value.isEmpty()) {
                    // 空值：移除节点的所有文本内容子节点，模拟请求中不存在此参数
                    while (node.hasChildNodes()) {
                        Node child = node.getFirstChild();
                        if (child.getNodeType() == Node.TEXT_NODE) {
                            node.removeChild(child);
                        } else {
                            break;
                        }
                    }
                } else {
                    node.setTextContent(value);
                }
            }

            // 序列化回字符串
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(writer));
            return writer.toString();
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] XML body替换失败: " + e.getMessage());
            return bodyStr;
        }
    }

    // ==================== Form Field 替换 ====================

    /**
     * 替换表单编码body中指定字段的值
     * 如果value为空字符串，则删除该字段
     */
    private static String replaceFormField(String bodyStr, String fieldName, String value) {
        return replaceUrlEncodedPairs(bodyStr, fieldName, value);
    }

    // ==================== Multipart Field 替换 ====================

    /**
     * 替换multipart/form-data body中指定字段的值
     * 如果value为空字符串，则删除该字段对应的part
     * 如果fieldName不存在，则追加新的part
     *
     * @param bodyStr      multipart body内容
     * @param contentType  Content-Type头值（包含boundary参数）
     * @param fieldName    要替换的表单字段名
     * @param value        新值
     * @return 替换后的body内容
     */
    private static String replaceMultipartField(String bodyStr, String contentType, String fieldName, String value) {
        // 从Content-Type中提取boundary
        String boundary = extractBoundary(contentType);
        if (boundary == null) {
            LogManager.getInstance().printError("[!] multipart/form-data boundary提取失败，无法替换");
            return bodyStr;
        }

        String boundaryDelimiter = "--" + boundary;
        String boundaryEnd = boundaryDelimiter + "--";

        // 按boundary分隔各part
        String[] parts = bodyStr.split(boundaryDelimiter);
        List<String> resultParts = new ArrayList<>();
        boolean replaced = false;

        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];

            // 跳过前导空白和结尾标记
            if (part.trim().isEmpty() || part.trim().startsWith("--")) {
                continue;
            }

            // 解析part：子header和子body以\r\n\r\n分隔
            int subBodyOffset = part.indexOf("\r\n\r\n");
            if (subBodyOffset < 0) {
                // 无子body的part，直接保留
                resultParts.add(part);
                continue;
            }

            String subHeaders = part.substring(0, subBodyOffset);
            String subBody = part.substring(subBodyOffset + 4);

            // 从Content-Disposition提取name参数
            String partFieldName = extractMultipartFieldName(subHeaders);

            if (partFieldName != null && partFieldName.equals(fieldName)) {
                // 检查是否为二进制part（有非text/plain的Content-Type子header）
                if (isBinaryPart(subHeaders)) {
                    LogManager.getInstance().printOutput("[*] 跳过二进制multipart part替换 (field=" + fieldName + ")");
                    resultParts.add(part);
                    replaced = true;
                    continue;
                }

                replaced = true;
                if (!value.isEmpty()) {
                    // 替换子body内容
                    String newPart = subHeaders + "\r\n\r\n" + value;
                    // 保留原始part尾部的\r\n（如果有）
                    if (subBody.endsWith("\r\n")) {
                        newPart += "\r\n";
                    }
                    resultParts.add(newPart);
                }
                // value为空则删除该part（不添加到resultParts）
            } else {
                resultParts.add(part);
            }
        }

        // 字段不存在时追加新part
        if (!replaced && !value.isEmpty()) {
            String newPart = "Content-Disposition: form-data; name=\"" + fieldName + "\"\r\n\r\n" + value + "\r\n";
            resultParts.add(newPart);
        }

        // 重新组装multipart body
        StringBuilder result = new StringBuilder();
        for (String part : resultParts) {
            result.append(boundaryDelimiter).append("\r\n").append(part);
        }
        result.append(boundaryEnd);

        return result.toString();
    }

    /**
     * 从Content-Type头中提取boundary参数
     * 支持格式: boundary=xxx 或 boundary="xxx"
     */
    private static String extractBoundary(String contentType) {
        if (contentType == null) return null;

        // 查找boundary=参数
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
     * 判断multipart part是否为二进制内容
     * 如果part的子header中有Content-Type且不是text/plain，则视为二进制
     */
    private static boolean isBinaryPart(String subHeaders) {
        String[] lines = subHeaders.split("\r\n");
        for (String line : lines) {
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String name = line.substring(0, colonIdx).trim().toLowerCase();
                String val = line.substring(colonIdx + 1).trim().toLowerCase();
                if (name.equals("content-type") && !val.startsWith("text/plain")) {
                    return true;
                }
            }
        }
        return false;
    }

    // ==================== URL Parameter 替换 ====================

    /**
     * 替换请求行中URL查询参数的值
     * 请求行格式如：GET /path?param1=val1&param2=val2 HTTP/1.1
     * 如果参数不存在，则追加到查询字符串末尾
     * 如果value为空字符串，则从查询字符串中删除该参数
     *
     * @param headerStr  包含请求行的完整header字符串
     * @param paramName  要替换的查询参数名
     * @param value      新值
     * @return 修改后的header字符串
     */
    private static String replaceUrlParam(String headerStr, String paramName, String value) {
        // 找到请求行（第一行，以\r\n结尾）
        int firstCRLF = headerStr.indexOf("\r\n");
        if (firstCRLF < 0) {
            // 没有完整的请求行，无法替换URL参数
            LogManager.getInstance().printError("[!] 无法解析请求行，URL参数替换失败");
            return headerStr;
        }

        String requestLine = headerStr.substring(0, firstCRLF);
        String restHeaders = headerStr.substring(firstCRLF);

        // 解析请求行：METHOD PATH HTTP_VERSION
        String[] parts = requestLine.split("\\s+");
        if (parts.length < 2) {
            LogManager.getInstance().printError("[!] 请求行格式异常，URL参数替换失败: " + requestLine);
            return headerStr;
        }

        String method = parts[0];
        String originalPath = parts[1];
        String httpVersion = parts.length >= 3 ? parts[2] : "HTTP/1.1";

        // 分离路径和查询字符串
        int queryIdx = originalPath.indexOf('?');
        String pathPart;
        String queryString;

        if (queryIdx >= 0) {
            pathPart = originalPath.substring(0, queryIdx);
            queryString = originalPath.substring(queryIdx + 1);
        } else {
            pathPart = originalPath;
            queryString = "";
        }

        // 处理查询参数
        String newQueryString = replaceUrlEncodedPairs(queryString, paramName, value);

        // 重建路径
        String newPath;
        if (newQueryString.isEmpty()) {
            newPath = pathPart;
        } else {
            newPath = pathPart + "?" + newQueryString;
        }

        // 重建请求行
        String newRequestLine = method + " " + newPath + " " + httpVersion;

        return newRequestLine + restHeaders;
    }

    /**
     * 在URL编码的键值对字符串中替换/添加/删除指定参数
     * 适用于 URL 查询参数和 x-www-form-urlencoded 表单字段
     *
     * @param pairsStr  原始键值对字符串（如 "key1=val1&key2=val2"）
     * @param keyName   要替换的键名
     * @param value     新值（空字符串表示删除该键）
     * @return 修改后的键值对字符串
     */
    private static String replaceUrlEncodedPairs(String pairsStr, String keyName, String value) {
        if (pairsStr == null || pairsStr.isEmpty()) {
            if (!value.isEmpty()) {
                return URLEncoder.encode(keyName, StandardCharsets.UTF_8) + "=" +
                        URLEncoder.encode(value, StandardCharsets.UTF_8);
            }
            return "";
        }

        String[] pairs = pairsStr.split("&");
        List<String> resultPairs = new ArrayList<>();
        boolean replaced = false;

        for (String pair : pairs) {
            int eqIdx = pair.indexOf('=');
            if (eqIdx > 0) {
                String key = URLDecoder.decode(pair.substring(0, eqIdx), StandardCharsets.UTF_8);
                if (key.equals(keyName)) {
                    replaced = true;
                    if (!value.isEmpty()) {
                        resultPairs.add(URLEncoder.encode(keyName, StandardCharsets.UTF_8) + "=" +
                                URLEncoder.encode(value, StandardCharsets.UTF_8));
                    }
                    // value为空则删除该键
                } else {
                    resultPairs.add(pair);
                }
            } else {
                // 无等号或空参数名的项（罕见），直接保留
                resultPairs.add(pair);
            }
        }

        if (!replaced && !value.isEmpty()) {
            resultPairs.add(URLEncoder.encode(keyName, StandardCharsets.UTF_8) + "=" +
                    URLEncoder.encode(value, StandardCharsets.UTF_8));
        }

        return String.join("&", resultPairs);
    }

    // ==================== 工具方法 ====================

    /**
     * 安全过滤令牌值中的换行符
     * 将换行符替换为空格，防止HTTP header注入或body结构破坏
     * 此过滤仅影响运行时替换，不影响数据库存储的原始值
     *
     * @param value      原始令牌值
     * @param expression 令牌位置表达式（用于日志提示）
     * @return 过滤后的安全值
     */
    private static String sanitizeNewlines(String value, String expression) {
        if (value.contains("\n") || value.contains("\r")) {
            LogManager.getInstance().printOutput("[*] 令牌值包含换行符，替换时已转换为空格 (location=" + expression + ")");
            value = value.replace("\r\n", " ").replace("\n", " ").replace("\r", " ");
        }
        return value;
    }

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
}
