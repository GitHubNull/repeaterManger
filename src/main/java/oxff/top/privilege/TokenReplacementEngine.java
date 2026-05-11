package oxff.top.privilege;

import burp.BurpExtender;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import oxff.top.http.RequestDataHelper;
import oxff.top.privilege.model.TokenLocation;
import oxff.top.privilege.model.TokenLocationType;
import oxff.top.privilege.model.UserSession;
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
 * 支持4种位置类型：HEADER / JSON_BODY / XML_BODY / FORM_FIELD
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

        // 分类处理：header类型的和body类型的分开
        List<TokenLocation> headerLocations = new ArrayList<>();
        List<TokenLocation> bodyLocations = new ArrayList<>();

        for (TokenLocation loc : locations) {
            if (loc.getType() == TokenLocationType.HEADER) {
                headerLocations.add(loc);
            } else {
                bodyLocations.add(loc);
            }
        }

        // 替换Header中的令牌
        for (TokenLocation loc : headerLocations) {
            String value = session.getTokenValue(loc.getId());
            if (value == null) {
                continue;
            }
            // 安全过滤：将换行符替换为空格，防止HTTP header注入
            value = sanitizeNewlines(value, loc.getExpression());
            try {
                headerStr = replaceHeader(headerStr, loc.getExpression(), value);
            } catch (Exception e) {
                BurpExtender.printError("[!] Header令牌替换失败 (expression=" + loc.getExpression() + "): " + e.getMessage());
            }
        }

        // 替换Body中的令牌
        if (!bodyStr.isEmpty() && !bodyLocations.isEmpty()) {
            for (TokenLocation loc : bodyLocations) {
                String value = session.getTokenValue(loc.getId());
                if (value == null) {
                    continue;
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
                        default:
                            break;
                    }
                } catch (Exception e) {
                    BurpExtender.printError("[!] Body令牌替换失败 (type=" + loc.getType() + ", expression=" + loc.getExpression() + "): " + e.getMessage());
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
     * 如果value为空字符串，则删除该Header行
     */
    private static String replaceHeader(String headerStr, String headerName, String value) {
        String[] lines = headerStr.split("\r\n", -1);
        StringBuilder sb = new StringBuilder();
        boolean replaced = false;
        String headerNameLower = headerName.toLowerCase();

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String currentName = line.substring(0, colonIdx).trim().toLowerCase();
                if (currentName.equals(headerNameLower)) {
                    replaced = true;
                    if (!value.isEmpty()) {
                        sb.append(headerName).append(": ").append(value);
                    }
                    // value为空则删除该header行（不追加）
                } else {
                    sb.append(line);
                }
            } else {
                // 请求行或其他非header行，直接保留
                sb.append(line);
            }

            // 添加行分隔符（最后一行的请求行之后也要加）
            if (i < lines.length - 1) {
                sb.append("\r\n");
            }
        }

        if (!replaced && !value.isEmpty()) {
            // Header不存在，追加新Header（在最后\r\n\r\n之前）
            int lastDoubleCRLF = sb.lastIndexOf("\r\n\r\n");
            if (lastDoubleCRLF > 0) {
                sb.insert(lastDoubleCRLF, "\r\n" + headerName + ": " + value);
            } else {
                sb.append("\r\n").append(headerName).append(": ").append(value);
            }
        }

        return sb.toString();
    }

    // ==================== JSON Body 替换 ====================

    /**
     * 替换JSON body中指定路径的值
     * 路径格式如 $.data.token 或 $.users[0].sessionId
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
            setJsonValueAtPath(root, path, value);
            return root.toString();
        } catch (Exception e) {
            BurpExtender.printError("[!] JSON body替换失败: " + e.getMessage());
            return bodyStr;
        }
    }

    /**
     * 在JSON结构中按路径设置值
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
                    array.set(idx, new JsonPrimitive(value));
                }
            }
        } else {
            if (current.isJsonObject()) {
                current.getAsJsonObject().addProperty(lastSegment, value);
            }
        }
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
                node.setTextContent(value);
            }

            // 序列化回字符串
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(writer));
            return writer.toString();
        } catch (Exception e) {
            BurpExtender.printError("[!] XML body替换失败: " + e.getMessage());
            return bodyStr;
        }
    }

    // ==================== Form Field 替换 ====================

    /**
     * 替换表单编码body中指定字段的值
     * 如果value为空字符串，则删除该字段
     */
    private static String replaceFormField(String bodyStr, String fieldName, String value) {
        String[] pairs = bodyStr.split("&");
        List<String> resultPairs = new ArrayList<>();
        boolean replaced = false;

        for (String pair : pairs) {
            int eqIdx = pair.indexOf('=');
            if (eqIdx > 0) {
                String key = URLDecoder.decode(pair.substring(0, eqIdx), StandardCharsets.UTF_8);
                if (key.equals(fieldName)) {
                    replaced = true;
                    if (!value.isEmpty()) {
                        resultPairs.add(URLEncoder.encode(fieldName, StandardCharsets.UTF_8) + "=" +
                                URLEncoder.encode(value, StandardCharsets.UTF_8));
                    }
                    // value为空则删除该字段
                } else {
                    resultPairs.add(pair);
                }
            } else {
                resultPairs.add(pair);
            }
        }

        if (!replaced && !value.isEmpty()) {
            resultPairs.add(URLEncoder.encode(fieldName, StandardCharsets.UTF_8) + "=" +
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
            BurpExtender.printOutput("[*] 令牌值包含换行符，替换时已转换为空格 (location=" + expression + ")");
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
