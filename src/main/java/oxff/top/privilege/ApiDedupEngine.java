package oxff.top.privilege;

import burp.BurpExtender;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import oxff.top.http.HttpRequestHelper;
import oxff.top.privilege.model.DedupKeepPolicy;
import oxff.top.privilege.model.DedupStrategy;
import org.w3c.dom.Document;
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
 * API去重引擎
 * 根据可配置的去重策略，从HTTP请求中提取去重键，并对请求列表执行去重过滤
 *
 * 支持6种去重策略：PATH / API / JSON_BODY_FIELD / XML_BODY_FIELD / FORM_FIELD / URL_PARAM
 * 支持3种保留策略：FIRST / LAST / MIDDLE
 */
public class ApiDedupEngine {

    private ApiDedupEngine() {
        // 工具类禁止实例化
    }

    /**
     * 计算单条请求的去重键
     *
     * @param requestBytes 原始请求字节数组
     * @param httpService  HTTP服务信息（可为null）
     * @param strategy     去重策略
     * @param expression   去重表达式（当策略为body/param类型时指定字段名/路径）
     * @return 去重键字符串，如果提取失败返回null
     */
    public static String computeDedupKey(byte[] requestBytes, HttpService httpService,
                                          DedupStrategy strategy, String expression) {
        if (requestBytes == null || requestBytes.length == 0) {
            return null;
        }

        try {
            HttpRequest reqInfo;
            if (httpService != null) {
                reqInfo = HttpRequest.httpRequest(httpService, ByteArray.byteArray(requestBytes));
            } else {
                reqInfo = HttpRequest.httpRequest(ByteArray.byteArray(requestBytes));
            }

            switch (strategy) {
                case PATH:
                    return extractPath(reqInfo);
                case API:
                    return extractApi(reqInfo, requestBytes);
                case JSON_BODY_FIELD:
                    return extractBodyFieldValue(reqInfo, requestBytes, "application/json", expression);
                case XML_BODY_FIELD:
                    return extractXmlFieldValue(reqInfo, requestBytes, expression);
                case FORM_FIELD:
                    return extractBodyFieldValue(reqInfo, requestBytes, "x-www-form-urlencoded", expression);
                case URL_PARAM:
                    return extractUrlParamValue(reqInfo, expression);
                default:
                    return extractPath(reqInfo);
            }
        } catch (Exception e) {
            BurpExtender.printOutput("[*] ApiDedupEngine: 计算去重键失败: " + e.getMessage());
            return null;
        }
    }

    /**
     * 对请求列表执行前置去重（在保存到DB之前调用）
     * 根据 keepPolicy 决定保留同一去重键的哪条记录
     *
     * @param items      待去重的请求列表（每项包含原始HttpRequestResponse和请求字节数组）
     * @param strategy   去重策略
     * @param expression 去重表达式
     * @param keepPolicy 保留策略
     * @param <T>        列表元素类型（需要调用者提供键提取函数）
     * @return 去重后的列表
     */
    public static <T> List<T> deduplicate(List<T> items,
                                           java.util.function.Function<T, String> keyExtractor,
                                           DedupKeepPolicy keepPolicy) {
        if (items == null || items.isEmpty()) {
            return items;
        }

        // 按去重键分组，保持插入顺序
        Map<String, List<T>> groups = new LinkedHashMap<>();
        for (T item : items) {
            String key = keyExtractor.apply(item);
            if (key == null) {
                key = "__NULL_KEY__";
            }
            groups.computeIfAbsent(key, k -> new ArrayList<>()).add(item);
        }

        List<T> result = new ArrayList<>();
        for (Map.Entry<String, List<T>> entry : groups.entrySet()) {
            List<T> group = entry.getValue();
            if (group.size() == 1) {
                result.add(group.get(0));
            } else {
                switch (keepPolicy) {
                    case FIRST:
                        result.add(group.get(0));
                        break;
                    case LAST:
                        result.add(group.get(group.size() - 1));
                        break;
                    case MIDDLE:
                        int mid = group.size() / 2;
                        result.add(group.get(mid));
                        break;
                    default:
                        result.add(group.get(0));
                        break;
                }
            }
        }

        return result;
    }

    /**
     * 线程安全地去重检查：检查去重键是否已在集合中，若不在则添加
     * 使用 ConcurrentHashMap.newKeySet() 保证原子性
     *
     * @param processedKeys 已处理键集合
     * @param key           当前请求的去重键
     * @return true 如果键已存在（应跳过），false 如果键不存在且已添加
     */
    public static boolean checkAndAddKey(Set<String> processedKeys, String key) {
        if (key == null) {
            return false;
        }
        // ConcurrentHashMap.newKeySet() 的 add 方法是原子的
        // add() 返回 true 表示添加成功（键不存在），false 表示键已存在
        return !processedKeys.add(key);
    }

    // ==================== 去重键提取方法 ====================

    /**
     * 提取URL路径作为去重键
     */
    private static String extractPath(HttpRequest reqInfo) {
        try {
            java.net.URL parsedUrl = new java.net.URL(reqInfo.url());
            String path = parsedUrl.getPath();
            return path != null && !path.isEmpty() ? path : "/";
        } catch (Exception e) {
            // 从请求行解析
            String headerStr = new String(reqInfo.toByteArray().getBytes(), StandardCharsets.ISO_8859_1);
            int firstSpace = headerStr.indexOf(' ');
            if (firstSpace > 0) {
                int secondSpace = headerStr.indexOf(' ', firstSpace + 1);
                if (secondSpace > firstSpace) {
                    String pathPart = headerStr.substring(firstSpace + 1, secondSpace);
                    int queryIdx = pathPart.indexOf('?');
                    return queryIdx > 0 ? pathPart.substring(0, queryIdx) : pathPart;
                }
            }
            return "/";
        }
    }

    /**
     * 提取API值作为去重键（使用API提取规则引擎）
     */
    private static String extractApi(HttpRequest reqInfo, byte[] requestBytes) {
        try {
            java.net.URL parsedUrl = new java.net.URL(reqInfo.url());
            String path = parsedUrl.getPath() != null ? parsedUrl.getPath() : "/";
            String query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";
            return HttpRequestHelper.computeApiFromRequest(path, query, requestBytes);
        } catch (Exception e) {
            return HttpRequestHelper.computeApiFromRequest("/", "", requestBytes);
        }
    }

    /**
     * 提取Body中指定字段值作为去重键（支持JSON和form-urlencoded）
     */
    private static String extractBodyFieldValue(HttpRequest reqInfo, byte[] requestBytes,
                                                 String contentTypeHint, String expression) {
        // 检查Content-Type
        String contentType = extractContentType(reqInfo);
        if (contentType == null) {
            return null;
        }

        // 提取body
        String bodyStr = extractBodyString(reqInfo, requestBytes);
        if (bodyStr == null || bodyStr.isEmpty()) {
            return null;
        }

        if (contentTypeHint.equals("application/json") && contentType.contains("application/json")) {
            return extractJsonFieldValue(bodyStr, expression);
        } else if (contentTypeHint.equals("x-www-form-urlencoded") && contentType.contains("x-www-form-urlencoded")) {
            return extractFormFieldValue(bodyStr, expression);
        }

        return null;
    }

    /**
     * 提取XML Body中指定XPath节点的值作为去重键
     */
    private static String extractXmlFieldValue(HttpRequest reqInfo, byte[] requestBytes, String xpathExpression) {
        String contentType = extractContentType(reqInfo);
        if (contentType == null || !contentType.contains("xml")) {
            return null;
        }

        String bodyStr = extractBodyString(reqInfo, requestBytes);
        if (bodyStr == null || bodyStr.isEmpty()) {
            return null;
        }

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(bodyStr)));

            XPathFactory xPathFactory = XPathFactory.newInstance();
            XPath xpath = xPathFactory.newXPath();
            org.w3c.dom.Node node = (org.w3c.dom.Node) xpath.evaluate(xpathExpression, doc, XPathConstants.NODE);

            if (node != null) {
                String textContent = node.getTextContent();
                return textContent != null ? textContent : "";
            }
            return null;
        } catch (Exception e) {
            BurpExtender.printOutput("[*] ApiDedupEngine: XML字段提取失败: " + e.getMessage());
            return null;
        }
    }

    /**
     * 提取URL查询参数中指定参数的值作为去重键
     */
    private static String extractUrlParamValue(HttpRequest reqInfo, String paramName) {
        try {
            java.net.URL parsedUrl = new java.net.URL(reqInfo.url());
            String query = parsedUrl.getQuery();
            if (query == null || query.isEmpty()) {
                return null;
            }
            return extractFormFieldValue(query, paramName);
        } catch (Exception e) {
            return null;
        }
    }

    // ==================== 辅助方法 ====================

    /**
     * 从HttpRequest中提取Content-Type头
     */
    private static String extractContentType(HttpRequest reqInfo) {
        List<String> headers = convertHeadersToStringList(reqInfo.headers());
        for (String header : headers) {
            int colonIdx = header.indexOf(':');
            if (colonIdx > 0) {
                String name = header.substring(0, colonIdx).trim();
                if (name.equalsIgnoreCase("Content-Type")) {
                    return header.substring(colonIdx + 1).trim();
                }
            }
        }
        return null;
    }

    /**
     * 提取请求Body字符串
     */
    private static String extractBodyString(HttpRequest reqInfo, byte[] requestBytes) {
        try {
            int bodyOffset = reqInfo.bodyOffset();
            if (bodyOffset > 0 && bodyOffset < requestBytes.length) {
                byte[] bodyBytes = Arrays.copyOfRange(requestBytes, bodyOffset, requestBytes.length);
                return new String(bodyBytes, StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            // fallback
        }
        return null;
    }

    /**
     * 从JSON body中提取指定字段的值
     */
    private static String extractJsonFieldValue(String bodyStr, String jsonPath) {
        try {
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
            JsonElement value = navigateJsonPath(root, path);
            return value != null && !value.isJsonNull() ? value.getAsString() : null;
        } catch (Exception e) {
            BurpExtender.printOutput("[*] ApiDedupEngine: JSON字段提取失败: " + e.getMessage());
            return null;
        }
    }

    /**
     * 导航JSON路径获取值
     */
    private static JsonElement navigateJsonPath(JsonElement current, String path) {
        if (current == null || current.isJsonNull()) return null;

        String[] segments = splitJsonPath(path);
        JsonElement elem = current;
        for (String segment : segments) {
            if (elem == null || elem.isJsonNull()) return null;
            if (segment.startsWith("[") && segment.endsWith("]")) {
                if (!elem.isJsonArray()) return null;
                int idx = Integer.parseInt(segment.substring(1, segment.length() - 1));
                elem = elem.getAsJsonArray().get(idx);
            } else {
                if (!elem.isJsonObject()) return null;
                elem = elem.getAsJsonObject().get(segment);
            }
        }
        return elem;
    }

    /**
     * 分割JSONPath路径段
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
     * 从URL编码的键值对字符串中提取指定字段的值
     * 适用于URL查询参数和x-www-form-urlencoded表单
     */
    private static String extractFormFieldValue(String pairsStr, String fieldName) {
        if (pairsStr == null || pairsStr.isEmpty() || fieldName == null || fieldName.isEmpty()) {
            return null;
        }

        String[] pairs = pairsStr.split("&");
        for (String pair : pairs) {
            int eqIdx = pair.indexOf('=');
            if (eqIdx > 0) {
                try {
                    String key = URLDecoder.decode(pair.substring(0, eqIdx), StandardCharsets.UTF_8);
                    if (key.equals(fieldName)) {
                        return URLDecoder.decode(pair.substring(eqIdx + 1), StandardCharsets.UTF_8);
                    }
                } catch (Exception e) {
                    // 跳过解析失败的键值对
                }
            }
        }
        return null;
    }

    /**
     * 将Montoya API的HttpHeader列表转换为字符串列表
     */
    private static List<String> convertHeadersToStringList(List<burp.api.montoya.http.message.HttpHeader> rawHeaders) {
        List<String> result = new ArrayList<>();
        for (burp.api.montoya.http.message.HttpHeader header : rawHeaders) {
            String name = header.name();
            String value = header.value();
            if (name != null && value != null) {
                result.add(name + ": " + value);
            } else if (name != null) {
                result.add(name);
            }
        }
        return result;
    }
}
