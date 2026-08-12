package org.oxff.repeater.ui;

import javax.swing.table.DefaultTableModel;
import javax.swing.RowFilter;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;

/**
 * 请求表自定义搜索过滤器 - 支持 URL/Header/Body/响应Header/响应Body 范围搜索
 * Header 和 Body 数据不在表格列中，需从 requestDataMap/responseDataMap 获取原始字节进行解析匹配
 */
public class RequestSearchFilter extends RowFilter<DefaultTableModel, Integer> {

    private final Map<Integer, byte[]> requestDataMap;
    private final Map<Integer, byte[]> responseDataMap;
    private final SearchConfig config;

    /**
     * 创建请求搜索过滤器
     *
     * @param requestDataMap  请求原始数据映射 (ID → byte[])
     * @param responseDataMap 响应原始数据映射 (ID → byte[])
     * @param config          搜索配置
     */
    public RequestSearchFilter(Map<Integer, byte[]> requestDataMap, Map<Integer, byte[]> responseDataMap, SearchConfig config) {
        this.requestDataMap = requestDataMap;
        this.responseDataMap = responseDataMap;
        this.config = config;
    }

    @Override
    public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
        Set<SearchConfig.SearchScope> scopes = config.scope();

        // 如果没有指定范围，默认搜索 URL
        if (scopes.isEmpty()) {
            scopes = Set.of(SearchConfig.SearchScope.URL);
        }

        // 获取请求 ID
        int requestId = (Integer) entry.getValue(0);
        byte[] data = requestDataMap.get(requestId);
        byte[] responseData = responseDataMap != null ? responseDataMap.get(requestId) : null;

        for (SearchConfig.SearchScope scope : scopes) {
            switch (scope) {
                case URL:
                    String urlText = buildUrlText(entry);
                    if (!config.matches(urlText)) {
                        return false;
                    }
                    break;

                case HEADER:
                    String headers = extractHeaders(data);
                    if (!config.matches(headers)) {
                        return false;
                    }
                    break;

                case BODY:
                    String body = extractBody(data);
                    if (!config.matches(body)) {
                        return false;
                    }
                    break;

                case RESPONSE_HEADER:
                    String respHeaders = extractResponseHeaders(responseData);
                    if (!config.matches(respHeaders)) {
                        return false;
                    }
                    break;

                case RESPONSE_BODY:
                    String respBody = extractResponseBody(responseData);
                    if (!config.matches(respBody)) {
                        return false;
                    }
                    break;
            }
        }

        return true; // 所有 scope 都匹配成功
    }

    /**
     * 从表格行构建 URL 文本 (domain + path + query)
     */
    private String buildUrlText(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
        // 列索引: 4=Domain, 5=Path, 6=Query
        Object domain = entry.getValue(4);
        Object path = entry.getValue(5);
        Object query = entry.getValue(6);

        StringBuilder sb = new StringBuilder();
        if (domain != null) sb.append(domain.toString());
        if (path != null) sb.append(path.toString());
        if (query != null && !query.toString().isEmpty()) {
            sb.append("?").append(query.toString());
        }
        return sb.toString();
    }

    /**
     * 从原始请求字节提取请求头部分
     * 取第一个 \r\n\r\n 前面的部分，去掉第一行请求行（如 GET /path HTTP/1.1）
     */
    static String extractHeaders(byte[] rawData) {
        if (rawData == null || rawData.length == 0) {
            return "";
        }

        String rawText = decodeBytes(rawData);
        int headerEnd = rawText.indexOf("\r\n\r\n");

        if (headerEnd < 0) {
            // 没有 \r\n\r\n 分隔符，整个数据视为 headers（去掉请求行）
            int firstLineEnd = rawText.indexOf("\r\n");
            if (firstLineEnd < 0) {
                return ""; // 只有请求行，没有其他 header
            }
            return rawText.substring(firstLineEnd + 2);
        }

        String headersSection = rawText.substring(0, headerEnd);
        int firstLineEnd = headersSection.indexOf("\r\n");
        if (firstLineEnd < 0) {
            return headersSection; // 没有请求行，只有 headers
        }
        return headersSection.substring(firstLineEnd + 2);
    }

    /**
     * 从原始请求字节提取请求体部分
     * 取第一个 \r\n\r\n 后面的部分
     */
    static String extractBody(byte[] rawData) {
        if (rawData == null || rawData.length == 0) {
            return "";
        }

        String rawText = decodeBytes(rawData);
        int headerEnd = rawText.indexOf("\r\n\r\n");

        if (headerEnd < 0) {
            return ""; // 没有 body 分隔符，body 为空
        }

        return rawText.substring(headerEnd + 4);
    }

    /**
     * 从原始响应字节提取响应头部分
     * 取第一个 \r\n\r\n 前面的部分，去掉第一行状态行（如 HTTP/1.1 200 OK）
     */
    static String extractResponseHeaders(byte[] rawData) {
        if (rawData == null || rawData.length == 0) {
            return "";
        }

        String rawText = decodeBytes(rawData);
        int headerEnd = rawText.indexOf("\r\n\r\n");

        if (headerEnd < 0) {
            // 没有 \r\n\r\n 分隔符，整个数据视为 headers（去掉状态行）
            int firstLineEnd = rawText.indexOf("\r\n");
            if (firstLineEnd < 0) {
                return ""; // 只有状态行，没有其他 header
            }
            return rawText.substring(firstLineEnd + 2);
        }

        String headersSection = rawText.substring(0, headerEnd);
        int firstLineEnd = headersSection.indexOf("\r\n");
        if (firstLineEnd < 0) {
            return headersSection; // 没有状态行，只有 headers
        }
        return headersSection.substring(firstLineEnd + 2);
    }

    /**
     * 从原始响应字节提取响应体部分
     * 取第一个 \r\n\r\n 后面的部分
     */
    static String extractResponseBody(byte[] rawData) {
        if (rawData == null || rawData.length == 0) {
            return "";
        }

        String rawText = decodeBytes(rawData);
        int headerEnd = rawText.indexOf("\r\n\r\n");

        if (headerEnd < 0) {
            return ""; // 没有 body 分隔符，body 为空
        }

        return rawText.substring(headerEnd + 4);
    }

    /**
     * 解码字节为文本
     * 优先使用 UTF-8，解码失败时 fallback 到 ISO-8859-1（不会丢字节）
     */
    private static String decodeBytes(byte[] data) {
        try {
            return new String(data, StandardCharsets.UTF_8);
        } catch (Exception e) {
            // UTF-8 解码失败（含非法字节），fallback 到 ISO-8859-1
            return new String(data, StandardCharsets.ISO_8859_1);
        }
    }
}