package org.oxff.repeater.privilege;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * FetchRequestParser 单元测试
 * 覆盖 Chrome DevTools 两种 fetch 格式的解析与转换
 */
class FetchRequestParserTest {

    // ==================== 格式检测测试 ====================

    @Test
    void testDetectRawHttp() {
        String rawHttp = "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assertEquals(FetchRequestParser.ClipboardFormat.RAW_HTTP,
                FetchRequestParser.detectFormat(rawHttp));
    }

    @Test
    void testDetectRawHttpPost() {
        String rawHttp = "POST /api/login HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assertEquals(FetchRequestParser.ClipboardFormat.RAW_HTTP,
                FetchRequestParser.detectFormat(rawHttp));
    }

    @Test
    void testDetectFetchBrowser() {
        String fetch = "fetch(\"https://example.com/api\", {\"method\":\"GET\"});";
        assertEquals(FetchRequestParser.ClipboardFormat.FETCH_BROWSER,
                FetchRequestParser.detectFormat(fetch));
    }

    @Test
    void testDetectFetchNodeJs() {
        String fetch = "fetch(\"https://example.com/api\", {\"headers\":{\"cookie\":\"session=abc\"}});";
        assertEquals(FetchRequestParser.ClipboardFormat.FETCH_NODEJS,
                FetchRequestParser.detectFormat(fetch));
    }

    @Test
    void testDetectUnknown() {
        assertEquals(FetchRequestParser.ClipboardFormat.UNKNOWN,
                FetchRequestParser.detectFormat("some random text"));
        assertEquals(FetchRequestParser.ClipboardFormat.UNKNOWN,
                FetchRequestParser.detectFormat(null));
        assertEquals(FetchRequestParser.ClipboardFormat.UNKNOWN,
                FetchRequestParser.detectFormat(""));
    }

    // ==================== fetch 浏览器格式转换测试 ====================

    @Test
    void testConvertFetchBrowserGet() {
        String fetch = "fetch(\"https://api.example.com/v1/users\", {\n" +
                "  \"headers\": {\n" +
                "    \"accept\": \"application/json\",\n" +
                "    \"authorization\": \"Bearer token123\"\n" +
                "  },\n" +
                "  \"method\": \"GET\",\n" +
                "  \"mode\": \"cors\"\n" +
                "});";

        byte[] raw = FetchRequestParser.convertToRawHttp(fetch);
        String http = new String(raw, StandardCharsets.UTF_8);

        assertTrue(http.startsWith("GET /v1/users HTTP/1.1"));
        assertTrue(http.contains("Host: api.example.com"));
        assertTrue(http.contains("accept: application/json"));
        assertTrue(http.contains("authorization: Bearer token123"));
    }

    @Test
    void testConvertFetchBrowserPostWithBody() {
        String fetch = "fetch(\"https://api.example.com/login\", {\n" +
                "  \"headers\": {\n" +
                "    \"content-type\": \"application/json\"\n" +
                "  },\n" +
                "  \"body\": \"{\\\"username\\\":\\\"admin\\\",\\\"password\\\":\\\"123456\\\"}\",\n" +
                "  \"method\": \"POST\"\n" +
                "});";

        byte[] raw = FetchRequestParser.convertToRawHttp(fetch);
        String http = new String(raw, StandardCharsets.UTF_8);

        assertTrue(http.startsWith("POST /login HTTP/1.1"));
        assertTrue(http.contains("Host: api.example.com"));
        assertTrue(http.contains("content-type: application/json"));
        assertTrue(http.contains("Content-Length: 40"));
        assertTrue(http.contains("{\"username\":\"admin\",\"password\":\"123456\"}"));
    }

    @Test
    void testConvertFetchBrowserWithQueryParams() {
        String fetch = "fetch(\"https://api.example.com/search?q=test&page=1\", {\n" +
                "  \"method\": \"GET\"\n" +
                "});";

        byte[] raw = FetchRequestParser.convertToRawHttp(fetch);
        String http = new String(raw, StandardCharsets.UTF_8);

        assertTrue(http.startsWith("GET /search?q=test&page=1 HTTP/1.1"));
        assertTrue(http.contains("Host: api.example.com"));
    }

    @Test
    void testConvertFetchBrowserWithPort() {
        String fetch = "fetch(\"https://api.example.com:8443/secure\", {\n" +
                "  \"method\": \"GET\"\n" +
                "});";

        byte[] raw = FetchRequestParser.convertToRawHttp(fetch);
        String http = new String(raw, StandardCharsets.UTF_8);

        assertTrue(http.startsWith("GET /secure HTTP/1.1"));
        assertTrue(http.contains("Host: api.example.com:8443"));
    }

    @Test
    void testConvertFetchBrowserNoOptions() {
        String fetch = "fetch(\"https://example.com/api\");";

        byte[] raw = FetchRequestParser.convertToRawHttp(fetch);
        String http = new String(raw, StandardCharsets.UTF_8);

        assertTrue(http.startsWith("GET /api HTTP/1.1"));
        assertTrue(http.contains("Host: example.com"));
    }

    @Test
    void testConvertFetchBrowserWithReferrer() {
        String fetch = "fetch(\"https://example.com/api\", {\n" +
                "  \"headers\": {\n" +
                "    \"accept\": \"*/*\"\n" +
                "  },\n" +
                "  \"referrer\": \"https://example.com/\",\n" +
                "  \"referrerPolicy\": \"strict-origin-when-cross-origin\",\n" +
                "  \"method\": \"GET\",\n" +
                "  \"mode\": \"cors\"\n" +
                "});";

        byte[] raw = FetchRequestParser.convertToRawHttp(fetch);
        String http = new String(raw, StandardCharsets.UTF_8);

        // referrer 和 referrerPolicy 不应出现在 HTTP 报文中（它们不是 HTTP headers）
        assertTrue(http.contains("accept: */*"));
        assertFalse(http.contains("referrer:"));
        assertFalse(http.contains("referrerPolicy:"));
        assertFalse(http.contains("mode:"));
    }

    // ==================== fetch Node.js 格式转换测试 ====================

    @Test
    void testConvertFetchNodeJsWithCookie() {
        String fetch = "fetch(\"https://admin.example.com/api/users\", {\n" +
                "  \"headers\": {\n" +
                "    \"accept\": \"application/json\",\n" +
                "    \"authorization\": \"Bearer admin_token_456\",\n" +
                "    \"cookie\": \"session_id=abc123; user=admin\"\n" +
                "  },\n" +
                "  \"body\": null,\n" +
                "  \"method\": \"GET\",\n" +
                "  \"credentials\": \"include\"\n" +
                "});";

        byte[] raw = FetchRequestParser.convertToRawHttp(fetch);
        String http = new String(raw, StandardCharsets.UTF_8);

        assertTrue(http.startsWith("GET /api/users HTTP/1.1"));
        assertTrue(http.contains("Host: admin.example.com"));
        assertTrue(http.contains("authorization: Bearer admin_token_456"));
        assertTrue(http.contains("cookie: session_id=abc123; user=admin"));
        assertTrue(http.contains("accept: application/json"));
        // body 为 null，不应有 Content-Length
        assertFalse(http.contains("Content-Length"));
    }

    @Test
    void testConvertFetchNodeJsPostWithCookieAndBody() {
        String fetch = "fetch(\"https://api.example.com/api/v1/login\", {\n" +
                "  \"headers\": {\n" +
                "    \"accept\": \"application/json, text/plain, */*\",\n" +
                "    \"content-type\": \"application/json\",\n" +
                "    \"cookie\": \"SESSION=xyz789\"\n" +
                "  },\n" +
                "  \"body\": \"{\\\"account\\\":\\\"admin\\\",\\\"password\\\":\\\"admin123\\\"}\",\n" +
                "  \"method\": \"POST\"\n" +
                "});";

        byte[] raw = FetchRequestParser.convertToRawHttp(fetch);
        String http = new String(raw, StandardCharsets.UTF_8);

        assertTrue(http.startsWith("POST /api/v1/login HTTP/1.1"));
        assertTrue(http.contains("Host: api.example.com"));
        assertTrue(http.contains("cookie: SESSION=xyz789"));
        assertTrue(http.contains("content-type: application/json"));
        assertTrue(http.contains("{\"account\":\"admin\",\"password\":\"admin123\"}"));
    }

    // ==================== 边界条件测试 ====================

    @Test
    void testConvertFetchWithUrlEncodedBody() {
        String fetch = "fetch(\"https://example.com/login\", {\n" +
                "  \"headers\": {\n" +
                "    \"content-type\": \"application/x-www-form-urlencoded\"\n" +
                "  },\n" +
                "  \"body\": \"username=admin&password=secret&remember=on\",\n" +
                "  \"method\": \"POST\"\n" +
                "});";

        byte[] raw = FetchRequestParser.convertToRawHttp(fetch);
        String http = new String(raw, StandardCharsets.UTF_8);

        assertTrue(http.contains("Content-Length: 42"));
        assertTrue(http.contains("username=admin&password=secret&remember=on"));
    }

    @Test
    void testConvertFetchWithEmptyBody() {
        String fetch = "fetch(\"https://example.com/api\", {\n" +
                "  \"headers\": {\n" +
                "    \"content-type\": \"application/json\"\n" +
                "  },\n" +
                "  \"body\": \"\",\n" +
                "  \"method\": \"POST\"\n" +
                "});";

        byte[] raw = FetchRequestParser.convertToRawHttp(fetch);
        String http = new String(raw, StandardCharsets.UTF_8);

        // 空 body 不应添加 Content-Length: 0（简化处理，也可以添加）
        // 这里我们验证至少不会报错
        assertTrue(http.startsWith("POST /api HTTP/1.1"));
    }

    @Test
    void testConvertFetchWithEscapedQuotesInBody() {
        String fetch = "fetch(\"https://example.com/api\", {\n" +
                "  \"body\": \"{\\\"name\\\":\\\"John \\\"Doe\\\"}\",\n" +
                "  \"method\": \"POST\"\n" +
                "});";

        byte[] raw = FetchRequestParser.convertToRawHttp(fetch);
        String http = new String(raw, StandardCharsets.UTF_8);

        // 转义引号应被正确解析为实际引号
        assertTrue(http.contains("{\"name\":\"John \"Doe\"}"));
    }

    @Test
    void testConvertFetchWithSingleQuotes() {
        String fetch = "fetch('https://example.com/api', {\n" +
                "  'headers': {\n" +
                "    'accept': 'application/json'\n" +
                "  },\n" +
                "  'method': 'GET'\n" +
                "});";

        byte[] raw = FetchRequestParser.convertToRawHttp(fetch);
        String http = new String(raw, StandardCharsets.UTF_8);

        assertTrue(http.startsWith("GET /api HTTP/1.1"));
        assertTrue(http.contains("accept: application/json"));
    }

    @Test
    void testConvertFetchWithSpecialCharactersInHeader() {
        String fetch = "fetch(\"https://example.com/api\", {\n" +
                "  \"headers\": {\n" +
                "    \"x-custom\": \"value with spaces and \\n newlines\"\n" +
                "  },\n" +
                "  \"method\": \"GET\"\n" +
                "});";

        byte[] raw = FetchRequestParser.convertToRawHttp(fetch);
        String http = new String(raw, StandardCharsets.UTF_8);

        assertTrue(http.contains("x-custom: value with spaces and \n newlines"));
    }

    @Test
    void testConvertFetchWithDefaultMethod() {
        // 没有 method 字段，默认应为 GET
        String fetch = "fetch(\"https://example.com/api\", {\n" +
                "  \"headers\": {\n" +
                "    \"accept\": \"application/json\"\n" +
                "  }\n" +
                "});";

        byte[] raw = FetchRequestParser.convertToRawHttp(fetch);
        String http = new String(raw, StandardCharsets.UTF_8);

        assertTrue(http.startsWith("GET /api HTTP/1.1"));
    }

    @Test
    void testConvertFetchWithRootPath() {
        String fetch = "fetch(\"https://example.com/\", {\"method\":\"GET\"});";

        byte[] raw = FetchRequestParser.convertToRawHttp(fetch);
        String http = new String(raw, StandardCharsets.UTF_8);

        assertTrue(http.startsWith("GET / HTTP/1.1"));
    }

    @Test
    void testConvertFetchWithNoPath() {
        String fetch = "fetch(\"https://example.com\", {\"method\":\"GET\"});";

        byte[] raw = FetchRequestParser.convertToRawHttp(fetch);
        String http = new String(raw, StandardCharsets.UTF_8);

        assertTrue(http.startsWith("GET / HTTP/1.1"));
    }

    // ==================== 异常测试 ====================

    @Test
    void testConvertNullFetch() {
        assertThrows(IllegalArgumentException.class, () ->
                FetchRequestParser.convertToRawHttp(null));
    }

    @Test
    void testConvertEmptyFetch() {
        assertThrows(IllegalArgumentException.class, () ->
                FetchRequestParser.convertToRawHttp(""));
    }

    @Test
    void testConvertInvalidFetch() {
        assertThrows(IllegalArgumentException.class, () ->
                FetchRequestParser.convertToRawHttp("not a fetch call"));
    }

    @Test
    void testConvertInvalidUrl() {
        assertThrows(IllegalArgumentException.class, () ->
                FetchRequestParser.convertToRawHttp("fetch(\"not-a-url\")"));
    }

    // ==================== 真实场景模拟测试 ====================

    @Test
    void testRealWorldAdminSessionFetch() {
        // 模拟从 Chrome DevTools 复制的管理员会话 fetch (Node.js)
        String fetch = "fetch(\"https://internal.corp.com/api/admin/users\", {\n" +
                "  \"headers\": {\n" +
                "    \"accept\": \"application/json\",\n" +
                "    \"accept-language\": \"zh-CN,zh;q=0.9\",\n" +
                "    \"authorization\": \"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\",\n" +
                "    \"cache-control\": \"no-cache\",\n" +
                "    \"content-type\": \"application/json\",\n" +
                "    \"cookie\": \"SESSION_ID=admin_session_abc123; ROLE=admin; USER_ID=1001\",\n" +
                "    \"pragma\": \"no-cache\",\n" +
                "    \"sec-ch-ua\": \"\\\"Google Chrome\\\";v=\\\"119\\\"\",\n" +
                "    \"user-agent\": \"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\"\n" +
                "  },\n" +
                "  \"body\": \"{\\\"action\\\":\\\"list\\\",\\\"page\\\":1,\\\"size\\\":20}\",\n" +
                "  \"method\": \"POST\",\n" +
                "  \"credentials\": \"include\"\n" +
                "});";

        byte[] raw = FetchRequestParser.convertToRawHttp(fetch);
        String http = new String(raw, StandardCharsets.UTF_8);

        // 验证请求行
        assertTrue(http.startsWith("POST /api/admin/users HTTP/1.1"));
        // 验证 Host
        assertTrue(http.contains("Host: internal.corp.com"));
        // 验证 Authorization（越权测试最关心的字段）
        assertTrue(http.contains("authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."));
        // 验证 Cookie（Node.js 格式特有）
        assertTrue(http.contains("cookie: SESSION_ID=admin_session_abc123; ROLE=admin; USER_ID=1001"));
        // 验证 body
        assertTrue(http.contains("{\"action\":\"list\",\"page\":1,\"size\":20}"));
        // 验证 Content-Length
        assertTrue(http.contains("Content-Length: 36"));
    }

    @Test
    void testRealWorldBrowserFetch() {
        // 模拟从 Chrome DevTools 复制的普通浏览器 fetch
        String fetch = "fetch(\"https://api.github.com/user/repos\", {\n" +
                "  \"headers\": {\n" +
                "    \"accept\": \"application/vnd.github.v3+json\",\n" +
                "    \"authorization\": \"token ghp_xxxxxxxxxxxx\"\n" +
                "  },\n" +
                "  \"referrer\": \"https://github.com/\",\n" +
                "  \"referrerPolicy\": \"origin\",\n" +
                "  \"body\": null,\n" +
                "  \"method\": \"GET\",\n" +
                "  \"mode\": \"cors\",\n" +
                "  \"credentials\": \"include\"\n" +
                "});";

        byte[] raw = FetchRequestParser.convertToRawHttp(fetch);
        String http = new String(raw, StandardCharsets.UTF_8);

        assertTrue(http.startsWith("GET /user/repos HTTP/1.1"));
        assertTrue(http.contains("Host: api.github.com"));
        assertTrue(http.contains("authorization: token ghp_xxxxxxxxxxxx"));
        // 浏览器 fetch 不应包含 cookie header（由浏览器自动管理）
        assertFalse(http.contains("cookie:"));
        // body 为 null，不应有 Content-Length
        assertFalse(http.contains("Content-Length"));
    }
}
