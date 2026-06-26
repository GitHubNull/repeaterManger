package org.oxff.repeater.privilege;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Chrome DevTools "Copy as fetch" / "Copy as fetch (Node.js)" format parser.
 * <p>
 * Converts fetch code snippets copied from Chrome DevTools Network panel
 * into raw HTTP request messages, so that existing {@link SessionParserEngine}
 * can be reused for session token parsing.
 * </p>
 *
 * <p>Supports two formats:</p>
 * <ul>
 *   <li><b>fetch (browser)</b>: includes headers, body, method, mode, credentials, referrer, referrerPolicy</li>
 *   <li><b>fetch (Node.js)</b>: similar to browser format, but additionally includes cookie header</li>
 * </ul>
 *
 * @since 2.x
 */
public class FetchRequestParser {

    /**
     * Clipboard content format enum
     */
    public enum ClipboardFormat {
        RAW_HTTP,       // Raw HTTP message (starts with METHOD / HTTP)
        FETCH_BROWSER,  // Chrome "Copy as fetch"
        FETCH_NODEJS,   // Chrome "Copy as fetch (Node.js)"
        UNKNOWN         // Unrecognized
    }

    /**
     * Internal data structure: parsed fetch request
     */
    private static class FetchRequest {
        String url;
        String method = "GET";
        final Map<String, String> headers = new LinkedHashMap<>();
        String body = null;
    }

    /**
     * Detect the format type of input text.
     *
     * @param text clipboard content
     * @return detected {@link ClipboardFormat}
     */
    public static ClipboardFormat detectFormat(String text) {
        if (text == null || text.trim().isEmpty()) {
            return ClipboardFormat.UNKNOWN;
        }

        String trimmed = text.trim();

        // 1. Detect raw HTTP message (starts with HTTP method)
        if (looksLikeRawHttp(trimmed)) {
            return ClipboardFormat.RAW_HTTP;
        }

        // 2. Detect fetch call
        if (trimmed.toLowerCase().startsWith("fetch(")) {
            // Distinguish browser fetch vs Node.js fetch
            // Node.js format usually contains "cookie" header
            if (trimmed.contains("\"cookie\"") || trimmed.contains("'cookie'")) {
                return ClipboardFormat.FETCH_NODEJS;
            }
            return ClipboardFormat.FETCH_BROWSER;
        }

        return ClipboardFormat.UNKNOWN;
    }

    /**
     * Convert fetch format code to raw HTTP request message byte array.
     *
     * @param fetchCode Chrome copied fetch code
     * @return raw HTTP request message (UTF-8 encoded)
     * @throws IllegalArgumentException if parsing fails
     */
    public static byte[] convertToRawHttp(String fetchCode) {
        if (fetchCode == null || fetchCode.trim().isEmpty()) {
            throw new IllegalArgumentException("fetch code cannot be empty");
        }

        FetchRequest req = parseFetchCall(fetchCode.trim());
        if (req == null) {
            throw new IllegalArgumentException("Unable to parse fetch call, please check the format");
        }

        return buildRawHttpRequest(req);
    }

    // ==================== Private parsing methods ====================

    /**
     * Check if text looks like a raw HTTP message
     */
    private static boolean looksLikeRawHttp(String text) {
        String upper = text.toUpperCase();
        return upper.startsWith("GET ") || upper.startsWith("POST ") ||
               upper.startsWith("PUT ") || upper.startsWith("DELETE ") ||
               upper.startsWith("PATCH ") || upper.startsWith("HEAD ") ||
               upper.startsWith("OPTIONS ") || upper.startsWith("TRACE ") ||
               upper.startsWith("CONNECT ") ||
               text.contains("HTTP/1.1") || text.contains("HTTP/1.0") ||
               text.contains("HTTP/2");
    }

    /**
     * Parse fetch call using character-level scanning.
     * Supports both single and double quotes for URL and options.
     */
    private static FetchRequest parseFetchCall(String code) {
        // Remove trailing semicolon if present
        if (code.endsWith(";")) {
            code = code.substring(0, code.length() - 1).trim();
        }

        // Must start with "fetch("
        if (!code.toLowerCase().startsWith("fetch(")) {
            return null;
        }

        // Position after "fetch("
        int pos = 6; // length of "fetch("
        // Skip whitespace
        while (pos < code.length() && Character.isWhitespace(code.charAt(pos))) {
            pos++;
        }

        // Parse URL (quoted string)
        FetchRequest req = new FetchRequest();
        req.url = parseQuotedString(code, pos);
        if (req.url == null) {
            return null;
        }

        // Advance pos past the URL string
        pos = skipQuotedString(code, pos);
        if (pos < 0) {
            return null;
        }

        // Skip whitespace
        while (pos < code.length() && Character.isWhitespace(code.charAt(pos))) {
            pos++;
        }

        // Check for comma
        if (pos < code.length() && code.charAt(pos) == ',') {
            pos++;
            // Skip whitespace
            while (pos < code.length() && Character.isWhitespace(code.charAt(pos))) {
                pos++;
            }
        }

        // Check for options object
        if (pos < code.length() && code.charAt(pos) == '{') {
            String optionsBlock = extractBalancedBraces(code, pos);
            if (optionsBlock != null) {
                parseOptionsBlock(optionsBlock, req);
            }
        }

        return req;
    }

    /**
     * Parse a quoted string starting at position pos.
     * Returns the unescaped string content, or null if not a valid quoted string.
     */
    private static String parseQuotedString(String text, int pos) {
        if (pos >= text.length()) {
            return null;
        }
        char quote = text.charAt(pos);
        if (quote != '"' && quote != '\'') {
            return null;
        }

        StringBuilder sb = new StringBuilder();
        boolean escaped = false;
        for (int i = pos + 1; i < text.length(); i++) {
            char c = text.charAt(i);
            if (escaped) {
                sb.append(c);
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == quote) {
                return sb.toString();
            } else {
                sb.append(c);
            }
        }
        return null; // Unterminated string
    }

    /**
     * Skip past a quoted string starting at position pos.
     * Returns the position after the closing quote, or -1 if invalid.
     */
    private static int skipQuotedString(String text, int pos) {
        if (pos >= text.length()) {
            return -1;
        }
        char quote = text.charAt(pos);
        if (quote != '"' && quote != '\'') {
            return -1;
        }

        boolean escaped = false;
        for (int i = pos + 1; i < text.length(); i++) {
            char c = text.charAt(i);
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == quote) {
                return i + 1;
            }
        }
        return -1; // Unterminated string
    }

    /**
     * Extract a balanced braces block starting at position pos.
     * Returns the content including the outer braces, or null if invalid.
     */
    private static String extractBalancedBraces(String text, int pos) {
        if (pos >= text.length() || text.charAt(pos) != '{') {
            return null;
        }

        int braceDepth = 0;
        int start = pos;
        boolean inQuote = false;
        char quoteChar = 0;
        boolean escaped = false;

        for (int i = pos; i < text.length(); i++) {
            char c = text.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (!inQuote && (c == '"' || c == '\'')) {
                inQuote = true;
                quoteChar = c;
                continue;
            }
            if (inQuote && c == quoteChar) {
                inQuote = false;
                continue;
            }
            if (!inQuote) {
                if (c == '{') {
                    braceDepth++;
                } else if (c == '}') {
                    braceDepth--;
                    if (braceDepth == 0) {
                        return text.substring(start, i + 1);
                    }
                }
            }
        }
        return null; // Unbalanced braces
    }

    /**
     * Parse options block fields
     */
    private static void parseOptionsBlock(String block, FetchRequest req) {
        // Remove outer braces
        String content = block.substring(1, block.length() - 1).trim();
        if (content.isEmpty()) {
            return;
        }

        // Extract method
        String method = extractFieldValue(content, "method");
        if (method != null && !method.isEmpty()) {
            req.method = method.toUpperCase();
        }

        // Extract body
        String body = extractFieldValue(content, "body");
        if (body != null) {
            req.body = unescapeJsString(body);
        } else if (fieldExists(content, "body")) {
            // body is null or undefined
            req.body = null;
        }

        // Extract headers object
        Map<String, String> headers = extractHeadersObject(content);
        if (headers != null) {
            req.headers.putAll(headers);
        }
    }

    /**
     * Check if a field exists in the content (supports both quote types)
     */
    private static boolean fieldExists(String content, String fieldName) {
        return indexOfFieldKey(content, "\"" + fieldName + "\"") >= 0
                || indexOfFieldKey(content, "'" + fieldName + "'") >= 0;
    }

    /**
     * Extract a string field value from JS object content.
     * Returns the raw string value (still escaped), or null if not found/not a string.
     */
    private static String extractFieldValue(String content, String fieldName) {
        // Try double-quoted key
        String result = extractFieldValueWithKey(content, "\"" + fieldName + "\"");
        if (result != null) {
            return result;
        }
        // Try single-quoted key
        return extractFieldValueWithKey(content, "'" + fieldName + "'");
    }

    /**
     * Extract field value using a specific key string
     */
    private static String extractFieldValueWithKey(String content, String key) {
        int idx = indexOfFieldKey(content, key);
        if (idx < 0) {
            return null;
        }

        String afterKey = content.substring(idx + key.length()).trim();
        if (!afterKey.startsWith(":")) {
            return null;
        }
        afterKey = afterKey.substring(1).trim();

        // Check for null/undefined
        if (afterKey.startsWith("null") || afterKey.startsWith("undefined")) {
            return null;
        }

        // Extract string value
        if (afterKey.startsWith("\"") || afterKey.startsWith("'")) {
            char quote = afterKey.charAt(0);
            return parseQuotedString(afterKey, 0);
        }

        // Non-string value: extract until next comma at top level
        return extractValueUntilComma(afterKey);
    }

    /**
     * Find the position of a field key in JS object content.
     * Ensures it's a complete key name, not part of another word.
     */
    private static int indexOfFieldKey(String text, String key) {
        int idx = text.indexOf(key);
        while (idx >= 0) {
            boolean beforeOk = idx == 0 || !isJsIdentifierChar(text.charAt(idx - 1));
            boolean afterOk = idx + key.length() >= text.length() ||
                    !isJsIdentifierChar(text.charAt(idx + key.length()));
            if (beforeOk && afterOk) {
                return idx;
            }
            idx = text.indexOf(key, idx + 1);
        }
        return -1;
    }

    private static boolean isJsIdentifierChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c == '$';
    }

    /**
     * Extract value until next comma at top level (not inside braces/brackets/quotes)
     */
    private static String extractValueUntilComma(String text) {
        int braceDepth = 0;
        int bracketDepth = 0;
        boolean inQuote = false;
        char quoteChar = 0;
        boolean escaped = false;

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (!inQuote && (c == '"' || c == '\'')) {
                inQuote = true;
                quoteChar = c;
                continue;
            }
            if (inQuote && c == quoteChar) {
                inQuote = false;
                continue;
            }
            if (!inQuote) {
                if (c == '{') braceDepth++;
                else if (c == '}') braceDepth--;
                else if (c == '[') bracketDepth++;
                else if (c == ']') bracketDepth--;
                else if (c == ',' && braceDepth == 0 && bracketDepth == 0) {
                    return text.substring(0, i).trim();
                }
            }
        }
        return text.trim();
    }

    /**
     * Extract headers object from JS object content
     */
    private static Map<String, String> extractHeadersObject(String content) {
        // Find "headers" or 'headers' key
        int headersIdx = indexOfFieldKey(content, "\"headers\"");
        if (headersIdx < 0) {
            headersIdx = indexOfFieldKey(content, "'headers'");
        }
        if (headersIdx < 0) {
            return null;
        }

        String afterHeaders = content.substring(headersIdx + 9); // skip "headers" or 'headers'
        afterHeaders = afterHeaders.trim();
        if (!afterHeaders.startsWith(":")) {
            return null;
        }
        afterHeaders = afterHeaders.substring(1).trim();

        // Extract the headers object
        String headersBlock = extractBalancedBraces(afterHeaders, 0);
        if (headersBlock == null) {
            return null;
        }

        // Parse key-value pairs inside the headers object
        String headersContent = headersBlock.substring(1, headersBlock.length() - 1);
        return parseKeyValuePairs(headersContent);
    }

    /**
     * Parse comma-separated key-value pairs from JS object content
     */
    private static Map<String, String> parseKeyValuePairs(String content) {
        Map<String, String> result = new LinkedHashMap<>();
        if (content == null || content.trim().isEmpty()) {
            return result;
        }

        List<String> pairs = splitByCommaRespectingStructure(content);
        for (String pair : pairs) {
            pair = pair.trim();
            if (pair.isEmpty()) {
                continue;
            }

            int colonIdx = findColonOutsideQuotes(pair);
            if (colonIdx < 0) {
                continue;
            }

            String key = pair.substring(0, colonIdx).trim();
            String value = pair.substring(colonIdx + 1).trim();

            // Unquote key
            key = unquote(key);
            // Unquote and unescape value
            value = unescapeJsString(unquote(value));

            if (!key.isEmpty()) {
                result.put(key, value);
            }
        }

        return result;
    }

    /**
     * Find colon position outside of quotes
     */
    private static int findColonOutsideQuotes(String text) {
        boolean inQuote = false;
        char quoteChar = 0;
        boolean escaped = false;

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '"' || c == '\'') {
                if (!inQuote) {
                    inQuote = true;
                    quoteChar = c;
                } else if (c == quoteChar) {
                    inQuote = false;
                }
                continue;
            }
            if (!inQuote && c == ':') {
                return i;
            }
        }
        return -1;
    }

    /**
     * Split by comma respecting quotes, braces, and brackets
     */
    private static List<String> splitByCommaRespectingStructure(String text) {
        List<String> parts = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuote = false;
        char quoteChar = 0;
        boolean escaped = false;
        int braceDepth = 0;
        int bracketDepth = 0;

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (escaped) {
                current.append(c);
                escaped = false;
                continue;
            }
            if (c == '\\') {
                current.append(c);
                escaped = true;
                continue;
            }
            if (c == '"' || c == '\'') {
                current.append(c);
                if (!inQuote) {
                    inQuote = true;
                    quoteChar = c;
                } else if (c == quoteChar) {
                    inQuote = false;
                }
                continue;
            }
            if (!inQuote) {
                if (c == '{') {
                    braceDepth++;
                } else if (c == '}') {
                    braceDepth--;
                } else if (c == '[') {
                    bracketDepth++;
                } else if (c == ']') {
                    bracketDepth--;
                } else if (c == ',' && braceDepth == 0 && bracketDepth == 0) {
                    parts.add(current.toString());
                    current = new StringBuilder();
                    continue;
                }
            }
            current.append(c);
        }

        if (current.length() > 0) {
            parts.add(current.toString());
        }

        return parts;
    }

    /**
     * Remove surrounding quotes from a string
     */
    private static String unquote(String text) {
        if (text == null || text.length() < 2) {
            return text;
        }
        if ((text.startsWith("\"") && text.endsWith("\"")) ||
            (text.startsWith("'") && text.endsWith("'"))) {
            return text.substring(1, text.length() - 1);
        }
        return text;
    }

    /**
     * Unescape JavaScript string escape sequences
     */
    private static String unescapeJsString(String text) {
        if (text == null) {
            return null;
        }

        StringBuilder sb = new StringBuilder();
        boolean escaped = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (escaped) {
                switch (c) {
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case '\\': sb.append('\\'); break;
                    case '"': sb.append('"'); break;
                    case '\'': sb.append('\''); break;
                    case 'u':
                        // Unicode escape
                        if (i + 4 < text.length()) {
                            try {
                                String hex = text.substring(i + 1, i + 5);
                                sb.append((char) Integer.parseInt(hex, 16));
                                i += 4;
                            } catch (NumberFormatException e) {
                                sb.append('u');
                            }
                        } else {
                            sb.append('u');
                        }
                        break;
                    case 'x':
                        // Hex escape
                        if (i + 2 < text.length()) {
                            try {
                                String hex = text.substring(i + 1, i + 3);
                                sb.append((char) Integer.parseInt(hex, 16));
                                i += 2;
                            } catch (NumberFormatException e) {
                                sb.append('x');
                            }
                        } else {
                            sb.append('x');
                        }
                        break;
                    default:
                        sb.append(c);
                }
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else {
                sb.append(c);
            }
        }

        // If trailing unclosed escape, keep backslash
        if (escaped) {
            sb.append('\\');
        }

        return sb.toString();
    }

    // ==================== HTTP message building ====================

    /**
     * Build raw HTTP request from FetchRequest
     */
    private static byte[] buildRawHttpRequest(FetchRequest req) {
        try {
            URL url = new URL(req.url);
            String path = url.getPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            }
            String query = url.getQuery();
            if (query != null && !query.isEmpty()) {
                path = path + "?" + query;
            }

            List<String> lines = new ArrayList<>();

            // 1. Request line
            lines.add(req.method + " " + path + " HTTP/1.1");

            // 2. Host header
            int port = url.getPort();
            String host = url.getHost();
            if (port != -1 && port != url.getDefaultPort()) {
                host = host + ":" + port;
            }
            lines.add("Host: " + host);

            // 3. Other headers (exclude Host, already added)
            boolean hasContentLength = false;
            boolean hasContentType = false;

            for (Map.Entry<String, String> entry : req.headers.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();

                if (key.equalsIgnoreCase("Host")) {
                    continue;
                }
                if (key.equalsIgnoreCase("Content-Length")) {
                    hasContentLength = true;
                }
                if (key.equalsIgnoreCase("Content-Type")) {
                    hasContentType = true;
                }

                lines.add(key + ": " + value);
            }

            // 4. Handle body
            byte[] bodyBytes = null;
            if (req.body != null && !req.body.isEmpty()) {
                bodyBytes = req.body.getBytes(StandardCharsets.UTF_8);
                if (!hasContentLength) {
                    lines.add("Content-Length: " + bodyBytes.length);
                }
                if (!hasContentType) {
                    lines.add("Content-Type: application/x-www-form-urlencoded");
                }
            }

            // 5. Empty line separating headers and body
            lines.add("");

            // 6. Assemble
            String headerPart = String.join("\r\n", lines);
            if (bodyBytes != null && bodyBytes.length > 0) {
                byte[] headerBytes = headerPart.getBytes(StandardCharsets.UTF_8);
                byte[] result = new byte[headerBytes.length + bodyBytes.length];
                System.arraycopy(headerBytes, 0, result, 0, headerBytes.length);
                System.arraycopy(bodyBytes, 0, result, headerBytes.length, bodyBytes.length);
                return result;
            } else {
                return headerPart.getBytes(StandardCharsets.UTF_8);
            }

        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid URL format: " + req.url, e);
        }
    }
}
