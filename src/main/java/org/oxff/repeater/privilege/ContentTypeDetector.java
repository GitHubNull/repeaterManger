package org.oxff.repeater.privilege;

import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

/**
 * 内容类型检测器 - 无状态工具类
 * 从 HTTP 响应头部或响应体内容推断数据格式，用于相似度算法路由
 */
public class ContentTypeDetector {

    /**
     * 检测到的内容类型枚举
     */
    public enum ContentType {
        JSON,   // JSON 格式
        XML,    // XML 格式（含 SOAP）
        HTML,   // HTML 格式
        TEXT,   // 纯文本/其他
        BINARY  // 二进制数据
    }

    private ContentTypeDetector() {
    }

    /**
     * 从 HTTP Content-Type 头部解析内容类型
     *
     * @param contentTypeHeader Content-Type 头部值，如 "application/json; charset=utf-8"
     * @return 检测到的内容类型，无法识别时返回 TEXT
     */
    public static ContentType detectFromHeader(String contentTypeHeader) {
        if (contentTypeHeader == null || contentTypeHeader.isEmpty()) {
            return ContentType.TEXT;
        }

        String lower = contentTypeHeader.toLowerCase();

        if (lower.contains("json")) {
            return ContentType.JSON;
        }
        if (lower.contains("xml")) {
            // application/xml, text/xml, application/soap+xml
            return ContentType.XML;
        }
        if (lower.contains("html")) {
            return ContentType.HTML;
        }
        if (lower.contains("octet-stream") || lower.contains("image/")
                || lower.contains("video/") || lower.contains("audio/")
                || lower.contains("pdf") || lower.contains("zip")) {
            return ContentType.BINARY;
        }

        return ContentType.TEXT;
    }

    /**
     * 从响应体内容推断内容类型
     * 检测优先级：JSON → XML → HTML → TEXT
     *
     * @param body 响应体文本
     * @return 检测到的内容类型
     */
    public static ContentType detect(String body) {
        if (body == null || body.isEmpty()) {
            return ContentType.TEXT;
        }

        String trimmed = body.trim();

        // 尝试 JSON 解析（最快路径：JSON 对象或数组开头）
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            try {
                JsonParser.parseString(trimmed);
                return ContentType.JSON;
            } catch (JsonSyntaxException e) {
                // 不是有效 JSON，继续尝试
            }
        }

        // 尝试 XML 解析（以 < 开头但不是 HTML）
        if (trimmed.startsWith("<")) {
            if (isHtml(trimmed)) {
                return ContentType.HTML;
            }
            if (isValidXml(trimmed)) {
                return ContentType.XML;
            }
        }

        return ContentType.TEXT;
    }

    /**
     * 结合头部和内容体检测内容类型
     * 优先使用头部信息，头部无法确定时用内容推断
     *
     * @param contentTypeHeader Content-Type 头部值
     * @param body              响应体文本
     * @return 检测到的内容类型
     */
    public static ContentType detect(String contentTypeHeader, String body) {
        // 优先使用头部
        if (contentTypeHeader != null && !contentTypeHeader.isEmpty()) {
            ContentType fromHeader = detectFromHeader(contentTypeHeader);
            if (fromHeader != ContentType.TEXT) {
                return fromHeader;
            }
        }
        // 头部无法确定，用内容推断
        return detect(body);
    }

    /**
     * 粗略判断是否为 HTML
     */
    private static boolean isHtml(String text) {
        String lower = text.toLowerCase();
        // 检查常见 HTML 标签
        return lower.startsWith("<!doctype html") || lower.startsWith("<html")
                || (lower.contains("<head") && lower.contains("<body"))
                || (lower.contains("<div") && lower.contains("</div>"));
    }

    /**
     * 尝试解析 XML（仅验证格式，不深度遍历）
     */
    private static boolean isValidXml(String text) {
        try {
            var builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            builder.parse(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)));
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
