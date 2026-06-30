package org.oxff.repeater.http;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * HTTP 报文解析工具类 — 提供字节级 header/body 分离方法
 * <p>
 * 使用字节级查找分隔符，避免 UTF-8 多字节字符导致字符串索引与字节偏移错位(BUG-007)。
 * ReplayEngine 和 AutoTestEngine 统一调用此类，消除重复代码。
 */
public class HttpMessageParser {

    private HttpMessageParser() {
    }

    /**
     * 字节级查找 HTTP 响应 header/body 分隔符
     *
     * @param data 响应字节数组
     * @return 分隔符起始位置的字节偏移，未找到返回 -1
     */
    public static int findHeaderBodySeparator(byte[] data) {
        if (data == null || data.length < 2) return -1;

        // 优先查找 \r\n\r\n (CRLF + CRLF)
        for (int i = 0; i < data.length - 3; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n'
                    && data[i + 2] == '\r' && data[i + 3] == '\n') {
                return i;
            }
        }
        // 回退查找 \n\n (LF + LF)
        for (int i = 0; i < data.length - 1; i++) {
            if (data[i] == '\n' && data[i + 1] == '\n') {
                return i;
            }
        }
        return -1;
    }

    /**
     * 从响应字节数组中提取纯响应体（不含响应头和状态行）
     * <p>
     * 相似度计算应仅基于响应体内容，排除响应头的影响。
     *
     * @param responseBytes 完整 HTTP 响应字节数组
     * @return 纯响应体字节数组，无法分离时返回完整内容作为 fallback
     */
    public static byte[] extractResponseBody(byte[] responseBytes) {
        if (responseBytes == null || responseBytes.length == 0) return new byte[0];
        try {
            int separatorPos = findHeaderBodySeparator(responseBytes);
            if (separatorPos < 0) {
                // 无法分离头和体时，返回完整内容作为 fallback
                return responseBytes;
            }
            // 计算分隔符长度（\r\n\r\n=4 或 \n\n=2）
            int separatorLen = (responseBytes[separatorPos] == '\r') ? 4 : 2;
            int bodyStart = separatorPos + separatorLen;
            if (bodyStart < responseBytes.length) {
                return Arrays.copyOfRange(responseBytes, bodyStart, responseBytes.length);
            }
            return new byte[0]; // 分隔符在末尾，无响应体
        } catch (Exception e) {
            return responseBytes;
        }
    }

    /**
     * 从响应字节数组中提取响应头字符串（不含响应体）
     *
     * @param responseBytes 完整 HTTP 响应字节数组
     * @return 响应头字符串（UTF-8），无法分离时返回完整内容
     */
    public static String extractResponseHeaders(byte[] responseBytes) {
        if (responseBytes == null || responseBytes.length == 0) return "";
        try {
            int separatorPos = findHeaderBodySeparator(responseBytes);
            if (separatorPos < 0) {
                return new String(responseBytes, StandardCharsets.UTF_8);
            }
            return new String(responseBytes, 0, separatorPos, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }
}
