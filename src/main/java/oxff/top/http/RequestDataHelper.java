package oxff.top.http;

import burp.BurpExtender;
import burp.IHttpService;
import burp.IRequestInfo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 请求数据工具类 - 提供HTTP请求验证、修复和构建的静态方法
 */
public class RequestDataHelper {

    /**
     * 检查文本是否为有效的HTTP请求
     */
    public static boolean isValidHttpRequest(String text) {
        if (text == null || text.isEmpty()) {
            return false;
        }

        try {
            // 简单检查是否包含HTTP方法和HTTP版本
            String[] firstLines = text.split("\r\n|\n", 2);
            if (firstLines.length == 0) {
                return false;
            }

            String firstLine = firstLines[0].trim();
            boolean isValidMethod = firstLine.matches("(?i)(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE)\\s+.+\\s+HTTP/.+");
            boolean isValidResponse = firstLine.matches("HTTP/.+\\s+\\d+\\s+.*");

            if (!isValidMethod && !isValidResponse) {
                return false;
            }

            // 检查是否包含必要的头部
            boolean hasHost = false;
            boolean hasContentLength = false;
            String[] lines = text.split("\r\n|\n");

            for (String line : lines) {
                if (line.toLowerCase().startsWith("host:")) {
                    hasHost = true;
                }
                if (line.toLowerCase().startsWith("content-length:")) {
                    hasContentLength = true;
                }
                // 如果同时找到Host和Content-Length，可以提前返回
                if (hasHost && hasContentLength) {
                    return true;
                }
            }

            // 对于GET请求，不需要Content-Length
            if (firstLine.toUpperCase().startsWith("GET") && hasHost) {
                return true;
            }

            // 对于其他请求，需要Content-Length
            return hasHost && hasContentLength;

        } catch (Exception e) {
            BurpExtender.printError("[!] 验证HTTP请求时出错: " + e.getMessage());
            return false;
        }
    }

    /**
     * 尝试修复损坏的二进制数据
     */
    public static String repairBinaryData(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }

        // 记录原始数据用于调试
        BurpExtender.printOutput("[*] 尝试修复请求数据，大小: " + data.length + " 字节");

        StringBuilder sb = new StringBuilder();

        // 尝试识别HTTP头部和正文的分隔符
        int bodyStart = -1;
        for (int i = 0; i < data.length - 3; i++) {
            // 查找\r\n\r\n序列，这通常用于分隔HTTP头部和正文
            if (data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n') {
                bodyStart = i + 4;
                break;
            }
        }

        // 如果找到了分隔符
        if (bodyStart > 0) {
            // 分别处理头部和正文
            String headers = new String(Arrays.copyOfRange(data, 0, bodyStart),
                                      java.nio.charset.StandardCharsets.ISO_8859_1);
            sb.append(headers);

            // 检查是否为多部分表单数据
            if (headers.toLowerCase().contains("content-type: multipart/form-data")) {
                // 对于多部分表单数据，使用ISO-8859-1编码处理整个请求
                return new String(data, java.nio.charset.StandardCharsets.ISO_8859_1);
            }

            // 对于正文部分，尝试智能选择编码
            if (bodyStart < data.length) {
                byte[] body = Arrays.copyOfRange(data, bodyStart, data.length);

                // 尝试检测正文是否包含二进制数据
                boolean isBinary = false;
                for (byte b : body) {
                    if (b == 0 || (b < 32 && b != '\r' && b != '\n' && b != '\t')) {
                        isBinary = true;
                        break;
                    }
                }

                if (isBinary) {
                    // 对于二进制数据，使用Base64编码显示
                    sb.append("[二进制数据，长度: ").append(body.length).append(" 字节]\n");
                    sb.append(java.util.Base64.getEncoder().encodeToString(body));
                } else {
                    // 对于文本数据，尝试使用UTF-8解码
                    try {
                        sb.append(new String(body, java.nio.charset.StandardCharsets.UTF_8));
                    } catch (Exception e) {
                        // 如果UTF-8解码失败，回退到ISO-8859-1
                        sb.append(new String(body, java.nio.charset.StandardCharsets.ISO_8859_1));
                    }
                }
            }

            return sb.toString();
        } else {
            // 如果找不到分隔符，尝试检测数据是否为纯二进制
            boolean isBinary = false;
            for (byte b : data) {
                if (b == 0 || (b < 32 && b != '\r' && b != '\n' && b != '\t')) {
                    isBinary = true;
                    break;
                }
            }

            if (isBinary) {
                // 对于二进制数据，以可读形式展示
                sb.append("HTTP/1.1 自动生成的请求头\r\n");
                sb.append("Content-Type: application/octet-stream\r\n");
                sb.append("Content-Length: ").append(data.length).append("\r\n\r\n");
                sb.append("[二进制数据，长度: ").append(data.length).append(" 字节]\n");
                sb.append(java.util.Base64.getEncoder().encodeToString(data));
            } else {
                // 对于可能的文本数据，尝试UTF-8和ISO-8859-1
                try {
                    return new String(data, java.nio.charset.StandardCharsets.UTF_8);
                } catch (Exception e) {
                    return new String(data, java.nio.charset.StandardCharsets.ISO_8859_1);
                }
            }

            return sb.toString();
        }
    }

    /**
     * 创建基本HTTP请求模板
     */
    public static String createBasicRequest() {
        StringBuilder sb = new StringBuilder();
        sb.append("GET / HTTP/1.1\r\n");
        sb.append("Host: example.com\r\n");
        sb.append("User-Agent: Mozilla/5.0\r\n");
        sb.append("Accept: */*\r\n");
        sb.append("Connection: close\r\n");
        sb.append("\r\n");
        return sb.toString();
    }

    /**
     * 修正请求的 Content-Length 头，确保与实际 body 大小一致。
     * 对于 POST/PUT/PATCH 请求，即使 body 为空也显式设置 Content-Length: 0，
     * 防止服务器等待 body 数据导致超时（表现为请求耗时 10+ 秒）。
     */
    public static byte[] fixContentLength(byte[] requestBytes, IHttpService service) {
        try {
            IRequestInfo reqInfo = BurpExtender.helpers.analyzeRequest(service, requestBytes);
            int bodyOffset = reqInfo.getBodyOffset();
            byte[] body = Arrays.copyOfRange(requestBytes, bodyOffset, requestBytes.length);
            List<String> headers = new ArrayList<>(reqInfo.getHeaders());
            String method = reqInfo.getMethod().toUpperCase();

            // 移除现有的 Content-Length
            headers.removeIf(h -> h.toLowerCase().startsWith("content-length:"));

            // 添加正确的 Content-Length
            if (body.length > 0) {
                headers.add("Content-Length: " + body.length);
            } else if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
                headers.add("Content-Length: 0");
            }

            return BurpExtender.helpers.buildHttpMessage(headers, body);
        } catch (Exception e) {
            BurpExtender.printError("[!] 修正 Content-Length 失败: " + e.getMessage());
            return requestBytes;
        }
    }
}
