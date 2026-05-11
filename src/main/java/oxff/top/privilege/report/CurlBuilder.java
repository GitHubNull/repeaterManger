package oxff.top.privilege.report;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import oxff.top.http.RequestResponseRecord;

import java.util.List;

/**
 * cURL 命令构建器
 * 从 RequestResponseRecord 构建可执行的 cURL 命令
 */
public class CurlBuilder {

    private CurlBuilder() {
    }

    /**
     * 从请求记录构建 cURL 命令
     */
    public static String build(RequestResponseRecord record) {
        if (record == null || record.getRequestData() == null || record.getRequestData().length == 0) {
            return "# No request data available";
        }

        try {
            HttpRequest httpRequest = HttpRequest.httpRequest(ByteArray.byteArray(record.getRequestData()));
            StringBuilder curl = new StringBuilder();

            curl.append("curl");

            // Method (only if not GET)
            String method = httpRequest.method();
            if (!"GET".equalsIgnoreCase(method)) {
                curl.append(" -X ").append(escapeShell(method));
            }

            // URL
            String url = record.getUrl();
            curl.append(" '").append(escapeShellUrl(url)).append("'");

            // Headers (skip Host and Content-Length)
            List<burp.api.montoya.http.message.HttpHeader> headers = httpRequest.headers();
            if (headers != null) {
                for (burp.api.montoya.http.message.HttpHeader header : headers) {
                    String name = header.name();
                    if ("Host".equalsIgnoreCase(name) || "Content-Length".equalsIgnoreCase(name)) {
                        continue;
                    }
                    curl.append(" \\\n  -H '").append(escapeShell(header.name()))
                            .append(": ").append(escapeShell(header.value())).append("'");
                }
            }

            // Body
            byte[] body = httpRequest.body() != null ? httpRequest.body().getBytes() : null;
            if (body != null && body.length > 0) {
                if (isBinaryBody(body)) {
                    curl.append(" \\\n  # [Binary body omitted — ").append(body.length).append(" bytes]");
                } else {
                    String contentType = BinaryContentRenderer.extractContentTypeFromRequest(record.getRequestData());
                    String bodyStr = BinaryContentRenderer.decodeBody(body, contentType);
                    curl.append(" \\\n  -d '").append(escapeShell(bodyStr)).append("'");
                }
            }

            return curl.toString();
        } catch (Exception e) {
            return "# Failed to build curl command: " + e.getMessage();
        }
    }

    /**
     * 检测是否为二进制 body
     */
    private static boolean isBinaryBody(byte[] data) {
        if (data == null || data.length == 0) return false;
        int nonPrintable = 0;
        int checkLen = Math.min(data.length, 1024);
        for (int i = 0; i < checkLen; i++) {
            byte b = data[i];
            if (b < 0x09 || (b > 0x0D && b < 0x20) || b == 0x7F) {
                nonPrintable++;
            }
        }
        return (double) nonPrintable / checkLen > 0.3;
    }

    private static String escapeShell(String s) {
        if (s == null) return "";
        return s.replace("'", "'\\''");
    }

    private static String escapeShellUrl(String s) {
        if (s == null) return "";
        return s.replace("'", "'\\''");
    }
}
