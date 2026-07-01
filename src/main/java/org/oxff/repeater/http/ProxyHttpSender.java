package org.oxff.repeater.http;

import org.oxff.repeater.logging.LogManager;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

/**
 * 代理HTTP请求发送器 - 使用java.net.HttpURLConnection通过指定代理发送请求
 * 绕过Burp的请求管道，直接使用系统代理设置
 */
public class ProxyHttpSender {

    /**
     * 通过代理发送HTTP请求
     *
     * @param requestBytes   原始请求字节数组
     * @param service        HTTP服务信息
     * @param timeoutSeconds 超时时间(秒)
     * @return 响应字节数组（包含完整的HTTP响应：状态行+头+体），失败返回null
     */
    public byte[] send(byte[] requestBytes, HttpService service, int timeoutSeconds) {
        HttpURLConnection conn = null;
        try {
            String protocol = service.secure() ? "https" : "http";
            String host = service.host();
            int port = service.port();

            // 解析请求行获取方法和路径
            String requestStr = new String(requestBytes, "UTF-8");
            String firstLine = requestStr.substring(0, requestStr.indexOf("\r\n"));
            String[] requestParts = firstLine.split("\\s+");
            String method = requestParts[0];
            String path = requestParts.length >= 2 ? requestParts[1] : "/";

            // 构建完整URL
            String urlStr = String.format("%s://%s:%d%s", protocol, host, port, path);
            URL url = new URL(urlStr);

            // 创建代理对象
            ProxyConfig proxyConfig = ProxyConfig.getInstance();
            Proxy proxy = proxyConfig.toJavaProxy();

            // 打开连接并配置
            conn = (HttpURLConnection) url.openConnection(proxy);
            conn.setRequestMethod(method);
            conn.setConnectTimeout(timeoutSeconds * 1000);
            conn.setReadTimeout(timeoutSeconds * 1000);
            conn.setInstanceFollowRedirects(false);

            // 应用请求头
            boolean hasContentType = applyHeaders(conn, service, requestBytes);

            // 准备并写入请求体
            int bodyOffset = findBodyOffset(requestBytes);
            prepareAndWriteBody(conn, requestBytes, bodyOffset, method, hasContentType);

            // 读取并返回响应
            return readResponse(conn);

        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 代理请求失败: " + e.getMessage());
            return null;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    /**
     * 将请求的HTTP头部应用到代理连接上
     */
    private boolean applyHeaders(HttpURLConnection conn, HttpService service, byte[] requestBytes) {
        HttpRequest requestInfo = HttpRequest.httpRequest(service, ByteArray.byteArray(requestBytes));
        List<String> headers = RequestManager.convertHeadersToStringList(requestInfo.headers());
        boolean hasContentType = false;
        for (int i = 0; i < headers.size(); i++) {
            String header = headers.get(i);
            int colonIdx = header.indexOf(':');
            if (colonIdx > 0) {
                String headerName = header.substring(0, colonIdx).trim();
                String headerValue = header.substring(colonIdx + 1).trim();
                if (headerName.equalsIgnoreCase("Host") || headerName.equalsIgnoreCase("Proxy-Connection")) {
                    continue;
                }
                if (headerName.equalsIgnoreCase("Content-Type")) {
                    hasContentType = true;
                }
                conn.setRequestProperty(headerName, headerValue);
            }
        }

        // 处理HTTPS信任所有证书
        if (conn instanceof HttpsURLConnection) {
            setupTrustAllSSL((HttpsURLConnection) conn);
        }

        return hasContentType;
    }

    /**
     * 准备代理连接的请求体输出并写入body数据
     */
    private void prepareAndWriteBody(HttpURLConnection conn, byte[] requestBytes,
                                      int bodyOffset, String method, boolean hasContentType) throws IOException {
        boolean hasBody = bodyOffset > 0 && bodyOffset < requestBytes.length;
        boolean isBodyMethod = method.equalsIgnoreCase("POST")
                || method.equalsIgnoreCase("PUT")
                || method.equalsIgnoreCase("PATCH");

        if (hasBody) {
            conn.setDoOutput(true);
            if (!hasContentType) {
                conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            }
        } else if (isBodyMethod) {
            conn.setDoOutput(true);
            conn.setFixedLengthStreamingMode(0);
        }

        conn.connect();

        if (hasBody) {
            byte[] bodyBytes = new byte[requestBytes.length - bodyOffset];
            System.arraycopy(requestBytes, bodyOffset, bodyBytes, 0, bodyBytes.length);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(bodyBytes);
                os.flush();
            }
        } else if (isBodyMethod) {
            try (OutputStream os = conn.getOutputStream()) {
                os.flush();
            }
        }
    }

    /**
     * 从代理连接读取完整的HTTP响应（状态行 + 响应头 + 响应体）
     */
    private byte[] readResponse(HttpURLConnection conn) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int responseCode = conn.getResponseCode();
        String responseMessage = conn.getResponseMessage();

        // 构建状态行
        String statusLine = String.format("HTTP/1.1 %d %s\r\n", responseCode,
                responseMessage != null ? responseMessage : "");
        baos.write(statusLine.getBytes("UTF-8"));

        // 构建响应头
        for (Map.Entry<String, List<String>> entry : conn.getHeaderFields().entrySet()) {
            String headerName = entry.getKey();
            if (headerName == null) continue;
            for (String headerValue : entry.getValue()) {
                baos.write(String.format("%s: %s\r\n", headerName, headerValue).getBytes("UTF-8"));
            }
        }
        baos.write("\r\n".getBytes("UTF-8"));

        // 读取响应体
        InputStream is = null;
        try {
            is = conn.getInputStream();
        } catch (Exception e) {
            is = conn.getErrorStream();
            if (is == null) {
                LogManager.getInstance().printError(
                    "[!] 响应流获取失败，错误流也为空: " + e.getMessage());
            }
        }

        if (is != null) {
            try (InputStream inputStream = is) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesRead);
                }
            }
        }

        byte[] response = baos.toByteArray();
        LogManager.getInstance().printOutput(
                String.format("[D] 代理响应: HTTP %d, 响应总大小: %d 字节", responseCode, response.length));
        return response;
    }

    /**
     * 查找请求体起始偏移量
     */
    private int findBodyOffset(byte[] requestBytes) {
        // 查找 \r\n\r\n 分隔符
        for (int i = 0; i < requestBytes.length - 3; i++) {
            if (requestBytes[i] == '\r' && requestBytes[i + 1] == '\n'
                && requestBytes[i + 2] == '\r' && requestBytes[i + 3] == '\n') {
                return i + 4;
            }
        }
        // 查找 \n\n 分隔符（非标准但偶尔出现）
        for (int i = 0; i < requestBytes.length - 1; i++) {
            if (requestBytes[i] == '\n' && requestBytes[i + 1] == '\n') {
                return i + 2;
            }
        }
        return -1;
    }

    /**
     * 配置HTTPS连接信任所有SSL证书
     */
    private void setupTrustAllSSL(HttpsURLConnection conn) {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            }, new java.security.SecureRandom());
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.setHostnameVerifier((hostname, session) -> true);
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 设置SSL信任失败: " + e.getMessage());
        }
    }
}
