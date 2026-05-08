package oxff.top.http;

import burp.BurpExtender;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import oxff.top.api.MontoyaApiHolder;
import oxff.top.service.HistoryRecordingService;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

/**
 * HTTP请求管理器类 - 负责发送请求和处理响应
 */
public class RequestManager {
    
    /**
     * 请求回调接口
     */
    public interface RequestCallback {
        void onSuccess(byte[] response, long requestTimeMs, long responseTimeMs, long durationMs);
        void onFailure(String errorMessage, long requestTimeMs, long responseTimeMs, long durationMs);
    }
    
    // 不再重试，单次请求直接返回结果（重试会导致请求耗时翻倍）
    private final ExecutorService executor;
    private final HistoryRecordingService recordingService;
    private final MontoyaApi api;
    
    /**
     * 创建请求管理器
     */
    public RequestManager() {
        this(MontoyaApiHolder.getApi());
    }

    /**
     * 创建请求管理器（传入MontoyaApi实例）
     */
    public RequestManager(MontoyaApi api) {
        this.api = api;

        // 创建线程池执行器，避免阻塞UI线程
        executor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "RepeaterManager-RequestThread");
            t.setDaemon(true);
            return t;
        });
        
        // 初始化历史记录服务
        this.recordingService = HistoryRecordingService.getInstance();
    }
    
    /**
     * 发送HTTP请求并返回响应
     * 
     * @param requestBytes 原始请求字节数组
     * @param timeoutSeconds 超时时间(秒)
     * @return 响应字节数组，失败返回null
     */
    public byte[] makeHttpRequest(byte[] requestBytes, int timeoutSeconds) {
        return makeHttpRequest(requestBytes, timeoutSeconds, -1, null);
    }
    
    /**
     * 发送HTTP请求并返回响应（带历史记录）
     * 
     * @param requestBytes 原始请求字节数组
     * @param timeoutSeconds 超时时间(秒)
     * @param requestId 关联的请求ID，用于历史记录
     * @return 响应字节数组，失败返回null
     */
    public byte[] makeHttpRequest(byte[] requestBytes, int timeoutSeconds, int requestId) {
        return makeHttpRequest(requestBytes, timeoutSeconds, requestId, null);
    }
    
    /**
     * 发送HTTP请求并返回响应（带历史记录和HTTP服务信息）
     * 
     * @param requestBytes 原始请求字节数组
     * @param timeoutSeconds 超时时间(秒)
     * @param requestId 关联的请求ID，用于历史记录
     * @param httpService 原始HTTP服务信息（包含正确的协议、主机、端口），可为null
     * @return 响应字节数组，失败返回null
     */
    public byte[] makeHttpRequest(byte[] requestBytes, int timeoutSeconds, int requestId, HttpService httpService) {
        if (requestBytes == null || requestBytes.length == 0) {
            BurpExtender.printError("[!] 请求数据为空");
            return null;
        }
        
        // 构建HTTP服务对象
        HttpService service = buildHttpService(requestBytes, httpService);
        
        // 使用Montoya API解析请求，确保协议正确
        HttpRequest httpRequest = HttpRequest.httpRequest(service, ByteArray.byteArray(requestBytes));
        
        String host = service.host();
        int port = service.port();
        boolean isSecure = service.secure();
        
        BurpExtender.printOutput(
            String.format("[*] 正在发送请求到 %s://%s:%d (超时时间: %d秒)", 
                isSecure ? "https" : "http", host, port, timeoutSeconds));
        
        // 记录请求开始时间
        long startTime = System.currentTimeMillis();
        
        // 创建Future任务（单次请求，不重试，避免耗时翻倍）
        Future<byte[]> future = executor.submit(() -> {
            try {
                // 修正 Content-Length，确保与实际 body 一致（类似 Burp Repeater 的自动修正）
                byte[] fixedBytes = RequestDataHelper.fixContentLength(requestBytes, service);

                // 单次发送，不重试
                HttpRequest requestToSend = HttpRequest.httpRequest(service, ByteArray.byteArray(fixedBytes));
                HttpRequestResponse requestResponse = api.http().sendRequest(requestToSend);

                long responseTime = System.currentTimeMillis() - startTime;

                // 检查响应是否为null（连接失败、超时等情况）
                if (requestResponse == null || requestResponse.response() == null) {
                    BurpExtender.printError("[!] 请求发送失败：未收到响应（目标可能不可达或连接被拒绝）");
                    recordingService.recordFailure(requestId, fixedBytes, httpRequest,
                                                 "未收到响应（目标可能不可达或连接被拒绝）", responseTime, service);
                    return null;
                }

                byte[] response = requestResponse.response().toByteArray().getBytes();

                if (response != null && response.length > 0) {
                    HttpResponse httpResponse = HttpResponse.httpResponse(ByteArray.byteArray(response));
                    // 检测 Burp 内部错误响应（如 HTTP/0.9 1337 表示未收到有效响应头）
                    int statusCode = httpResponse.statusCode();
                    if (isBurpErrorResponse(statusCode, response)) {
                        String errorMsg = String.format(
                            "服务器返回异常响应 (HTTP %d)，可能是请求格式错误或目标不支持", statusCode);
                        BurpExtender.printError("[!] " + errorMsg);
                        recordingService.recordFailure(requestId, fixedBytes, httpRequest,
                                                     errorMsg, responseTime, service);
                        return null;
                    }
                    recordingService.recordSuccess(requestId, fixedBytes, response,
                                                  httpRequest, httpResponse, responseTime, service);
                    return response;
                } else {
                    BurpExtender.printError("[!] 收到空响应");
                    recordingService.recordFailure(requestId, fixedBytes, httpRequest,
                                                 "收到空响应", responseTime, service);
                    return null;
                }
            } catch (Exception e) {
                long responseTime = System.currentTimeMillis() - startTime;
                BurpExtender.printError("[!] 请求发送失败: " + e.getMessage());
                recordingService.recordFailure(requestId, requestBytes, httpRequest,
                                             "请求发送失败: " + e.getMessage(), responseTime, service);
                return null;
            }
        });
        
        try {
            // 设置超时
            return future.get(timeoutSeconds, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            BurpExtender.printError("[!] 请求超时 (" + timeoutSeconds + "秒)");
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            BurpExtender.printError("[!] 请求被中断: " + e.getMessage());
            return null;
        } catch (ExecutionException e) {
            BurpExtender.printError("[!] 执行请求时出错: " + e.getMessage());
            return null;
        } catch (Exception e) {
            BurpExtender.printError("[!] 未知错误: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * 异步发送HTTP请求
     * 
     * @param requestBytes 原始请求字节数组
     * @param timeoutSeconds 超时时间(秒)
     * @param callback 请求回调接口
     */
    public void makeHttpRequestAsync(byte[] requestBytes, int timeoutSeconds, RequestCallback callback) {
        makeHttpRequestAsync(requestBytes, timeoutSeconds, -1, null, callback);
    }
    
    /**
     * 异步发送HTTP请求（带历史记录）
     * 
     * @param requestBytes 原始请求字节数组
     * @param timeoutSeconds 超时时间(秒)
     * @param requestId 关联的请求ID，用于历史记录
     * @param callback 请求回调接口
     */
    public void makeHttpRequestAsync(byte[] requestBytes, int timeoutSeconds, int requestId, RequestCallback callback) {
        makeHttpRequestAsync(requestBytes, timeoutSeconds, requestId, null, callback);
    }
    
    /**
     * 异步发送HTTP请求（带历史记录和HTTP服务信息）
     * 
     * @param requestBytes 原始请求字节数组
     * @param timeoutSeconds 超时时间(秒)
     * @param requestId 关联的请求ID，用于历史记录
     * @param httpService 原始HTTP服务信息（包含正确的协议、主机、端口），可为null
     * @param callback 请求回调接口
     */
    public void makeHttpRequestAsync(byte[] requestBytes, int timeoutSeconds, int requestId, 
                                      HttpService httpService, RequestCallback callback) {
        if (requestBytes == null || requestBytes.length == 0) {
            BurpExtender.printError("[!] 请求数据为空");
            if (callback != null) {
                callback.onFailure("请求数据为空", 0, 0, 0);
            }
            return;
        }
        
        // 在后台线程中执行请求
        executor.submit(() -> {
            // 记录请求开始时间（在外层try之前，确保异常分支也能访问）
            final long startTime = System.currentTimeMillis();
            
            try {
                // 构建HTTP服务对象
                HttpService service = buildHttpService(requestBytes, httpService);
                
                // 使用Montoya API解析请求，确保协议正确
                HttpRequest requestInfo = HttpRequest.httpRequest(service, ByteArray.byteArray(requestBytes));
                
                String host = service.host();
                int port = service.port();
                boolean isSecure = service.secure();
                
                BurpExtender.printOutput(
                    String.format("[*] 正在发送请求到 %s://%s:%d (超时时间: %d秒)",
                        isSecure ? "https" : "http", host, port, timeoutSeconds));

                // 检查是否启用代理模式
                ProxyConfig proxyConfig = ProxyConfig.getInstance();
                if (proxyConfig.isProxyEnabled()) {
                    BurpExtender.printOutput(
                        String.format("[D] 通过代理 %s:%d 发送请求",
                            proxyConfig.getProxyHost(), proxyConfig.getProxyPort()));
                    byte[] proxyResponse = makeHttpRequestWithProxy(
                        requestBytes, service, timeoutSeconds);
                    long responseTime = System.currentTimeMillis() - startTime;
                    if (proxyResponse != null) {
                        HttpResponse httpResponse = HttpResponse.httpResponse(ByteArray.byteArray(proxyResponse));
                        recordingService.recordSuccess(requestId, requestBytes, proxyResponse,
                            requestInfo, httpResponse, responseTime, service);
                        BurpExtender.printOutput(
                            String.format("[+] 代理请求成功完成，耗时: %d ms，响应大小: %d 字节",
                                responseTime, proxyResponse.length));
                        if (callback != null) {
                            callback.onSuccess(proxyResponse, startTime, System.currentTimeMillis(), responseTime);
                        }
                    } else {
                        BurpExtender.printError("[!] 代理请求返回空响应");
                        recordingService.recordFailure(requestId, requestBytes, requestInfo,
                                                     "代理请求返回空响应", responseTime, service);
                        if (callback != null) {
                            callback.onFailure("代理请求返回空响应", startTime, System.currentTimeMillis(), responseTime);
                        }
                    }
                    return;
                }

                // 修正 Content-Length，确保与实际 body 一致（类似 Burp Repeater 的自动修正功能）
                byte[] fixedBytes = RequestDataHelper.fixContentLength(requestBytes, service);

                // 单次发送，不重试，避免请求耗时翻倍
                HttpRequest requestToSend = HttpRequest.httpRequest(service, ByteArray.byteArray(fixedBytes));
                HttpRequestResponse requestResponse = api.http().sendRequest(requestToSend);

                long responseTime = System.currentTimeMillis() - startTime;

                // 检查响应是否为null（连接失败、超时等情况）
                if (requestResponse == null || requestResponse.response() == null) {
                    BurpExtender.printError("[!] 请求发送失败：未收到响应（目标可能不可达或连接被拒绝）");
                    recordingService.recordFailure(requestId, fixedBytes, requestInfo,
                                                 "未收到响应（目标可能不可达或连接被拒绝）", responseTime, service);
                    if (callback != null) {
                        callback.onFailure("未收到响应（目标可能不可达或连接被拒绝）", startTime, System.currentTimeMillis(), responseTime);
                    }
                    return;
                }

                byte[] response = requestResponse.response().toByteArray().getBytes();

                if (response != null && response.length > 0) {
                    HttpResponse httpResponse = HttpResponse.httpResponse(ByteArray.byteArray(response));
                    // 检测 Burp 内部错误响应（如 HTTP/0.9 1337 表示未收到有效响应头）
                    int statusCode = httpResponse.statusCode();
                    if (isBurpErrorResponse(statusCode, response)) {
                        String errorMsg = String.format(
                            "服务器返回异常响应 (HTTP %d)，可能是请求格式错误或目标不支持", statusCode);
                        BurpExtender.printError("[!] " + errorMsg);
                        recordingService.recordFailure(requestId, fixedBytes, requestInfo,
                                                     errorMsg, responseTime, service);
                        if (callback != null) {
                            callback.onFailure(errorMsg, startTime, System.currentTimeMillis(), responseTime);
                        }
                        return;
                    }
                    recordingService.recordSuccess(requestId, fixedBytes, response,
                                                  requestInfo, httpResponse, responseTime, service);
                    BurpExtender.printOutput(
                        String.format("[+] 请求成功完成，耗时: %d ms，响应大小: %d 字节",
                            responseTime, response.length));
                    if (callback != null) {
                        callback.onSuccess(response, startTime, System.currentTimeMillis(), responseTime);
                    }
                } else {
                    BurpExtender.printError("[!] 收到空响应");
                    recordingService.recordFailure(requestId, fixedBytes, requestInfo,
                                                 "收到空响应", responseTime, service);
                    if (callback != null) {
                        callback.onFailure("收到空响应", startTime, System.currentTimeMillis(), responseTime);
                    }
                }
            } catch (Exception e) {
                BurpExtender.printError("[!] 发送请求时发生异常: " + e.getMessage());
                // 记录异常堆栈信息
                e.printStackTrace();
                
                // 记录异常的历史记录
                long responseTime = System.currentTimeMillis() - startTime;
                try {
                    // 重新构建HTTP服务信息和请求信息
                    HttpService service = buildHttpService(requestBytes, httpService);
                    HttpRequest requestInfo = HttpRequest.httpRequest(service, ByteArray.byteArray(requestBytes));
                    
                    recordingService.recordFailure(requestId, requestBytes, requestInfo, 
                                                 "发送请求时发生异常: " + e.getMessage(), responseTime, service);
                } catch (Exception ex) {
                    // 如果创建HTTP服务失败，使用基本的请求分析
                    BurpExtender.printError("[!] 创建HTTP服务失败，使用基本请求分析: " + ex.getMessage());
                    HttpRequest requestInfo = HttpRequest.httpRequest(ByteArray.byteArray(requestBytes));
                    recordingService.recordFailure(requestId, requestBytes, requestInfo, 
                                                 "发送请求时发生异常: " + e.getMessage(), responseTime);
                }
                
                if (callback != null) {
                    callback.onFailure("发送请求时发生异常: " + e.getMessage(), startTime, System.currentTimeMillis(), responseTime);
                }
            }
        });
    }
    
    /**
     * 构建HTTP服务对象
     * 优先使用原始HTTP服务信息（包含正确的协议），否则从请求数据中推断
     * 
     * @param requestBytes 请求数据
     * @param originalService 原始HTTP服务信息，可为null
     * @return 构建好的HTTP服务对象
     */
    private HttpService buildHttpService(byte[] requestBytes, HttpService originalService) {
        // 如果有原始HTTP服务信息，优先使用它来保留正确的协议
        if (originalService != null) {
            return originalService;
        }
        
        // 没有原始HTTP服务信息，优先用 SDK 的 url() 方法解析
        HttpRequest tempRequestInfo = HttpRequest.httpRequest(ByteArray.byteArray(requestBytes));
        try {
            String urlStr = tempRequestInfo.url();
            java.net.URL url = new java.net.URL(urlStr);
            String host = url.getHost();
            int port = url.getPort() == -1 ? url.getDefaultPort() : url.getPort();
            boolean isSecure = url.getProtocol().equalsIgnoreCase("https");
            return HttpService.httpService(host, port, isSecure);
        } catch (Exception e) {
            // SDK url() 失败，回退到从 Header 中提取
            List<String> headerStrings = convertHeadersToStringList(tempRequestInfo.headers());
            String host = extractHostFromHeaders(headerStrings);
            int port = extractPortFromHeaders(headerStrings);
            boolean isSecure = determineIsHttpsFromHeaders(headerStrings, port);
            return HttpService.httpService(host, port, isSecure);
        }
    }
    
    /**
     * 从 HTTP 头部列表中提取主机名（仅从PHost 头解析，不依赖请求行）
     */
    private String extractHostFromHeaders(List<String> headers) {
        for (String header : headers) {
            if (header.toLowerCase().startsWith("host:")) {
                String hostHeader = header.substring(5).trim();
                String[] hostParts = hostHeader.split(":");
                return hostParts[0];
            }
        }
        return "";
    }
    
    /**
     * 从 HTTP 头部列表中提取端口号（仅从 Host 头解析，不依赖请求行）
     */
    private int extractPortFromHeaders(List<String> headers) {
        for (String header : headers) {
            if (header.toLowerCase().startsWith("host:")) {
                String hostHeader = header.substring(5).trim();
                String[] hostParts = hostHeader.split(":");
                if (hostParts.length > 1) {
                    try {
                        return Integer.parseInt(hostParts[1]);
                    } catch (NumberFormatException e) {
                        // 忽略
                    }
                }
                break;
            }
        }
        return 80;
    }
    
    /**
     * 从 HTTP 头部列表判断是否为 HTTPS（仅从 Host 头和端口判断，不依赖请求行）
     */
    private boolean determineIsHttpsFromHeaders(List<String> headers, int port) {
        for (String header : headers) {
            if (header.toLowerCase().startsWith("host:")) {
                String hostValue = header.substring(5).trim();
                if (hostValue.endsWith(":443")) {
                    return true;
                }
                break;
            }
        }
        return port == 443;
    }
    
    /**
     * 通过代理发送HTTP请求
     * 使用java.net.HttpURLConnection通过指定代理发送请求，绕过Burp的请求管道
     *
     * @param requestBytes 原始请求字节数组
     * @param service HTTP服务信息
     * @param timeoutSeconds 超时时间(秒)
     * @return 响应字节数组（包含完整的HTTP响应：状态行+头+体），失败返回null
     */
    private byte[] makeHttpRequestWithProxy(byte[] requestBytes, HttpService service, int timeoutSeconds) {
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

            // 打开连接
            conn = (HttpURLConnection) url.openConnection(proxy);
            conn.setRequestMethod(method);
            conn.setConnectTimeout(timeoutSeconds * 1000);
            conn.setReadTimeout(timeoutSeconds * 1000);
            conn.setInstanceFollowRedirects(false);

            // 解析请求头（headers() 不含请求行，全部是标准 HTTP 头部）
            HttpRequest requestInfo = HttpRequest.httpRequest(service, ByteArray.byteArray(requestBytes));
            List<String> headers = convertHeadersToStringList(requestInfo.headers());
            boolean hasContentType = false;
            for (int i = 0; i < headers.size(); i++) {
                String header = headers.get(i);
                int colonIdx = header.indexOf(':');
                if (colonIdx > 0) {
                    String headerName = header.substring(0, colonIdx).trim();
                    String headerValue = header.substring(colonIdx + 1).trim();
                    // 跳过Host头（由URLConnection自动设置）和Proxy相关头
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

            // 判断是否有请求体
            int bodyOffset = findBodyOffset(requestBytes);
            boolean hasBody = bodyOffset > 0 && bodyOffset < requestBytes.length;
            boolean isBodyMethod = method.equalsIgnoreCase("POST") || method.equalsIgnoreCase("PUT") || method.equalsIgnoreCase("PATCH");

            if (hasBody) {
                conn.setDoOutput(true);
                if (!hasContentType) {
                    conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                }
            } else if (isBodyMethod) {
                // POST/PUT/PATCH 即使 body 为空，也必须调用 setDoOutput(true) 并显式写入空 body
                // 否则 HttpURLConnection 不会正确关闭输出流，代理会等待 body 数据直到超时（~10秒）
                conn.setDoOutput(true);
                conn.setFixedLengthStreamingMode(0);
            }

            // 发送请求
            conn.connect();

            if (hasBody) {
                byte[] bodyBytes = new byte[requestBytes.length - bodyOffset];
                System.arraycopy(requestBytes, bodyOffset, bodyBytes, 0, bodyBytes.length);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(bodyBytes);
                    os.flush();
                }
            } else if (isBodyMethod) {
                // 显式获取并关闭输出流，通知代理 body 传输完成
                try (OutputStream os = conn.getOutputStream()) {
                    os.flush();
                }
            }

            // 读取响应
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            int responseCode = conn.getResponseCode();
            String responseMessage = conn.getResponseMessage();

            // 构建状态行
            String statusLine = String.format("HTTP/1.1 %d %s\r\n", responseCode, responseMessage != null ? responseMessage : "");
            baos.write(statusLine.getBytes("UTF-8"));

            // 构建响应头
            for (Map.Entry<String, List<String>> entry : conn.getHeaderFields().entrySet()) {
                String headerName = entry.getKey();
                if (headerName == null) continue; // 跳过状态行
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
            }

            if (is != null) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesRead);
                }
                is.close();
            }

            byte[] response = baos.toByteArray();
            BurpExtender.printOutput(
                String.format("[D] 代理响应: HTTP %d, 响应总大小: %d 字节", responseCode, response.length));
            return response;

        } catch (Exception e) {
            BurpExtender.printError("[!] 代理请求失败: " + e.getMessage());
            return null;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    /**
     * 查找请求体起始偏移量
     * 在HTTP请求中，头部和正文之间以\r\n\r\n分隔
     *
     * @param requestBytes 原始请求字节数组
     * @return 请求体起始偏移量，如果没有正文则返回-1
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
     * 仅用于调试代理场景，生产环境慎用
     *
     * @param conn HTTPS连接对象
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
            BurpExtender.printError("[!] 设置SSL信任失败: " + e.getMessage());
        }
    }

    /**
     * 检测响应是否为 Burp Suite 内部错误响应。
     * Burp 使用特殊的状态码和协议标识来表示请求/响应层面的异常：
     * - HTTP/0.9 1337: 未收到有效的响应头（No response headers received）
     * - 状态码 0 或 超大状态码（>999）: 非标准 HTTP 响应
     *
     * @param statusCode 响应状态码
     * @param responseBytes 响应原始字节
     * @return true 如果是 Burp 错误响应
     */
    private boolean isBurpErrorResponse(int statusCode, byte[] responseBytes) {
        // 1337 是 Burp 的 "No response headers received" 错误码
        if (statusCode == 1337) {
            return true;
        }
        // 状态码超出标准 HTTP 范围 (100-599) 或为 0，表示非标准响应
        if (statusCode == 0 || statusCode > 999) {
            return true;
        }
        // 检查响应是否以 HTTP/0.9 开头（Burp 对无效响应的包装格式）
        if (responseBytes != null && responseBytes.length > 8) {
            String start = new String(responseBytes, 0, Math.min(responseBytes.length, 20),
                    java.nio.charset.StandardCharsets.ISO_8859_1);
            if (start.startsWith("HTTP/0.9")) {
                return true;
            }
        }
        return false;
    }

    /**
     * 关闭请求管理器，清理资源
     */
    public void shutdown() {
        // 关闭历史记录服务
        if (recordingService != null) {
            recordingService.shutdown();
        }
        
        // 关闭请求执行器
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /**
     * 将Montoya API的HttpHeader列表转换为字符串列表
     * 注意：Montoya SDK 的 headers() 返回的是纯 HTTP 头部，不包含请求行
     * 若需要请求行信息，应使用 method()、path()、httpVersion() 等方法单独获取
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
