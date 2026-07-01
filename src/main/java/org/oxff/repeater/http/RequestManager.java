package org.oxff.repeater.http;

import org.oxff.repeater.logging.LogManager;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.oxff.repeater.api.MontoyaApiHolder;
import org.oxff.repeater.service.HistoryRecordingService;

import burp.api.montoya.http.message.HttpHeader;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.List;
import java.util.concurrent.*;

/**
 * HTTP请求管理器类 - 负责发送请求和处理响应
 */
public class RequestManager {
    
    // 不再重试，单次请求直接返回结果（重试会导致请求耗时翻倍）
    private final ExecutorService executor;
    private final HistoryRecordingService recordingService;
    private final MontoyaApi api;
    private final ProxyHttpSender proxyHttpSender;
    
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
        this.proxyHttpSender = new ProxyHttpSender();

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
        return makeHttpRequest(requestBytes, timeoutSeconds, -1, null, false);
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
        return makeHttpRequest(requestBytes, timeoutSeconds, requestId, null, false);
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
        return makeHttpRequest(requestBytes, timeoutSeconds, requestId, httpService, false);
    }

    /**
     * 发送HTTP请求并返回响应（带历史记录、HTTP服务信息和HTTP/2标志）
     *
     * @param requestBytes 原始请求字节数组
     * @param timeoutSeconds 超时时间(秒)
     * @param requestId 关联的请求ID，用于历史记录
     * @param httpService 原始HTTP服务信息（包含正确的协议、主机、端口），可为null
     * @param useHttp2 是否使用HTTP/2协议发送请求
     * @return 响应字节数组，失败返回null
     */
    public byte[] makeHttpRequest(byte[] requestBytes, int timeoutSeconds, int requestId, HttpService httpService, boolean useHttp2) {
        if (requestBytes == null || requestBytes.length == 0) {
            LogManager.getInstance().printError("[!] 请求数据为空");
            return null;
        }

        // 构建HTTP服务对象和请求信息
        HttpService service = buildHttpService(requestBytes, httpService);
        HttpRequest requestInfo = HttpRequest.httpRequest(service, ByteArray.byteArray(requestBytes));

        logSendStart(service, useHttp2, timeoutSeconds);
        long startTime = System.currentTimeMillis();

        Future<byte[]> future = executor.submit(() -> {
            try {
                // 代理路径：委托给 ProxyHttpSender
                byte[] proxyResponse = tryProxySend(requestBytes, service, requestInfo, requestId, startTime, timeoutSeconds);
                if (proxyResponse != null) return proxyResponse;

                // 直接发送路径
                return doSendAndProcess(requestBytes, service, requestInfo, requestId, useHttp2, timeoutSeconds, startTime, null);
            } catch (Exception e) {
                long responseTime = System.currentTimeMillis() - startTime;
                LogManager.getInstance().printError("[!] 请求发送失败: " + e.getMessage());
                if (requestId > 0) {
                    recordingService.recordFailure(requestId, requestBytes, requestInfo,
                            "请求发送失败: " + e.getMessage(), responseTime, service);
                }
                return null;
            }
        });

        try {
            return future.get(timeoutSeconds, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            LogManager.getInstance().printError("[!] 请求超时 (" + timeoutSeconds + "秒)");
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LogManager.getInstance().printError("[!] 请求被中断: " + e.getMessage());
            return null;
        } catch (ExecutionException e) {
            LogManager.getInstance().printError("[!] 执行请求时出错: " + e.getMessage());
            return null;
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 未知错误: " + e.getMessage());
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
        makeHttpRequestAsync(requestBytes, timeoutSeconds, -1, null, false, callback);
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
        makeHttpRequestAsync(requestBytes, timeoutSeconds, requestId, null, false, callback);
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
        makeHttpRequestAsync(requestBytes, timeoutSeconds, requestId, httpService, false, callback);
    }

    /**
     * 异步发送HTTP请求（带历史记录、HTTP服务信息和HTTP/2标志）
     *
     * @param requestBytes 原始请求字节数组
     * @param timeoutSeconds 超时时间(秒)
     * @param requestId 关联的请求ID，用于历史记录
     * @param httpService 原始HTTP服务信息（包含正确的协议、主机、端口），可为null
     * @param useHttp2 是否使用HTTP/2协议发送请求
     * @param callback 请求回调接口
     */
    public void makeHttpRequestAsync(byte[] requestBytes, int timeoutSeconds, int requestId, 
                                      HttpService httpService, boolean useHttp2, RequestCallback callback) {
        if (requestBytes == null || requestBytes.length == 0) {
            LogManager.getInstance().printError("[!] 请求数据为空");
            if (callback != null) {
                callback.onFailure("请求数据为空", 0, 0, 0);
            }
            return;
        }

        // 在后台线程中执行请求
        executor.submit(() -> {
            final long startTime = System.currentTimeMillis();

            try {
                // 构建HTTP服务对象和请求信息
                HttpService service = buildHttpService(requestBytes, httpService);
                HttpRequest requestInfo = HttpRequest.httpRequest(service, ByteArray.byteArray(requestBytes));

                logSendStart(service, useHttp2, timeoutSeconds);

                // 代理路径：委托给 ProxyHttpSender
                byte[] proxyResponse = tryProxySend(requestBytes, service, requestInfo, requestId, startTime, timeoutSeconds);
                if (proxyResponse != null) {
                    if (proxyResponse.length > 0) {
                        LogManager.getInstance().printOutput(
                            String.format("[+] 代理请求成功完成，耗时: %d ms，响应大小: %d 字节",
                                System.currentTimeMillis() - startTime, proxyResponse.length));
                        if (callback != null) {
                            callback.onSuccess(proxyResponse, startTime, System.currentTimeMillis(),
                                    System.currentTimeMillis() - startTime);
                        }
                    }
                    return;
                }

                // 直接发送路径
                byte[] response = doSendAndProcess(requestBytes, service, requestInfo, requestId,
                        useHttp2, timeoutSeconds, startTime, callback);

                if (response != null && response.length > 0) {
                    LogManager.getInstance().printOutput(
                        String.format("[+] 请求成功完成，耗时: %d ms，响应大小: %d 字节",
                            System.currentTimeMillis() - startTime, response.length));
                    if (callback != null) {
                        callback.onSuccess(response, startTime, System.currentTimeMillis(),
                                System.currentTimeMillis() - startTime);
                    }
                } else if (callback != null) {
                    callback.onFailure("收到空响应", startTime, System.currentTimeMillis(),
                            System.currentTimeMillis() - startTime);
                }
            } catch (Exception e) {
                LogManager.getInstance().printError("[!] 发送请求时发生异常: " + e.getMessage());
                e.printStackTrace();

                long responseTime = System.currentTimeMillis() - startTime;
                if (requestId > 0) {
                    try {
                        HttpService service = buildHttpService(requestBytes, httpService);
                        HttpRequest requestInfo = HttpRequest.httpRequest(service, ByteArray.byteArray(requestBytes));
                        recordingService.recordFailure(requestId, requestBytes, requestInfo,
                                "发送请求时发生异常: " + e.getMessage(), responseTime, service);
                    } catch (Exception ex) {
                        LogManager.getInstance().printError("[!] 创建HTTP服务失败，使用基本请求分析: " + ex.getMessage());
                        HttpRequest requestInfo = HttpRequest.httpRequest(ByteArray.byteArray(requestBytes));
                        recordingService.recordFailure(requestId, requestBytes, requestInfo,
                                "发送请求时发生异常: " + e.getMessage(), responseTime);
                    }
                }

                if (callback != null) {
                    callback.onFailure("发送请求时发生异常: " + e.getMessage(), startTime,
                            System.currentTimeMillis(), responseTime);
                }
            }
        });
    }

    // ==================== 共享核心方法 ====================

    /**
     * 记录发送开始日志
     */
    private void logSendStart(HttpService service, boolean useHttp2, int timeoutSeconds) {
        LogManager.getInstance().printOutput(
            String.format("[*] 正在发送请求到 %s://%s:%d (协议: %s, 超时时间: %d秒)",
                service.secure() ? "https" : "http", service.host(), service.port(),
                useHttp2 ? "HTTP/2" : "HTTP/1.1", timeoutSeconds));
    }

    /**
     * 尝试通过代理发送请求。
     * @return null = 代理未启用（调用方继续直接发送）；非空 = 代理已处理（含失败时返回空数组）
     */
    private byte[] tryProxySend(byte[] requestBytes, HttpService service, HttpRequest requestInfo,
                                 int requestId, long startTime, int timeoutSeconds) {
        ProxyConfig proxyConfig = ProxyConfig.getInstance();
        if (!proxyConfig.isProxyEnabled()) {
            return null;
        }

        LogManager.getInstance().printOutput(
            String.format("[D] 通过代理 %s:%d 发送请求",
                proxyConfig.getProxyHost(), proxyConfig.getProxyPort()));

        byte[] proxyResponse = proxyHttpSender.send(requestBytes, service, timeoutSeconds);
        long responseTime = System.currentTimeMillis() - startTime;

        if (proxyResponse != null && proxyResponse.length > 0) {
            HttpResponse httpResponse = HttpResponse.httpResponse(ByteArray.byteArray(proxyResponse));
            if (requestId > 0) {
                recordingService.recordSuccess(requestId, requestBytes, proxyResponse,
                    requestInfo, httpResponse, responseTime, service);
            }
            return proxyResponse;
        } else {
            LogManager.getInstance().printError("[!] 代理请求返回空响应");
            if (requestId > 0) {
                recordingService.recordFailure(requestId, requestBytes, requestInfo,
                    "代理请求返回空响应", responseTime, service);
            }
            return new byte[0];
        }
    }

    /**
     * 直接发送HTTP请求并处理响应（含HTTP/2回退、Burp错误检测、历史记录）
     */
    private byte[] doSendAndProcess(byte[] requestBytes, HttpService service, HttpRequest requestInfo,
                                     int requestId, boolean useHttp2, int timeoutSeconds,
                                     long startTime, RequestCallback callback) throws Exception {
        // 修正 Content-Length
        byte[] fixedBytes = RequestDataHelper.fixContentLength(requestBytes, service);

        // 构建请求
        HttpRequest requestToSend = buildRequestToSend(service, fixedBytes, useHttp2);

        // 带超时的发送
        HttpRequestResponse requestResponse = sendWithTimeout(requestToSend, timeoutSeconds);
        long responseTime = System.currentTimeMillis() - startTime;

        // 检查空响应
        if (requestResponse == null || requestResponse.response() == null) {
            if (useHttp2) {
                LogManager.getInstance().printOutput("[*] HTTP/2 请求未收到响应，尝试回退到 HTTP/1.1");
                HttpRequest http1Request = buildRequestToSend(service, fixedBytes, false);
                requestResponse = sendWithTimeout(http1Request, timeoutSeconds);
                responseTime = System.currentTimeMillis() - startTime;
                if (requestResponse == null || requestResponse.response() == null) {
                    recordAndCallback(requestId, fixedBytes, requestInfo,
                        "HTTP/2 回退后仍未收到响应", responseTime, service, callback, startTime);
                    return null;
                }
            } else {
                recordAndCallback(requestId, fixedBytes, requestInfo,
                    "未收到响应（目标可能不可达或连接被拒绝）", responseTime, service, callback, startTime);
                return null;
            }
        }

        byte[] response = requestResponse.response().toByteArray().getBytes();

        // HTTP/2 空响应回退
        if (response == null || response.length == 0) {
            if (useHttp2) {
                LogManager.getInstance().printOutput("[*] HTTP/2 请求返回空响应，自动回退到 HTTP/1.1 重试");
                HttpRequest http1Request = buildRequestToSend(service, fixedBytes, false);
                requestResponse = sendWithTimeout(http1Request, timeoutSeconds);
                responseTime = System.currentTimeMillis() - startTime;
                if (requestResponse != null && requestResponse.response() != null) {
                    response = requestResponse.response().toByteArray().getBytes();
                }
            }
        }

        // 处理最终响应
        if (response != null && response.length > 0) {
            HttpResponse httpResponse = HttpResponse.httpResponse(ByteArray.byteArray(response));
            int statusCode = httpResponse.statusCode();
            if (isBurpErrorResponse(statusCode, response)) {
                String errorMsg = String.format(
                    "服务器返回异常响应 (HTTP %d)，可能是请求格式错误或目标不支持", statusCode);
                LogManager.getInstance().printError("[!] " + errorMsg);
                if (requestId > 0) {
                    recordingService.recordFailure(requestId, fixedBytes, requestInfo,
                        errorMsg, responseTime, service);
                }
                if (callback != null) {
                    callback.onFailure(errorMsg, startTime, System.currentTimeMillis(), responseTime);
                }
                return null;
            }
            if (requestId > 0) {
                recordingService.recordSuccess(requestId, fixedBytes, response,
                    requestInfo, httpResponse, responseTime, service);
            }
            return response;
        } else {
            recordAndCallback(requestId, fixedBytes, requestInfo,
                "收到空响应", responseTime, service, callback, startTime);
            return null;
        }
    }

    /**
     * 带超时控制的HTTP请求发送（Thread+join模式）
     */
    private HttpRequestResponse sendWithTimeout(HttpRequest requestToSend, int timeoutSeconds) throws Exception {
        final HttpRequestResponse[] resultHolder = {null};
        final Exception[] errorHolder = {null};
        Thread sendThread = new Thread(() -> {
            try {
                resultHolder[0] = api.http().sendRequest(requestToSend);
            } catch (Exception ex) {
                errorHolder[0] = ex;
            }
        }, "RepeaterManager-HttpSend");
        sendThread.setDaemon(true);
        sendThread.start();

        long sendTimeoutMs = (timeoutSeconds + 10) * 1000L;
        sendThread.join(sendTimeoutMs);

        if (sendThread.isAlive()) {
            sendThread.interrupt();
            return null; // timeout
        }

        if (errorHolder[0] != null) {
            throw errorHolder[0];
        }

        return resultHolder[0];
    }

    /**
     * 记录历史失败 + 可选回调通知
     */
    private void recordAndCallback(int requestId, byte[] fixedBytes, HttpRequest requestInfo,
                                    String errorMsg, long responseTime, HttpService service,
                                    RequestCallback callback, long startTime) {
        LogManager.getInstance().printError("[!] " + errorMsg);
        if (requestId > 0) {
            recordingService.recordFailure(requestId, fixedBytes, requestInfo,
                errorMsg, responseTime, service);
        }
        if (callback != null) {
            callback.onFailure(errorMsg, startTime, System.currentTimeMillis(), responseTime);
        }
    }

    /**
     * 根据协议版本构建要发送的HttpRequest
     * HTTP/2请求使用 http2Request 构建，包含伪头部和独立的headers/body；
     * HTTP/1请求使用 httpRequest 构建（现有逻辑）
     *
     * @param service HTTP服务信息（host/port/secure）
     * @param requestBytes 请求数据字节数组
     * @param useHttp2 是否使用HTTP/2协议
     * @return 构建好的HttpRequest对象
     */

    /**
     * HTTP/2 中不应出现的 HTTP/1 专有头部名称集合
     * 这些头部在 HTTP/2 中被伪头部替代，需从 headers 列表中移除
     */
    private static final Set<String> HTTP1_EXCLUSIVE_HEADERS = new HashSet<>(Arrays.asList(
            "host", "connection", "transfer-encoding", "upgrade", "keep-alive", "proxy-connection"));

    private HttpRequest buildRequestToSend(HttpService service, byte[] requestBytes, boolean useHttp2) {
        if (useHttp2) {
            // HTTP/2: 先用 HTTP/1 解析出请求信息，再构造伪头部 + 普通头部，用 http2Request 重建
            HttpRequest tempRequest = HttpRequest.httpRequest(service, ByteArray.byteArray(requestBytes));

            // 提取 HTTP/2 伪头部所需的元数据
            String method = tempRequest.method();
            String pathWithQuery = tempRequest.path(); // 包含查询参数
            String scheme = service.secure() ? "https" : "http";
            String authority = service.host();
            int port = service.port();
            // 非标准端口需要附加到 authority 中
            if ((service.secure() && port != 443) || (!service.secure() && port != 80)) {
                authority = authority + ":" + port;
            }

            // 构建 HTTP/2 headers 列表：伪头部在前，然后是普通头部（移除 HTTP/1 专有头部）
            List<HttpHeader> http2Headers = new ArrayList<>();
            http2Headers.add(HttpHeader.httpHeader(":method", method));
            http2Headers.add(HttpHeader.httpHeader(":path", pathWithQuery));
            http2Headers.add(HttpHeader.httpHeader(":scheme", scheme));
            http2Headers.add(HttpHeader.httpHeader(":authority", authority));

            // 添加普通头部（跳过 HTTP/1 专有头部，如 Host 被 :authority 替代）
            for (HttpHeader header : tempRequest.headers()) {
                if (!HTTP1_EXCLUSIVE_HEADERS.contains(header.name().toLowerCase())) {
                    http2Headers.add(header);
                }
            }

            ByteArray body = tempRequest.body();
            return HttpRequest.http2Request(service, http2Headers, body);
        } else {
            // HTTP/1: 使用标准 httpRequest 构建
            return HttpRequest.httpRequest(service, ByteArray.byteArray(requestBytes));
        }
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
    static List<String> convertHeadersToStringList(List<burp.api.montoya.http.message.HttpHeader> rawHeaders) {
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
