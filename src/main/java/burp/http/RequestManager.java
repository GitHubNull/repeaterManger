package burp.http;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import java.util.List;
import java.util.concurrent.*;

/**
 * HTTP请求管理器类 - 负责发送请求和处理响应
 */
public class RequestManager {
    
    private static final int MAX_RETRIES = 3;
    private final ExecutorService executor;
    
    /**
     * 创建请求管理器
     */
    public RequestManager() {
        // 创建线程池执行器，避免阻塞UI线程
        executor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "EnhancedRepeater-RequestThread");
            t.setDaemon(true);
            return t;
        });
    }
    
    /**
     * 发送HTTP请求并返回响应
     * 
     * @param requestBytes 原始请求字节数组
     * @param timeoutSeconds 超时时间(秒)
     * @return 响应字节数组，失败返回null
     */
    public byte[] makeHttpRequest(byte[] requestBytes, int timeoutSeconds) {
        if (requestBytes == null || requestBytes.length == 0) {
            BurpExtender.printError("[!] 请求数据为空");
            return null;
        }
        
        // 解析请求信息
        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(requestBytes);
        
        // 提取主机和端口信息
        String host = getHostFromRequest(requestInfo);
        int port = getPortFromRequest(requestInfo);
        boolean isSecure = isHttpsRequest(requestInfo, port);
        
        // 创建HTTP服务对象
        IHttpService httpService = BurpExtender.helpers.buildHttpService(
                host, port, isSecure);
        
        BurpExtender.printOutput(
            String.format("[*] 正在发送请求到 %s://%s:%d (超时时间: %d秒)", 
                isSecure ? "https" : "http", host, port, timeoutSeconds));
        
        // 创建Future任务
        Future<byte[]> future = executor.submit(() -> {
            // 重试机制
            for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
                try {
                    if (attempt > 0) {
                        // 非首次尝试，输出重试信息
                        BurpExtender.printOutput(
                            String.format("[*] 第%d次重试发送请求...", attempt + 1));
                        // 指数退避策略
                        Thread.sleep(1000 * (1 << attempt));
                    }
                    
                    // 创建请求对象
                    IHttpRequestResponse requestResponse = 
                        BurpExtender.callbacks.makeHttpRequest(httpService, requestBytes);
                    
                    // 获取响应数据
                    byte[] response = requestResponse.getResponse();
                    
                    if (response != null && response.length > 0) {
                        return response;
                    } else {
                        BurpExtender.printError("[!] 收到空响应，准备重试...");
                    }
                } catch (Exception e) {
                    BurpExtender.printError("[!] 请求发送失败: " + e.getMessage());
                }
            }
            
            BurpExtender.printError("[!] 达到最大重试次数，请求失败");
            return null;
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
     * 从请求头提取主机名
     */
    private String extractHost(List<String> headers) {
        // 首先检查第一行的URL
        String firstLine = headers.get(0);
        String[] parts = firstLine.split("\\s+");
        
        if (parts.length >= 2) {
            String urlPart = parts[1];
            if (urlPart.startsWith("http://") || urlPart.startsWith("https://")) {
                try {
                    java.net.URL url = new java.net.URL(urlPart);
                    return url.getHost();
                } catch (Exception e) {
                    // 如果URL解析失败，继续尝试Host头
                }
            }
        }
        
        // 从Host头中提取
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
     * 从请求头提取端口号
     */
    private int extractPort(List<String> headers, String host) {
        // 默认端口
        int port = 80;
        
        // 首先检查第一行的URL
        String firstLine = headers.get(0);
        String[] parts = firstLine.split("\\s+");
        
        if (parts.length >= 2) {
            String urlPart = parts[1];
            if (urlPart.startsWith("http://") || urlPart.startsWith("https://")) {
                try {
                    java.net.URL url = new java.net.URL(urlPart);
                    if (url.getPort() != -1) {
                        return url.getPort();
                    } else {
                        return url.getDefaultPort();
                    }
                } catch (Exception e) {
                    // 如果URL解析失败，继续尝试Host头
                }
            }
        }
        
        // 从Host头中提取端口
        for (String header : headers) {
            if (header.toLowerCase().startsWith("host:")) {
                String hostHeader = header.substring(5).trim();
                String[] hostParts = hostHeader.split(":");
                
                if (hostParts.length > 1) {
                    try {
                        port = Integer.parseInt(hostParts[1]);
                    } catch (NumberFormatException e) {
                        // 忽略端口解析错误，使用默认端口
                    }
                }
                break;
            }
        }
        
        // 根据是否为HTTPS设置默认端口
        if (determineIsHttps(headers, port) && port == 80) {
            port = 443;
        }
        
        return port;
    }
    
    /**
     * 判断是否为HTTPS请求
     */
    private boolean determineIsHttps(List<String> headers, int port) {
        // 首先检查第一行是否包含HTTPS
        String firstLine = headers.get(0);
        if (firstLine.contains("https://")) {
            return true;
        }
        
        // 然后根据端口判断
        return port == 443;
    }
    
    /**
     * 从请求信息中提取主机名
     */
    private String getHostFromRequest(IRequestInfo requestInfo) {
        return extractHost(requestInfo.getHeaders());
    }
    
    /**
     * 从请求信息中提取端口号
     */
    private int getPortFromRequest(IRequestInfo requestInfo) {
        return extractPort(requestInfo.getHeaders(), getHostFromRequest(requestInfo));
    }
    
    /**
     * 判断是否为HTTPS请求
     */
    private boolean isHttpsRequest(IRequestInfo requestInfo, int port) {
        return determineIsHttps(requestInfo.getHeaders(), port);
    }
    
    /**
     * 关闭请求管理器，清理资源
     */
    public void shutdown() {
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
} 