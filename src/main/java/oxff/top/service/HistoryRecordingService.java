package oxff.top.service;

import burp.BurpExtender;
import burp.IRequestInfo;
import burp.IResponseInfo;
import oxff.top.db.HistoryDAO;
import oxff.top.db.DatabaseManager;
import oxff.top.http.RequestResponseRecord;
import java.util.Date;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 历史记录录制服务 - 统一管理HTTP请求响应的历史记录
 * 确保所有HTTP请求都能被记录到历史表中，无论成功或失败
 */
public class HistoryRecordingService {
    private static HistoryRecordingService instance;
    private final HistoryDAO historyDAO;
    private final ExecutorService executor;
    private final BlockingQueue<RecordingTask> pendingTasks;
    private final AtomicBoolean isRunning;
    
    /**
     * 录制任务
     */
    private static class RecordingTask {
        final RequestResponseRecord record;
        final RecordingCallback callback;
        
        RecordingTask(RequestResponseRecord record, RecordingCallback callback) {
            this.record = record;
            this.callback = callback;
        }
    }
    
    /**
     * 录制回调接口
     */
    public interface RecordingCallback {
        void onSuccess(int historyId);
        void onFailure(String error);
    }
    
    private HistoryRecordingService() {
        this.historyDAO = new HistoryDAO();
        this.pendingTasks = new LinkedBlockingQueue<>();
        this.isRunning = new AtomicBoolean(true);
        
        // 创建后台线程池处理录制任务
        this.executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "HistoryRecordingService");
            t.setDaemon(true);
            return t;
        });
        
        // 启动后台录制线程
        startRecordingThread();
    }
    
    /**
     * 获取单例实例
     */
    public static synchronized HistoryRecordingService getInstance() {
        if (instance == null) {
            instance = new HistoryRecordingService();
        }
        return instance;
    }
    
    /**
     * 启动后台录制线程
     */
    private void startRecordingThread() {
        executor.submit(() -> {
            while (isRunning.get()) {
                try {
                    RecordingTask task = pendingTasks.poll(1, TimeUnit.SECONDS);
                    if (task != null) {
                        processRecordingTask(task);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    BurpExtender.printError("[!] 录制任务处理异常: " + e.getMessage());
                }
            }
        });
    }
    
    /**
     * 处理录制任务
     */
    private void processRecordingTask(RecordingTask task) {
        try {
            // 验证数据库连接
            if (!DatabaseManager.getInstance().isConnectionValid()) {
                BurpExtender.printError("[!] 数据库连接无效，跳过历史记录保存");
                if (task.callback != null) {
                    task.callback.onFailure("数据库连接无效");
                }
                return;
            }
            
            // 保存历史记录
            int historyId = historyDAO.saveHistory(task.record);
            
            if (historyId > 0) {
                BurpExtender.printOutput("[+] 历史记录保存成功，ID: " + historyId);
                if (task.callback != null) {
                    task.callback.onSuccess(historyId);
                }
            } else {
                BurpExtender.printError("[!] 历史记录保存失败");
                if (task.callback != null) {
                    task.callback.onFailure("保存失败");
                }
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 处理录制任务失败: " + e.getMessage());
            if (task.callback != null) {
                task.callback.onFailure("处理失败: " + e.getMessage());
            }
        }
    }
    
    /**
     * 记录成功的HTTP请求响应
     */
    public void recordSuccess(int requestId, byte[] requestBytes, byte[] responseBytes, 
                             IRequestInfo requestInfo, IResponseInfo responseInfo, long responseTime) {
        try {
            // 创建历史记录
            RequestResponseRecord record = createRecordFromRequest(requestId, requestInfo);
            record.setStatusCode(responseInfo.getStatusCode());
            record.setResponseLength(responseBytes != null ? responseBytes.length : 0);
            record.setResponseTime((int) responseTime);
            record.setRequestData(requestBytes);
            record.setResponseData(responseBytes);
            record.setTimestamp(new Date());
            
            // 异步提交录制任务
            RecordingTask task = new RecordingTask(record, new RecordingCallback() {
                @Override
                public void onSuccess(int historyId) {
                    if (requestId <= 0) {
                        BurpExtender.printOutput("[+] HTTP请求历史记录已保存（未保存请求），ID: " + historyId);
                    } else {
                        BurpExtender.printOutput("[+] HTTP请求历史记录已保存（关联请求ID: " + requestId + "），ID: " + historyId);
                    }
                }
                
                @Override
                public void onFailure(String error) {
                    BurpExtender.printError("[!] HTTP请求历史记录保存失败: " + error);
                }
            });
            
            if (!pendingTasks.offer(task)) {
                BurpExtender.printError("[!] 历史记录任务队列已满，无法添加任务");
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 创建HTTP成功历史记录失败: " + e.getMessage());
        }
    }
    
    /**
     * 记录失败的HTTP请求
     */
    public void recordFailure(int requestId, byte[] requestBytes, IRequestInfo requestInfo, 
                             String errorMessage, long responseTime) {
        try {
            // 创建历史记录
            RequestResponseRecord record = createRecordFromRequest(requestId, requestInfo);
            record.setStatusCode(0); // 失败状态码设为0
            record.setResponseLength(0);
            record.setResponseTime((int) responseTime);
            record.setRequestData(requestBytes);
            record.setResponseData(null);
            record.setTimestamp(new Date());
            record.setComment("请求失败: " + errorMessage);
            
            // 异步提交录制任务
            RecordingTask task = new RecordingTask(record, new RecordingCallback() {
                @Override
                public void onSuccess(int historyId) {
                    if (requestId <= 0) {
                        BurpExtender.printOutput("[+] HTTP失败请求历史记录已保存（未保存请求），ID: " + historyId);
                    } else {
                        BurpExtender.printOutput("[+] HTTP失败请求历史记录已保存（关联请求ID: " + requestId + "），ID: " + historyId);
                    }
                }
                
                @Override
                public void onFailure(String error) {
                    BurpExtender.printError("[!] HTTP失败请求历史记录保存失败: " + error);
                }
            });
            
            if (!pendingTasks.offer(task)) {
                BurpExtender.printError("[!] 历史记录任务队列已满，无法添加任务");
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 创建HTTP失败历史记录失败: " + e.getMessage());
        }
    }
    
    /**
     * 从请求信息创建记录
     */
    private RequestResponseRecord createRecordFromRequest(int requestId, IRequestInfo requestInfo) {
        try {
            // 尝试使用Burp的URL解析
            java.net.URL url = requestInfo.getUrl();
            if (url != null && url.getHost() != null && !url.getHost().isEmpty()) {
                String protocol = url.getProtocol();
                String host = url.getHost();
                String path = url.getPath() != null ? url.getPath() : "/";
                String query = url.getQuery() != null ? url.getQuery() : "";
                String method = requestInfo.getMethod();
                
                return new RequestResponseRecord(requestId, protocol, host, path, query, method);
            }
            
            // 如果Burp的URL解析不完整，使用增强的备用方法
            return createRecordFromRequestFallback(requestId, requestInfo);
            
        } catch (Exception e) {
            // 如果标准URL解析失败，使用备用方法
            BurpExtender.printOutput("[*] 使用备用方法解析URL创建历史记录: " + e.getMessage());
            return createRecordFromRequestFallback(requestId, requestInfo);
        }
    }
    
    /**
     * 增强的备用URL解析方法
     */
    private RequestResponseRecord createRecordFromRequestFallback(int requestId, IRequestInfo requestInfo) {
        String method = requestInfo.getMethod();
        List<String> headers = requestInfo.getHeaders();
        
        if (headers == null || headers.isEmpty()) {
            return new RequestResponseRecord(requestId, "http", "unknown", "/", "", method);
        }
        
        String firstLine = headers.get(0);
        String[] parts = firstLine.split("\\s+");
        
        if (parts.length < 2) {
            return new RequestResponseRecord(requestId, "http", "unknown", "/", "", method);
        }
        
        String urlPart = parts[1];
        String protocol = "http";
        String host = "";
        String path = "/";
        String query = "";
        
        // 尝试解析完整URL
        if (urlPart.startsWith("http://") || urlPart.startsWith("https://")) {
            try {
                java.net.URL parsedUrl = new java.net.URL(urlPart);
                protocol = parsedUrl.getProtocol();
                host = parsedUrl.getHost();
                path = parsedUrl.getPath() != null ? parsedUrl.getPath() : "/";
                query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";
                
                // 验证主机名有效性
                if (host != null && !host.isEmpty() && !host.equals("unknown")) {
                    return new RequestResponseRecord(requestId, protocol, host, path, query, method);
                }
            } catch (Exception ex) {
                // 解析失败，继续尝试其他方法
                BurpExtender.printOutput("[*] 完整URL解析失败，尝试从Host头解析: " + ex.getMessage());
            }
        }
        
        // 从Host头获取主机信息
        host = extractHostFromHeaders(headers);
        
        // 如果Host头解析成功，解析路径和查询参数
        if (host != null && !host.isEmpty() && !host.equals("unknown")) {
            // 确定协议（基于端口或默认）
            protocol = determineProtocolFromHeaders(headers, host);
            
            // 解析路径和查询参数
            if (urlPart.startsWith("http://") || urlPart.startsWith("https://")) {
                // 已经尝试过完整URL解析，失败的情况下可能是URL格式有问题
                path = "/";
            } else {
                // 相对路径，直接使用
                int queryIndex = urlPart.indexOf('?');
                if (queryIndex > 0) {
                    path = urlPart.substring(0, queryIndex);
                    query = urlPart.substring(queryIndex + 1);
                } else {
                    path = urlPart;
                }
            }
            
            // 确保路径不为空
            if (path == null || path.isEmpty()) {
                path = "/";
            }
            
            return new RequestResponseRecord(requestId, protocol, host, path, query, method);
        }
        
        // 最后的备用方案
        return new RequestResponseRecord(requestId, "http", "unknown", "/", "", method);
    }
    
    /**
     * 从请求头提取主机名
     */
    private String extractHostFromHeaders(List<String> headers) {
        for (String header : headers) {
            if (header.toLowerCase().startsWith("host:")) {
                String hostHeader = header.substring(5).trim();
                if (hostHeader.isEmpty()) {
                    continue;
                }
                
                // 移除端口号
                int colonIndex = hostHeader.indexOf(':');
                if (colonIndex > 0) {
                    hostHeader = hostHeader.substring(0, colonIndex);
                }
                
                // 验证主机名格式
                if (hostHeader.matches("^[a-zA-Z0-9.-]+$")) {
                    return hostHeader;
                }
            }
        }
        return "unknown";
    }
    
    /**
     * 从请求头确定协议
     */
    private String determineProtocolFromHeaders(List<String> headers, String host) {
        // 检查Host头中的端口
        for (String header : headers) {
            if (header.toLowerCase().startsWith("host:")) {
                String hostHeader = header.substring(5).trim();
                if (hostHeader.contains(":443")) {
                    return "https";
                }
                break;
            }
        }
        
        // 检查其他可能指示HTTPS的头部
        for (String header : headers) {
            String lowerHeader = header.toLowerCase();
            if (lowerHeader.startsWith("x-forwarded-proto:")) {
                String proto = header.substring("x-forwarded-proto:".length()).trim();
                if ("https".equals(proto)) {
                    return "https";
                }
            }
        }
        
        // 默认HTTP
        return "http";
    }
    
    /**
     * 关闭服务
     */
    public void shutdown() {
        isRunning.set(false);
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