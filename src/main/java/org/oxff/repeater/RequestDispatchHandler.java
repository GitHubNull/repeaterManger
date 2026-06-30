package org.oxff.repeater;

import org.oxff.repeater.logging.LogManager;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.oxff.repeater.db.history.HistoryWriteDAO;
import org.oxff.repeater.http.HttpRequestHelper;
import org.oxff.repeater.http.RequestDataHelper;
import org.oxff.repeater.http.RequestManager;
import org.oxff.repeater.http.RequestResponseRecord;
import org.oxff.repeater.privilege.ReplayEngine;
import org.oxff.repeater.privilege.ScopeManager;
import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.model.JudgmentResult;
import org.oxff.repeater.ui.editor.BurpRequestPanel;
import org.oxff.repeater.ui.editor.BurpResponsePanel;
import org.oxff.repeater.ui.history.HistoryPanel;
import org.oxff.repeater.ui.RequestListPanel;
import org.oxff.repeater.ui.StatusPanel;

import javax.swing.*;
import java.awt.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 请求调度处理器 - 管理HTTP请求发送、响应处理和历史记录更新
 * 从 RepeaterManagerUI 中提取的请求处理逻辑
 */
public class RequestDispatchHandler {

    // UI组件引用
    private final JPanel mainPanel;
    private final BurpRequestPanel requestPanel;
    private final BurpResponsePanel responsePanel;
    private final HistoryPanel historyPanel;
    private final RequestListPanel requestListPanel;
    private final StatusPanel statusPanel;

    // 功能组件
    private final RequestManager requestManager;

    // 后台持久化线程池（将DB写操作从EDT卸载到后台，避免UI阻塞）
    private final ExecutorService dbPersistExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "PrivilegeTest-DBPersist");
        t.setDaemon(true);
        return t;
    });

    // 当前请求状态（volatile: 后台线程写/EDT线程读，保证可见性）
    private volatile int currentRequestId = -1;
    private volatile HttpService currentHttpService = null;

    // 权限测试模式状态（volatile: 多线程读写，保证可见性）
    private volatile boolean privilegeTestMode = false;

    // 模式变更监听器列表
    private final List<ModeChangeListener> modeListeners = new ArrayList<>();

    /**
     * 模式变更监听器接口
     */
    public interface ModeChangeListener {
        void onModeChanged(boolean privilegeTestMode);
    }

    // 请求历史记录映射: 请求ID -> 历史记录列表（ConcurrentHashMap: 多线程并发读写安全）
    private final Map<Integer, List<RequestResponseRecord>> requestHistoryMap = new ConcurrentHashMap<>();

    // 请求ID -> HttpService映射: 保存每个请求的原始HttpService（含正确的协议、主机、端口）
    // 避免从数据库/Host头重建时丢失非标准端口（如9527）
    // ConcurrentHashMap: 后台线程和EDT线程并发访问
    private final Map<Integer, HttpService> httpServiceMap = new ConcurrentHashMap<>();

    // 请求ID -> 是否使用HTTP/2映射: 跟踪每个请求的原始协议版本
    // 避免重放HTTP/2请求时降级为HTTP/1.1
    // ConcurrentHashMap: 后台线程和EDT线程并发访问
    private final Map<Integer, Boolean> httpVersionMap = new ConcurrentHashMap<>();

    /**
     * 创建请求调度处理器
     */
    public RequestDispatchHandler(JPanel mainPanel,
                                   BurpRequestPanel requestPanel,
                                   BurpResponsePanel responsePanel,
                                   HistoryPanel historyPanel,
                                   RequestListPanel requestListPanel,
                                   StatusPanel statusPanel,
                                   RequestManager requestManager) {
        this.mainPanel = mainPanel;
        this.requestPanel = requestPanel;
        this.responsePanel = responsePanel;
        this.historyPanel = historyPanel;
        this.requestListPanel = requestListPanel;
        this.statusPanel = statusPanel;
        this.requestManager = requestManager;
    }

    public void setCurrentRequestId(int requestId) {
        this.currentRequestId = requestId;
    }

    public int getCurrentRequestId() {
        return currentRequestId;
    }

    public void setCurrentHttpService(HttpService httpService) {
        this.currentHttpService = httpService;
    }

    public HttpService getCurrentHttpService() {
        return currentHttpService;
    }

    public void setPrivilegeTestMode(boolean enabled) {
        if (this.privilegeTestMode == enabled) {
            return; // no-op guard
        }
        this.privilegeTestMode = enabled;

        // 联动代理监听器：开启越权模式时自动注册ProxyRequestHandler监听代理流量，
        // 关闭时自动注销。ProxyRequestHandler使用continueWith()不做任何阻断，
        // 仅将匹配Scope的流量副本提交给AutoTestEngine进行越权重放测试。
        // 注意：批量权限测试(setPrivilegeTestRequests)会先setPrivilegeTestMode(false)再setPrivilegeTestMode(true)，
        // 短暂注销-重注册是预期行为——避免批量处理期间代理监听器与手动触发的重放产生竞争。
        try {
            ScopeManager.getInstance().setAutoTestEnabled(enabled);
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 联动代理监听器失败: " + e.getMessage());
        }

        // 模式变更监听器在EDT上通知，避免在后台线程中直接操作Swing组件
        fireModeChanged(enabled);
    }

    public boolean isPrivilegeTestMode() {
        return privilegeTestMode;
    }

    public void addModeChangeListener(ModeChangeListener listener) {
        if (listener != null) {
            modeListeners.add(listener);
        }
    }

    public void removeModeChangeListener(ModeChangeListener listener) {
        modeListeners.remove(listener);
    }

    private void fireModeChanged(boolean newMode) {
        for (ModeChangeListener listener : modeListeners) {
            try {
                listener.onModeChanged(newMode);
            } catch (Exception e) {
                LogManager.getInstance().printError("[!] 模式变更监听器异常: " + e.getMessage());
            }
        }
    }

    public Map<Integer, List<RequestResponseRecord>> getRequestHistoryMap() {
        return requestHistoryMap;
    }

    /**
     * 保存请求ID对应的HttpService（含正确端口信息）
     */
    public void saveHttpService(int requestId, HttpService httpService) {
        if (requestId >= 0 && httpService != null) {
            httpServiceMap.put(requestId, httpService);
        }
    }

    /**
     * 获取请求ID对应的已保存HttpService
     * @return 已保存的HttpService，如果不存在返回null
     */
    public HttpService getSavedHttpService(int requestId) {
        return httpServiceMap.get(requestId);
    }

    /**
     * 保存请求ID对应的HTTP协议版本标志
     * @param requestId 请求ID
     * @param isHttp2 是否为HTTP/2协议
     */
    public void saveHttpVersion(int requestId, boolean isHttp2) {
        if (requestId >= 0) {
            httpVersionMap.put(requestId, isHttp2);
        }
    }

    /**
     * 获取请求ID对应的HTTP协议版本标志
     * @return true表示使用HTTP/2，false或不存表示HTTP/1.1
     */
    public boolean isHttp2(int requestId) {
        return httpVersionMap.getOrDefault(requestId, false);
    }

    /**
     * 发送当前请求
     * 如果处于权限测试模式，调用ReplayEngine进行多用户重放
     */
    public void sendRequest() {
        try {
            byte[] requestBytes = requestPanel.getRequest();
            if (requestBytes == null || requestBytes.length == 0) {
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(mainPanel,
                        "请求不能为空", "错误", JOptionPane.ERROR_MESSAGE);
                });
                return;
            }

            // 统一在发送前修正 Content-Length，使 DB 与 UI 使用同一份修正后的字节（BUG-006）
            // fixContentLength 为幂等操作，RequestManager 内部的重复调用不会产生副作用
            final byte[] finalRequestBytes;
            if (currentHttpService != null) {
                finalRequestBytes = RequestDataHelper.fixContentLength(requestBytes, currentHttpService);
            } else {
                finalRequestBytes = requestBytes;
            }

            // 权限测试模式：调用ReplayEngine
            if (privilegeTestMode) {
                sendPrivilegeTestRequest(finalRequestBytes);
                return;
            }

            LogManager.getInstance().printOutput("[*] 正在发送请求...");
            responsePanel.clear();

            int timeout = requestPanel.getTimeout();

            SwingUtilities.invokeLater(() -> {
                setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
            });

            requestManager.makeHttpRequestAsync(finalRequestBytes, timeout, currentRequestId, currentHttpService, isHttp2(currentRequestId), new RequestManager.RequestCallback() {
                @Override
                public void onSuccess(byte[] response, long requestTimeMs, long responseTimeMs, long durationMs) {
                    SwingUtilities.invokeLater(() -> {
                        try {
                            handleResponseSuccess(finalRequestBytes, response, requestTimeMs, responseTimeMs, durationMs);
                        } catch (Exception ex) {
                            LogManager.getInstance().printError("[!] 处理响应时发生异常: " + ex.getMessage());
                            JOptionPane.showMessageDialog(mainPanel,
                                "处理响应时出错: " + ex.getMessage(),
                                "响应处理异常",
                                JOptionPane.ERROR_MESSAGE);
                        } finally {
                            setCursor(Cursor.getDefaultCursor());
                        }
                    });
                }

                @Override
                public void onFailure(String errorMessage, long requestTimeMs, long responseTimeMs, long durationMs) {
                    SwingUtilities.invokeLater(() -> {
                        try {
                            handleResponseFailure(finalRequestBytes, errorMessage, requestTimeMs, responseTimeMs, durationMs);
                            LogManager.getInstance().printError("[!] 请求失败: " + errorMessage);
                            JOptionPane.showMessageDialog(mainPanel,
                                "请求失败或超时，未收到响应数据: " + errorMessage,
                                "请求错误",
                                JOptionPane.ERROR_MESSAGE);
                        } finally {
                            setCursor(Cursor.getDefaultCursor());
                        }
                    });
                }
            });

        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 准备请求时发生错误: " + e.getMessage());
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(mainPanel,
                    "准备请求时出错: " + e.getMessage(),
                    "请求异常",
                    JOptionPane.ERROR_MESSAGE);
                setCursor(Cursor.getDefaultCursor());
            });
        }
    }

    /**
     * 处理请求成功的响应
     */
    public void handleResponseSuccess(byte[] requestBytes, byte[] response, long requestTimeMs, long responseTimeMs, long durationMs) {
        if (response != null && response.length > 0) {
            try {
                responsePanel.setResponse(response);

                HttpRequest requestInfo;
                if (currentHttpService != null) {
                    requestInfo = HttpRequest.httpRequest(currentHttpService, ByteArray.byteArray(requestBytes));
                } else {
                    requestInfo = HttpRequest.httpRequest(ByteArray.byteArray(requestBytes));
                }
                HttpResponse responseInfo = HttpResponse.httpResponse(ByteArray.byteArray(response));

                String method = requestInfo.method();
                String url = HttpRequestHelper.extractUrlFromRequest(requestBytes, requestInfo, currentHttpService);
                int statusCode = responseInfo.statusCode();

                // 状态栏使用实际状态码判断成功/失败（BUG-005：原硬编码为 true）
                boolean success = statusCode >= 100 && statusCode < 400;
                statusPanel.updateStatus(success, response.length, requestTimeMs, responseTimeMs, durationMs);

                if (currentRequestId >= 0) {
                    String protocol = "http";
                    String host = "";
                    String path = "/";
                    String query = "";

                    try {
                        URL parsedUrl = new URL(requestInfo.url());
                        protocol = parsedUrl.getProtocol();
                        host = HttpRequestHelper.resolveDomainWithPort(parsedUrl, currentHttpService);
                        path = parsedUrl.getPath();
                        query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";
                    } catch (Exception e) {
                        LogManager.getInstance().printOutput("[*] 使用备选方法解析URL组件: " + url);
                        if (url.startsWith("https://")) {
                            protocol = "https";
                            url = url.substring(8);
                        } else if (url.startsWith("http://")) {
                            url = url.substring(7);
                        }

                        int pathIndex = url.indexOf('/');
                        if (pathIndex > 0) {
                            host = url.substring(0, pathIndex);
                            url = url.substring(pathIndex);
                        } else {
                            host = url;
                            url = "/";
                        }

                        int queryIndex = url.indexOf('?');
                        if (queryIndex > 0) {
                            path = url.substring(0, queryIndex);
                            query = url.substring(queryIndex + 1);
                        } else {
                            path = url;
                        }
                    }

                    String reqApiValue = HttpRequestHelper.computeApiFromRequest(path, query, requestBytes);
                    requestListPanel.updateRequest(currentRequestId, reqApiValue, protocol, host, path, query, method);
                }

                RequestResponseRecord record;
                try {
                    URL parsedUrl = new URL(requestInfo.url());
                    String recordHost = HttpRequestHelper.resolveDomainWithPort(parsedUrl, currentHttpService);
                    record = new RequestResponseRecord(
                        currentRequestId,
                        parsedUrl.getProtocol(),
                        recordHost,
                        parsedUrl.getPath(),
                        parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "",
                        method
                    );
                } catch (Exception e) {
                    LogManager.getInstance().printOutput("[*] 使用备选方法解析URL: " + url);

                    String protocol = "http";
                    String host = "";
                    String path = "/";
                    String query = "";

                    if (url.startsWith("https://")) {
                        protocol = "https";
                        url = url.substring(8);
                    } else if (url.startsWith("http://")) {
                        url = url.substring(7);
                    }

                    int pathIndex = url.indexOf('/');
                    if (pathIndex > 0) {
                        host = url.substring(0, pathIndex);
                        url = url.substring(pathIndex);
                    } else {
                        host = url;
                        url = "/";
                    }

                    int queryIndex = url.indexOf('?');
                    if (queryIndex > 0) {
                        path = url.substring(0, queryIndex);
                        query = url.substring(queryIndex + 1);
                    } else {
                        path = url;
                    }

                    record = new RequestResponseRecord(
                        currentRequestId,
                        protocol,
                        host,
                        path,
                        query,
                        method
                    );
                }

                record.setStatusCode(statusCode);
                record.setResponseLength(response.length);
                record.setResponseTime((int) durationMs);
                record.setRequestData(requestBytes);
                record.setResponseData(response);
                record.setTimestamp(new Date());

                addHistoryRecord(currentRequestId, record);

                record.setApi(HttpRequestHelper.computeApiFromRequest(record.getPath(),
                        record.getQueryParameters() != null ? record.getQueryParameters() : "", requestBytes));
                historyPanel.addHistoryRecord(record);

                LogManager.getInstance().printOutput(String.format(
                    "%s 请求完成: %s %s → HTTP %d (%d 字节)",
                    statusCode > 0 && statusCode < 400 ? "[+]" : "[!]",
                    method, url, statusCode, response.length));
            } catch (Exception ex) {
                LogManager.getInstance().printError("[!] 处理响应时发生异常: " + ex.getMessage());
                JOptionPane.showMessageDialog(mainPanel,
                    "处理响应时出错: " + ex.getMessage(),
                    "响应处理异常",
                    JOptionPane.ERROR_MESSAGE);
            }
        } else {
            LogManager.getInstance().printError("[!] 请求失败: 无响应数据");
            JOptionPane.showMessageDialog(mainPanel,
                "请求失败或超时，未收到响应数据",
                "请求错误",
                JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * 处理请求失败的响应
     */
    public void handleResponseFailure(byte[] requestBytes, String errorMessage, long requestTimeMs, long responseTimeMs, long durationMs) {
        statusPanel.updateStatus(false, 0, requestTimeMs, responseTimeMs, durationMs);
        try {
            HttpRequest requestInfo;
            if (currentHttpService != null) {
                requestInfo = HttpRequest.httpRequest(currentHttpService, ByteArray.byteArray(requestBytes));
            } else {
                requestInfo = HttpRequest.httpRequest(ByteArray.byteArray(requestBytes));
            }

            String method = requestInfo.method();
            String url = HttpRequestHelper.extractUrlFromRequest(requestBytes, requestInfo, currentHttpService);

            String protocol = "http";
            String host = "";
            String path = "/";
            String query = "";

            try {
                URL parsedUrl = new URL(requestInfo.url());
                protocol = parsedUrl.getProtocol();
                host = HttpRequestHelper.resolveDomainWithPort(parsedUrl, currentHttpService);
                path = parsedUrl.getPath();
                query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";
            } catch (Exception e) {
                LogManager.getInstance().printOutput("[*] 使用备选方法解析URL组件: " + url);
                if (url.startsWith("https://")) {
                    protocol = "https";
                    url = url.substring(8);
                } else if (url.startsWith("http://")) {
                    url = url.substring(7);
                }

                int pathIndex = url.indexOf('/');
                if (pathIndex > 0) {
                    host = url.substring(0, pathIndex);
                    url = url.substring(pathIndex);
                } else {
                    host = url;
                    url = "/";
                }

                int queryIndex = url.indexOf('?');
                if (queryIndex > 0) {
                    path = url.substring(0, queryIndex);
                    query = url.substring(queryIndex + 1);
                } else {
                    path = url;
                }
            }

            if (currentRequestId >= 0) {
                String reqApiValue = HttpRequestHelper.computeApiFromRequest(path, query, requestBytes);
                requestListPanel.updateRequest(currentRequestId, reqApiValue, protocol, host, path, query, method);
            }

            RequestResponseRecord record = new RequestResponseRecord(
                currentRequestId,
                protocol,
                host,
                path,
                query,
                method
            );

            record.setStatusCode(0);
            record.setResponseLength(0);
            record.setResponseTime((int) durationMs);
            record.setRequestData(requestBytes);
            record.setResponseData(new byte[0]);
            record.setTimestamp(new Date());
            record.setComment("请求失败: " + errorMessage);

            addHistoryRecord(currentRequestId, record);

            record.setApi(HttpRequestHelper.computeApiFromRequest(record.getPath(),
                    record.getQueryParameters() != null ? record.getQueryParameters() : "", requestBytes));
            historyPanel.addHistoryRecord(record);

            LogManager.getInstance().printOutput(String.format(
                "[+] 请求失败已记录: %s %s → 错误: %s",
                method, url, errorMessage));
        } catch (Exception ex) {
            LogManager.getInstance().printError("[!] 处理失败响应时发生异常: " + ex.getMessage());
        }
    }

    /**
     * 添加历史记录到指定请求ID
     */
    public void addHistoryRecord(int requestId, RequestResponseRecord record) {
        if (requestId < 0) {
            return;
        }

        List<RequestResponseRecord> historyList = requestHistoryMap.computeIfAbsent(
            requestId, k -> new ArrayList<>());

        synchronized (historyList) {
            historyList.add(0, record);
        }

        LogManager.getInstance().printOutput(
            String.format("[+] 已添加历史记录到请求ID %d，当前历史记录数量: %d",
                requestId, historyList.size()));
    }

    /**
     * 根据历史记录更新状态栏
     */
    public void updateStatusFromRecord(RequestResponseRecord record) {
        if (record == null) {
            statusPanel.clear();
            return;
        }

        int statusCode = record.getStatusCode();
        // 标准 HTTP 成功范围: 1xx-3xx；1337/0/超范围状态码均为失败
        boolean success = statusCode >= 100 && statusCode < 400;

        int responseSize = 0;
        byte[] responseData = record.getResponseData();
        if (responseData != null) {
            responseSize = responseData.length;
        }

        int durationMs = record.getResponseTime();
        long timestampMs = record.getTimestamp() != null ? record.getTimestamp().getTime() : 0;
        long requestTimeMs = timestampMs - durationMs;
        long responseTimeMs = timestampMs;

        statusPanel.updateStatus(success, responseSize, requestTimeMs, responseTimeMs, durationMs);
    }

    public void setCursor(Cursor cursor) {
        mainPanel.setCursor(cursor);
        requestPanel.setCursor(cursor);
        responsePanel.setCursor(cursor);
        historyPanel.setCursor(cursor);
        requestListPanel.setCursor(cursor);
    }

    /**
     * 权限测试模式发送请求
     * 使用ReplayEngine遍历所有已启用用户会话，替换令牌后重放
     */
    private void sendPrivilegeTestRequest(byte[] requestBytes) {
        // 委托给参数化版本，使用当前共享状态（仅在非并发单次调用时安全）
        sendPrivilegeTestRequestDirect(requestBytes, currentHttpService, currentRequestId);
    }

    /**
     * 参数化的权限测试请求发送 - 直接接收requestId和httpService
     * 解决EDT事件队列竞态条件：当多个setPrivilegeTestRequest快速连续执行时，
     * 通过invokeLater投递的sendRequest()会读到最后一个requestId。
     * 此方法在调用时即确定requestId/httpService/requestBytes，不依赖volatile共享状态。
     *
     * @param requestBytes  请求字节数组
     * @param httpService   HTTP服务信息（协议、主机、端口）
     * @param requestId     请求ID（调用时已确定）
     */
    public void sendPrivilegeTestRequestDirect(byte[] requestBytes, HttpService httpService, int requestId) {
        SessionManager sessionManager = SessionManager.getInstance();

        if (!sessionManager.hasEnabledSessions()) {
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(mainPanel,
                    "没有已启用的用户会话，请先在\"权限测试\"标签页中配置用户会话",
                    "权限测试配置缺失",
                    JOptionPane.WARNING_MESSAGE);
            });
            return;
        }

        LogManager.getInstance().printOutput(String.format("[*] 权限测试模式：开始重放请求 (requestId=%d)...", requestId));
        responsePanel.clear();

        SwingUtilities.invokeLater(() -> {
            setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        });

        ReplayEngine replayEngine = ReplayEngine.getInstance();
        boolean deduped = replayEngine.replay(requestBytes, httpService, requestId, requestManager, isHttp2(requestId),
                new ReplayEngine.ReplayCallback() {
                    @Override
                    public void onReplayComplete(RequestResponseRecord record, boolean isFirst) {
                        // 添加到历史记录映射
                        addHistoryRecord(record.getRequestId(), record);

                        // 设置API值
                        record.setApi(HttpRequestHelper.computeApiFromRequest(
                                record.getPath(),
                                record.getQueryParameters() != null ? record.getQueryParameters() : "",
                                record.getRequestData()));

                        // 先更新UI历史面板（已在EDT上），再异步持久化到DB
                        historyPanel.addHistoryRecord(record);

                        // DB持久化：卸载到后台线程，避免saveHistory阻塞EDT
                        final RequestResponseRecord dbRecord = record;
                        dbPersistExecutor.submit(() -> {
                            try {
                                HistoryWriteDAO historyWriteDAO = new HistoryWriteDAO();
                                int historyId = historyWriteDAO.saveHistory(dbRecord);
                                if (historyId > 0) {
                                    dbRecord.setId(historyId);
                                } else {
                                    LogManager.getInstance().printError("[!] 越权测试记录保存到数据库失败，报告将无法统计该条记录");
                                }
                            } catch (Exception ex) {
                                LogManager.getInstance().printError("[!] 保存越权测试记录异常: " + ex.getMessage());
                            }
                        });

                        // 基准用户的响应显示在响应面板
                        if (isFirst && record.getResponseData() != null && record.getResponseData().length > 0) {
                            responsePanel.setResponse(record.getResponseData());
                            updateStatusFromRecord(record);
                        }

                        // 打印判决结果日志
                        if (isFirst) {
                            LogManager.getInstance().printOutput(String.format(
                                    "[*] 权限测试重放完成: requestId=%d, 用户=%s, 判决=基准用户(不参与比较)",
                                    record.getRequestId(),
                                    record.getUserSessionName()));
                        } else {
                            JudgmentResult judgment = JudgmentResult.fromString(record.getJudgment());
                            LogManager.getInstance().printOutput(String.format(
                                    "[*] 权限测试重放完成: requestId=%d, 用户=%s, 判决=%s, 相似度=%.2f",
                                    record.getRequestId(),
                                    record.getUserSessionName(),
                                    judgment.getDisplayName(),
                                    record.getSimilarity()));
                        }
                    }

                    @Override
                    public void onAllComplete() {
                        SwingUtilities.invokeLater(() -> {
                            setCursor(Cursor.getDefaultCursor());
                        });
                        LogManager.getInstance().printOutput("[+] 权限测试重放全部完成");
                    }
                });

        // 如果请求因去重被跳过，恢复光标状态
        if (deduped) {
            SwingUtilities.invokeLater(() -> setCursor(Cursor.getDefaultCursor()));
        }
    }

    public void loadHistoryRecord(RequestResponseRecord record) {
        if (record != null) {
            requestPanel.setRequest(record.getRequestData());
            responsePanel.setResponse(record.getResponseData());
            updateStatusFromRecord(record);

            LogManager.getInstance().printOutput("[+] 已加载历史记录: " + record.toString());
        }
    }

    /**
     * 批量权限测试 - 逐个请求ID执行越权重放
     * 在后台线程中逐条处理，复用现有的 ReplayEngine 逻辑
     *
     * @param requestIds 要执行权限测试的请求ID列表
     */
    public void batchSendPrivilegeTestRequests(List<Integer> requestIds) {
        if (requestIds == null || requestIds.isEmpty()) return;

        SessionManager sessionManager = SessionManager.getInstance();
        if (!sessionManager.hasEnabledSessions()) {
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(mainPanel,
                    "没有已启用的用户会话，请先在\"权限测试\"标签页中配置用户会话",
                    "权限测试配置缺失",
                    JOptionPane.WARNING_MESSAGE);
            });
            return;
        }

        LogManager.getInstance().printOutput(String.format("[*] 批量权限测试：开始处理 %d 条请求...", requestIds.size()));

        // 清除ReplayEngine的去重记录，确保新批次从干净状态开始
        ReplayEngine.getInstance().clearProcessedApis();

        SwingUtilities.invokeLater(() -> setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR)));

        int totalCount = requestIds.size();
        AtomicInteger completedCount = new AtomicInteger(0);

        // 在后台线程逐条处理
        new Thread(() -> {
            for (int i = 0; i < requestIds.size(); i++) {
                int requestId = requestIds.get(i);
                try {
                    // 从 requestDataMap 获取请求字节数组
                    byte[] requestBytes = requestListPanel.getRequestData(requestId);
                    if (requestBytes == null || requestBytes.length == 0) {
                        LogManager.getInstance().printError("[!] 批量权限测试：请求ID " + requestId + " 数据为空，跳过");
                        completedCount.incrementAndGet();
                        statusPanel.showBatchProgress(completedCount.get(), totalCount, "权限测试");
                        continue;
                    }

                    // 从 httpServiceMap 获取 HttpService
                    HttpService httpService = httpServiceMap.get(requestId);

                    // 临时设置当前请求状态
                    currentRequestId = requestId;
                    currentHttpService = httpService;

                    // 使用 CountDownLatch 等待当前请求的所有会话重放完成
                    java.util.concurrent.CountDownLatch latch = new java.util.concurrent.CountDownLatch(1);

                    SwingUtilities.invokeLater(() -> responsePanel.clear());

                    ReplayEngine replayEngine = ReplayEngine.getInstance();
                    boolean deduped = replayEngine.replay(requestBytes, httpService, requestId, requestManager, isHttp2(requestId),
                            new ReplayEngine.ReplayCallback() {
                                @Override
                                public void onReplayComplete(RequestResponseRecord rec, boolean isFirst) {
                                    addHistoryRecord(rec.getRequestId(), rec);

                                    rec.setApi(HttpRequestHelper.computeApiFromRequest(
                                            rec.getPath(),
                                            rec.getQueryParameters() != null ? rec.getQueryParameters() : "",
                                            rec.getRequestData()));

                                    // 先更新UI（已在EDT上），再异步持久化到DB
                                    historyPanel.addHistoryRecord(rec);

                                    // DB持久化：卸载到后台线程，避免saveHistory阻塞EDT导致UI转圈
                                    final RequestResponseRecord dbRec = rec;
                                    dbPersistExecutor.submit(() -> {
                                        try {
                                            HistoryWriteDAO historyWriteDAO = new HistoryWriteDAO();
                                            int historyId = historyWriteDAO.saveHistory(dbRec);
                                            if (historyId > 0) {
                                                dbRec.setId(historyId);
                                            }
                                        } catch (Exception ex) {
                                            LogManager.getInstance().printError("[!] 批量越权测试记录保存异常: " + ex.getMessage());
                                        }
                                    });

                                    if (isFirst && rec.getResponseData() != null && rec.getResponseData().length > 0) {
                                        SwingUtilities.invokeLater(() -> {
                                            responsePanel.setResponse(rec.getResponseData());
                                            updateStatusFromRecord(rec);
                                        });
                                    }

                                    if (isFirst) {
                                        LogManager.getInstance().printOutput(String.format(
                                                "[*] 批量权限测试 [%d/%d]: 用户=%s (基准用户，不参与比较)",
                                                completedCount.get() + 1, totalCount,
                                                rec.getUserSessionName()));
                                    } else {
                                        LogManager.getInstance().printOutput(String.format(
                                                "[*] 批量权限测试 [%d/%d]: 用户=%s, 判决=%s",
                                                completedCount.get() + 1, totalCount,
                                                rec.getUserSessionName(),
                                                JudgmentResult.toDisplayName(rec.getJudgment())));
                                    }
                                }

                                @Override
                                public void onAllComplete() {
                                    int done = completedCount.incrementAndGet();
                                    statusPanel.showBatchProgress(done, totalCount, "权限测试");
                                    latch.countDown();
                                }
                            });

                    // 如果请求因去重被跳过，直接计数并释放latch
                    if (deduped) {
                        int done = completedCount.incrementAndGet();
                        statusPanel.showBatchProgress(done, totalCount, "权限测试");
                        latch.countDown();
                    } else {
                        // 等待当前请求的所有重放完成后再处理下一条
                        // BUG修复：原代码 latch.await() 无超时，当 EDT 队列积压大量 onReplayComplete 任务时，
                        // onAllComplete（通过 invokeLater 排在 EDT 队列尾部）会延迟很久才执行 latch.countDown()，
                        // 导致 batch-privilege-test 线程无限阻塞。
                        // 修复：添加超时（基于会话数 × 单请求超时 + 30秒缓冲），超时后跳过当前请求继续下一条。
                        SessionManager sm = SessionManager.getInstance();
                        int sessionCount = sm.getEnabledSessions().size();
                        int perRequestTimeout = sm.getRequestTimeout();
                        // 单条请求所有会话重放的最大耗时：会话数 × (请求超时+10秒缓冲) + 重放延迟 + 30秒EDT缓冲
                        long latchTimeoutMs = (long) sessionCount * (perRequestTimeout + 10) * 1000L
                                + (long) sessionCount * sm.getReplayDelay() + 30000L;
                        if (!latch.await(latchTimeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                            LogManager.getInstance().printError(String.format(
                                    "[!] 批量权限测试：请求ID %d 等待重放完成超时（%d秒），跳过继续下一条",
                                    requestId, latchTimeoutMs / 1000));
                            if (!deduped) {
                                completedCount.incrementAndGet();
                                statusPanel.showBatchProgress(completedCount.get(), totalCount, "权限测试");
                            }
                        }
                    }

                } catch (Exception e) {
                    LogManager.getInstance().printError("[!] 批量权限测试：请求ID " + requestId + " 处理异常: " + e.getMessage());
                    completedCount.incrementAndGet();
                    statusPanel.showBatchProgress(completedCount.get(), totalCount, "权限测试");
                }
            }

            // 全部完成
            SwingUtilities.invokeLater(() -> {
                setCursor(Cursor.getDefaultCursor());
                statusPanel.clearBatchProgress();
                LogManager.getInstance().printOutput(String.format("[+] 批量权限测试完成：共处理 %d 条请求", totalCount));
            });
        }, "batch-privilege-test").start();
    }

    /**
     * 批量普通重放 - 逐条发送选中的历史记录请求
     *
     * @param records 要重放的历史记录列表
     */
    public void batchSendRequests(List<RequestResponseRecord> records) {
        if (records == null || records.isEmpty()) return;

        LogManager.getInstance().printOutput(String.format("[*] 批量重放：开始处理 %d 条请求...", records.size()));

        SwingUtilities.invokeLater(() -> setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR)));

        int totalCount = records.size();
        AtomicInteger completedCount = new AtomicInteger(0);

        new Thread(() -> {
            for (int i = 0; i < records.size(); i++) {
                RequestResponseRecord record = records.get(i);
                try {
                    byte[] requestBytes = record.getRequestData();
                    if (requestBytes == null || requestBytes.length == 0) {
                        LogManager.getInstance().printError("[!] 批量重放：请求数据为空，跳过");
                        completedCount.incrementAndGet();
                        statusPanel.showBatchProgress(completedCount.get(), totalCount, "重放");
                        continue;
                    }

                    int requestId = record.getRequestId();
                    HttpService httpService = httpServiceMap.get(requestId);

                    // 临时设置当前请求状态
                    currentRequestId = requestId;
                    currentHttpService = httpService;

                    java.util.concurrent.CountDownLatch latch = new java.util.concurrent.CountDownLatch(1);

                    requestManager.makeHttpRequestAsync(requestBytes, requestPanel.getTimeout(),
                            requestId, httpService, isHttp2(requestId), new RequestManager.RequestCallback() {
                                @Override
                                public void onSuccess(byte[] response, long requestTimeMs, long responseTimeMs, long durationMs) {
                                    SwingUtilities.invokeLater(() -> {
                                        try {
                                            handleResponseSuccess(requestBytes, response, requestTimeMs, responseTimeMs, durationMs);
                                        } catch (Exception ex) {
                                            LogManager.getInstance().printError("[!] 批量重放处理响应异常: " + ex.getMessage());
                                        }
                                    });
                                    latch.countDown();
                                }

                                @Override
                                public void onFailure(String errorMessage, long requestTimeMs, long responseTimeMs, long durationMs) {
                                    SwingUtilities.invokeLater(() -> {
                                        handleResponseFailure(requestBytes, errorMessage, requestTimeMs, responseTimeMs, durationMs);
                                    });
                                    latch.countDown();
                                }
                            });

                    latch.await();
                    int done = completedCount.incrementAndGet();
                    statusPanel.showBatchProgress(done, totalCount, "重放");

                } catch (Exception e) {
                    LogManager.getInstance().printError("[!] 批量重放：处理异常: " + e.getMessage());
                    completedCount.incrementAndGet();
                    statusPanel.showBatchProgress(completedCount.get(), totalCount, "重放");
                }
            }

            SwingUtilities.invokeLater(() -> {
                setCursor(Cursor.getDefaultCursor());
                statusPanel.clearBatchProgress();
                LogManager.getInstance().printOutput(String.format("[+] 批量重放完成：共处理 %d 条请求", totalCount));
            });
        }, "batch-replay").start();
    }
}
