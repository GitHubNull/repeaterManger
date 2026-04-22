package oxff.top;

import burp.BurpExtender;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import oxff.top.http.HttpRequestHelper;
import oxff.top.http.RequestManager;
import oxff.top.http.RequestResponseRecord;
import oxff.top.ui.editor.BurpRequestPanel;
import oxff.top.ui.editor.BurpResponsePanel;
import oxff.top.ui.history.HistoryPanel;
import oxff.top.ui.RequestListPanel;
import oxff.top.ui.StatusPanel;

import javax.swing.*;
import java.awt.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 请求调度处理器 - 管理HTTP请求发送、响应处理和历史记录更新
 * 从EnhancedRepeaterUI中提取的请求处理逻辑
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

    // 当前请求状态
    private int currentRequestId = -1;
    private HttpService currentHttpService = null;

    // 请求历史记录映射: 请求ID -> 历史记录列表
    private final Map<Integer, List<RequestResponseRecord>> requestHistoryMap = new HashMap<>();

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

    public Map<Integer, List<RequestResponseRecord>> getRequestHistoryMap() {
        return requestHistoryMap;
    }

    /**
     * 发送当前请求
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

            BurpExtender.printOutput("[*] 正在发送请求...");
            responsePanel.clear();

            int timeout = requestPanel.getTimeout();

            SwingUtilities.invokeLater(() -> {
                setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
            });

            requestManager.makeHttpRequestAsync(requestBytes, timeout, currentRequestId, currentHttpService, new RequestManager.RequestCallback() {
                @Override
                public void onSuccess(byte[] response, long requestTimeMs, long responseTimeMs, long durationMs) {
                    SwingUtilities.invokeLater(() -> {
                        try {
                            handleResponseSuccess(requestBytes, response, requestTimeMs, responseTimeMs, durationMs);
                        } catch (Exception ex) {
                            BurpExtender.printError("[!] 处理响应时发生异常: " + ex.getMessage());
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
                            handleResponseFailure(requestBytes, errorMessage, requestTimeMs, responseTimeMs, durationMs);
                            BurpExtender.printError("[!] 请求失败: " + errorMessage);
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
            BurpExtender.printError("[!] 准备请求时发生错误: " + e.getMessage());
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
            statusPanel.updateStatus(true, response.length, requestTimeMs, responseTimeMs, durationMs);
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

                if (currentRequestId >= 0) {
                    String protocol = "http";
                    String host = "";
                    String path = "/";
                    String query = "";

                    try {
                        URL parsedUrl = new URL(requestInfo.url());
                        protocol = parsedUrl.getProtocol();
                        host = parsedUrl.getHost();
                        path = parsedUrl.getPath();
                        query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";
                    } catch (Exception e) {
                        BurpExtender.printOutput("[*] 使用备选方法解析URL组件: " + url);
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
                    record = new RequestResponseRecord(
                        currentRequestId,
                        parsedUrl.getProtocol(),
                        parsedUrl.getHost(),
                        parsedUrl.getPath(),
                        parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "",
                        method
                    );
                } catch (Exception e) {
                    BurpExtender.printOutput("[*] 使用备选方法解析URL: " + url);

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

                BurpExtender.printOutput(String.format(
                    "[+] 请求完成: %s %s → HTTP %d (%d 字节)",
                    method, url, statusCode, response.length));
            } catch (Exception ex) {
                BurpExtender.printError("[!] 处理响应时发生异常: " + ex.getMessage());
                JOptionPane.showMessageDialog(mainPanel,
                    "处理响应时出错: " + ex.getMessage(),
                    "响应处理异常",
                    JOptionPane.ERROR_MESSAGE);
            }
        } else {
            BurpExtender.printError("[!] 请求失败: 无响应数据");
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
                host = parsedUrl.getHost();
                path = parsedUrl.getPath();
                query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";
            } catch (Exception e) {
                BurpExtender.printOutput("[*] 使用备选方法解析URL组件: " + url);
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

            BurpExtender.printOutput(String.format(
                "[+] 请求失败已记录: %s %s → 错误: %s",
                method, url, errorMessage));
        } catch (Exception ex) {
            BurpExtender.printError("[!] 处理失败响应时发生异常: " + ex.getMessage());
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

        historyList.add(0, record);

        BurpExtender.printOutput(
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
        boolean success = statusCode > 0 && statusCode < 400;

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

    public void loadHistoryRecord(RequestResponseRecord record) {
        if (record != null) {
            requestPanel.setRequest(record.getRequestData());
            responsePanel.setResponse(record.getResponseData());
            updateStatusFromRecord(record);

            BurpExtender.printOutput("[+] 已加载历史记录: " + record.toString());
        }
    }
}
