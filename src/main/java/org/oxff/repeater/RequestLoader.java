package org.oxff.repeater;

import org.oxff.repeater.logging.LogManager;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.oxff.repeater.db.RequestDAO;
import org.oxff.repeater.http.HttpRequestHelper;
import org.oxff.repeater.privilege.ReplayEngine;
import org.oxff.repeater.service.GarbageCollectorService;
import org.oxff.repeater.db.DatabaseManager;
import org.oxff.repeater.ui.editor.BurpRequestPanel;
import org.oxff.repeater.ui.editor.BurpResponsePanel;
import org.oxff.repeater.ui.history.HistoryPanel;
import org.oxff.repeater.ui.RequestListPanel;
import org.oxff.repeater.ui.StatusPanel;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 请求加载器 — 负责将 Burp 请求加载到 UI 面板并保存到数据库
 * 从 RepeaterManagerUI 中提取，遵循单一职责原则
 */
public class RequestLoader {

    private final JTabbedPane tabbedPane;
    private final BurpRequestPanel requestPanel;
    private final BurpResponsePanel responsePanel;
    private final HistoryPanel historyPanel;
    private final RequestListPanel requestListPanel;
    private final StatusPanel statusPanel;
    private final RequestDispatchHandler dispatchHandler;

    public RequestLoader(JTabbedPane tabbedPane,
                         BurpRequestPanel requestPanel, BurpResponsePanel responsePanel,
                         HistoryPanel historyPanel, RequestListPanel requestListPanel,
                         StatusPanel statusPanel, RequestDispatchHandler dispatchHandler) {
        this.tabbedPane = tabbedPane;
        this.requestPanel = requestPanel;
        this.responsePanel = responsePanel;
        this.historyPanel = historyPanel;
        this.requestListPanel = requestListPanel;
        this.statusPanel = statusPanel;
        this.dispatchHandler = dispatchHandler;
    }

    /**
     * 设置请求内容 - 用于从右键菜单接收请求
     * @return 数据库生成的请求ID，失败返回-1
     */
    public int setRequest(HttpRequestResponse requestResponse) {
        try {
            if (requestResponse != null && requestResponse.request() != null) {
                byte[] request = requestResponse.request().toByteArray().getBytes();

                String url;
                String method;
                String protocol = "http";
                String domain = "";
                String path = "/";
                String query = "";

                HttpService httpService = requestResponse.httpService();
                HttpRequest httpRequest = requestResponse.request();

                url = httpRequest.url();
                method = httpRequest.method();
                HttpRequestHelper.UrlParts urlParts = HttpRequestHelper.parseUrlComponents(url, url, httpService);
                protocol = urlParts.protocol;
                domain = urlParts.host;
                path = urlParts.path;
                query = urlParts.query;

                RequestDAO requestDAO = new RequestDAO();
                int dbId = requestDAO.saveRequest(protocol, domain, path, query, method, request);

                if (dbId <= 0) {
                    LogManager.getInstance().printError("[!] 保存请求到数据库失败");
                    return -1;
                }

                String apiValue = HttpRequestHelper.computeApiFromRequest(path, query, request);

                requestListPanel.addRequest(dbId, apiValue, method, protocol, domain, path, query, request);
                dispatchHandler.setCurrentRequestId(dbId);
                dispatchHandler.setCurrentHttpService(httpService);
                dispatchHandler.saveHttpService(dbId, httpService);

                boolean isHttp2 = "HTTP/2".equals(httpRequest.httpVersion());
                dispatchHandler.saveHttpVersion(dbId, isHttp2);
                if (isHttp2) {
                    LogManager.getInstance().printOutput("[+] 检测到 HTTP/2 请求，已记录协议版本，重放时将保持 HTTP/2");
                }

                if (requestResponse.response() != null) {
                    saveOriginalResponseAsBaseline(dbId, requestResponse);
                }

                requestPanel.setRequest(request);

                if (requestResponse.response() != null) {
                    byte[] originalResponse = requestResponse.response().toByteArray().getBytes();
                    responsePanel.setResponse(originalResponse);
                    int originalStatusCode = requestResponse.response().statusCode();
                    boolean success = originalStatusCode >= 100 && originalStatusCode < 400;
                    statusPanel.updateStatus(success, originalResponse.length, 0, 0, 0);
                } else {
                    responsePanel.clear();
                    statusPanel.clear();
                }

                historyPanel.setBorderTitle("请求历史记录 - " + protocol + "://" + domain + path + (query.isEmpty() ? "" : "?" + query));
                historyPanel.clearHistory();
                dispatchHandler.getRequestHistoryMap().put(dispatchHandler.getCurrentRequestId(), new ArrayList<>());

                LogManager.getInstance().printOutput("[+] 请求已加载到 Repeater Manager: " + protocol + "://" + domain + path + (query.isEmpty() ? "" : "?" + query));

                if (dispatchHandler.isPrivilegeTestMode()) {
                    new RequestDAO().markAsPrivilegeTest(dbId);
                    requestListPanel.updatePrivilegeTestFlag(dbId, true);
                    LogManager.getInstance().printOutput("[*] 权限测试模式已开启，自动触发越权重放...");
                    final int capturedId = dbId;
                    final HttpService capturedSvc = httpService;
                    final byte[] capturedReq = request;
                    SwingUtilities.invokeLater(() ->
                        dispatchHandler.sendPrivilegeTestRequestDirect(capturedReq, capturedSvc, capturedId));
                }

                return dbId;
            }
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 设置请求失败: " + e.getMessage());
            e.printStackTrace();
        }
        return -1;
    }

    public void setPrivilegeTestRequest(HttpRequestResponse requestResponse) {
        try {
            if (requestResponse != null && requestResponse.request() != null) {
                dispatchHandler.setPrivilegeTestMode(false);

                final byte[] capturedRequestBytes = requestResponse.request().toByteArray().getBytes();
                final HttpService capturedHttpService = requestResponse.httpService();

                int dbId = setRequest(requestResponse);

                if (dbId > 0) {
                    new RequestDAO().markAsPrivilegeTest(dbId);
                    requestListPanel.updatePrivilegeTestFlag(dbId, true);
                    saveOriginalResponseAsBaseline(dbId, requestResponse);
                }

                tabbedPane.setSelectedIndex(0);

                dispatchHandler.setPrivilegeTestMode(true);
                LogManager.getInstance().printOutput(String.format("[*] 权限测试模式已开启，准备重放请求 (requestId=%d)...", dbId));

                final int capturedRequestId = dbId;
                SwingUtilities.invokeLater(() ->
                    dispatchHandler.sendPrivilegeTestRequestDirect(
                        capturedRequestBytes, capturedHttpService, capturedRequestId));
            }
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 设置权限测试请求失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public List<Integer> setRequests(List<HttpRequestResponse> requestResponses) {
        List<Integer> dbIds = new ArrayList<>();
        if (requestResponses == null || requestResponses.isEmpty()) return dbIds;

        for (int i = 0; i < requestResponses.size(); i++) {
            HttpRequestResponse rr = requestResponses.get(i);
            try {
                int dbId = setRequest(rr);
                if (dbId > 0) {
                    dbIds.add(dbId);
                }
            } catch (Exception e) {
                LogManager.getInstance().printError("[!] 批量加载请求时第 " + (i + 1) + " 条失败: " + e.getMessage());
            }
        }

        if (!dbIds.isEmpty()) {
            LogManager.getInstance().printOutput(String.format("[+] 批量加载完成：成功 %d / %d 条", dbIds.size(), requestResponses.size()));
        }

        return dbIds;
    }

    public void setPrivilegeTestRequests(List<HttpRequestResponse> requestResponses) {
        if (requestResponses == null || requestResponses.isEmpty()) return;

        try {
            dispatchHandler.setPrivilegeTestMode(false);
            ReplayEngine.getInstance().clearProcessedApis();

            org.oxff.repeater.privilege.DedupConfigManager dedupConfigManager =
                    org.oxff.repeater.privilege.DedupConfigManager.getInstance();
            final List<HttpRequestResponse> dedupedRequests;
            int originalSize = requestResponses.size();
            dedupedRequests = org.oxff.repeater.privilege.ApiDedupEngine.deduplicate(
                    requestResponses,
                    rr -> {
                        if (rr == null || rr.request() == null) return "__NULL__";
                        byte[] requestBytes = rr.request().toByteArray().getBytes();
                        return dedupConfigManager.computeDedupKey(
                                requestBytes, rr.httpService());
                    },
                    dedupConfigManager.getKeepPolicy()
            );
            if (dedupedRequests.size() < originalSize) {
                LogManager.getInstance().printOutput(String.format(
                        "[*] 批量权限测试：去重过滤 %d -> %d 条（去除 %d 条重复）",
                        originalSize, dedupedRequests.size(), originalSize - dedupedRequests.size()));
            }

            requestListPanel.setBatchAddMode(true);
            dispatchHandler.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
            tabbedPane.setSelectedIndex(0);

            int total = dedupedRequests.size();
            LogManager.getInstance().printOutput(String.format("[*] 批量权限测试：开始处理 %d 条请求...", total));

            GarbageCollectorService gcService = DatabaseManager.getInstance().getGcService();
            if (gcService != null) {
                gcService.pause();
            }

            new Thread(() -> {
                List<Integer> dbIds = new ArrayList<>();
                RequestDAO requestDAO = new RequestDAO();

                for (int i = 0; i < dedupedRequests.size(); i++) {
                    HttpRequestResponse rr = dedupedRequests.get(i);
                    try {
                        if (rr == null || rr.request() == null) continue;

                        byte[] request = rr.request().toByteArray().getBytes();
                        HttpService httpService = rr.httpService();
                        HttpRequest httpRequest = rr.request();

                        String method;
                        String protocol = "http";
                        String domain = "";
                        String path = "/";
                        String query = "";

                        method = httpRequest.method();
                        HttpRequestHelper.UrlParts urlParts = HttpRequestHelper.parseUrlComponents(
                            httpRequest.url(), httpRequest.url(), httpService);
                        protocol = urlParts.protocol;
                        domain = urlParts.host;
                        path = urlParts.path;
                        query = urlParts.query;

                        int dbId = requestDAO.saveRequest(protocol, domain, path, query, method, request);
                        if (dbId <= 0) {
                            LogManager.getInstance().printError("[!] 批量权限测试：保存请求到数据库失败，第 " + (i + 1) + " 条");
                            continue;
                        }

                        requestDAO.markAsPrivilegeTest(dbId);

                        if (httpService != null) {
                            dispatchHandler.saveHttpService(dbId, httpService);
                        }

                        saveOriginalResponseAsBaseline(dbId, rr);

                        dispatchHandler.getRequestHistoryMap().put(dbId, new ArrayList<>());

                        String apiValue = HttpRequestHelper.computeApiFromRequest(path, query, request);

                        dbIds.add(dbId);

                        final int finalDbId = dbId;
                        final String finalApi = apiValue;
                        final String finalMethod = method;
                        final String finalProtocol = protocol;
                        final String finalDomain = domain;
                        final String finalPath = path;
                        final String finalQuery = query;
                        final byte[] finalRequest = request;
                        SwingUtilities.invokeLater(() -> {
                            requestListPanel.addRequest(finalDbId, finalApi, finalMethod, finalProtocol,
                                    finalDomain, finalPath, finalQuery, true, finalRequest);
                        });

                    } catch (Exception e) {
                        LogManager.getInstance().printError("[!] 批量加载请求时第 " + (i + 1) + " 条失败: " + e.getMessage());
                    }
                }

                if (dbIds.isEmpty()) {
                    LogManager.getInstance().printError("[!] 批量权限测试：所有请求保存失败");
                    if (gcService != null) {
                        gcService.resume();
                    }
                    SwingUtilities.invokeLater(() -> {
                        requestListPanel.setBatchAddMode(false);
                        dispatchHandler.setCursor(Cursor.getDefaultCursor());
                    });
                    return;
                }

                LogManager.getInstance().printOutput(String.format("[+] 批量权限测试：保存完成，成功 %d / %d 条，开始重放...",
                        dbIds.size(), total));

                if (gcService != null) {
                    gcService.resume();
                }

                SwingUtilities.invokeLater(() -> {
                    requestListPanel.exitBatchModeQuiet();
                    dispatchHandler.setCurrentRequestId(dbIds.get(dbIds.size() - 1));
                    dispatchHandler.setCursor(Cursor.getDefaultCursor());

                    dispatchHandler.setPrivilegeTestMode(true);
                    LogManager.getInstance().printOutput(String.format("[*] 权限测试模式已开启，准备批量重放 %d 条请求...", dbIds.size()));

                    dispatchHandler.batchSendPrivilegeTestRequests(dbIds);
                });
            }, "batch-privilege-test-setup").start();

        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 批量设置权限测试请求失败: " + e.getMessage());
            e.printStackTrace();
            requestListPanel.setBatchAddMode(false);
            dispatchHandler.setCursor(Cursor.getDefaultCursor());
        }
    }

    /**
     * 保存原始响应报文到 requests 表（作为基线）
     */
    public void saveOriginalResponseAsBaseline(int requestId, HttpRequestResponse requestResponse) {
        try {
            if (requestResponse.response() == null) {
                LogManager.getInstance().printOutput("[*] 原始报文无响应数据，跳过基线保存");
                return;
            }

            byte[] responseData = requestResponse.response().toByteArray().getBytes();
            int statusCode = requestResponse.response().statusCode();

            RequestDAO requestDAO = new RequestDAO();
            boolean saved = requestDAO.saveOriginalResponse(requestId, responseData, statusCode, 0);
            if (saved) {
                LogManager.getInstance().printOutput("[+] 原始响应基线已保存到 requests 表，requestId: " + requestId);
            } else {
                LogManager.getInstance().printError("[!] 保存原始响应基线失败，requestId: " + requestId);
            }
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 保存原始响应基线异常: " + e.getMessage());
        }
    }
}
