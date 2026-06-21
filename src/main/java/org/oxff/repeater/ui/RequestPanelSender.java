package org.oxff.repeater.ui;

import burp.BurpExtender;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.oxff.repeater.api.MontoyaApiHolder;
import org.oxff.repeater.db.RequestDAO;
import org.oxff.repeater.db.history.HistoryWriteDAO;
import org.oxff.repeater.http.HttpRequestHelper;
import org.oxff.repeater.http.RequestDataHelper;

import javax.swing.*;
import java.net.URL;

/**
 * RequestPanel的请求发送处理器 - 管理请求发送、响应处理和历史记录保存
 */
public class RequestPanelSender {

    private final RequestPanel requestPanel;
    private final MainUI mainUI;
    private final JButton sendButton;
    private final MontoyaApi api;

    /**
     * 创建请求发送处理器
     * @param requestPanel 所属的请求面板
     * @param mainUI 主UI引用（用于更新历史面板）
     * @param sendButton 发送按钮（用于控制启用/禁用状态）
     */
    public RequestPanelSender(RequestPanel requestPanel, MainUI mainUI, JButton sendButton) {
        this.requestPanel = requestPanel;
        this.mainUI = mainUI;
        this.sendButton = sendButton;
        this.api = MontoyaApiHolder.getApi();
    }

    /**
     * 发送请求并处理响应（异步方式，不阻塞UI线程）
     */
    public void sendRequest() {
        byte[] request = null;
        String url = null;

        try {
            request = requestPanel.getRequest();
            if (request == null || request.length == 0) {
                BurpExtender.printError("[!] 请求数据为空");
                return;
            }

            // 使用Montoya API解析请求以获取URL
            HttpRequest httpRequest = HttpRequest.httpRequest(ByteArray.byteArray(request));
            url = httpRequest.url();
            // 检测原始请求是否为 HTTP/2
            final boolean useHttp2 = "HTTP/2".equals(httpRequest.httpVersion());

            BurpExtender.printOutput("[*] 正在发送请求到 " + url + " (协议: " + (useHttp2 ? "HTTP/2" : "HTTP/1.1") + ", 超时时间: " + requestPanel.getTimeout() + "秒)");

            sendButton.setEnabled(false);
            sendButton.setText("发送中...");

            final byte[] finalRequest = request;
            final String finalUrl = url;
            final long requestStartTime = System.currentTimeMillis();

            new Thread(() -> {
                try {
                    URL urlObj = new URL(finalUrl);
                    String host = urlObj.getHost();
                    int port = urlObj.getPort() == -1 ? urlObj.getDefaultPort() : urlObj.getPort();
                    boolean useHttps = urlObj.getProtocol().equalsIgnoreCase("https");

                    HttpService httpService = HttpService.httpService(host, port, useHttps);

                    byte[] fixedRequest = RequestDataHelper.fixContentLength(finalRequest, httpService);

                    // 根据原始协议版本选择构建方式：HTTP/2 使用 http2Request（含伪头部）
                    HttpRequest requestToSend;
                    if (useHttp2) {
                        HttpRequest tempRequest = HttpRequest.httpRequest(httpService, ByteArray.byteArray(fixedRequest));

                        // 构造 HTTP/2 伪头部
                        String scheme = useHttps ? "https" : "http";
                        String authority = host;
                        if ((useHttps && port != 443) || (!useHttps && port != 80)) {
                            authority = host + ":" + port;
                        }

                        java.util.List<burp.api.montoya.http.message.HttpHeader> http2Headers = new java.util.ArrayList<>();
                        http2Headers.add(burp.api.montoya.http.message.HttpHeader.httpHeader(":method", tempRequest.method()));
                        http2Headers.add(burp.api.montoya.http.message.HttpHeader.httpHeader(":path", tempRequest.path()));
                        http2Headers.add(burp.api.montoya.http.message.HttpHeader.httpHeader(":scheme", scheme));
                        http2Headers.add(burp.api.montoya.http.message.HttpHeader.httpHeader(":authority", authority));

                        // 添加普通头部（跳过 HTTP/1 专有头部）
                        java.util.Set<String> skipHeaders = new java.util.HashSet<>(java.util.Arrays.asList(
                                "host", "connection", "transfer-encoding", "upgrade", "keep-alive", "proxy-connection"));
                        for (burp.api.montoya.http.message.HttpHeader header : tempRequest.headers()) {
                            if (!skipHeaders.contains(header.name().toLowerCase())) {
                                http2Headers.add(header);
                            }
                        }

                        requestToSend = HttpRequest.http2Request(httpService, http2Headers, tempRequest.body());
                    } else {
                        requestToSend = HttpRequest.httpRequest(httpService, ByteArray.byteArray(fixedRequest));
                    }
                    HttpRequestResponse response = api.http().sendRequest(requestToSend);

                    byte[] responseData = response.response().toByteArray().getBytes();
                    final long elapsedMs = System.currentTimeMillis() - requestStartTime;

                    // 检测 Burp 内部错误响应（如 HTTP/0.9 1337）
                    int statusCode = response.response().statusCode();
                    boolean isBurpError = statusCode == 1337 || statusCode == 0 || statusCode > 999;
                    if (!isBurpError && responseData.length > 8) {
                        String start = new String(responseData, 0, Math.min(responseData.length, 20),
                                java.nio.charset.StandardCharsets.ISO_8859_1);
                        if (start.startsWith("HTTP/0.9")) {
                            isBurpError = true;
                        }
                    }

                    if (isBurpError) {
                        SwingUtilities.invokeLater(() -> {
                            BurpExtender.printError(String.format(
                                "[!] 服务器返回异常响应 (HTTP %d)，可能是请求格式错误或目标不支持", statusCode));
                            JOptionPane.showMessageDialog(requestPanel,
                                String.format("服务器返回异常响应 (HTTP %d)，\n可能是请求格式错误或目标服务不支持", statusCode),
                                "响应错误",
                                JOptionPane.ERROR_MESSAGE);
                        });
                    } else if (responseData != null && responseData.length > 0) {
                        final int finalStatusCode = statusCode;
                        SwingUtilities.invokeLater(() -> {
                            try {
                                handleSuccessfulResponse(finalRequest, requestToSend, responseData, finalStatusCode, finalUrl, elapsedMs);
                            } catch (Exception e) {
                                BurpExtender.printError("[!] 处理响应时出错: " + e.getMessage());
                            }
                        });
                    } else {
                        SwingUtilities.invokeLater(() -> {
                            BurpExtender.printError("[!] 请求发送失败");
                            JOptionPane.showMessageDialog(requestPanel,
                                "请求发送失败，未收到响应",
                                "错误",
                                JOptionPane.ERROR_MESSAGE);
                        });
                    }
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> {
                        BurpExtender.printError("[!] 发送请求时出错: " + e.getMessage());
                        JOptionPane.showMessageDialog(requestPanel,
                            "发送请求失败: " + e.getMessage(),
                            "错误",
                            JOptionPane.ERROR_MESSAGE);
                    });
                } finally {
                    long elapsedMs = System.currentTimeMillis() - requestStartTime;
                    saveHistoryRecord(finalRequest, finalUrl, elapsedMs);
                    SwingUtilities.invokeLater(() -> {
                        sendButton.setEnabled(true);
                        sendButton.setText("发送请求");
                    });
                }
            }, "RepeaterManager-SendRequest").start();

        } catch (Exception e) {
            BurpExtender.printError("[!] 准备请求时出错: " + e.getMessage());
            sendButton.setEnabled(true);
            sendButton.setText("发送请求");
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(
                    requestPanel,
                    "准备请求失败: " + e.getMessage(),
                    "错误",
                    JOptionPane.ERROR_MESSAGE
                );
            });
        }
    }

    /**
     * 处理成功响应（在EDT中调用）
     *
     * @param request      原始请求数据
     * @param requestInfo  请求信息对象
     * @param responseData 响应数据（已提取，避免重复转换）
     * @param statusCode   响应状态码
     * @param url          请求URL
     * @param elapsedMs    请求耗时（毫秒）
     */
    private void handleSuccessfulResponse(byte[] request, HttpRequest requestInfo, byte[] responseData, int statusCode, String url, long elapsedMs) {
        try {
            URL parsedUrl = new URL(url);
            String protocol = parsedUrl.getProtocol();
            String domain = HttpRequestHelper.resolveDomainWithPort(parsedUrl, null);
            String path = parsedUrl.getPath();
            String query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";
            String method = requestInfo.method();

            RequestDAO requestDAO = new RequestDAO();
            int requestId = requestDAO.saveRequest(protocol, domain, path, query, method, request);

            if (requestId > 0) {
                HistoryWriteDAO historyWriteDAO = new HistoryWriteDAO();

                org.oxff.repeater.http.RequestResponseRecord record = new org.oxff.repeater.http.RequestResponseRecord(
                    requestId, protocol, domain, path, query, method);
                record.setStatusCode(statusCode);
                record.setResponseLength(responseData.length);
                record.setResponseTime((int) elapsedMs);
                record.setRequestData(request);
                record.setResponseData(responseData);
                record.setTimestamp(new java.util.Date());

                int historyId = historyWriteDAO.saveHistory(record);

                if (historyId > 0) {
                    if (mainUI != null && mainUI.getHistoryPanel() != null) {
                        mainUI.getHistoryPanel().addHistoryRecord(record);
                    }

                    BurpExtender.printOutput("[+] 请求和响应已保存到数据库，请求ID: " + requestId + ", 历史ID: " + historyId);
                } else {
                    BurpExtender.printError("[!] 保存响应到数据库失败");
                }
            } else {
                BurpExtender.printError("[!] 保存请求到数据库失败");
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 处理响应数据时出错: " + e.getMessage());
        }
    }

    /**
     * 保存历史记录
     */
    private void saveHistoryRecord(byte[] request, String url, long responseTime) {
        try {
            if (request == null) {
                BurpExtender.printError("[!] 无法保存历史记录：请求数据为空");
                return;
            }

            HttpRequest requestInfo = HttpRequest.httpRequest(ByteArray.byteArray(request));
            String method = requestInfo.method();

            URL parsedUrl;
            try {
                parsedUrl = new URL(url);
            } catch (Exception e) {
                BurpExtender.printError("[!] 保存历史记录时URL解析失败: " + e.getMessage());
                return;
            }

            String protocol = parsedUrl.getProtocol();
            String domain = HttpRequestHelper.resolveDomainWithPort(parsedUrl, null);
            String path = parsedUrl.getPath();
            String query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";

            int requestId = (int) (System.currentTimeMillis() % Integer.MAX_VALUE);

            org.oxff.repeater.http.RequestResponseRecord record = new org.oxff.repeater.http.RequestResponseRecord();
            record.setRequestId(requestId);
            record.setMethod(method);
            record.setProtocol(protocol);
            record.setDomain(domain);
            record.setPath(path);
            record.setQueryParameters(query);
            record.setRequestData(request);
            record.setResponseTime((int) responseTime);
            record.setTimestamp(new java.util.Date());
            record.setResponseData(new byte[0]);
            record.setStatusCode(0);
            record.setResponseLength(0);

            HistoryWriteDAO historyWriteDAO = new HistoryWriteDAO();
            int historyId = historyWriteDAO.saveHistory(record);

            if (historyId > 0) {
                BurpExtender.printOutput("[+] 历史记录已保存到数据库，历史ID: " + historyId);

                if (mainUI != null && mainUI.getHistoryPanel() != null) {
                    mainUI.getHistoryPanel().addHistoryRecord(record);
                }
            } else {
                BurpExtender.printError("[!] 保存历史记录到数据库失败");
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 保存历史记录时出错: " + e.getMessage());
        }
    }
}
