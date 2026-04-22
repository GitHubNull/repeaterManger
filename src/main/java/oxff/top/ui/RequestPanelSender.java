package oxff.top.ui;

import burp.BurpExtender;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import oxff.top.api.MontoyaApiHolder;
import oxff.top.db.RequestDAO;
import oxff.top.db.history.HistoryWriteDAO;
import oxff.top.http.RequestDataHelper;

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

            BurpExtender.printOutput("[*] 正在发送请求到 " + url + " (超时时间: " + requestPanel.getTimeout() + "秒)");

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

                    HttpRequest requestToSend = HttpRequest.httpRequest(httpService, ByteArray.byteArray(fixedRequest));
                    HttpRequestResponse response = api.http().sendRequest(requestToSend);

                    byte[] responseData = response.response().toByteArray().getBytes();
                    final long elapsedMs = System.currentTimeMillis() - requestStartTime;

                    if (responseData != null && responseData.length > 0) {
                        final byte[] finalResponseData = responseData;
                        SwingUtilities.invokeLater(() -> {
                            try {
                                handleSuccessfulResponse(finalRequest, requestToSend, response.response(), finalUrl, elapsedMs);
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
            }, "EnhancedRepeater-SendRequest").start();

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
     */
    private void handleSuccessfulResponse(byte[] request, HttpRequest requestInfo, HttpResponse response, String url, long elapsedMs) {
        try {
            URL parsedUrl = new URL(url);
            String protocol = parsedUrl.getProtocol();
            String domain = parsedUrl.getHost();
            String path = parsedUrl.getPath();
            String query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";
            String method = requestInfo.method();

            RequestDAO requestDAO = new RequestDAO();
            int requestId = requestDAO.saveRequest(protocol, domain, path, query, method, request);

            if (requestId > 0) {
                byte[] responseData = response.toByteArray().getBytes();
                HistoryWriteDAO historyWriteDAO = new HistoryWriteDAO();

                oxff.top.http.RequestResponseRecord record = new oxff.top.http.RequestResponseRecord(
                    requestId, protocol, domain, path, query, method);
                record.setStatusCode(response.statusCode());
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
            String domain = parsedUrl.getHost();
            String path = parsedUrl.getPath();
            String query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";

            int requestId = (int) (System.currentTimeMillis() % Integer.MAX_VALUE);

            oxff.top.http.RequestResponseRecord record = new oxff.top.http.RequestResponseRecord();
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
