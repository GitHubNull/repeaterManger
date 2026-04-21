package oxff.top;

import burp.*;
import oxff.top.http.RequestManager;
import oxff.top.http.RequestResponseRecord;
import oxff.top.ui.BurpRequestPanel;
import oxff.top.ui.BurpResponsePanel;
import oxff.top.ui.HistoryPanel;
import oxff.top.ui.RequestListPanel;
import oxff.top.ui.ConfigPanel;
import oxff.top.ui.LogPanel;
import oxff.top.ui.layout.LayoutManager;
import oxff.top.ui.layout.LayoutManager.LayoutType;
import oxff.top.db.HistoryDAO;
import oxff.top.db.RequestDAO;

import javax.swing.*;
import java.awt.*;
import java.awt.FlowLayout;
import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.net.URL;

/**
 * 增强型Repeater主界面 - 组装和协调所有组件
 *
 * 总体布局：
 * 1. 左侧（上下结构）：
 *    - 上部：请求报文列表面板，展示所有接收到的请求
 *    - 下部：当前选中请求的历史重放记录列表
 * 2. 右侧：请求和响应编辑/展示区域（可切换布局）
 */
public class EnhancedRepeaterUI implements ITab {
    
    // 主UI组件
    private final JPanel mainPanel;
    private final JSplitPane mainSplitPane;          // 左右分割
    private final JSplitPane leftSplitPane;          // 左侧上下分割
    private final JSplitPane editorSplitPane;        // 编辑区分割
    private final JTabbedPane tabbedPane;            // 选项卡面板
    
    // 功能面板
    private final RequestListPanel requestListPanel;  // 左侧请求列表
    private final BurpRequestPanel requestPanel;      // 右上请求编辑区
    private final BurpResponsePanel responsePanel;    // 右上响应展示区
    private final HistoryPanel historyPanel;          // 右下历史记录
    private final ConfigPanel configPanel;            // 配置面板
    private final LogPanel logPanel;                  // 日志面板
    
    // 布局管理器
    private final LayoutManager layoutManager;
    
    // 功能组件
    private final RequestManager requestManager;
    
    // 当前选中的请求ID（数据库中的ID）
    private int currentRequestId = -1;
    
    // 当前请求的原始HTTP服务信息（包含正确的协议、主机、端口）
    // 用于解决HTTPS请求被转为HTTP的问题
    private IHttpService currentHttpService = null;
    
    // 请求历史记录映射: 请求ID -> 历史记录列表
    private final Map<Integer, List<RequestResponseRecord>> requestHistoryMap = new HashMap<>();
    
    /**
     * 创建增强型Repeater界面
     */
    public EnhancedRepeaterUI() {
        // 初始化功能组件
        requestManager = new RequestManager();
        
        // 初始化主面板
        mainPanel = new JPanel(new BorderLayout());
        
        // 创建请求列表面板（左侧）
        requestListPanel = new RequestListPanel();
        requestListPanel.setRequestSelectedCallback(this::onRequestSelected);
        
        // 创建请求和响应面板（右上）
        requestPanel = new BurpRequestPanel();
        responsePanel = new BurpResponsePanel();
        
        // 创建编辑器分割面板
        editorSplitPane = new JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT, 
            requestPanel, 
            responsePanel
        );
        editorSplitPane.setResizeWeight(0.5);
        
        // 创建布局管理器
        layoutManager = new LayoutManager(editorSplitPane, LayoutType.HORIZONTAL);
        
        // 创建历史记录面板（右下）
        historyPanel = new HistoryPanel();
        
        // 设置发送请求按钮动作
        requestPanel.setSendButtonListener(e -> sendRequest());
        
        // 设置历史记录双击回调
        historyPanel.setOnSelectRecord(this::loadHistoryRecord);
        
        // 创建编辑区控制面板
        JPanel editorControlPanel = createEditorControlPanel();
        
        // 组合编辑区和控制面板
        JPanel editorPanel = new JPanel(new BorderLayout());
        editorPanel.add(editorControlPanel, BorderLayout.NORTH);
        editorPanel.add(editorSplitPane, BorderLayout.CENTER);
        
        // 创建左侧上下分割面板（请求列表 + 历史记录）
        leftSplitPane = new JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            requestListPanel,
            historyPanel
        );
        leftSplitPane.setResizeWeight(0.5);
        leftSplitPane.setDividerLocation(300);

        // 创建主分割面板（左右）
        mainSplitPane = new JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            leftSplitPane,
            editorPanel
        );
        mainSplitPane.setResizeWeight(0.3);
        mainSplitPane.setDividerLocation(350);
        
        // 创建配置面板
        configPanel = new ConfigPanel();

        // 创建日志面板
        logPanel = new LogPanel();

        // 创建选项卡面板
        tabbedPane = new JTabbedPane();
        tabbedPane.addTab("请求管理", mainSplitPane);
        tabbedPane.addTab("配置", configPanel);
        tabbedPane.addTab("日志", logPanel);

        // 注册LogPanel到LogManager
        oxff.top.logging.LogManager.getInstance().setLogPanel(logPanel);

        // 添加到主面板
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
    }
    
    /**
     * 创建编辑区域的控制面板
     */
    private JPanel createEditorControlPanel() {
        JPanel controlPanel = new JPanel(new BorderLayout());
        
        // 左侧工具按钮区
        JPanel leftToolPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton newRequestButton = new JButton("新建请求");
        newRequestButton.setToolTipText("创建新的空白请求");
        newRequestButton.addActionListener(e -> createNewRequest());
        
        JButton clearButton = new JButton("清空");
        clearButton.setToolTipText("清空当前请求和响应内容");
        clearButton.addActionListener(e -> {
            requestPanel.clear();
            responsePanel.clear();
        });
        
        leftToolPanel.add(newRequestButton);
        leftToolPanel.add(clearButton);
        
        // 右侧布局控制区
        JPanel rightToolPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        JComboBox<String> layoutComboBox = new JComboBox<>(new String[]{"左右布局", "上下布局", "仅请求", "仅响应"});
        layoutComboBox.setToolTipText("切换请求和响应的布局方式");
        layoutComboBox.addActionListener(e -> {
            String selectedLayout = (String) layoutComboBox.getSelectedItem();
            if ("左右布局".equals(selectedLayout)) {
                layoutManager.setLayout(LayoutType.HORIZONTAL);
            } else if ("上下布局".equals(selectedLayout)) {
                layoutManager.setLayout(LayoutType.VERTICAL);
            } else if ("仅请求".equals(selectedLayout)) {
                layoutManager.setLayoutRequestOnly();
            } else if ("仅响应".equals(selectedLayout)) {
                layoutManager.setLayoutResponseOnly();
            }
        });
        
        rightToolPanel.add(new JLabel("布局："));
        rightToolPanel.add(layoutComboBox);
        
        // 添加到控制面板
        controlPanel.add(leftToolPanel, BorderLayout.WEST);
        controlPanel.add(rightToolPanel, BorderLayout.EAST);
        
        return controlPanel;
    }
    
    /**
     * 创建新请求
     */
    private void createNewRequest() {
        requestPanel.clear();
        responsePanel.clear();
        
        // 新建请求时重置HTTP服务信息
        currentHttpService = null;
        
        // 创建新请求项并添加到列表，同时保存到数据库
        String newRequestTemplate = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        
        // 保存请求到数据库，获取数据库生成的ID
        RequestDAO requestDAO = new RequestDAO();
        int dbId = requestDAO.saveRequest("http", "example.com", "/", "", "GET", newRequestTemplate.getBytes());
        
        if (dbId <= 0) {
            BurpExtender.printError("[!] 创建新请求时保存到数据库失败");
            return;
        }
        
        requestListPanel.addRequest(dbId, "http", "example.com", "/", "", "GET", newRequestTemplate.getBytes());
        currentRequestId = dbId;
        
        // 更新历史面板标题
        historyPanel.setBorderTitle("请求历史记录 - 新建请求");
        
        // 清空历史记录并初始化新的历史记录列表
        historyPanel.clearHistory();
        requestHistoryMap.put(currentRequestId, new ArrayList<>());
    }
    
    /**
     * 请求列表选中回调
     */
    private void onRequestSelected(int requestId, byte[] requestData) {
        BurpExtender.printOutput("[*] 请求选中回调触发，请求ID: " + requestId);
        
        currentRequestId = requestId;
        
        // 清空编辑区域
        requestPanel.clear();
        responsePanel.clear();
        
        // 设置请求内容
        if (requestData != null && requestData.length > 0) {
            requestPanel.setRequest(requestData);
            BurpExtender.printOutput("[+] 已加载请求数据到编辑器，大小: " + requestData.length + " 字节");
            
            // 从请求列表的表格数据中获取协议、主机、端口信息，重建IHttpService
            // 这确保了从已保存请求重新发送时，HTTPS协议信息不会丢失
            currentHttpService = rebuildHttpServiceFromRequestList(requestId, requestData);
            
            // 获取请求信息，更新历史面板标题
            IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(currentHttpService, requestData);
            String url = extractUrlFromRequest(requestData, requestInfo);
            historyPanel.setBorderTitle("请求历史记录 - " + url);
            
            // 尝试加载该请求的最新响应数据
            loadLatestResponseForRequest(requestId);
            
            // 加载相关的历史记录
            loadHistoryForRequest(requestId);
        } else {
            BurpExtender.printOutput("[!] 请求数据为空，ID: " + requestId);
            currentHttpService = null;
            historyPanel.setBorderTitle("请求历史记录");
            historyPanel.clearHistory();
        }
    }
    
    /**
     * 从请求数据中重建IHttpService
     * 解决从已保存请求重新发送时HTTPS协议丢失的问题
     * 
     * @param requestId 请求ID
     * @param requestData 请求数据
     * @return 重建的IHttpService对象
     */
    private IHttpService rebuildHttpServiceFromRequestList(int requestId, byte[] requestData) {
        try {
            String protocol = "http";
            String host = "";
            int port = 80;
            
            // 从请求数据中提取host和port
            IRequestInfo tempInfo = BurpExtender.helpers.analyzeRequest(requestData);
            List<String> headers = tempInfo.getHeaders();
            
            // 提取host
            for (String header : headers) {
                if (header.toLowerCase().startsWith("host:")) {
                    String hostValue = header.substring(5).trim();
                    String[] hostParts = hostValue.split(":");
                    host = hostParts[0];
                    if (hostParts.length > 1) {
                        try {
                            port = Integer.parseInt(hostParts[1]);
                        } catch (NumberFormatException e) {
                            // 忽略
                        }
                    }
                    break;
                }
            }
            
            // 从数据库中获取保存的协议信息（按ID单条查询，避免全表扫描）
            try {
                oxff.top.db.RequestDAO requestDAO = new oxff.top.db.RequestDAO();
                java.util.Map<String, Object> request = requestDAO.getRequest(requestId);
                if (request != null) {
                    protocol = (String) request.get("protocol");
                    String dbDomain = (String) request.get("domain");
                    if (dbDomain != null && !dbDomain.isEmpty()) {
                        host = dbDomain;
                    }
                }
            } catch (Exception e) {
                BurpExtender.printOutput("[*] 从数据库获取协议信息失败，使用请求数据推断: " + e.getMessage());
            }
            
            // 综合判断HTTPS：优先数据库协议，再结合请求头判断
            boolean isSecure = protocol.equalsIgnoreCase("https");
            
            // 额外检查请求头中的HTTPS指示
            if (!isSecure) {
                String firstLine = headers.get(0);
                if (firstLine.contains("https://")) {
                    isSecure = true;
                }
                for (String header : headers) {
                    if (header.toLowerCase().startsWith("host:") && header.contains(":443")) {
                        isSecure = true;
                        break;
                    }
                }
            }
            
            // 根据协议设置默认端口
            if (isSecure && port == 80) {
                port = 443;
            } else if (!isSecure && port == 443) {
                port = 80;
            }
            
            if (host.isEmpty()) {
                host = "unknown";
            }
            
            return BurpExtender.helpers.buildHttpService(host, port, isSecure);
        } catch (Exception e) {
            BurpExtender.printError("[!] 重建IHttpService失败: " + e.getMessage());
            // 返回一个默认的HTTP服务
            return BurpExtender.helpers.buildHttpService("unknown", 80, false);
        }
    }
    
    /**
     * 加载指定请求ID的最新响应数据
     */
    private void loadLatestResponseForRequest(int requestId) {
        try {
            HistoryDAO historyDAO = new HistoryDAO();
            List<RequestResponseRecord> latestHistory = historyDAO.getLatestHistoryByRequestId(requestId, 1);
            
            if (latestHistory != null && !latestHistory.isEmpty()) {
                RequestResponseRecord latestRecord = latestHistory.get(0);
                byte[] responseData = latestRecord.getResponseData();
                
                if (responseData != null && responseData.length > 0) {
                    responsePanel.setResponse(responseData);
                    BurpExtender.printOutput("[+] 已加载请求ID " + requestId + " 的最新响应数据");
                }
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 加载最新响应数据失败: " + e.getMessage());
        }
    }
    
    /**
     * 加载指定请求ID的历史记录
     */
    private void loadHistoryForRequest(int requestId) {
        // 清空历史记录面板
        historyPanel.clearHistory();
        
        BurpExtender.printOutput(String.format("[*] 开始加载请求ID %d 的历史记录", requestId));
        
        // 优先从数据库加载历史记录
        try {
            HistoryDAO historyDAO = new HistoryDAO();
            List<RequestResponseRecord> dbHistoryList = historyDAO.getHistoryByRequestId(requestId);
            
            if (dbHistoryList != null && !dbHistoryList.isEmpty()) {
                BurpExtender.printOutput(
                    String.format("[*] 从数据库加载请求ID %d 的历史记录，共 %d 条", 
                        requestId, dbHistoryList.size()));
                
                // 将数据库中的历史记录添加到面板（按时间倒序）
                for (RequestResponseRecord record : dbHistoryList) {
                    historyPanel.addHistoryRecord(record);
                }
                
                // 同时更新内存中的历史记录映射
                requestHistoryMap.put(requestId, new ArrayList<>(dbHistoryList));
                
                BurpExtender.printOutput(String.format("[+] 请求ID %d 的历史记录加载完成", requestId));
                return; // 成功从数据库加载，直接返回
            } else {
                BurpExtender.printOutput(String.format("[*] 数据库中未找到请求ID %d 的历史记录", requestId));
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 从数据库加载历史记录失败: " + e.getMessage());
        }
        
        // 如果数据库中没有或加载失败，尝试从内存映射中获取
        List<RequestResponseRecord> historyList = requestHistoryMap.get(requestId);
        
        // 如果存在历史记录，则添加到历史面板中
        if (historyList != null && !historyList.isEmpty()) {
            BurpExtender.printOutput(
                String.format("[*] 从内存加载请求ID %d 的历史记录，共 %d 条", 
                    requestId, historyList.size()));
            
            // 将历史记录添加到面板
            for (RequestResponseRecord record : historyList) {
                historyPanel.addHistoryRecord(record);
            }
        } else {
            BurpExtender.printOutput(
                String.format("[*] 请求ID %d 没有历史记录", requestId));
        }
        
        // 确保历史面板显示正确的标题
        historyPanel.setBorderTitle("请求历史记录 - ID: " + requestId);
    }
    
    /**
     * 发送请求并处理响应
     */
    private void sendRequest() {
        try {
            // 获取请求数据
            byte[] requestBytes = requestPanel.getRequest();
            if (requestBytes == null || requestBytes.length == 0) {
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(mainPanel, 
                        "请求不能为空", "错误", JOptionPane.ERROR_MESSAGE);
                });
                return;
            }
            
            // 显示正在发送的提示
            BurpExtender.printOutput("[*] 正在发送请求...");
            
            // 清空之前的响应
            responsePanel.clear();
            
            // 获取超时设置
            int timeout = requestPanel.getTimeout();
            
            // 设置等待光标
            SwingUtilities.invokeLater(() -> {
                setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
            });
            
            // 在后台线程中执行请求，避免UI冻结
            // 传递currentHttpService以保留正确的协议信息（如HTTPS）
            requestManager.makeHttpRequestAsync(requestBytes, timeout, currentRequestId, currentHttpService, new RequestManager.RequestCallback() {
                @Override
                public void onSuccess(byte[] response) {
                    // 在EDT中更新UI
                    SwingUtilities.invokeLater(() -> {
                        try {
                            handleResponseSuccess(requestBytes, response);
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
                public void onFailure(String errorMessage) {
                    // 在EDT中更新UI
                    SwingUtilities.invokeLater(() -> {
                        try {
                            // Record the failed request in history
                            handleResponseFailure(requestBytes, errorMessage);
                            
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
    private void handleResponseSuccess(byte[] requestBytes, byte[] response) {
        if (response != null && response.length > 0) {
            try {
                // 设置响应面板内容
                responsePanel.setResponse(response);
                
                // 解析请求和响应信息
                // 使用currentHttpService来解析请求，确保协议信息正确（如HTTPS）
                IRequestInfo requestInfo;
                if (currentHttpService != null) {
                    requestInfo = BurpExtender.helpers.analyzeRequest(currentHttpService, requestBytes);
                } else {
                    requestInfo = BurpExtender.helpers.analyzeRequest(requestBytes);
                }
                IResponseInfo responseInfo = BurpExtender.helpers.analyzeResponse(response);
                
                String method = requestInfo.getMethod();
                String url = extractUrlFromRequest(requestBytes, requestInfo);
                int statusCode = responseInfo.getStatusCode();
                
                // 更新请求列表中的当前请求（如果是新增的请求）
                if (currentRequestId >= 0) {
                    String protocol = "http";
                    String host = "";
                    String path = "/";
                    String query = "";
                    
                    try {
                        URL parsedUrl = requestInfo.getUrl();
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
                    
                    requestListPanel.updateRequest(currentRequestId, protocol, host, path, query, method);
                }
                
                // 创建历史记录用于UI显示（数据库保存已由HistoryRecordingService完成）
                RequestResponseRecord record;
                try {
                    URL parsedUrl = requestInfo.getUrl();
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
                record.setResponseTime(0);
                record.setRequestData(requestBytes);
                record.setResponseData(response);
                record.setTimestamp(new Date());
                
                // 添加到当前请求的历史记录（仅内存）
                addHistoryRecord(currentRequestId, record);
                
                // 更新历史面板显示
                historyPanel.addHistoryRecord(record);
                
                // 记录日志
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
            // 响应为空
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
    private void handleResponseFailure(byte[] requestBytes, String errorMessage) {
        try {
            // 解析请求信息
            // 使用currentHttpService来解析请求，确保协议信息正确（如HTTPS）
            IRequestInfo requestInfo;
            if (currentHttpService != null) {
                requestInfo = BurpExtender.helpers.analyzeRequest(currentHttpService, requestBytes);
            } else {
                requestInfo = BurpExtender.helpers.analyzeRequest(requestBytes);
            }
            
            String method = requestInfo.getMethod();
            String url = extractUrlFromRequest(requestBytes, requestInfo);
            
            String protocol = "http";
            String host = "";
            String path = "/";
            String query = "";
            
            try {
                URL parsedUrl = requestInfo.getUrl();
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
            
            // 更新请求列表中的当前请求
            if (currentRequestId >= 0) {
                requestListPanel.updateRequest(currentRequestId, protocol, host, path, query, method);
            }
            
            // 创建历史记录用于UI显示（数据库保存已由HistoryRecordingService完成）
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
            record.setResponseTime(0);
            record.setRequestData(requestBytes);
            record.setResponseData(new byte[0]);
            record.setTimestamp(new Date());
            record.setComment("请求失败: " + errorMessage);
            
            // 添加到当前请求的历史记录（仅内存）
            addHistoryRecord(currentRequestId, record);
            
            // 更新历史面板显示
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
    private void addHistoryRecord(int requestId, RequestResponseRecord record) {
        if (requestId < 0) {
            return;
        }
        
        // 获取该请求ID的历史记录列表，如果不存在则创建新列表
        List<RequestResponseRecord> historyList = requestHistoryMap.computeIfAbsent(
            requestId, k -> new ArrayList<>());
        
        // 添加记录到列表开头（最新的记录显示在前面）
        historyList.add(0, record);
        
        // 记录日志
        BurpExtender.printOutput(
            String.format("[+] 已添加历史记录到请求ID %d，当前历史记录数量: %d", 
                requestId, historyList.size()));
    }
    
    /**
     * 设置鼠标指针样式
     */
    private void setCursor(Cursor cursor) {
        mainPanel.setCursor(cursor);
        requestPanel.setCursor(cursor);
        responsePanel.setCursor(cursor);
        historyPanel.setCursor(cursor);
        requestListPanel.setCursor(cursor);
    }
    
    /**
     * 加载历史记录项
     */
    private void loadHistoryRecord(RequestResponseRecord record) {
        if (record != null) {
            // 设置请求数据
            requestPanel.setRequest(record.getRequestData());
            
            // 设置响应数据
            responsePanel.setResponse(record.getResponseData());
            
            BurpExtender.printOutput("[+] 已加载历史记录: " + record.toString());
        }
    }
    
    /**
     * 设置请求内容 - 用于从右键菜单接收请求
     */
    public void setRequest(IHttpRequestResponse requestResponse) {
        try {
            if (requestResponse != null && requestResponse.getRequest() != null) {
                byte[] request = requestResponse.getRequest();
                
                // 提取URL和方法信息
                String url;
                String method;
                String protocol = "http";
                String domain = "";
                String path = "/";
                String query = "";
                
                try {
                    // 首先尝试使用HTTP服务信息进行分析
                    IHttpService httpService = requestResponse.getHttpService();
                    if (httpService != null) {
                        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(requestResponse);
                        url = requestInfo.getUrl().toString();
                        method = requestInfo.getMethod();
                        
                        // 解析URL组件
                        URL parsedUrl = requestInfo.getUrl();
                        protocol = parsedUrl.getProtocol();
                        domain = parsedUrl.getHost();
                        path = parsedUrl.getPath();
                        query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";
                    } else {
                        // 如果没有HTTP服务信息，从请求头中提取
                        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(request);
                        method = requestInfo.getMethod();
                        
                        // 使用辅助方法提取URL
                        url = extractUrlFromRequest(request, requestInfo);
                        
                        // 解析URL组件
                        if (url.startsWith("https://")) {
                            protocol = "https";
                            url = url.substring(8);
                        } else if (url.startsWith("http://")) {
                            url = url.substring(7);
                        }
                        
                        int pathIndex = url.indexOf('/');
                        if (pathIndex > 0) {
                            domain = url.substring(0, pathIndex);
                            url = url.substring(pathIndex);
                        } else {
                            domain = url;
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
                } catch (Exception e) {
                    // 如果分析失败，设置默认值
                    BurpExtender.printError("[!] 分析请求时出错: " + e.getMessage());
                    method = "UNKNOWN";
                    url = "分析请求出错";
                }
                
                // 保存请求到数据库，获取数据库生成的ID
                RequestDAO requestDAO = new RequestDAO();
                int dbId = requestDAO.saveRequest(protocol, domain, path, query, method, request);
                
                if (dbId <= 0) {
                    BurpExtender.printError("[!] 保存请求到数据库失败");
                    return;
                }
                
                // 添加到请求列表，使用数据库ID
                requestListPanel.addRequest(dbId, protocol, domain, path, query, method, request);
                currentRequestId = dbId;
                
                // 保存原始HTTP服务信息，用于后续发送请求时保留正确的协议（如HTTPS）
                currentHttpService = requestResponse.getHttpService();
                
                // 设置请求内容
                requestPanel.setRequest(request);
                
                // 清空响应内容
                responsePanel.clear();
                
                // 更新历史面板标题
                historyPanel.setBorderTitle("请求历史记录 - " + protocol + "://" + domain + path + (query.isEmpty() ? "" : "?" + query));
                
                // 清空历史记录并初始化新的历史记录列表
                historyPanel.clearHistory();
                requestHistoryMap.put(currentRequestId, new ArrayList<>());
                
                BurpExtender.printOutput("[+] 请求已加载到增强型Repeater: " + protocol + "://" + domain + path + (query.isEmpty() ? "" : "?" + query));
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 设置请求失败: " + e.getMessage());
            e.printStackTrace(new java.io.PrintStream(BurpExtender.callbacks.getStderr()));
        }
    }
    
    /**
     * 获取标签页标题
     */
    @Override
    public String getTabCaption() {
        return "增强型Repeater";
    }
    
    /**
     * 获取UI组件
     */
    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
    
    /**
     * 关闭资源
     */
    public void close() {
        if (requestManager != null) {
            requestManager.shutdown();
        }
    }
    
    /**
     * 从请求中安全地提取URL信息
     * 
     * @param requestBytes 请求字节数组
     * @param requestInfo 已分析的请求信息
     * @return 提取的URL，如果提取失败则返回简化URL或默认值
     */
    private String extractUrlFromRequest(byte[] requestBytes, IRequestInfo requestInfo) {
        try {
            // 尝试使用标准方式获取URL
            return requestInfo.getUrl().toString();
        } catch (Exception e) {
            // 如果标准方式失败，从请求头中提取
            try {
                List<String> headers = requestInfo.getHeaders();
                String firstLine = headers.get(0); // 例如："GET /path HTTP/1.1"
                
                // 从Host头中提取主机名
                String host = "";
                for (String header : headers) {
                    if (header.toLowerCase().startsWith("host:")) {
                        host = header.substring(5).trim();
                        break;
                    }
                }
                
                // 构建URL
                String[] parts = firstLine.split("\\s+");
                if (parts.length >= 2) {
                    String path = parts[1];
                    if (!host.isEmpty()) {
                        // 综合判断是否为HTTPS
                        boolean isHttps = false;
                        // 1. 请求行URL包含https://（绝对URL形式）
                        if (path.startsWith("https://")) {
                            isHttps = true;
                        }
                        // 2. Host头包含443端口
                        if (host.contains(":443")) {
                            isHttps = true;
                        }
                        // 3. 如果有currentHttpService，使用其协议信息
                        if (currentHttpService != null && 
                            "https".equalsIgnoreCase(currentHttpService.getProtocol())) {
                            isHttps = true;
                        }
                        
                        String url = (isHttps ? "https://" : "http://") + host + path;
                        // 修复可能的双重协议前缀
                        while (url.startsWith("http://http://") || url.startsWith("https://https://") ||
                               url.startsWith("http://https://") || url.startsWith("https://http://")) {
                            url = url.replace("http://", "").replace("https://", "");
                            url = (isHttps ? "https://" : "http://") + url;
                        }
                        return url;
                    } else {
                        return path; // 如果找不到Host，至少显示路径
                    }
                }
                
                return "未知URL (从路径获取失败)";
            } catch (Exception ex) {
                BurpExtender.printError("[!] 提取URL失败: " + ex.getMessage());
                return "未知URL";
            }
        }
    }
    
    /**
     * 刷新所有数据
     * 在数据库导入后调用，用于重新加载UI中显示的数据
     */
    public void refreshAllData() {
        BurpExtender.printOutput("[*] 开始刷新界面数据...");

        // 清空当前数据
        requestListPanel.clearAllRequests();
        historyPanel.clearAllHistory();

        // 重置当前选中的请求ID
        currentRequestId = -1;

        // 清空请求历史记录映射
        requestHistoryMap.clear();

        new Thread(() -> {
            try {
                // 1. 加载请求数据（使用addRequest避免重复插入数据库）
                RequestDAO requestDAO = new RequestDAO();
                java.util.List<java.util.Map<String, Object>> requests = requestDAO.getAllRequests();
                BurpExtender.printOutput("[+] 从数据库加载 " + requests.size() + " 条请求记录");

                for (java.util.Map<String, Object> request : requests) {
                    int dbId = (Integer) request.get("id");
                    String protocol = (String) request.get("protocol");
                    String domain = (String) request.get("domain");
                    String path = (String) request.get("path");
                    String query = (String) request.get("query");
                    String method = (String) request.get("method");
                    byte[] requestData = (byte[]) request.get("request_data");

                    requestListPanel.addRequest(dbId, protocol, domain, path, query, method, requestData);

                    java.awt.Color color = (java.awt.Color) request.get("color");
                    String comment = (String) request.get("comment");
                    if (color != null) {
                        requestListPanel.getRequestColors().put(dbId, color);
                    }
                    if (comment != null && !comment.isEmpty()) {
                        requestListPanel.updateRequestComment(dbId, comment);
                    }
                }

                // 2. 加载历史记录到内存缓存
                HistoryDAO historyDAO = new HistoryDAO();
                java.util.List<RequestResponseRecord> allHistory = historyDAO.getAllHistory();
                BurpExtender.printOutput("[+] 从数据库加载 " + allHistory.size() + " 条历史记录");

                for (RequestResponseRecord record : allHistory) {
                    int requestId = record.getRequestId();
                    if (requestId > 0) {
                        requestHistoryMap.computeIfAbsent(requestId, k -> new ArrayList<>()).add(record);
                    }
                }

                BurpExtender.printOutput("[+] 数据刷新完成");
            } catch (Exception e) {
                BurpExtender.printError("[!] 刷新数据时出错: " + e.getMessage());
            }
        }).start();
    }
}