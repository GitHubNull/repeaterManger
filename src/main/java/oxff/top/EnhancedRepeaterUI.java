package oxff.top;

import burp.*;
import oxff.top.http.RequestManager;
import oxff.top.http.RequestResponseRecord;
import oxff.top.ui.BurpRequestPanel;
import oxff.top.ui.BurpResponsePanel;
import oxff.top.ui.HistoryPanel;
import oxff.top.ui.RequestListPanel;
import oxff.top.ui.ConfigPanel;
import oxff.top.ui.layout.LayoutManager;
import oxff.top.ui.layout.LayoutManager.LayoutType;
import oxff.top.db.HistoryDAO;

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
 * 1. 左侧：请求报文列表面板，展示所有接收到的请求
 * 2. 右侧：
 *    - 上部：请求和响应编辑/展示区域（可切换布局）
 *    - 下部：当前选中请求的历史重放记录列表
 */
public class EnhancedRepeaterUI implements ITab {
    
    // 主UI组件
    private final JPanel mainPanel;
    private final JSplitPane mainSplitPane;          // 左右分割
    private final JSplitPane rightSplitPane;         // 右侧上下分割
    private final JSplitPane editorSplitPane;        // 编辑区分割
    private final JTabbedPane tabbedPane;            // 选项卡面板
    
    // 功能面板
    private final RequestListPanel requestListPanel;  // 左侧请求列表
    private final BurpRequestPanel requestPanel;      // 右上请求编辑区
    private final BurpResponsePanel responsePanel;    // 右上响应展示区
    private final HistoryPanel historyPanel;          // 右下历史记录
    private final ConfigPanel configPanel;            // 配置面板
    
    // 布局管理器
    private final LayoutManager layoutManager;
    
    // 功能组件
    private final RequestManager requestManager;
    
    // 当前选中的请求ID（在requestListPanel中的ID）
    private int currentRequestId = -1;
    private int nextRequestId = 1;  // 用于生成新的请求ID
    
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
        
        // 创建右侧上下分割面板
        rightSplitPane = new JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            editorPanel,
            historyPanel
        );
        rightSplitPane.setResizeWeight(0.7);
        rightSplitPane.setDividerLocation(500);
        
        // 创建主分割面板（左右）
        mainSplitPane = new JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            requestListPanel,
            rightSplitPane
        );
        mainSplitPane.setResizeWeight(0.3);
        mainSplitPane.setDividerLocation(350);
        
        // 创建配置面板
        configPanel = new ConfigPanel();
        
        // 创建选项卡面板
        tabbedPane = new JTabbedPane();
        tabbedPane.addTab("请求管理", mainSplitPane);
        tabbedPane.addTab("配置", configPanel);
        
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
        
        // 创建新请求项并添加到列表
        requestListPanel.addRequest(nextRequestId, "http", "example.com", "/", "", "GET", null);
        currentRequestId = nextRequestId;
        nextRequestId++;
        
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
        currentRequestId = requestId;
        
        // 清空编辑区域
        requestPanel.clear();
        responsePanel.clear();
        
        // 设置请求内容
        if (requestData != null && requestData.length > 0) {
            requestPanel.setRequest(requestData);
            
            // 获取请求信息，更新历史面板标题
            IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(requestData);
            String url = extractUrlFromRequest(requestData, requestInfo);
            historyPanel.setBorderTitle("请求历史记录 - " + url);
            
            // 加载相关的历史记录
            loadHistoryForRequest(requestId);
        } else {
            historyPanel.setBorderTitle("请求历史记录");
            historyPanel.clearHistory();
        }
    }
    
    /**
     * 加载指定请求ID的历史记录
     */
    private void loadHistoryForRequest(int requestId) {
        // 清空历史记录面板
        historyPanel.clearHistory();
        
        // 获取该请求ID的历史记录
        List<RequestResponseRecord> historyList = requestHistoryMap.get(requestId);
        
        // 如果存在历史记录，则添加到历史面板中
        if (historyList != null && !historyList.isEmpty()) {
            BurpExtender.printOutput(
                String.format("[*] 加载请求ID %d 的历史记录，共 %d 条", 
                    requestId, historyList.size()));
            
            // 将历史记录添加到面板
            for (RequestResponseRecord record : historyList) {
                historyPanel.addHistoryRecord(record);
            }
        } else {
            BurpExtender.printOutput(
                String.format("[*] 请求ID %d 没有历史记录", requestId));
        }
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
            requestManager.makeHttpRequestAsync(requestBytes, timeout, new RequestManager.RequestCallback() {
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
                IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(requestBytes);
                IResponseInfo responseInfo = BurpExtender.helpers.analyzeResponse(response);
                
                String method = requestInfo.getMethod();
                String url = extractUrlFromRequest(requestBytes, requestInfo);
                int statusCode = responseInfo.getStatusCode();
                
                // 更新请求列表中的当前请求（如果是新增的请求）
                if (currentRequestId >= 0) {
                    // 使用extractUrlFromRequest方法解析URL组件，避免直接调用getUrl()
                    String protocol = "http";
                    String host = "";
                    String path = "/";
                    String query = "";
                    
                    try {
                        // 尝试使用标准方式获取URL组件
                        URL parsedUrl = requestInfo.getUrl();
                        protocol = parsedUrl.getProtocol();
                        host = parsedUrl.getHost();
                        path = parsedUrl.getPath();
                        query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";
                    } catch (Exception e) {
                        // 如果标准方式失败，从URL字符串中解析
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
                
                // 创建历史记录
                RequestResponseRecord record;
                try {
                    // 尝试使用标准方式创建记录
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
                    // 如果获取URL失败，使用提取的URL字符串和简单解析
                    BurpExtender.printOutput("[*] 使用备选方法解析URL: " + url);
                    
                    // 解析URL组件
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
                
                // 设置其他属性
                long responseTime = 0; // We don't have timing info in async version, set to 0
                record.setStatusCode(statusCode);
                record.setResponseLength(response.length);
                record.setResponseTime((int)responseTime);
                record.setRequestData(requestBytes);
                record.setResponseData(response);
                record.setTimestamp(new Date());
                
                // 保存到数据库
                HistoryDAO historyDAO = new HistoryDAO();
                int historyId = historyDAO.saveHistory(record);
                
                if (historyId > 0) {
                    // 添加到当前请求的历史记录
                    addHistoryRecord(currentRequestId, record);
                    
                    // 更新历史面板显示
                    historyPanel.addHistoryRecord(record);
                    
                    // 记录日志
                    BurpExtender.printOutput(String.format(
                        "[+] 请求完成: %s %s → HTTP %d (%d 字节)", 
                        method, url, statusCode, response.length));
                } else {
                    BurpExtender.printError("[!] 保存历史记录到数据库失败");
                }
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
            IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(requestBytes);
            
            String method = requestInfo.getMethod();
            String url = extractUrlFromRequest(requestBytes, requestInfo);
            
            // 使用extractUrlFromRequest方法解析URL组件，避免直接调用getUrl()
            String protocol = "http";
            String host = "";
            String path = "/";
            String query = "";
            
            try {
                // 尝试使用标准方式获取URL组件
                URL parsedUrl = requestInfo.getUrl();
                protocol = parsedUrl.getProtocol();
                host = parsedUrl.getHost();
                path = parsedUrl.getPath();
                query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";
            } catch (Exception e) {
                // 如果标准方式失败，从URL字符串中解析
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
            
            // 更新请求列表中的当前请求（如果是新增的请求）
            if (currentRequestId >= 0) {
                requestListPanel.updateRequest(currentRequestId, protocol, host, path, query, method);
            }
            
            // 创建历史记录
            RequestResponseRecord record = new RequestResponseRecord(
                currentRequestId,
                protocol,
                host,
                path,
                query,
                method
            );
            
            // 设置失败相关的属性
            record.setStatusCode(0); // 0 indicates failure
            record.setResponseLength(0);
            record.setResponseTime(0);
            record.setRequestData(requestBytes);
            record.setResponseData(new byte[0]); // Empty response for failed requests
            record.setTimestamp(new Date());
            record.setComment("请求失败: " + errorMessage);
            
            // 保存到数据库
            HistoryDAO historyDAO = new HistoryDAO();
            int historyId = historyDAO.saveHistory(record);
            
            if (historyId > 0) {
                // 添加到当前请求的历史记录
                addHistoryRecord(currentRequestId, record);
                
                // 更新历史面板显示
                historyPanel.addHistoryRecord(record);
                
                // 记录日志
                BurpExtender.printOutput(String.format(
                    "[+] 请求失败已记录: %s %s → 错误: %s", 
                    method, url, errorMessage));
            } else {
                BurpExtender.printError("[!] 保存失败请求历史记录到数据库失败");
            }
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
                
                // 添加到请求列表
                requestListPanel.addRequest(nextRequestId, protocol, domain, path, query, method, request);
                currentRequestId = nextRequestId;
                nextRequestId++;
                
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
                        // 简单地判断是否为HTTPS
                        boolean isHttps = false;
                        if (path.startsWith("https://")) {
                            isHttps = true;
                        } else if (host.contains(":443")) {
                            isHttps = true;
                        }
                        
                        String url = (isHttps ? "https://" : "http://") + host + path;
                        if (url.startsWith("http://http://") || url.startsWith("https://https://")) {
                            url = url.substring(7); // 修复可能的双重协议
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
        
        try {
            // 创建一个MainUI实例，通过它调用loadPersistedData方法加载数据
            oxff.top.ui.MainUI mainUI = new oxff.top.ui.MainUI(requestListPanel, requestPanel, responsePanel, historyPanel);
            
            // 调用加载数据方法
            mainUI.loadPersistedData();
            
            BurpExtender.printOutput("[+] 数据刷新请求已提交，请等待数据加载完成");
        } catch (Exception e) {
            BurpExtender.printError("[!] 刷新数据时出错: " + e.getMessage());
            e.printStackTrace();
        }
    }
}