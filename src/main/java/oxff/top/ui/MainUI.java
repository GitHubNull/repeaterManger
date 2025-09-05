package oxff.top.ui;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import oxff.top.db.DatabaseManager;
import oxff.top.db.RequestDAO;
import oxff.top.db.HistoryDAO;
import oxff.top.http.RequestResponseRecord;
import oxff.top.service.AutoSaveService;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.Map;

/**
 * 插件主UI界面
 */
public class MainUI extends JPanel {
    private static final long serialVersionUID = 1L;
    
    // 保留以供将来使用，例如在需要直接访问Burp API时
    @SuppressWarnings("unused")
    private IBurpExtenderCallbacks callbacks;
    @SuppressWarnings("unused")
    private IExtensionHelpers helpers;
    private final RequestListPanel requestListPanel;
    private final RequestPanel requestPanel;
    private final ResponsePanel responsePanel;
    private final HistoryPanel historyPanel;
    private ConfigPanel configPanel;
    private final DatabaseManager dbManager;
    private final RequestDAO requestDAO;
    private final HistoryDAO historyDAO;
    private final AutoSaveService autoSaveService;
    
    /**
     * 创建主UI
     * 
     * @param callbacks Burp扩展回调
     * @param helpers Burp辅助功能
     */
    public MainUI(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        super(new BorderLayout());
        
        this.callbacks = callbacks;
        this.helpers = helpers;
        
        // 初始化数据库
        this.dbManager = DatabaseManager.getInstance();
        boolean dbInitialized = dbManager.initialize();
        if (!dbInitialized) {
            BurpExtender.printError("[!] 无法初始化数据库，持久化功能将不可用");
        }
        
        // 创建数据访问对象
        this.requestDAO = new RequestDAO();
        this.historyDAO = new HistoryDAO();
        
        // 创建自动保存服务
        this.autoSaveService = new AutoSaveService();
        this.autoSaveService.setMainUI(this);
        
        // 创建UI组件
        requestListPanel = new RequestListPanel();
        requestPanel = new RequestPanel(this);
        responsePanel = new ResponsePanel();
        historyPanel = new HistoryPanel();
        configPanel = new ConfigPanel();
        
        // 创建请求/响应分离面板
        JSplitPane requestResponseSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        requestResponseSplitPane.setTopComponent(requestPanel);
        requestResponseSplitPane.setBottomComponent(responsePanel);
        requestResponseSplitPane.setResizeWeight(0.5);
        
        // 创建右侧分离面板（请求/响应和历史记录）
        JSplitPane rightSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightSplitPane.setTopComponent(requestResponseSplitPane);
        rightSplitPane.setBottomComponent(historyPanel);
        rightSplitPane.setResizeWeight(0.7);
        
        // 创建主分离面板（左侧请求列表和右侧面板）
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplitPane.setLeftComponent(requestListPanel);
        mainSplitPane.setRightComponent(rightSplitPane);
        mainSplitPane.setResizeWeight(0.3);
        
        // 创建选项卡面板，添加主界面和配置面板
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("请求管理", mainSplitPane);
        tabbedPane.addTab("配置", configPanel);
        
        // 添加到主面板
        add(tabbedPane, BorderLayout.CENTER);
        
        // 设置回调
        setupCallbacks();
        
        // 加载持久化数据
        loadPersistedData();
        
        // 启动自动保存服务
        if (dbInitialized) {
            autoSaveService.start();
        }
    }
    
    /**
     * 使用现有组件创建主UI
     * 用于刷新数据时重用现有UI组件
     */
    public MainUI(RequestListPanel requestListPanel, RequestPanel requestPanel, 
                  ResponsePanel responsePanel, HistoryPanel historyPanel) {
        this.requestListPanel = requestListPanel;
        this.requestPanel = requestPanel;
        this.responsePanel = responsePanel;
        this.historyPanel = historyPanel;
        
        // 将没有初始化的final字段设为null
        this.callbacks = null;
        this.helpers = null;
        this.configPanel = null;
        
        // 初始化数据库和DAO
        this.dbManager = DatabaseManager.getInstance();
        this.requestDAO = new RequestDAO();
        this.historyDAO = new HistoryDAO();
        
        // 初始化自动保存服务（但不启动它，因为这是一个临时实例）
        this.autoSaveService = new AutoSaveService(requestDAO, historyDAO);
    }
    
    /**
     * 使用Burp面板组件创建主UI
     * 用于从EnhancedRepeaterUI中调用，处理不同类型的请求和响应面板
     * 
     * @param requestListPanel 请求列表面板
     * @param burpRequestPanel Burp请求面板
     * @param burpResponsePanel Burp响应面板
     * @param historyPanel 历史记录面板
     */
    public MainUI(RequestListPanel requestListPanel, oxff.top.ui.BurpRequestPanel burpRequestPanel,
                  oxff.top.ui.BurpResponsePanel burpResponsePanel, HistoryPanel historyPanel) {
        this.requestListPanel = requestListPanel;
        
        // 由于类型不匹配，但这里只是用于数据刷新，我们可以使用null值
        // 实际操作中使用的是传入的burpRequestPanel和burpResponsePanel
        this.requestPanel = null;
        this.responsePanel = null;
        this.historyPanel = historyPanel;
        
        // 将没有初始化的字段设为null
        this.callbacks = null;
        this.helpers = null;
        this.configPanel = null;
        
        // 初始化数据库和DAO
        this.dbManager = DatabaseManager.getInstance();
        this.requestDAO = new RequestDAO();
        this.historyDAO = new HistoryDAO();
        
        // 初始化自动保存服务（但不启动它，因为这是一个临时实例）
        this.autoSaveService = new AutoSaveService(requestDAO, historyDAO);
        
        BurpExtender.printOutput("[*] 使用增强型Repeater面板创建临时MainUI实例，用于数据刷新");
    }
    
    /**
     * 设置回调函数
     */
    private void setupCallbacks() {
        // 设置请求选中回调
        requestListPanel.setRequestSelectedCallback((requestId, requestData) -> {
            // 加载请求到右侧面板
            requestPanel.setRequest(requestData);
            
            // 加载相关的历史记录
            loadHistoryForRequest(requestId);
        });
        
        // 设置历史记录选中回调
        historyPanel.setOnSelectRecord(record -> {
            if (record != null) {
                // 加载请求和响应
                requestPanel.setRequest(record.getRequestData());
                responsePanel.setResponse(record.getResponseData());
            }
        });
        
        // 启动自动保存服务
        if (dbManager != null && autoSaveService != null) {
            BurpExtender.printOutput("[*] 准备启动自动保存服务...");
            autoSaveService.start();
        } else {
            BurpExtender.printError("[!] 无法启动自动保存服务，组件未正确初始化");
        }
    }
    
    /**
     * 加载特定请求的历史记录
     */
    private void loadHistoryForRequest(int requestId) {
        new Thread(() -> {
            // 清空现有历史
            historyPanel.clearHistory();
            
            // 加载请求相关的历史记录
            List<RequestResponseRecord> records = historyDAO.getHistoryByRequestId(requestId);
            for (RequestResponseRecord record : records) {
                historyPanel.addHistoryRecord(record);
            }
        }).start();
    }
    
    /**
     * 加载持久化数据
     */
    public void loadPersistedData() {
        new Thread(() -> {
            try {
                // 加载请求数据
                List<Map<String, Object>> requests = requestDAO.getAllRequests();
                BurpExtender.printOutput("[+] 从数据库加载 " + requests.size() + " 条请求记录");
                
                for (Map<String, Object> request : requests) {
                    // 获取数据库ID（仅用于日志记录和调试）
                    // int id = (Integer) request.get("id");
                    String protocol = (String) request.get("protocol");
                    String domain = (String) request.get("domain");
                    String path = (String) request.get("path");
                    String query = (String) request.get("query");
                    String method = (String) request.get("method");
                    byte[] requestData = (byte[]) request.get("request_data");
                    
                    // 构建URL
                    String url = protocol + "://" + domain + path;
                    if (query != null && !query.isEmpty()) {
                        url += "?" + query;
                    }
                    
                    // 添加到请求列表面板
                    int localId = requestListPanel.addNewRequest(url, method, requestData);
                    
                    // 设置颜色和备注
                    java.awt.Color color = (java.awt.Color) request.get("color");
                    String comment = (String) request.get("comment");
                    
                    if (color != null) {
                        Map<Integer, Color> colors = requestListPanel.getRequestColors();
                        if (colors != null) {
                            colors.put(localId, color);
                        }
                    }
                    
                    if (comment != null && !comment.isEmpty()) {
                        requestListPanel.updateRequestComment(localId, comment);
                    }
                }
                
                BurpExtender.printOutput("[+] 请求数据加载完成");
                
            } catch (Exception e) {
                BurpExtender.printError("[!] 加载持久化数据失败: " + e.getMessage());
            }
        }).start();
    }
    
    /**
     * 关闭插件时清理资源
     */
    public void onUnload() {
        // 停止自动保存服务
        if (autoSaveService != null) {
            autoSaveService.stop();
        }
        
        // 执行最后一次保存
        autoSaveService.saveNow();
        
        // 关闭数据库连接
        if (dbManager != null) {
            dbManager.close();
        }
    }
    
    /**
     * 获取请求列表面板
     */
    public RequestListPanel getRequestListPanel() {
        return requestListPanel;
    }
    
    /**
     * 获取请求面板
     */
    public RequestPanel getRequestPanel() {
        return requestPanel;
    }
    
    /**
     * 获取响应面板
     */
    public ResponsePanel getResponsePanel() {
        return responsePanel;
    }
    
    /**
     * 获取历史记录面板
     */
    public HistoryPanel getHistoryPanel() {
        return historyPanel;
    }
} 