package oxff.top;

import burp.BurpExtender;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.HttpService;
import oxff.top.http.RequestManager;
import oxff.top.http.RequestResponseRecord;
import oxff.top.http.HttpRequestHelper;
import oxff.top.ui.editor.BurpRequestPanel;
import oxff.top.ui.editor.BurpResponsePanel;
import oxff.top.ui.history.HistoryPanel;
import oxff.top.ui.RequestListPanel;
import oxff.top.ui.config.ConfigPanel;
import oxff.top.ui.DataPanel;
import oxff.top.ui.LogPanel;
import oxff.top.ui.StatusPanel;
import oxff.top.ui.layout.LayoutManager;
import oxff.top.ui.layout.LayoutManager.LayoutType;
import oxff.top.ui.privilege.PrivilegeTestPanel;
import oxff.top.ui.UsageTutorialPanel;
import oxff.top.ui.AboutPanel;
import oxff.top.db.history.HistoryReadDAO;
import oxff.top.db.history.HistoryWriteDAO;
import oxff.top.db.RequestDAO;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.net.URL;

/**
 * Repeater Manager 主界面 - 组装和协调所有组件
 *
 * 总体布局：
 * 1. 左侧（上下结构）：
 *    - 上部：请求报文列表面板，展示所有接收到的请求
 *    - 下部：当前选中请求的历史重放记录列表
 * 2. 右侧：请求和响应编辑/展示区域（可切换布局）
 */
public class RepeaterManagerUI {

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
    private final DataPanel dataPanel;                // 数据面板
    private final LogPanel logPanel;                  // 日志面板
    private final StatusPanel statusPanel;            // 底部状态栏
    private final PrivilegeTestPanel privilegeTestPanel; // 权限测试配置面板

    // 布局管理器
    private final LayoutManager layoutManager;

    // 功能组件
    private final RequestManager requestManager;

    // 请求调度处理器
    private final RequestDispatchHandler dispatchHandler;

    // 模式切换按钮
    private JToggleButton modeToggleButton;

    /**
     * 创建 Repeater Manager 界面
     *
     * @param api MontoyaApi实例，用于创建编辑器等
     */
    public RepeaterManagerUI(MontoyaApi api) {
        // 不再保存api字段，通过子组件间接使用
        // 初始化功能组件
        requestManager = new RequestManager(api);

        // 初始化主面板
        mainPanel = new JPanel(new BorderLayout());

        // 创建请求列表面板（左侧）
        requestListPanel = new RequestListPanel();
        requestListPanel.setRequestSelectedCallback(this::onRequestSelected);

        // 创建请求和响应面板（右上），传入MontoyaApi用于创建编辑器
        requestPanel = new BurpRequestPanel(api);
        responsePanel = new BurpResponsePanel(api);

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

        // 创建状态栏（底部）
        statusPanel = new StatusPanel();

        // 初始化请求调度处理器
        dispatchHandler = new RequestDispatchHandler(mainPanel, requestPanel, responsePanel, historyPanel, requestListPanel, statusPanel, requestManager);

        // 注册模式变更监听器：同步状态栏指示
        dispatchHandler.addModeChangeListener(mode -> {
            SwingUtilities.invokeLater(() -> statusPanel.setModeIndicator(mode));
        });

        // 注册模式变更监听器：同步切换按钮状态
        dispatchHandler.addModeChangeListener(mode -> {
            SwingUtilities.invokeLater(() -> {
                if (modeToggleButton != null) {
                    modeToggleButton.setSelected(mode);
                    if (mode) {
                        modeToggleButton.setText("权限测试");
                        modeToggleButton.setForeground(new Color(200, 80, 0));
                        modeToggleButton.setFont(modeToggleButton.getFont().deriveFont(Font.BOLD));
                    } else {
                        modeToggleButton.setText("普通模式");
                        modeToggleButton.setForeground(UIManager.getColor("Button.foreground"));
                        modeToggleButton.setFont(modeToggleButton.getFont().deriveFont(Font.PLAIN));
                    }
                }
            });
        });

        // 设置发送请求按钮动作
        requestPanel.setSendButtonListener(e -> dispatchHandler.sendRequest());

        // 设置历史记录双击回调
        historyPanel.setOnSelectRecord(dispatchHandler::loadHistoryRecord);

        // 创建编辑区控制面板
        JPanel editorControlPanel = createEditorControlPanel();

        // 组合编辑区和控制面板
        JPanel editorPanel = new JPanel(new BorderLayout());
        editorPanel.add(editorControlPanel, BorderLayout.NORTH);
        editorPanel.add(editorSplitPane, BorderLayout.CENTER);
        editorPanel.add(statusPanel, BorderLayout.SOUTH);

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
        configPanel.setOnDataChanged(() -> SwingUtilities.invokeLater(() -> refreshAllData()));

        // 创建数据面板
        dataPanel = new DataPanel();
        dataPanel.setOnDataChanged(() -> SwingUtilities.invokeLater(() -> refreshAllData()));

        // 创建日志面板
        logPanel = new LogPanel();

        // 创建权限测试配置面板
        privilegeTestPanel = new PrivilegeTestPanel();

        // 创建使用教程面板
        UsageTutorialPanel usageTutorialPanel = new UsageTutorialPanel();

        // 创建关于面板
        AboutPanel aboutPanel = new AboutPanel();

        // 创建选项卡面板
        tabbedPane = new JTabbedPane();
        tabbedPane.addTab("请求管理", mainSplitPane);
        tabbedPane.addTab("权限测试", privilegeTestPanel);
        tabbedPane.addTab("数据", dataPanel);
        tabbedPane.addTab("配置", configPanel);
        tabbedPane.addTab("日志", logPanel);
        tabbedPane.addTab("使用教程", usageTutorialPanel);
        tabbedPane.addTab("关于", aboutPanel);

        // 监听标签页切换（不再绑定权限测试模式，模式通过工具栏按钮独立控制）
        tabbedPane.addChangeListener(e -> {
            // Tab切换不再自动改变权限测试模式
        });

        // 注册LogPanel到LogManager
        oxff.top.logging.LogManager.getInstance().setLogPanel(logPanel);

        // 添加到主面板
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
    }

    /**
     * 获取UI组件（供registerSuiteTab使用）
     */
    public Component getUiComponent() {
        return mainPanel;
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
            statusPanel.clear();
        });

        leftToolPanel.add(newRequestButton);
        leftToolPanel.add(clearButton);

        // 分隔符
        leftToolPanel.add(new JSeparator(SwingConstants.VERTICAL));

        // 模式切换按钮
        modeToggleButton = new JToggleButton("普通模式");
        modeToggleButton.setToolTipText("切换普通模式/权限测试模式 — 开启后从右键菜单发送的请求将自动进行越权重放");
        modeToggleButton.addActionListener(e -> {
            boolean selected = modeToggleButton.isSelected();
            if (selected) {
                modeToggleButton.setText("权限测试");
                modeToggleButton.setForeground(new Color(200, 80, 0));
                modeToggleButton.setFont(modeToggleButton.getFont().deriveFont(Font.BOLD));
            } else {
                modeToggleButton.setText("普通模式");
                modeToggleButton.setForeground(UIManager.getColor("Button.foreground"));
                modeToggleButton.setFont(modeToggleButton.getFont().deriveFont(Font.PLAIN));
            }
            dispatchHandler.setPrivilegeTestMode(selected);
            BurpExtender.printOutput("[*] 权限测试模式: " + (selected ? "已开启" : "已关闭"));
        });
        leftToolPanel.add(modeToggleButton);

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
        statusPanel.clear();

        // 新建请求时重置HTTP服务信息
        dispatchHandler.setCurrentHttpService(null);

        // 创建新请求项并添加到列表，同时保存到数据库
        String newRequestTemplate = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

        // 保存请求到数据库，获取数据库生成的ID
        RequestDAO requestDAO = new RequestDAO();
        int dbId = requestDAO.saveRequest("http", "example.com", "/", "", "GET", newRequestTemplate.getBytes());

        if (dbId <= 0) {
            BurpExtender.printError("[!] 创建新请求时保存到数据库失败");
            return;
        }

        requestListPanel.addRequest(dbId, "/", "GET", "http", "example.com", "/", "", newRequestTemplate.getBytes());
        dispatchHandler.setCurrentRequestId(dbId);

        // 更新历史面板标题
        historyPanel.setBorderTitle("请求历史记录 - 新建请求");

        // 清空历史记录并初始化新的历史记录列表
        historyPanel.clearHistory();
        dispatchHandler.getRequestHistoryMap().put(dispatchHandler.getCurrentRequestId(), new ArrayList<>());
    }

    /**
     * 请求列表选中回调
     */
    private void onRequestSelected(int requestId, byte[] requestData) {
        BurpExtender.printOutput("[*] 请求选中回调触发，请求ID: " + requestId);

        dispatchHandler.setCurrentRequestId(requestId);

        // 清空编辑区域
        requestPanel.clear();
        responsePanel.clear();
        statusPanel.clear();

        // 设置请求内容
        if (requestData != null && requestData.length > 0) {
            requestPanel.setRequest(requestData);
            BurpExtender.printOutput("[+] 已加载请求数据到编辑器，大小: " + requestData.length + " 字节");

            // 从请求列表的表格数据中获取协议、主机、端口信息，重建HttpService
            // 优先使用已保存的原始HttpService（包含正确的非标准端口如9527）
            HttpService savedService = dispatchHandler.getSavedHttpService(requestId);
            if (savedService != null) {
                dispatchHandler.setCurrentHttpService(savedService);
            } else {
                // 没有保存的HttpService（如从数据库恢复的旧数据），从请求数据重建
                dispatchHandler.setCurrentHttpService(HttpRequestHelper.rebuildHttpService(requestId, requestData));
            }

            // 获取请求信息，更新历史面板标题
            HttpRequest httpRequest = HttpRequest.httpRequest(ByteArray.byteArray(requestData));
            HttpService service = dispatchHandler.getCurrentHttpService();
            if (service != null) {
                httpRequest = HttpRequest.httpRequest(service, ByteArray.byteArray(requestData));
            }
            String url = HttpRequestHelper.extractUrlFromRequest(requestData, httpRequest, service);
            historyPanel.setBorderTitle("请求历史记录 - " + url);

            // 尝试加载该请求的最新响应数据
            loadLatestResponseForRequest(requestId);

            // 加载相关的历史记录
            loadHistoryForRequest(requestId);
        } else {
            BurpExtender.printOutput("[!] 请求数据为空，ID: " + requestId);
            dispatchHandler.setCurrentHttpService(null);
            historyPanel.setBorderTitle("请求历史记录");
            historyPanel.clearHistory();
        }
    }

    /**
     * 加载指定请求ID的最新响应数据
     */
    private void loadLatestResponseForRequest(int requestId) {
        try {
            HistoryReadDAO historyReadDAO = new HistoryReadDAO();
            List<RequestResponseRecord> latestHistory = historyReadDAO.getLatestHistoryByRequestId(requestId, 1);

            if (latestHistory != null && !latestHistory.isEmpty()) {
                RequestResponseRecord latestRecord = latestHistory.get(0);
                byte[] responseData = latestRecord.getResponseData();

                if (responseData != null && responseData.length > 0) {
                    responsePanel.setResponse(responseData);
                    dispatchHandler.updateStatusFromRecord(latestRecord);
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
            HistoryReadDAO historyReadDAO = new HistoryReadDAO();
            List<RequestResponseRecord> dbHistoryList = historyReadDAO.getHistoryByRequestId(requestId);

            if (dbHistoryList != null && !dbHistoryList.isEmpty()) {
                BurpExtender.printOutput(
                    String.format("[*] 从数据库加载请求ID %d 的历史记录，共 %d 条",
                        requestId, dbHistoryList.size()));

                for (RequestResponseRecord record : dbHistoryList) {
                    historyPanel.addHistoryRecord(record);
                }

                dispatchHandler.getRequestHistoryMap().put(requestId, new ArrayList<>(dbHistoryList));

                BurpExtender.printOutput(String.format("[+] 请求ID %d 的历史记录加载完成", requestId));
                return;
            } else {
                BurpExtender.printOutput(String.format("[*] 数据库中未找到请求ID %d 的历史记录", requestId));
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 从数据库加载历史记录失败: " + e.getMessage());
        }

        // 如果数据库中没有或加载失败，尝试从内存映射中获取
        List<RequestResponseRecord> historyList = dispatchHandler.getRequestHistoryMap().get(requestId);

        if (historyList != null && !historyList.isEmpty()) {
            BurpExtender.printOutput(
                String.format("[*] 从内存加载请求ID %d 的历史记录，共 %d 条",
                    requestId, historyList.size()));

            for (RequestResponseRecord record : historyList) {
                historyPanel.addHistoryRecord(record);
            }
        } else {
            BurpExtender.printOutput(
                String.format("[*] 请求ID %d 没有历史记录", requestId));
        }

        historyPanel.setBorderTitle("请求历史记录 - ID: " + requestId);
    }

    /**
     * 设置请求内容 - 用于从右键菜单接收请求
     * @return 数据库生成的请求ID，失败返回-1
     */
    public int setRequest(HttpRequestResponse requestResponse) {
        try {
            if (requestResponse != null && requestResponse.request() != null) {
                byte[] request = requestResponse.request().toByteArray().getBytes();

                // 提取URL和方法信息
                String url;
                String method;
                String protocol = "http";
                String domain = "";
                String path = "/";
                String query = "";

                // 提取HttpService（供后续保存使用）
                HttpService httpService = requestResponse.httpService();
                HttpRequest httpRequest = requestResponse.request();

                try {
                    url = httpRequest.url();
                    method = httpRequest.method();

                    // 解析URL组件
                    URL parsedUrl = new URL(url);
                    protocol = parsedUrl.getProtocol();
                    // 保留非标准端口号：HTTP非80、HTTPS非443时，domain需包含端口
                    // 否则数据库存储的domain丢失端口，导致重建HttpService时端口错误
                    domain = parsedUrl.getHost();
                    int urlPort = parsedUrl.getPort();
                    if (urlPort != -1 && urlPort != parsedUrl.getDefaultPort()) {
                        domain = domain + ":" + urlPort;
                    }
                    path = parsedUrl.getPath();
                    query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";
                } catch (Exception e) {
                    BurpExtender.printError("[!] 分析请求时出错: " + e.getMessage());
                    method = "UNKNOWN";
                    url = "分析请求出错";
                }

                // 保存请求到数据库，获取数据库生成的ID
                RequestDAO requestDAO = new RequestDAO();
                int dbId = requestDAO.saveRequest(protocol, domain, path, query, method, request);

                if (dbId <= 0) {
                    BurpExtender.printError("[!] 保存请求到数据库失败");
                    return -1;
                }

                // 提取API值用于列表显示
                String apiValue = HttpRequestHelper.computeApiFromRequest(path, query, request);

                // 添加到请求列表，使用数据库ID
                requestListPanel.addRequest(dbId, apiValue, method, protocol, domain, path, query, request);
                dispatchHandler.setCurrentRequestId(dbId);

                // 保存原始HTTP服务信息，用于后续发送请求时保留正确的协议（如HTTPS）
                dispatchHandler.setCurrentHttpService(httpService);

                // 将HttpService保存到持久化映射，避免切换请求时丢失端口信息
                dispatchHandler.saveHttpService(dbId, httpService);

                // 设置请求内容
                requestPanel.setRequest(request);

                // 清空响应内容
                responsePanel.clear();
                statusPanel.clear();

                // 更新历史面板标题
                historyPanel.setBorderTitle("请求历史记录 - " + protocol + "://" + domain + path + (query.isEmpty() ? "" : "?" + query));

                // 清空历史记录并初始化新的历史记录列表
                historyPanel.clearHistory();
                dispatchHandler.getRequestHistoryMap().put(dispatchHandler.getCurrentRequestId(), new ArrayList<>());

                BurpExtender.printOutput("[+] 请求已加载到 Repeater Manager: " + protocol + "://" + domain + path + (query.isEmpty() ? "" : "?" + query));

                // 越权测试模式下自动触发越权重放
                if (dispatchHandler.isPrivilegeTestMode()) {
                    new RequestDAO().markAsPrivilegeTest(dbId);
                    requestListPanel.updatePrivilegeTestFlag(dbId, true);
                    BurpExtender.printOutput("[*] 权限测试模式已开启，自动触发越权重放...");
                    SwingUtilities.invokeLater(() -> dispatchHandler.sendRequest());
                }

                return dbId;
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 设置请求失败: " + e.getMessage());
            e.printStackTrace();
        }
        return -1;
    }

    /**
     * 设置请求内容并启动权限测试模式 - 用于从右键菜单"发送到权限测试"接收请求
     * 自动加载请求、切换到请求管理标签页、开启权限测试模式、触发重放
     */
    public void setPrivilegeTestRequest(HttpRequestResponse requestResponse) {
        try {
            if (requestResponse != null && requestResponse.request() != null) {
                // 先用常规方式加载请求（复用setRequest的逻辑）
                int dbId = setRequest(requestResponse);

                // 标记为越权测试请求
                if (dbId > 0) {
                    new RequestDAO().markAsPrivilegeTest(dbId);
                    requestListPanel.updatePrivilegeTestFlag(dbId, true);
                }

                // 切换到请求管理标签页
                tabbedPane.setSelectedIndex(0);

                // 开启权限测试模式
                dispatchHandler.setPrivilegeTestMode(true);
                BurpExtender.printOutput("[*] 权限测试模式已开启，准备重放请求...");

                // 自动触发权限测试重放
                SwingUtilities.invokeLater(() -> dispatchHandler.sendRequest());
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 设置权限测试请求失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 添加自动化测试的权限测试历史记录
     * 供 AutoTestEngine 通过 BurpExtender 调用
     */
    public void addPrivilegeTestHistoryRecord(RequestResponseRecord record) {
        if (record == null) return;

        // 持久化到数据库（与 HistoryPanel.addHistoryRecord(int, HttpRequestResponse) 保持一致）
        HistoryWriteDAO historyWriteDAO = new HistoryWriteDAO();
        int historyId = historyWriteDAO.saveHistory(record);
        if (historyId > 0) {
            record.setId(historyId);
            BurpExtender.printOutput("[+] 越权测试记录已保存到数据库，ID: " + historyId);
        } else {
            BurpExtender.printError("[!] 越权测试记录保存到数据库失败");
        }

        // 添加到历史面板
        historyPanel.addHistoryRecord(record);
        // 添加到内存映射
        int requestId = record.getRequestId();
        if (requestId > 0) {
            dispatchHandler.getRequestHistoryMap().computeIfAbsent(requestId, k -> new ArrayList<>()).add(record);
            // 标记父请求为越权测试
            new RequestDAO().markAsPrivilegeTest(requestId);
            requestListPanel.updatePrivilegeTestFlag(requestId, true);
        }
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
     * 刷新所有数据
     * 在数据库导入后调用，用于重新加载UI中显示的数据
     */
    public void refreshAllData() {
        BurpExtender.printOutput("[*] 开始刷新界面数据...");

        requestListPanel.clearAllRequests();
        historyPanel.clearAllHistory();
        dispatchHandler.setCurrentRequestId(-1);
        dispatchHandler.getRequestHistoryMap().clear();

        new Thread(() -> {
            try {
                RequestDAO requestDAO = new RequestDAO();
                java.util.List<java.util.Map<String, Object>> requests = requestDAO.getAllRequests();
                BurpExtender.printOutput("[+] 从数据库加载 " + requests.size() + " 条请求记录");

                for (java.util.Map<String, Object> request : requests) {
                    int dbId = (Integer) request.get("id");
                    String api = (String) request.get("api");
                    String protocol = (String) request.get("protocol");
                    String domain = (String) request.get("domain");
                    String path = (String) request.get("path");
                    String query = (String) request.get("query");
                    String method = (String) request.get("method");
                    byte[] requestData = (byte[]) request.get("request_data");
                    boolean isPrivilegeTest = request.containsKey("is_privilege_test") && (Boolean) request.get("is_privilege_test");

                    requestListPanel.addRequest(dbId, api, method, protocol, domain, path, query, isPrivilegeTest, requestData);

                    java.awt.Color color = (java.awt.Color) request.get("color");
                    String comment = (String) request.get("comment");
                    if (color != null) {
                        requestListPanel.getRequestColors().put(dbId, color);
                    }
                    if (comment != null && !comment.isEmpty()) {
                        requestListPanel.updateRequestComment(dbId, comment);
                    }
                }

                HistoryReadDAO historyReadDAO = new HistoryReadDAO();
                java.util.List<RequestResponseRecord> allHistory = historyReadDAO.getAllHistory();
                BurpExtender.printOutput("[+] 从数据库加载 " + allHistory.size() + " 条历史记录");

                for (RequestResponseRecord record : allHistory) {
                    int requestId = record.getRequestId();
                    if (requestId > 0) {
                        dispatchHandler.getRequestHistoryMap().computeIfAbsent(requestId, k -> new ArrayList<>()).add(record);
                    }
                }

                BurpExtender.printOutput("[+] 数据刷新完成");
            } catch (Exception e) {
                BurpExtender.printError("[!] 刷新数据时出错: " + e.getMessage());
            }
        }).start();
    }
}
