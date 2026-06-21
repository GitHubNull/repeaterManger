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
import oxff.top.db.DatabaseManager;
import oxff.top.service.GarbageCollectorService;
import oxff.top.privilege.ReplayEngine;
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

        // 将 dispatchHandler 传递给 historyPanel，供右键菜单批量操作使用
        historyPanel.setDispatchHandler(dispatchHandler);

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

        // 注册模式变更监听器：同步ScopeConfigTab的autoTestCheckbox状态
        // 越权模式联动代理监听器（setPrivilegeTestMode→ScopeManager.setAutoTestEnabled），
        // ScopeConfigTab的复选框需同步反映代理监听器的开启/关闭状态
        // 必须在privilegeTestPanel初始化后注册，否则编译器报"变量未初始化"错误
        dispatchHandler.addModeChangeListener(mode -> {
            SwingUtilities.invokeLater(() -> {
                if (privilegeTestPanel != null) {
                    privilegeTestPanel.syncScopeConfigAutoTestState();
                }
            });
        });

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

            // 加载相关的历史记录（批量添加模式下使用静默模式，避免"没有历史记录"噪音日志）
            loadHistoryForRequest(requestId, requestListPanel.isBatchAddMode());
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
     * @param requestId 请求ID
     * @param silent true时不输出"没有历史记录"等调试日志（批量模式下新请求无历史是正常现象）
     */
    private void loadHistoryForRequest(int requestId, boolean silent) {
        // 清空历史记录面板
        historyPanel.clearHistory();

        if (!silent) {
            BurpExtender.printOutput(String.format("[*] 开始加载请求ID %d 的历史记录", requestId));
        }

        // 优先从数据库加载历史记录
        try {
            HistoryReadDAO historyReadDAO = new HistoryReadDAO();
            List<RequestResponseRecord> dbHistoryList = historyReadDAO.getHistoryByRequestId(requestId);

            if (dbHistoryList != null && !dbHistoryList.isEmpty()) {
                if (!silent) {
                    BurpExtender.printOutput(
                        String.format("[*] 从数据库加载请求ID %d 的历史记录，共 %d 条",
                            requestId, dbHistoryList.size()));
                }

                for (RequestResponseRecord record : dbHistoryList) {
                    historyPanel.addHistoryRecord(record);
                }

                dispatchHandler.getRequestHistoryMap().put(requestId, new ArrayList<>(dbHistoryList));

                if (!silent) {
                    BurpExtender.printOutput(String.format("[+] 请求ID %d 的历史记录加载完成", requestId));
                }
                return;
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 从数据库加载历史记录失败: " + e.getMessage());
        }

        // 如果数据库中没有或加载失败，尝试从内存映射中获取
        List<RequestResponseRecord> historyList = dispatchHandler.getRequestHistoryMap().get(requestId);

        if (historyList != null && !historyList.isEmpty()) {
            if (!silent) {
                BurpExtender.printOutput(
                    String.format("[*] 从内存加载请求ID %d 的历史记录，共 %d 条",
                        requestId, historyList.size()));
            }

            for (RequestResponseRecord record : historyList) {
                historyPanel.addHistoryRecord(record);
            }
        } else {
            // 数据库和内存中均无历史记录，尝试从 requests 表加载原始响应基线
            // 越权测试场景下，saveOriginalResponseAsBaseline 将原始响应保存到了 requests 表，
            // 但未创建 history 记录，导致点击请求时响应区域为空白
            try {
                RequestDAO requestDAO = new RequestDAO();
                byte[] baselineResponse = requestDAO.getOriginalResponseData(requestId);
                int baselineStatusCode = requestDAO.getOriginalResponseStatusCode(requestId);

                if (baselineResponse != null && baselineResponse.length > 0) {
                    // 从 requestDataMap 获取请求数据，构造一条基线历史记录
                    byte[] requestData = requestListPanel.getRequestData(requestId);
                    if (requestData != null) {
                        RequestResponseRecord baselineRecord = new RequestResponseRecord();
                        baselineRecord.setId(-1); // 临时记录，无数据库ID
                        baselineRecord.setRequestId(requestId);
                        baselineRecord.setRequestData(requestData);
                        baselineRecord.setResponseData(baselineResponse);
                        baselineRecord.setStatusCode(baselineStatusCode);
                        baselineRecord.setResponseLength(baselineResponse.length);
                        baselineRecord.setResponseTime(0);
                        baselineRecord.setUserSessionName("(原始基线)");
                        baselineRecord.setComment("原始响应基线");
                        baselineRecord.setTimestamp(new java.util.Date());

                        // 尝试从请求字节数组解析HTTP元数据
                        HttpService savedService = dispatchHandler.getSavedHttpService(requestId);
                        if (savedService != null) {
                            try {
                                HttpRequest reqInfo = HttpRequest.httpRequest(savedService, ByteArray.byteArray(requestData));
                                java.net.URL parsedUrl = new java.net.URL(reqInfo.url());
                                baselineRecord.setMethod(reqInfo.method());
                                baselineRecord.setProtocol(parsedUrl.getProtocol());
                                baselineRecord.setDomain(HttpRequestHelper.resolveDomainWithPort(parsedUrl, savedService));
                                baselineRecord.setPath(parsedUrl.getPath());
                                baselineRecord.setQueryParameters(parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "");
                            } catch (Exception e) {
                                baselineRecord.setMethod("UNKNOWN");
                                baselineRecord.setProtocol(savedService.secure() ? "https" : "http");
                                baselineRecord.setDomain(HttpRequestHelper.resolveDomainFromService(savedService));
                                baselineRecord.setPath("/");
                            }
                        }

                        historyPanel.addHistoryRecord(baselineRecord);
                        dispatchHandler.getRequestHistoryMap().put(requestId, new ArrayList<>(List.of(baselineRecord)));

                        // 显示原始响应基线到响应面板
                        responsePanel.setResponse(baselineResponse);
                        dispatchHandler.updateStatusFromRecord(baselineRecord);

                        if (!silent) {
                            BurpExtender.printOutput(
                                String.format("[+] 从基线加载请求ID %d 的原始响应 (%d 字节)",
                                    requestId, baselineResponse.length));
                        }
                    }
                } else if (!silent) {
                    BurpExtender.printOutput(
                        String.format("[*] 请求ID %d 没有历史记录", requestId));
                }
            } catch (Exception e) {
                if (!silent) {
                    BurpExtender.printOutput(
                        String.format("[*] 请求ID %d 没有历史记录", requestId));
                }
            }
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
                    // 保留非标准端口号：优先从HttpService获取端口（url()可能不含显式端口，getPort()返回-1）
                    domain = HttpRequestHelper.resolveDomainWithPort(parsedUrl, httpService);
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

                // 保存原始HTTP协议版本（HTTP/2或HTTP/1.1），用于重放时保持协议不变
                boolean isHttp2 = "HTTP/2".equals(httpRequest.httpVersion());
                dispatchHandler.saveHttpVersion(dbId, isHttp2);
                if (isHttp2) {
                    BurpExtender.printOutput("[+] 检测到 HTTP/2 请求，已记录协议版本，重放时将保持 HTTP/2");
                }

                // 保存原始响应基线（如果原始请求有响应数据）
                // 当从 Proxy History / HTTP History 等处发送请求到插件时，原始响应已存在，
                // 保存为基线以便点击请求时显示原始响应，而不是空白
                if (requestResponse.response() != null) {
                    saveOriginalResponseAsBaseline(dbId, requestResponse);
                }

                // 设置请求内容
                requestPanel.setRequest(request);

                // 显示原始响应（如果有），否则清空
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
                    // 修复：直接使用参数化方法，避免EDT队列竞态导致currentRequestId被覆盖
                    final int capturedId = dbId;
                    final HttpService capturedSvc = httpService;
                    final byte[] capturedReq = request;
                    SwingUtilities.invokeLater(() ->
                        dispatchHandler.sendPrivilegeTestRequestDirect(capturedReq, capturedSvc, capturedId));
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
     *
     * 关键修复（EDT竞态条件）：当用户快速连续发送多个请求到权限测试时，
     * 多个setPrivilegeTestRequest调用在EDT上顺序执行，但通过invokeLater投递的
     * sendRequest()会排到所有setPrivilegeTestRequest之后执行。此时volatile的
     * currentRequestId已被最后一个调用覆盖为最后的ID，导致所有重放记录关联到同一个请求。
     * 修复方案：在调用时立即捕获requestId/httpService/requestBytes，通过参数化方法直接传递。
     */
    public void setPrivilegeTestRequest(HttpRequestResponse requestResponse) {
        try {
            if (requestResponse != null && requestResponse.request() != null) {
                // 先关闭权限测试模式，避免 setRequest() 内部误触发重放
                // （setRequest() 在 privilegeTestMode=true 时会自动触发重放，
                //   而本方法后续也会手动触发，导致双重重放）
                dispatchHandler.setPrivilegeTestMode(false);

                // 在调用setRequest之前，先捕获请求数据和HttpService
                // 这些值在EDT队列中后续事件执行时仍然有效
                final byte[] capturedRequestBytes = requestResponse.request().toByteArray().getBytes();
                final HttpService capturedHttpService = requestResponse.httpService();

                // 用常规方式加载请求（复用setRequest的逻辑）
                int dbId = setRequest(requestResponse);

                // 标记为越权测试请求
                if (dbId > 0) {
                    new RequestDAO().markAsPrivilegeTest(dbId);
                    requestListPanel.updatePrivilegeTestFlag(dbId, true);

                    // 保存原始响应作为基线 history 记录（user_session_name=NULL）
                    // 从 Proxy History 等模块发送时，原始响应已存在，必须落库作为比对基线
                    saveOriginalResponseAsBaseline(dbId, requestResponse);
                }

                // 切换到请求管理标签页
                tabbedPane.setSelectedIndex(0);

                // 开启权限测试模式
                dispatchHandler.setPrivilegeTestMode(true);
                BurpExtender.printOutput(String.format("[*] 权限测试模式已开启，准备重放请求 (requestId=%d)...", dbId));

                // 修复：直接使用参数化方法传递已捕获的requestId/httpService/requestBytes
                // 不再依赖volatile共享状态currentRequestId（它可能被后续调用覆盖）
                final int capturedRequestId = dbId;
                SwingUtilities.invokeLater(() ->
                    dispatchHandler.sendPrivilegeTestRequestDirect(
                        capturedRequestBytes, capturedHttpService, capturedRequestId));
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 设置权限测试请求失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 批量设置请求内容 - 用于从右键菜单接收多条请求
     * @return 成功保存的请求ID列表
     */
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
                BurpExtender.printError("[!] 批量加载请求时第 " + (i + 1) + " 条失败: " + e.getMessage());
            }
        }

        if (!dbIds.isEmpty()) {
            BurpExtender.printOutput(String.format("[+] 批量加载完成：成功 %d / %d 条", dbIds.size(), requestResponses.size()));
        }

        return dbIds;
    }

    /**
     * 批量设置请求内容并启动权限测试模式 - 用于从右键菜单"发送到权限测试"接收多条请求
     * 自动加载所有请求、切换到请求管理标签页、开启权限测试模式、批量重放
     *
     * 优化：将DB保存和基线存储移到后台线程，仅将添加行到UI列表的操作留在EDT上，
     * 避免150+请求的同步DB操作阻塞EDT导致UI卡顿。
     * 使用RequestListPanel的batchAddMode暂停每行添加时的ListSelectionListener回调，
     * 避免每行触发onRequestSelected→loadHistoryForRequest产生"没有历史记录"噪音日志。
     */
    public void setPrivilegeTestRequests(List<HttpRequestResponse> requestResponses) {
        if (requestResponses == null || requestResponses.isEmpty()) return;

        try {
            // 先关闭权限测试模式，避免误触发重放
            dispatchHandler.setPrivilegeTestMode(false);

            // 清除ReplayEngine的去重记录，确保新批次从干净状态开始
            ReplayEngine.getInstance().clearProcessedApis();

            // 前置去重：在保存到DB之前，根据配置的去重策略过滤重复请求
            oxff.top.privilege.DedupConfigManager dedupConfigManager =
                    oxff.top.privilege.DedupConfigManager.getInstance();
            final List<HttpRequestResponse> dedupedRequests;
            if (dedupConfigManager.hasActiveConfigs()) {
                int originalSize = requestResponses.size();
                dedupedRequests = oxff.top.privilege.ApiDedupEngine.deduplicate(
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
                    BurpExtender.printOutput(String.format(
                            "[*] 批量权限测试：去重过滤 %d -> %d 条（去除 %d 条重复）",
                            originalSize, dedupedRequests.size(), originalSize - dedupedRequests.size()));
                }
            } else {
                dedupedRequests = requestResponses;
            }

            // 开启批量添加模式，暂停每行添加时的ListSelectionListener回调
            requestListPanel.setBatchAddMode(true);

            // 设置等待光标
            dispatchHandler.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));

            // 切换到请求管理标签页
            tabbedPane.setSelectedIndex(0);

            int total = dedupedRequests.size();
            BurpExtender.printOutput(String.format("[*] 批量权限测试：开始处理 %d 条请求...", total));

            // 暂停GC服务，避免批量操作期间GC抢占DB连接池资源
            GarbageCollectorService gcService = DatabaseManager.getInstance().getGcService();
            if (gcService != null) {
                gcService.pause();
            }

            // 在后台线程中执行DB保存+基线存储，避免EDT阻塞
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

                        // 解析URL组件
                        String method;
                        String protocol = "http";
                        String domain = "";
                        String path = "/";
                        String query = "";

                        try {
                            method = httpRequest.method();
                            URL parsedUrl = new URL(httpRequest.url());
                            protocol = parsedUrl.getProtocol();
                            domain = HttpRequestHelper.resolveDomainWithPort(parsedUrl, httpService);
                            path = parsedUrl.getPath();
                            query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";
                        } catch (Exception e) {
                            BurpExtender.printError("[!] 分析请求URL时出错: " + e.getMessage());
                            method = "UNKNOWN";
                        }

                        // DB保存（后台线程中执行，不阻塞EDT）
                        int dbId = requestDAO.saveRequest(protocol, domain, path, query, method, request);
                        if (dbId <= 0) {
                            BurpExtender.printError("[!] 批量权限测试：保存请求到数据库失败，第 " + (i + 1) + " 条");
                            continue;
                        }

                        // 标记为越权测试请求
                        requestDAO.markAsPrivilegeTest(dbId);

                        // 保存HttpService映射
                        if (httpService != null) {
                            dispatchHandler.saveHttpService(dbId, httpService);
                        }

                        // 保存原始响应基线（后台线程中执行）
                        saveOriginalResponseAsBaseline(dbId, rr);

                        // 初始化内存历史映射（ConcurrentHashMap，后台线程put与EDT上get/put均线程安全）
                        dispatchHandler.getRequestHistoryMap().put(dbId, new ArrayList<>());

                        // 计算API值
                        String apiValue = HttpRequestHelper.computeApiFromRequest(path, query, request);

                        dbIds.add(dbId);

                        // 在EDT上添加行到请求列表（最小化EDT占用）
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
                        BurpExtender.printError("[!] 批量加载请求时第 " + (i + 1) + " 条失败: " + e.getMessage());
                    }
                }

                if (dbIds.isEmpty()) {
                    BurpExtender.printError("[!] 批量权限测试：所有请求保存失败");
                    // 恢复GC服务
                    if (gcService != null) {
                        gcService.resume();
                    }
                    SwingUtilities.invokeLater(() -> {
                        requestListPanel.setBatchAddMode(false);
                        dispatchHandler.setCursor(Cursor.getDefaultCursor());
                    });
                    return;
                }

                BurpExtender.printOutput(String.format("[+] 批量权限测试：保存完成，成功 %d / %d 条，开始重放...",
                        dbIds.size(), total));

                // 恢复GC服务（批量保存完成，连接池压力已降低）
                if (gcService != null) {
                    gcService.resume();
                }

                // 全部保存完成后，在EDT上关闭批量模式、恢复光标、开启越权模式、触发批量重放
                SwingUtilities.invokeLater(() -> {
                    // 使用静默退出批量模式，避免触发onRequestSelected回调
                    // （此时重放尚未开始，查询历史记录必然为空，会产生大量“没有历史记录”告警和无效DB查询）
                    requestListPanel.exitBatchModeQuiet();
                    dispatchHandler.setCurrentRequestId(dbIds.get(dbIds.size() - 1));
                    dispatchHandler.setCursor(Cursor.getDefaultCursor());

                    // 开启权限测试模式（联动代理监听器）
                    dispatchHandler.setPrivilegeTestMode(true);
                    BurpExtender.printOutput(String.format("[*] 权限测试模式已开启，准备批量重放 %d 条请求...", dbIds.size()));

                    // 批量触发权限测试重放
                    dispatchHandler.batchSendPrivilegeTestRequests(dbIds);
                });
            }, "batch-privilege-test-setup").start();

        } catch (Exception e) {
            BurpExtender.printError("[!] 批量设置权限测试请求失败: " + e.getMessage());
            e.printStackTrace();
            requestListPanel.setBatchAddMode(false);
            dispatchHandler.setCursor(Cursor.getDefaultCursor());
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
     * 将自动化测试的原始请求添加到请求列表面板和内存映射
     * 供 AutoTestEngine 通过 BurpExtender 调用
     */
    public void addAutoTestRequest(int requestId, String api, String method,
            String protocol, String domain, String path, String query, byte[] requestData) {
        requestListPanel.addRequest(requestId, api, method, protocol, domain, path, query, true, requestData);
        dispatchHandler.getRequestHistoryMap().computeIfAbsent(requestId, k -> new ArrayList<>());
    }

    /**
     * 保存原始响应报文到 requests 表（作为基线）
     * 在越权测试入口处调用：从 Proxy History / 其他模块发送报文到插件时，
     * HttpRequestResponse 已包含原始响应，必须将其持久化到 requests 表，供后续报文比对使用。
     *
     * @param requestId       请求在 requests 表中的 ID
     * @param requestResponse 含原始请求+响应的 Montoya 对象
     */
    private void saveOriginalResponseAsBaseline(int requestId, HttpRequestResponse requestResponse) {
        try {
            // 无原始响应则跳过（例如从 Proxy Intercept 直接 Forward 的情况）
            if (requestResponse.response() == null) {
                BurpExtender.printOutput("[*] 原始报文无响应数据，跳过基线保存");
                return;
            }

            byte[] responseData = requestResponse.response().toByteArray().getBytes();
            int statusCode = requestResponse.response().statusCode();

            // 保存到 requests 表的响应字段
            RequestDAO requestDAO = new RequestDAO();
            boolean saved = requestDAO.saveOriginalResponse(requestId, responseData, statusCode, 0);
            if (saved) {
                BurpExtender.printOutput("[+] 原始响应基线已保存到 requests 表，requestId: " + requestId);
            } else {
                BurpExtender.printError("[!] 保存原始响应基线失败，requestId: " + requestId);
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 保存原始响应基线异常: " + e.getMessage());
        }
    }

    /**
     * 关闭资源 - 在插件卸载时调用
     * 释放所有线程池、调度器和后台服务，避免资源泄漏
     */
    public void close() {
        // 关闭请求管理器（含线程池和HistoryRecordingService）
        if (requestManager != null) {
            requestManager.shutdown();
        }

        // 中断可能正在运行的批量操作线程
        // （batchSendPrivilegeTestRequests/batchSendRequests 创建的后台线程）
        // 这些线程会在下次循环时因 RequestManager 已关闭而自然退出
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
