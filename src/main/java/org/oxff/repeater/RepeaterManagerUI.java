package org.oxff.repeater;

import org.oxff.repeater.logging.LogManager;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.HttpService;
import org.oxff.repeater.http.RequestManager;
import org.oxff.repeater.http.RequestResponseRecord;
import org.oxff.repeater.http.HttpRequestHelper;
import org.oxff.repeater.ui.editor.BurpRequestPanel;
import org.oxff.repeater.ui.editor.BurpResponsePanel;
import org.oxff.repeater.ui.history.HistoryPanel;
import org.oxff.repeater.ui.RequestListPanel;
import org.oxff.repeater.ui.config.ConfigPanel;
import org.oxff.repeater.ui.DataPanel;
import org.oxff.repeater.ui.LogPanel;
import org.oxff.repeater.ui.StatusPanel;
import org.oxff.repeater.ui.layout.LayoutManager;
import org.oxff.repeater.ui.layout.LayoutManager.LayoutType;
import org.oxff.repeater.ui.privilege.PrivilegeTestPanel;
import org.oxff.repeater.ui.UsageTutorialPanel;
import org.oxff.repeater.ui.AboutPanel;
import org.oxff.repeater.db.history.HistoryReadDAO;
import org.oxff.repeater.db.history.HistoryWriteDAO;
import org.oxff.repeater.db.RequestDAO;
import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

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

    // 工具栏
    private final EditorToolBar editorToolBar;

    // 功能组件
    private final RequestManager requestManager;

    // 请求调度处理器
    private final RequestDispatchHandler dispatchHandler;

    // 请求加载器
    private final RequestLoader requestLoader;

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

        // 设置发送请求按钮动作
        requestPanel.setSendButtonListener(e -> dispatchHandler.sendRequest());

        // 设置历史记录双击回调
        historyPanel.setOnSelectRecord(dispatchHandler::loadHistoryRecord);

        // 创建编辑区工具栏（必须在模式变更监听器之前初始化，因为监听器引用其组件）
        editorToolBar = new EditorToolBar(requestPanel, responsePanel, statusPanel, dispatchHandler, layoutManager, mainPanel, this::createNewRequest);
        JPanel editorControlPanel = editorToolBar.build();

        // 注册模式变更监听器：同步切换按钮与标签状态
        dispatchHandler.addModeChangeListener(mode -> {
            SwingUtilities.invokeLater(() -> {
                if (editorToolBar.modeToggleButton != null) {
                    editorToolBar.modeToggleButton.setSelected(mode);
                }
                if (editorToolBar.normalModeLabel != null && editorToolBar.privilegeModeLabel != null) {
                    if (mode) {
                        editorToolBar.normalModeLabel.setFont(editorToolBar.normalModeLabel.getFont().deriveFont(Font.PLAIN));
                        editorToolBar.normalModeLabel.setForeground(UIManager.getColor("Label.foreground"));
                        editorToolBar.privilegeModeLabel.setFont(editorToolBar.privilegeModeLabel.getFont().deriveFont(Font.BOLD));
                        editorToolBar.privilegeModeLabel.setForeground(new Color(200, 80, 0));
                    } else {
                        editorToolBar.normalModeLabel.setFont(editorToolBar.normalModeLabel.getFont().deriveFont(Font.BOLD));
                        editorToolBar.normalModeLabel.setForeground(new Color(0, 0, 0));
                        editorToolBar.privilegeModeLabel.setFont(editorToolBar.privilegeModeLabel.getFont().deriveFont(Font.PLAIN));
                        editorToolBar.privilegeModeLabel.setForeground(UIManager.getColor("Label.foreground"));
                    }
                }
            });
        });

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
        org.oxff.repeater.logging.LogManager.getInstance().setLogPanel(logPanel);

        // 添加到主面板
        mainPanel.add(tabbedPane, BorderLayout.CENTER);

        // 初始化请求加载器（必须在所有面板创建之后）
        requestLoader = new RequestLoader(tabbedPane, requestPanel, responsePanel, historyPanel, requestListPanel, statusPanel, dispatchHandler);
    }

    /**
     * 获取UI组件（供registerSuiteTab使用）
     */
    public Component getUiComponent() {
        return mainPanel;
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
            LogManager.getInstance().printError("[!] 创建新请求时保存到数据库失败");
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

    // 请求选中防抖：避免 ListSelectionListener + MouseAdapter 双重触发
    private volatile int lastSelectedRequestId = -1;
    private volatile long lastSelectTime = 0;
    private static final long DEBOUNCE_MS = 300;

    /**
     * 请求列表选中回调
     */
    private void onRequestSelected(int requestId, byte[] requestData) {
        // 防抖：同一 requestId 在 300ms 内不重复处理
        long now = System.currentTimeMillis();
        if (requestId == lastSelectedRequestId && (now - lastSelectTime) < DEBOUNCE_MS) {
            return;
        }
        lastSelectedRequestId = requestId;
        lastSelectTime = now;

        LogManager.getInstance().printOutput("[*] 请求选中回调触发，请求ID: " + requestId);

        dispatchHandler.setCurrentRequestId(requestId);

        // 清空编辑区域
        requestPanel.clear();
        responsePanel.clear();
        statusPanel.clear();

        // 设置请求内容
        if (requestData != null && requestData.length > 0) {
            requestPanel.setRequest(requestData);
            LogManager.getInstance().printOutput("[+] 已加载请求数据到编辑器，大小: " + requestData.length + " 字节");

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

            // 优先加载基线响应（来自 requests 表），没有基线时才回退到最新历史响应
            // 修复：之前直接调用 loadLatestResponseForRequest 会拿到越权重放的历史响应，
            // 而不是基准报文自身的原始响应，导致点击基准报文时响应面板显示错误数据
            loadBaselineOrLatestResponse(requestId);

            // 加载相关的历史记录（批量添加模式下使用静默模式，避免"没有历史记录"噪音日志）
            loadHistoryForRequest(requestId, requestListPanel.isBatchAddMode());
        } else {
            LogManager.getInstance().printOutput("[!] 请求数据为空，ID: " + requestId);
            dispatchHandler.setCurrentHttpService(null);
            historyPanel.setBorderTitle("请求历史记录");
            historyPanel.clearHistory();
        }
    }

    /**
     * 加载请求的响应数据：优先尝试基线响应（来自 requests 表），
     * 没有基线时才回退到加载最新历史响应
     *
     * 问题背景：批量越权测试后，history 表中有多条重放记录，
     * 直接取最新历史响应会拿到重放报文的响应，而非基准报文自身的原始响应。
     * 基准响应在 send to repeater 时已通过 saveOriginalResponseAsBaseline 存入 requests 表。
     */
    private void loadBaselineOrLatestResponse(int requestId) {
        // 优先：从 requests 表加载基线响应（原始报文的响应）
        try {
            RequestDAO requestDAO = new RequestDAO();
            byte[] baselineResponse = requestDAO.getOriginalResponseData(requestId);
            int statusCode = requestDAO.getOriginalResponseStatusCode(requestId);

            if (baselineResponse != null && baselineResponse.length > 0) {
                responsePanel.setResponse(baselineResponse);
                boolean success = statusCode >= 100 && statusCode < 400;
                statusPanel.updateStatus(success, baselineResponse.length, 0, 0, 0);
                LogManager.getInstance().printOutput(
                    String.format("[+] 已加载请求ID %d 的基线响应 (%d 字节)", requestId, baselineResponse.length));
                return;
            }
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 加载基线响应失败: " + e.getMessage());
        }

        // 回退：没有基线响应时，尝试加载最新历史响应（兼容旧数据或纯重放场景）
        loadLatestResponseForRequest(requestId);
    }

    /**
     * 加载指定请求ID的最新响应数据（从 history 表）
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
                    LogManager.getInstance().printOutput("[+] 已加载请求ID " + requestId + " 的最新响应数据");
                }
            }
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 加载最新响应数据失败: " + e.getMessage());
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
            LogManager.getInstance().printOutput(String.format("[*] 开始加载请求ID %d 的历史记录", requestId));
        }

        // 优先从数据库加载历史记录
        try {
            HistoryReadDAO historyReadDAO = new HistoryReadDAO();
            List<RequestResponseRecord> dbHistoryList = historyReadDAO.getHistoryByRequestId(requestId);

            if (dbHistoryList != null && !dbHistoryList.isEmpty()) {
                if (!silent) {
                    LogManager.getInstance().printOutput(
                        String.format("[*] 从数据库加载请求ID %d 的历史记录，共 %d 条",
                            requestId, dbHistoryList.size()));
                }

                for (RequestResponseRecord record : dbHistoryList) {
                    historyPanel.addHistoryRecord(record);
                }

                dispatchHandler.getRequestHistoryMap().put(requestId, new ArrayList<>(dbHistoryList));

                if (!silent) {
                    LogManager.getInstance().printOutput(String.format("[+] 请求ID %d 的历史记录加载完成", requestId));
                }
                return;
            }
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 从数据库加载历史记录失败: " + e.getMessage());
        }

        // 如果数据库中没有或加载失败，尝试从内存映射中获取
        List<RequestResponseRecord> historyList = dispatchHandler.getRequestHistoryMap().get(requestId);

        if (historyList != null && !historyList.isEmpty()) {
            if (!silent) {
                LogManager.getInstance().printOutput(
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
                            LogManager.getInstance().printOutput(
                                String.format("[+] 从基线加载请求ID %d 的原始响应 (%d 字节)",
                                    requestId, baselineResponse.length));
                        }
                    }
                } else if (!silent) {
                    LogManager.getInstance().printOutput(
                        String.format("[*] 请求ID %d 没有历史记录", requestId));
                }
            } catch (Exception e) {
                if (!silent) {
                    LogManager.getInstance().printOutput(
                        String.format("[*] 请求ID %d 没有历史记录", requestId));
                }
            }
        }

        historyPanel.setBorderTitle("请求历史记录 - ID: " + requestId);
    }

    public RequestLoader getRequestLoader() {
        return requestLoader;
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
            LogManager.getInstance().printOutput("[+] 越权测试记录已保存到数据库，ID: " + historyId);
        } else {
            LogManager.getInstance().printError("[!] 越权测试记录保存到数据库失败");
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
     * 刷新权限测试数据（用户会话表格等）
     * 供BurpExtender在解析用户会话后调用
     */
    public void refreshPrivilegeTestData() {
        if (privilegeTestPanel != null) {
            SwingUtilities.invokeLater(() -> privilegeTestPanel.refreshSessionConfigData());
        }
    }

    /**
     * 刷新所有数据
     * 在数据库导入后调用，用于重新加载UI中显示的数据
     */
    public void refreshAllData() {
        LogManager.getInstance().printOutput("[*] 开始刷新界面数据...");

        requestListPanel.clearAllRequests();
        historyPanel.clearAllHistory();
        dispatchHandler.setCurrentRequestId(-1);
        dispatchHandler.getRequestHistoryMap().clear();

        new Thread(() -> {
            try {
                RequestDAO requestDAO = new RequestDAO();
                java.util.List<java.util.Map<String, Object>> requests = requestDAO.getAllRequests();
                LogManager.getInstance().printOutput("[+] 从数据库加载 " + requests.size() + " 条请求记录");

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
                LogManager.getInstance().printOutput("[+] 从数据库加载 " + allHistory.size() + " 条历史记录");

                for (RequestResponseRecord record : allHistory) {
                    int requestId = record.getRequestId();
                    if (requestId > 0) {
                        dispatchHandler.getRequestHistoryMap().computeIfAbsent(requestId, k -> new ArrayList<>()).add(record);
                    }
                }

                LogManager.getInstance().printOutput("[+] 数据刷新完成");
            } catch (Exception e) {
                LogManager.getInstance().printError("[!] 刷新数据时出错: " + e.getMessage());
            }
        }).start();
    }
}
