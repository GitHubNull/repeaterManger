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
import org.oxff.repeater.i18n.I18nManager;
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

        // 注册清空回调：清空调度处理器和历史面板数据
        // 注意：必须在 dispatchHandler/historyPanel/requestPanel/responsePanel 初始化之后注册，
        // 否则lambda引用未初始化的final字段会导致编译错误
        requestListPanel.setClearAllCallback(() -> {
            // 清空调度处理器中的历史映射
            dispatchHandler.getRequestHistoryMap().clear();
            dispatchHandler.setCurrentRequestId(-1);
            dispatchHandler.setCurrentHttpService(null);

            // 清空历史面板
            historyPanel.clearAllHistory();

            // 清空请求和响应面板
            requestPanel.setRequest(new byte[0]);
            responsePanel.clear();

            LogManager.getInstance().printOutput(I18nManager.tr("log.dispatcher.cleared"));
        });

        // 注册模式变更监听器：同步状态栏指示
        dispatchHandler.addModeChangeListener(mode -> {
            SwingUtilities.invokeLater(() -> statusPanel.setModeIndicator(mode));
        });

        // 设置发送请求按钮动作
        requestPanel.setSendButtonListener(e -> dispatchHandler.sendRequest());

        // 设置历史记录双击回调
        historyPanel.setOnSelectRecord(dispatchHandler::loadHistoryRecord);

        // 创建编辑区工具栏（必须在模式变更监听器之前初始化，因为监听器引用其组件）
        editorToolBar = new EditorToolBar(dispatchHandler, layoutManager, mainPanel);

        // 构建全局工具栏（插件顶部）
        JPanel globalToolBar = editorToolBar.buildGlobalToolBar();

        // 构建报文显示编辑工具栏（编辑区顶部）
        JPanel messageEditorToolBar = editorToolBar.buildMessageEditorToolBar();

        // 设置请求面板回调
        requestPanel.setOnNewRequest(this::createNewRequest);
        requestPanel.setOnClear(() -> {
            requestPanel.clear();
            responsePanel.clear();
            statusPanel.clear();
        });

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
        editorPanel.add(messageEditorToolBar, BorderLayout.NORTH);
        editorPanel.add(editorSplitPane, BorderLayout.CENTER);
        editorPanel.add(statusPanel, BorderLayout.SOUTH);
        
        // 设置编辑器面板最小宽度，确保分割线可以向右拖动
        // 避免重放后右组件首选宽度增大导致分割线被"锁死"在左侧
        editorPanel.setMinimumSize(new Dimension(300, 0));

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
        // 设置 resizeWeight 为 0，确保窗口大小变化时额外空间分配给右组件（编辑器区域），
        // 避免左组件（请求列表+历史记录）被过度压缩导致分割线拖动范围受限
        mainSplitPane.setResizeWeight(0.0);
        mainSplitPane.setDividerLocation(350);
        
        // 设置左组件最小宽度，确保分割线可以拖到更左的位置
        // 避免重放后右组件首选宽度增大导致分割线被"挤"到右侧
        leftSplitPane.setMinimumSize(new Dimension(200, 0));

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
        tabbedPane.addTab(I18nManager.tr("tab.request"), mainSplitPane);
        tabbedPane.addTab(I18nManager.tr("tab.privilege"), privilegeTestPanel);
        tabbedPane.addTab(I18nManager.tr("tab.data"), dataPanel);
        tabbedPane.addTab(I18nManager.tr("tab.config"), configPanel);
        tabbedPane.addTab(I18nManager.tr("tab.log"), logPanel);
        tabbedPane.addTab(I18nManager.tr("tab.tutorial"), usageTutorialPanel);
        tabbedPane.addTab(I18nManager.tr("tab.about"), aboutPanel);

        // 注册语言变更监听：刷新主选项卡标题
        I18nManager.getInstance().addLocaleChangeListener(this::refreshTabTitles);

        // 监听标签页切换（不再绑定权限测试模式，模式通过工具栏按钮独立控制）
        tabbedPane.addChangeListener(e -> {
            // Tab切换不再自动改变权限测试模式
        });

        // 注册LogPanel到LogManager
        org.oxff.repeater.logging.LogManager.getInstance().setLogPanel(logPanel);

        // 添加到主面板
        mainPanel.add(globalToolBar, BorderLayout.NORTH);
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
     * 语言变更时刷新主选项卡标题
     */
    private void refreshTabTitles() {
        if (tabbedPane == null || tabbedPane.getTabCount() < 7) {
            return;
        }
        tabbedPane.setTitleAt(0, I18nManager.tr("tab.request"));
        tabbedPane.setTitleAt(1, I18nManager.tr("tab.privilege"));
        tabbedPane.setTitleAt(2, I18nManager.tr("tab.data"));
        tabbedPane.setTitleAt(3, I18nManager.tr("tab.config"));
        tabbedPane.setTitleAt(4, I18nManager.tr("tab.log"));
        tabbedPane.setTitleAt(5, I18nManager.tr("tab.tutorial"));
        tabbedPane.setTitleAt(6, I18nManager.tr("tab.about"));
        tabbedPane.revalidate();
        tabbedPane.repaint();
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
            LogManager.getInstance().printError(I18nManager.tr("log.request.save.failed"));
            return;
        }

        requestListPanel.addRequest(dbId, "/", "GET", "http", "example.com", "/", "", newRequestTemplate.getBytes());
        dispatchHandler.setCurrentRequestId(dbId);

        // 更新历史面板标题
        historyPanel.setBorderTitle(I18nManager.tr("history.border.new"));

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

        LogManager.getInstance().printOutput(I18nManager.tr("log.request.selected", requestId));

        dispatchHandler.setCurrentRequestId(requestId);

        // 清空编辑区域
        requestPanel.clear();
        responsePanel.clear();
        statusPanel.clear();

        // 设置请求内容
        if (requestData != null && requestData.length > 0) {
            requestPanel.setRequest(requestData);
            LogManager.getInstance().printOutput(I18nManager.tr("log.request.loaded.editor", requestData.length));

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
            historyPanel.setBorderTitle(I18nManager.tr("history.border.title") + " - " + url);

            // 优先加载基线响应（来自 requests 表），没有基线时才回退到最新历史响应
            // 修复：之前直接调用 loadLatestResponseForRequest 会拿到越权重放的历史响应，
            // 而不是基准报文自身的原始响应，导致点击基准报文时响应面板显示错误数据
            loadBaselineOrLatestResponse(requestId);

            // 加载相关的历史记录（批量添加模式下使用静默模式，避免"没有历史记录"噪音日志）
            loadHistoryForRequest(requestId, requestListPanel.isBatchAddMode());
        } else {
            LogManager.getInstance().printOutput(I18nManager.tr("log.request.empty", requestId));
            dispatchHandler.setCurrentHttpService(null);
            historyPanel.setBorderTitle(I18nManager.tr("history.border.title"));
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
                    I18nManager.tr("log.baseline.loaded", requestId, baselineResponse.length));
                return;
            }
        } catch (Exception e) {
            LogManager.getInstance().printError(I18nManager.tr("log.baseline.load.failed", e.getMessage()));
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
                    LogManager.getInstance().printOutput(I18nManager.tr("log.latest.response.loaded", requestId));
                }
            }
        } catch (Exception e) {
            LogManager.getInstance().printError(I18nManager.tr("log.latest.response.failed", e.getMessage()));
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
            LogManager.getInstance().printOutput(I18nManager.tr("log.history.loading", requestId));
        }

        // 优先从数据库加载历史记录
        try {
            HistoryReadDAO historyReadDAO = new HistoryReadDAO();
            List<RequestResponseRecord> dbHistoryList = historyReadDAO.getHistoryByRequestId(requestId);

            if (dbHistoryList != null && !dbHistoryList.isEmpty()) {
                if (!silent) {
                    LogManager.getInstance().printOutput(
                        I18nManager.tr("log.history.fromdb", requestId, dbHistoryList.size()));
                }

                for (RequestResponseRecord record : dbHistoryList) {
                    historyPanel.addHistoryRecord(record);
                }

                dispatchHandler.getRequestHistoryMap().put(requestId, new ArrayList<>(dbHistoryList));

                if (!silent) {
                    LogManager.getInstance().printOutput(I18nManager.tr("log.history.load.done", requestId));
                }
                return;
            }
        } catch (Exception e) {
            LogManager.getInstance().printError(I18nManager.tr("log.history.db.failed", e.getMessage()));
        }

        // 如果数据库中没有或加载失败，尝试从内存映射中获取
        List<RequestResponseRecord> historyList = dispatchHandler.getRequestHistoryMap().get(requestId);

        if (historyList != null && !historyList.isEmpty()) {
            if (!silent) {
                LogManager.getInstance().printOutput(
                    I18nManager.tr("log.history.frommem", requestId, historyList.size()));
            }

            for (RequestResponseRecord record : historyList) {
                historyPanel.addHistoryRecord(record);
            }
        } else {
            // 数据库和内存中均无历史记录：属于正常情况（新发送的基准报文尚未重放）。
            // 基线响应已由 loadBaselineOrLatestResponse() 显示到响应面板，
            // 重放历史表格应保持为空，不插入伪造的基线记录。
            if (!silent) {
                LogManager.getInstance().printOutput(
                    I18nManager.tr("log.history.none", requestId));
            }
        }

        historyPanel.setBorderTitle(I18nManager.tr("history.border.title") + " - ID: " + requestId);
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
            LogManager.getInstance().printOutput(I18nManager.tr("log.privilege.record.saved", historyId));
        } else {
            LogManager.getInstance().printError(I18nManager.tr("log.privilege.record.failed"));
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
        LogManager.getInstance().printOutput(I18nManager.tr("log.refresh.start"));

        requestListPanel.clearAllRequests();
        historyPanel.clearAllHistory();
        dispatchHandler.setCurrentRequestId(-1);
        dispatchHandler.getRequestHistoryMap().clear();

        new Thread(() -> {
            try {
                RequestDAO requestDAO = new RequestDAO();
                java.util.List<java.util.Map<String, Object>> requests = requestDAO.getAllRequests();
                LogManager.getInstance().printOutput(I18nManager.tr("log.requests.loaded", requests.size()));

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
                LogManager.getInstance().printOutput(I18nManager.tr("log.refresh.history.loaded", allHistory.size()));

                for (RequestResponseRecord record : allHistory) {
                    int requestId = record.getRequestId();
                    if (requestId > 0) {
                        dispatchHandler.getRequestHistoryMap().computeIfAbsent(requestId, k -> new ArrayList<>()).add(record);
                    }
                }

                LogManager.getInstance().printOutput(I18nManager.tr("log.refresh.done"));
            } catch (Exception e) {
                LogManager.getInstance().printError(I18nManager.tr("log.refresh.failed", e.getMessage()));
            }
        }).start();
    }
}
