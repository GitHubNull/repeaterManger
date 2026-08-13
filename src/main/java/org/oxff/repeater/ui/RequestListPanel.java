package org.oxff.repeater.ui;

import org.oxff.repeater.i18n.I18nManager;
import org.oxff.repeater.model.RequestRecord;
import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.db.RequestDAO;
import org.oxff.repeater.db.history.HistoryUpdateDAO;
import org.oxff.repeater.api.MontoyaApiHolder;
import org.oxff.repeater.ui.comparer.ComparerPanel;
import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionListener;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 请求列表面板组件 - 负责显示和管理HTTP请求列表
 * 支持简单搜索（关键词/正则/大小写）和可折叠高级搜索（URL/Header/Body范围）
 */
public class RequestListPanel extends JPanel {
    private static final long serialVersionUID = 1L;
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    // 请求列表数据
    private final DefaultTableModel tableModel = new DefaultTableModel(
        buildColumnNames(), 0
    ) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };

    /**
     * 构建表格列名（从资源读取当前语言文本）
     */
    private static Object[] buildColumnNames() {
        return new Object[]{
            I18nManager.tr("request.list.col.id"),
            I18nManager.tr("request.list.col.api"),
            I18nManager.tr("request.list.col.method"),
            I18nManager.tr("request.list.col.protocol"),
            I18nManager.tr("request.list.col.domain"),
            I18nManager.tr("request.list.col.path"),
            I18nManager.tr("request.list.col.query"),
            I18nManager.tr("request.list.col.privilege"),
            I18nManager.tr("request.list.col.date"),
            I18nManager.tr("request.list.col.comment")
        };
    }

    private final JTable requestTable = new JTable(tableModel);
    private final Map<Integer, byte[]> requestDataMap = new ConcurrentHashMap<>();
    private final Map<Integer, byte[]> responseDataMap = new ConcurrentHashMap<>();
    private final Map<Integer, Color> requestColors = new HashMap<>();
    private final Map<Integer, String> requestComments = new HashMap<>();
    private final Map<Integer, String> requestJudgmentMap = new ConcurrentHashMap<>();

    // 右键菜单工厂（需注入报文比较面板引用）
    private RequestListContextMenu contextMenuFactory;

    // 回调函数
    private RequestSelectedCallback requestSelectedCallback;

    /** 批量添加模式标志：为true时暂停ListSelectionListener回调，避免每添加一行都触发onRequestSelected
     *  注意：仅限EDT线程读写，不需要volatile */
    private boolean batchAddMode = false;

    private TableRowSorter<DefaultTableModel> tableRowSorter;
    private int nextRequestId = 1;

    // 简单搜索组件
    private final JTextField simpleSearchField = new JTextField(20);

    // 高级搜索组件
    private final JToggleButton advancedToggleBtn = new JToggleButton(I18nManager.tr("request.list.search.advanced"));
    private final JPanel advancedContentPanel = new JPanel();
    private final JCheckBox urlScopeCb = new JCheckBox("URL", true);
    private final JCheckBox headerScopeCb = new JCheckBox("Header", false);
    private final JCheckBox bodyScopeCb = new JCheckBox("Body", false);
    private final JCheckBox respHeaderScopeCb = new JCheckBox("Header", false);
    private final JCheckBox respBodyScopeCb = new JCheckBox("Body", false);
    private final JTextField advancedSearchField = new JTextField(20);
    private final JComboBox<String> advancedMatchModeCombo = new JComboBox<>(buildMatchModeItems());
    private final JCheckBox advancedCaseSensitiveCb = new JCheckBox(I18nManager.tr("request.list.search.caseSensitive"));

    /**
     * 构建匹配模式下拉项（关键词/正则）
     */
    private static String[] buildMatchModeItems() {
        return new String[]{
            I18nManager.tr("request.list.search.keyword"),
            I18nManager.tr("request.list.search.regex")
        };
    }

    /**
     * 请求选中回调接口
     */
    public interface RequestSelectedCallback {
        void onRequestSelected(int requestId, byte[] requestData);
    }

    /**
     * 清空操作回调接口
     */
    public interface ClearAllCallback {
        void onClearAll();
    }

    private ClearAllCallback clearAllCallback;

    /**
     * 设置清空操作回调
     */
    public void setClearAllCallback(ClearAllCallback callback) {
        this.clearAllCallback = callback;
    }

    /**
     * 构造函数
     */
    public RequestListPanel() {
        setLayout(new BorderLayout());

        // 添加带标题的边框，突出其作为越权测试基准报文表的语义
        setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(),
            I18nManager.tr("request.list.title")
        ));

        // 创建搜索面板
        JPanel searchContainer = buildSearchPanel();
        add(searchContainer, BorderLayout.NORTH);

        // 设置表格
        requestTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        requestTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        // 设置列宽
        setupColumnWidths();

        // 注册右键菜单（每次右键时动态创建以反映当前选中数量）
        contextMenuFactory = new RequestListContextMenu(requestTable, tableModel, requestColors, requestComments, requestDataMap, responseDataMap);
        requestTable.setComponentPopupMenu(new JPopupMenu() {
            private static final long serialVersionUID = 1L;
            @Override
            public void show(Component invoker, int x, int y) {
                // 每次右键时动态重建菜单
                removeAll();
                JPopupMenu freshMenu = contextMenuFactory.createPopupMenu();
                for (MenuElement element : freshMenu.getSubElements()) {
                    if (element instanceof JMenuItem) {
                        add((JMenuItem) element);
                    } else if (element instanceof JMenu) {
                        add((JMenu) element);
                    } else if (element instanceof JSeparator) {
                        addSeparator();
                    }
                }
                super.show(invoker, x, y);
            }
        });

        requestTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && !batchAddMode) {
                int selectedRow = requestTable.getSelectedRow();
                if (selectedRow >= 0) {
                    int requestId = (int) tableModel.getValueAt(selectedRow, 0);
                    byte[] requestData = requestDataMap.get(requestId);
                    if (requestData != null && requestSelectedCallback != null) {
                        requestSelectedCallback.onRequestSelected(requestId, requestData);
                    }
                }
            }
        });

        // 处理单击已选中行的场景：Swing 的 ListSelectionListener 在选中行未变化时不触发，
        // 但用户从历史记录面板切换回基准报文表点击同一行时，需要重新加载基准报文的请求和响应
        requestTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                if (batchAddMode) return;
                int row = requestTable.rowAtPoint(e.getPoint());
                if (row < 0) return;
                // 仅当点击的是当前已选中的行时才手动触发回调
                // （点击未选中行时 ListSelectionListener 会自动处理）
                if (row == requestTable.getSelectedRow()) {
                    int requestId = (int) tableModel.getValueAt(row, 0);
                    byte[] requestData = requestDataMap.get(requestId);
                    if (requestData != null && requestSelectedCallback != null) {
                        requestSelectedCallback.onRequestSelected(requestId, requestData);
                    }
                }
            }
        });

        // 添加表格到滚动面板
        JScrollPane scrollPane = new JScrollPane(requestTable);
        add(scrollPane, BorderLayout.CENTER);

        // 设置搜索功能
        setupSearch();

        // 设置行颜色渲染器
        requestTable.setDefaultRenderer(Object.class, new RequestListTableRenderer(requestColors));

        // 注册语言变更监听：刷新面板文本
        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);
    }

    /**
     * 语言变更时刷新面板文本（边框标题、表格列名、搜索组件、下拉项）
     */
    private void refreshTexts() {
        // 边框标题
        setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(),
            I18nManager.tr("request.list.title")
        ));

        // 表格列名（重建列标识符）
        tableModel.setColumnIdentifiers(buildColumnNames());
        setupColumnWidths();

        // 搜索组件文本
        advancedCaseSensitiveCb.setText(I18nManager.tr("request.list.search.caseSensitive"));

        // 匹配模式下拉项（保持选中索引）
        int advMatchIndex = advancedMatchModeCombo.getSelectedIndex();
        advancedMatchModeCombo.setModel(new DefaultComboBoxModel<>(buildMatchModeItems()));
        if (advMatchIndex >= 0 && advMatchIndex < advancedMatchModeCombo.getItemCount()) {
            advancedMatchModeCombo.setSelectedIndex(advMatchIndex);
        }

        // 高级搜索切换按钮文本
        boolean expanded = advancedToggleBtn.isSelected();
        advancedToggleBtn.setText(I18nManager.tr(expanded ? "api.rule.advanced.hide" : "api.rule.advanced.show"));

        revalidate();
        repaint();
    }

    /**
     * 设置各列的宽度
     */
    private void setupColumnWidths() {
        javax.swing.table.TableColumnModel colModel = requestTable.getColumnModel();
        // ID列
        colModel.getColumn(0).setPreferredWidth(40);
        colModel.getColumn(0).setMaxWidth(50);
        // API列
        colModel.getColumn(1).setPreferredWidth(200);
        colModel.getColumn(1).setMaxWidth(400);
        // Method列
        colModel.getColumn(2).setPreferredWidth(60);
        colModel.getColumn(2).setMaxWidth(80);
        // Protocol列
        colModel.getColumn(3).setPreferredWidth(60);
        colModel.getColumn(3).setMaxWidth(80);
        // Domain列
        colModel.getColumn(4).setPreferredWidth(150);
        // Path列
        colModel.getColumn(5).setPreferredWidth(180);
        // Query列
        colModel.getColumn(6).setPreferredWidth(150);
        // 越权测试列
        colModel.getColumn(7).setPreferredWidth(70);
        colModel.getColumn(7).setMaxWidth(90);
        // Date列
        colModel.getColumn(8).setPreferredWidth(150);
        colModel.getColumn(8).setMaxWidth(180);
        // 备注列
        colModel.getColumn(9).setPreferredWidth(100);
    }

    /**
     * 构建搜索面板（简单搜索 + 可折叠高级搜索）
     */
    private JPanel buildSearchPanel() {
        JPanel searchContainer = new JPanel();
        searchContainer.setLayout(new BorderLayout());

        // 简单搜索栏（始终可见）
        JPanel simpleSearchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        simpleSearchPanel.add(new JLabel(I18nManager.tr("common.search")));
        simpleSearchPanel.add(simpleSearchField);
        JButton clearBtn = new JButton(I18nManager.tr("common.clear"));
        clearBtn.setToolTipText(I18nManager.tr("request.list.reset.tooltip"));
        clearBtn.addActionListener(e -> {
            simpleSearchField.setText("");
            advancedSearchField.setText("");
            applyFilter();
        });
        simpleSearchPanel.add(clearBtn);
        simpleSearchPanel.add(advancedToggleBtn);
        // 列显示控制按钮 - 位于高级搜索按钮旁边
        JButton columnControlBtn = new JButton(I18nManager.tr("request.menu.columnControl.toggle"));
        columnControlBtn.addActionListener(e -> {
            RequestColumnControlDialog dialog = new RequestColumnControlDialog(requestTable, requestTable, tableModel);
            dialog.setVisible(true);
        });
        simpleSearchPanel.add(columnControlBtn);

        searchContainer.add(simpleSearchPanel, BorderLayout.NORTH);

        // 高级搜索内容面板（默认不可见）
        advancedContentPanel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(2, 4, 2, 4);

        // 第一行：请求报文范围
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        advancedContentPanel.add(new JLabel(I18nManager.tr("request.list.scope.request") + ":"), gbc);
        gbc.gridx = 1; gbc.weightx = 0;
        advancedContentPanel.add(urlScopeCb, gbc);
        gbc.gridx = 2; gbc.weightx = 0;
        advancedContentPanel.add(headerScopeCb, gbc);
        gbc.gridx = 3; gbc.weightx = 0;
        advancedContentPanel.add(bodyScopeCb, gbc);

        // 第二行：响应报文范围
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        advancedContentPanel.add(new JLabel(I18nManager.tr("request.list.scope.response") + ":"), gbc);
        gbc.gridx = 1; gbc.weightx = 0;
        advancedContentPanel.add(respHeaderScopeCb, gbc);
        gbc.gridx = 2; gbc.weightx = 0;
        advancedContentPanel.add(respBodyScopeCb, gbc);

        // 第三行：搜索内容 + 匹配模式 + 大小写敏感
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        advancedContentPanel.add(new JLabel(I18nManager.tr("request.list.content") + ":"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0; gbc.gridwidth = 2;
        advancedContentPanel.add(advancedSearchField, gbc);
        gbc.gridx = 3; gbc.weightx = 0; gbc.gridwidth = 1;
        JPanel matchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        matchPanel.add(advancedMatchModeCombo);
        matchPanel.add(advancedCaseSensitiveCb);
        advancedContentPanel.add(matchPanel, gbc);

        advancedContentPanel.setVisible(false); // 默认收缩

        searchContainer.add(advancedContentPanel, BorderLayout.CENTER);

        // 高级搜索折叠/展开切换
        advancedToggleBtn.addActionListener(e -> {
            boolean expanded = advancedToggleBtn.isSelected();
            advancedContentPanel.setVisible(expanded);
            advancedToggleBtn.setText(I18nManager.tr(expanded ? "api.rule.advanced.hide" : "api.rule.advanced.show"));
            searchContainer.revalidate();
            searchContainer.repaint();
            applyFilter(); // 切换时重新过滤
        });

        return searchContainer;
    }

    /**
     * 设置搜索功能 - 为所有搜索控件添加事件监听器
     */
    private void setupSearch() {
        tableRowSorter = new TableRowSorter<>(tableModel);
        requestTable.setRowSorter(tableRowSorter);

        // 简单搜索框文本变化
        simpleSearchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { applyFilter(); }
            @Override
            public void removeUpdate(DocumentEvent e) { applyFilter(); }
            @Override
            public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });

        // 高级搜索框文本变化
        advancedSearchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { applyFilter(); }
            @Override
            public void removeUpdate(DocumentEvent e) { applyFilter(); }
            @Override
            public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });

        // 匹配模式切换
        ActionListener matchModeListener = e -> applyFilter();
        advancedMatchModeCombo.addActionListener(matchModeListener);

        // 大小写敏感切换
        ActionListener caseSensitiveListener = e -> applyFilter();
        advancedCaseSensitiveCb.addActionListener(caseSensitiveListener);

        // 搜索范围复选框切换
        ActionListener scopeListener = e -> applyFilter();
        urlScopeCb.addActionListener(scopeListener);
        headerScopeCb.addActionListener(scopeListener);
        bodyScopeCb.addActionListener(scopeListener);
        respHeaderScopeCb.addActionListener(scopeListener);
        respBodyScopeCb.addActionListener(scopeListener);
    }

    /**
     * 应用搜索过滤器
     * 根据当前搜索控件的状态构建 SearchConfig 和 RequestSearchFilter
     */
    private void applyFilter() {
        // 判断使用简单搜索还是高级搜索
        boolean useAdvancedSearch = advancedToggleBtn.isSelected()
                && advancedSearchField.getText().trim().length() > 0;

        String searchText;
        boolean isRegex;
        boolean caseSensitive;
        Set<SearchConfig.SearchScope> scope;

        if (useAdvancedSearch) {
            // 高级搜索覆盖简单搜索
            searchText = advancedSearchField.getText().trim();
            // 索引1=正则，与显示文本解耦
            isRegex = advancedMatchModeCombo.getSelectedIndex() == 1;
            caseSensitive = advancedCaseSensitiveCb.isSelected();
            scope = EnumSet.noneOf(SearchConfig.SearchScope.class);
            if (urlScopeCb.isSelected()) scope.add(SearchConfig.SearchScope.URL);
            if (headerScopeCb.isSelected()) scope.add(SearchConfig.SearchScope.HEADER);
            if (bodyScopeCb.isSelected()) scope.add(SearchConfig.SearchScope.BODY);
            if (respHeaderScopeCb.isSelected()) scope.add(SearchConfig.SearchScope.RESPONSE_HEADER);
            if (respBodyScopeCb.isSelected()) scope.add(SearchConfig.SearchScope.RESPONSE_BODY);
            if (scope.isEmpty()) scope = EnumSet.of(SearchConfig.SearchScope.URL); // 默认 URL
        } else {
            // 简单搜索：默认搜索 URL 列，关键词匹配，不区分大小写
            searchText = simpleSearchField.getText().trim();
            isRegex = false;
            caseSensitive = false;
            scope = EnumSet.of(SearchConfig.SearchScope.URL);
        }

        // 构建文本搜索过滤器（可为 null）
        RowFilter<DefaultTableModel, Integer> textFilter = null;
        if (!searchText.isEmpty()) {
            SearchConfig config = new SearchConfig(scope, searchText, isRegex, caseSensitive);
            textFilter = new RequestSearchFilter(requestDataMap, responseDataMap, config);
        }

        tableRowSorter.setRowFilter(textFilter);
    }

    /**
     * 获取请求数据映射（供外部访问）
     */
    public Map<Integer, byte[]> getRequestDataMap() {
        return requestDataMap;
    }

    /**
     * 获取响应数据映射（供外部访问）
     */
    public Map<Integer, byte[]> getResponseDataMap() {
        return responseDataMap;
    }

    /**
     * 设置响应数据（缓存到内存映射，供搜索使用）
     * @param requestId    请求 ID
     * @param responseData 原始响应字节数组
     */
    public void setResponseData(int requestId, byte[] responseData) {
        if (responseData != null && responseData.length > 0) {
            responseDataMap.put(requestId, responseData);
        }
    }

    /**
     * 获取响应数据
     * @param requestId 请求 ID
     * @return 原始响应字节数组，无响应时返回 null
     */
    public byte[] getResponseData(int requestId) {
        return responseDataMap.get(requestId);
    }

    /**
     * 设置请求选中回调
     */
    public void setRequestSelectedCallback(RequestSelectedCallback callback) {
        this.requestSelectedCallback = callback;
    }

    /**
     * 设置报文比较面板引用（转发给右键菜单工厂，供"发送到报文比较"使用）
     */
    public void setComparerPanel(ComparerPanel comparerPanel) {
        if (contextMenuFactory != null) {
            contextMenuFactory.setComparerPanel(comparerPanel);
        }
    }

    /**
     * 添加新的请求（简化版本）
     */
    public int addNewRequest(String url, String method) {
        // 创建一个基本的HTTP请求
        String requestTemplate = String.format("%s %s HTTP/1.1\r\nHost: example.com\r\n\r\n", method, url);
        byte[] requestData = requestTemplate.getBytes();
        return addNewRequest(url, method, requestData);
    }

    /**
     * 添加新的请求
     */
    public int addNewRequest(String url, String method, byte[] requestData) {
        int requestId = nextRequestId++;

        // 解析URL组件
        String protocol = url.startsWith("https://") ? "https" : "http";
        String remaining = url.substring(protocol.length() + 3); // 跳过 "://"

        String domain;
        String path;
        String query = "";

        int pathStart = remaining.indexOf('/');
        if (pathStart > 0) {
            domain = remaining.substring(0, pathStart);
            remaining = remaining.substring(pathStart);
        } else {
            domain = remaining;
            remaining = "/";
        }

        int queryStart = remaining.indexOf('?');
        if (queryStart > 0) {
            path = remaining.substring(0, queryStart);
            query = remaining.substring(queryStart + 1);
        } else {
            path = remaining;
        }

        // 创建记录并添加到表格
        RequestRecord record = new RequestRecord(requestId, protocol, domain, path, query, method, requestData);
        addRequestRecord(record);

        return requestId;
    }

    /**
     * 更新请求（带API值）
     */
    public void updateRequest(int requestId, String api, String protocol, String domain, String path, String query, String method) {
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            int rowId = (int) tableModel.getValueAt(i, 0);
            if (rowId == requestId) {
                tableModel.setValueAt(api, i, 1);       // API
                tableModel.setValueAt(method, i, 2);    // Method
                tableModel.setValueAt(protocol, i, 3);   // Protocol
                tableModel.setValueAt(domain, i, 4);     // Domain
                tableModel.setValueAt(path, i, 5);       // Path
                tableModel.setValueAt(query, i, 6);      // Query
                break;
            }
        }
    }

    /**
     * 更新请求
     */
    public void updateRequest(int requestId, String protocol, String domain, String path, String query, String method) {
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            int rowId = (int) tableModel.getValueAt(i, 0);
            if (rowId == requestId) {
                tableModel.setValueAt(method, i, 2);    // Method
                tableModel.setValueAt(protocol, i, 3);   // Protocol
                tableModel.setValueAt(domain, i, 4);     // Domain
                tableModel.setValueAt(path, i, 5);       // Path
                tableModel.setValueAt(query, i, 6);      // Query
                break;
            }
        }
    }

    /**
     * 清除所有请求
     */
    public void clearAllRequests() {
        tableModel.setRowCount(0);
        requestDataMap.clear();
        responseDataMap.clear();
        requestColors.clear();
        requestComments.clear();
        requestJudgmentMap.clear();
        nextRequestId = 1;
    }

    /**
     * 解析对话框父窗口
     * 优先使用Burp主窗口作为父窗口，避免对话框显示在Burp主窗口后面导致看起来"点击无反应"
     */
    private Component resolveDialogParent() {
        try {
            MontoyaApi api = MontoyaApiHolder.getApi();
            if (api != null) {
                Frame burpFrame = api.userInterface().swingUtils().suiteFrame();
                if (burpFrame != null) {
                    return burpFrame;
                }
            }
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 获取Burp主窗口失败，使用面板作为对话框父窗口: " + e.getMessage());
        }
        return this;
    }

    /**
     * 清空所有请求（带确认对话框）
     * 供全局工具栏的清空报文按钮调用
     */
    public void clearAllWithConfirm() {
        LogManager.getInstance().printOutput("[*] 清空按钮被点击，准备弹出确认对话框...");

        Component dialogParent = resolveDialogParent();

        if (tableModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(dialogParent,
                "当前没有需要清空的数据",
                "提示",
                JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // 注意：Burp的LookAndFeel禁用了JLabel的HTML渲染，HTML标签会被原样显示，
        // 因此使用纯Swing组件构建多行提示内容
        JPanel messagePanel = new JPanel();
        messagePanel.setLayout(new BoxLayout(messagePanel, BoxLayout.Y_AXIS));
        messagePanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        JLabel titleLabel = new JLabel("此操作将彻底清空以下数据：");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD));
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        messagePanel.add(titleLabel);
        messagePanel.add(Box.createVerticalStrut(8));

        String[] impactItems = {
            "• 所有基准报文（原始报文）",
            "• 所有基准报文对应的重放历史报文",
            "• 基准报文表格的ID计数（nextRequestId）",
            "• 重放历史表格中的序号字段（#字段）",
            "• 请求颜色、注释、判决结果等映射数据",
            "• 数据库中的请求记录和历史记录"
        };
        for (String item : impactItems) {
            JLabel itemLabel = new JLabel(item);
            itemLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
            messagePanel.add(itemLabel);
            messagePanel.add(Box.createVerticalStrut(2));
        }

        messagePanel.add(Box.createVerticalStrut(8));
        JLabel warnLabel = new JLabel("此操作不可恢复，确定要继续吗？");
        warnLabel.setFont(warnLabel.getFont().deriveFont(Font.BOLD));
        warnLabel.setForeground(new Color(200, 60, 60));
        warnLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        messagePanel.add(warnLabel);

        int result = JOptionPane.showConfirmDialog(
            dialogParent,
            messagePanel,
            "清空确认",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE
        );
        if (result == JOptionPane.YES_OPTION) {
            performClearAll();
        } else {
            LogManager.getInstance().printOutput("[*] 用户取消清空操作");
        }
    }

    /**
     * 执行实际的清空操作
     */
    private void performClearAll() {
        // 1. 清空UI表格和内存映射
        clearAllRequests();

        // 2. 清空数据库中的请求记录
        RequestDAO requestDAO = new RequestDAO();
        boolean requestsCleared = requestDAO.clearAllRequests();

        // 3. 清空数据库中的历史记录
        HistoryUpdateDAO historyUpdateDAO = new HistoryUpdateDAO();
        boolean historyCleared = historyUpdateDAO.clearAllHistory();

        // 4. 通知上层清空调度处理器数据
        if (clearAllCallback != null) {
            clearAllCallback.onClearAll();
        }

        if (requestsCleared && historyCleared) {
            LogManager.getInstance().printOutput("[+] 所有数据已清空");
        } else {
            LogManager.getInstance().printError("[!] 部分数据清空失败，请检查日志");
        }
    }

    /**
     * 获取请求颜色映射
     */
    public Map<Integer, Color> getRequestColors() {
        return requestColors;
    }

    /**
     * 设置请求的判决结果
     * @param requestId 请求 ID
     * @param judgment  判决结果（PENDING/ESCALATED/NOT_ESCALATED/ERROR）
     */
    public void setRequestJudgment(int requestId, String judgment) {
        requestJudgmentMap.put(requestId, judgment);
    }

    /**
     * 获取请求的判决结果
     * @param requestId 请求 ID
     * @return 判决结果，未设置时返回 null
     */
    public String getRequestJudgment(int requestId) {
        return requestJudgmentMap.get(requestId);
    }

    /**
     * 更新请求注释（同步更新映射和表格备注列）
     */
    public void updateRequestComment(int requestId, String comment) {
        requestComments.put(requestId, comment);
        // 同步更新表格备注列
        String displayComment = comment != null && comment.length() > 16
            ? comment.substring(0, 16) + "..." : (comment != null ? comment : "");
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            int rowId = (int) tableModel.getValueAt(i, 0);
            if (rowId == requestId) {
                tableModel.setValueAt(displayComment, i, 9); // 备注列索引=9
                break;
            }
        }
    }

    /**
     * 获取请求数量
     */
    public int getRequestCount() {
        return tableModel.getRowCount();
    }

    /**
     * 获取选中的请求ID
     */
    public int getSelectedRequestId() {
        int selectedRow = requestTable.getSelectedRow();
        if (selectedRow >= 0) {
            return (int) tableModel.getValueAt(selectedRow, 0);
        }
        return -1;
    }

    /**
     * 获取请求数据
     */
    public byte[] getRequestData(int requestId) {
        return requestDataMap.get(requestId);
    }

    /**
     * 设置请求颜色
     */
    public void setRequestColor(int requestId, Color color) {
        requestColors.put(requestId, color);
        requestTable.repaint();
    }

    /**
     * 获取请求注释
     */
    public String getRequestComment(int requestId) {
        return requestComments.get(requestId);
    }

    /**
     * 设置批量添加模式
     * 开启时暂停ListSelectionListener回调，避免每添加一行都触发onRequestSelected；
     * 关闭时恢复正常回调行为
     *
     * @param enabled true=批量模式（暂停回调），false=正常模式（恢复回调）
     */
    public void setBatchAddMode(boolean enabled) {
        this.batchAddMode = enabled;
        if (!enabled) {
            // 批量添加结束后，如果有选中行则触发一次回调
            int selectedRow = requestTable.getSelectedRow();
            if (selectedRow >= 0) {
                int requestId = (int) tableModel.getValueAt(selectedRow, 0);
                byte[] requestData = requestDataMap.get(requestId);
                if (requestData != null && requestSelectedCallback != null) {
                    requestSelectedCallback.onRequestSelected(requestId, requestData);
                }
            }
        }
    }

    /**
     * 静默退出批量添加模式（不触发onRequestSelected回调）
     * 用于批量权限测试场景：退出批量模式后立即开始重放，
     * 此时历史记录尚不存在，触发回调会导致无效DB查询和"没有历史记录"告警
     */
    public void exitBatchModeQuiet() {
        this.batchAddMode = false;
    }

    /**
     * 是否处于批量添加模式
     */
    public boolean isBatchAddMode() {
        return batchAddMode;
    }

    /**
     * 添加请求（带API值和越权测试标记）
     * 批量添加模式下自动静默（不逐条打印日志）
     */
    public void addRequest(int id, String api, String method, String protocol, String domain, String path, String query, boolean isPrivilegeTest, byte[] requestData) {
        // 添加到表格模型
        tableModel.addRow(new Object[]{
            id,
            api,
            method,
            protocol,
            domain,
            path,
            query,
            isPrivilegeTest ? "是" : "否",
            DATE_FORMAT.format(new Date()),
            ""  // 备注列初始为空
        });

        // 保存请求数据到内存映射
        if (requestData != null) {
            requestDataMap.put(id, requestData);
            // 批量添加模式下不逐条打印日志，避免150+请求产生大量噪音
            if (!batchAddMode) {
                LogManager.getInstance().printOutput("[+] 请求数据已保存到内存映射，ID: " + id + "，数据大小: " + requestData.length + " 字节");
            }
        }

        // 注意：数据库保存由调用方负责（setRequest/createNewRequest/refreshAllData），
        // 此处不再重复保存，避免产生重复记录消耗AUTOINCREMENT ID

        // 更新颜色和注释映射
        requestColors.put(id, null);
        requestComments.put(id, "");
    }

    /**
     * 添加请求（带API值，非越权测试）
     */
    public void addRequest(int id, String api, String method, String protocol, String domain, String path, String query, byte[] requestData) {
        addRequest(id, api, method, protocol, domain, path, query, false, requestData);
    }

    /**
     * 添加请求
     */
    public void addRequest(int id, String protocol, String domain, String path, String query, String method, byte[] requestData) {
        // 默认使用 path 作为 API 值
        addRequest(id, path, method, protocol, domain, path, query, requestData);
    }

    /**
     * 添加请求记录
     */
    public void addRequestRecord(RequestRecord record) {
        String apiValue = (record.getApi() != null) ? record.getApi() : record.getPath();
        tableModel.addRow(new Object[]{
            record.getId(),
            apiValue,
            record.getMethod(),
            record.getProtocol(),
            record.getDomain(),
            record.getPath(),
            record.getQuery(),
            record.isPrivilegeTest() ? "是" : "否",
            DATE_FORMAT.format(new Date()),
            ""  // 备注列初始为空
        });

        // 保存请求数据到内存映射
        if (record.getRequestData() != null) {
            requestDataMap.put(record.getId(), record.getRequestData());
            if (!batchAddMode) {
                LogManager.getInstance().printOutput("[+] 请求数据已保存到内存映射，ID: " + record.getId() + "，数据大小: " + record.getRequestData().length + " 字节");
            }
        }

        // 更新颜色和注释映射
        requestColors.put(record.getId(), null);
        requestComments.put(record.getId(), "");
    }

    /**
     * 更新请求的越权测试标记
     */
    public void updatePrivilegeTestFlag(int requestId, boolean isPrivilegeTest) {
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            int rowId = (int) tableModel.getValueAt(i, 0);
            if (rowId == requestId) {
                tableModel.setValueAt(isPrivilegeTest ? "是" : "否", i, 7);
                break;
            }
        }
    }
}