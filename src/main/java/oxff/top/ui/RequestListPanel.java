package oxff.top.ui;

import oxff.top.model.RequestRecord;
import burp.BurpExtender;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * 请求列表面板组件 - 负责显示和管理HTTP请求列表
 * 支持简单搜索（关键词/正则/大小写）和可折叠高级搜索（URL/Header/Body范围）
 */
public class RequestListPanel extends JPanel {
    private static final long serialVersionUID = 1L;
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    // 请求列表数据
    private final DefaultTableModel tableModel = new DefaultTableModel(
        new Object[]{"ID", "API", "Method", "Protocol", "Domain", "Path", "Query", "越权测试", "Date"}, 0
    ) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };

    private final JTable requestTable = new JTable(tableModel);
    private final Map<Integer, byte[]> requestDataMap = new HashMap<>();
    private final Map<Integer, Color> requestColors = new HashMap<>();
    private final Map<Integer, String> requestComments = new HashMap<>();

    // 回调函数
    private RequestSelectedCallback requestSelectedCallback;

    private TableRowSorter<DefaultTableModel> tableRowSorter;
    private int nextRequestId = 1;

    // 简单搜索组件
    private final JTextField simpleSearchField = new JTextField(20);
    private final JComboBox<String> simpleMatchModeCombo = new JComboBox<>(new String[]{"关键词", "正则"});
    private final JCheckBox simpleCaseSensitiveCb = new JCheckBox("大小写敏感");

    // 高级搜索组件
    private final JToggleButton advancedToggleBtn = new JToggleButton("▶ 高级搜索");
    private final JPanel advancedContentPanel = new JPanel();
    private final JCheckBox urlScopeCb = new JCheckBox("URL", true);
    private final JCheckBox headerScopeCb = new JCheckBox("Header", false);
    private final JCheckBox bodyScopeCb = new JCheckBox("Body", false);
    private final JTextField advancedSearchField = new JTextField(20);
    private final JComboBox<String> advancedMatchModeCombo = new JComboBox<>(new String[]{"关键词", "正则"});
    private final JCheckBox advancedCaseSensitiveCb = new JCheckBox("大小写敏感");

    /**
     * 请求选中回调接口
     */
    public interface RequestSelectedCallback {
        void onRequestSelected(int requestId, byte[] requestData);
    }

    /**
     * 构造函数
     */
    public RequestListPanel() {
        setLayout(new BorderLayout());

        // 创建搜索面板
        JPanel searchContainer = buildSearchPanel();
        add(searchContainer, BorderLayout.NORTH);

        // 设置表格
        requestTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        requestTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
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

        // 添加表格到滚动面板
        JScrollPane scrollPane = new JScrollPane(requestTable);
        add(scrollPane, BorderLayout.CENTER);

        // 设置搜索功能
        setupSearch();

        // 设置越权测试列宽
        requestTable.getColumnModel().getColumn(7).setPreferredWidth(70);
        requestTable.getColumnModel().getColumn(7).setMaxWidth(90);
    }

    /**
     * 构建搜索面板（简单搜索 + 可折叠高级搜索）
     */
    private JPanel buildSearchPanel() {
        JPanel searchContainer = new JPanel();
        searchContainer.setLayout(new BorderLayout());

        // 简单搜索栏（始终可见）
        JPanel simpleSearchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        simpleSearchPanel.add(new JLabel("搜索:"));
        simpleSearchPanel.add(simpleSearchField);
        simpleSearchPanel.add(simpleMatchModeCombo);
        simpleSearchPanel.add(simpleCaseSensitiveCb);
        JButton clearBtn = new JButton("清除");
        clearBtn.addActionListener(e -> {
            simpleSearchField.setText("");
            advancedSearchField.setText("");
            applyFilter();
        });
        simpleSearchPanel.add(clearBtn);
        simpleSearchPanel.add(advancedToggleBtn);

        searchContainer.add(simpleSearchPanel, BorderLayout.NORTH);

        // 高级搜索内容面板（默认不可见）
        advancedContentPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 4, 2));
        advancedContentPanel.add(new JLabel("范围:"));
        advancedContentPanel.add(urlScopeCb);
        advancedContentPanel.add(headerScopeCb);
        advancedContentPanel.add(bodyScopeCb);
        advancedContentPanel.add(new JLabel("内容:"));
        advancedContentPanel.add(advancedSearchField);
        advancedContentPanel.add(advancedMatchModeCombo);
        advancedContentPanel.add(advancedCaseSensitiveCb);
        advancedContentPanel.setVisible(false); // 默认收缩

        searchContainer.add(advancedContentPanel, BorderLayout.CENTER);

        // 高级搜索折叠/展开切换
        advancedToggleBtn.addActionListener(e -> {
            boolean expanded = advancedToggleBtn.isSelected();
            advancedContentPanel.setVisible(expanded);
            advancedToggleBtn.setText(expanded ? "▼ 高级搜索" : "▶ 高级搜索");
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
        simpleMatchModeCombo.addActionListener(matchModeListener);
        advancedMatchModeCombo.addActionListener(matchModeListener);

        // 大小写敏感切换
        ActionListener caseSensitiveListener = e -> applyFilter();
        simpleCaseSensitiveCb.addActionListener(caseSensitiveListener);
        advancedCaseSensitiveCb.addActionListener(caseSensitiveListener);

        // 搜索范围复选框切换
        ActionListener scopeListener = e -> applyFilter();
        urlScopeCb.addActionListener(scopeListener);
        headerScopeCb.addActionListener(scopeListener);
        bodyScopeCb.addActionListener(scopeListener);
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
            isRegex = "正则".equals(advancedMatchModeCombo.getSelectedItem());
            caseSensitive = advancedCaseSensitiveCb.isSelected();
            scope = EnumSet.noneOf(SearchConfig.SearchScope.class);
            if (urlScopeCb.isSelected()) scope.add(SearchConfig.SearchScope.URL);
            if (headerScopeCb.isSelected()) scope.add(SearchConfig.SearchScope.HEADER);
            if (bodyScopeCb.isSelected()) scope.add(SearchConfig.SearchScope.BODY);
            if (scope.isEmpty()) scope = EnumSet.of(SearchConfig.SearchScope.URL); // 默认 URL
        } else {
            // 简单搜索：默认搜索 URL 列
            searchText = simpleSearchField.getText().trim();
            isRegex = "正则".equals(simpleMatchModeCombo.getSelectedItem());
            caseSensitive = simpleCaseSensitiveCb.isSelected();
            scope = EnumSet.of(SearchConfig.SearchScope.URL);
        }

        // 搜索文本为空时，清除过滤器
        if (searchText.isEmpty()) {
            tableRowSorter.setRowFilter(null);
            return;
        }

        // 构建搜索配置和过滤器
        SearchConfig config = new SearchConfig(scope, searchText, isRegex, caseSensitive);
        RequestSearchFilter filter = new RequestSearchFilter(requestDataMap, config);
        tableRowSorter.setRowFilter(filter);
    }

    /**
     * 获取请求数据映射（供外部访问）
     */
    public Map<Integer, byte[]> getRequestDataMap() {
        return requestDataMap;
    }

    /**
     * 设置请求选中回调
     */
    public void setRequestSelectedCallback(RequestSelectedCallback callback) {
        this.requestSelectedCallback = callback;
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
        requestColors.clear();
        requestComments.clear();
        nextRequestId = 1;
    }

    /**
     * 获取请求颜色映射
     */
    public Map<Integer, Color> getRequestColors() {
        return requestColors;
    }

    /**
     * 更新请求注释
     */
    public void updateRequestComment(int requestId, String comment) {
        requestComments.put(requestId, comment);
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
     * 添加请求（带API值和越权测试标记）
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
            DATE_FORMAT.format(new Date())
        });

        // 保存请求数据到内存映射
        if (requestData != null) {
            requestDataMap.put(id, requestData);
            BurpExtender.printOutput("[+] 请求数据已保存到内存映射，ID: " + id + "，数据大小: " + requestData.length + " 字节");
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
            DATE_FORMAT.format(new Date())
        });

        // 保存请求数据到内存映射
        if (record.getRequestData() != null) {
            requestDataMap.put(record.getId(), record.getRequestData());
            BurpExtender.printOutput("[+] 请求数据已保存到内存映射，ID: " + record.getId() + "，数据大小: " + record.getRequestData().length + " 字节");
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