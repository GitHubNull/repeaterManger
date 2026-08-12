package org.oxff.repeater.ui.history;

import org.oxff.repeater.i18n.I18nManager;
import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.RequestDispatchHandler;
import org.oxff.repeater.db.history.HistoryUpdateDAO;
import org.oxff.repeater.db.history.HistoryWriteDAO;
import org.oxff.repeater.http.RequestResponseRecord;
import org.oxff.repeater.privilege.model.JudgmentResult;
import org.oxff.repeater.ui.comparer.ComparerPanel;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.RowFilter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.PatternSyntaxException;

/**
 * 历史记录面板 - 显示和管理HTTP请求历史
 */
public class HistoryPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private JTable historyTable;
    private DefaultTableModel historyTableModel;
    private final List<RequestResponseRecord> historyRecords;
    private Consumer<RequestResponseRecord> onSelectRecord;
    private final JTextField searchField;
    private TableRowSorter<DefaultTableModel> tableRowSorter;
    private HistoryContextMenu contextMenu;
    private RequestDispatchHandler dispatchHandler;
    private HistoryStatsBar statsBar;
    private ComparerPanel comparerPanel;

    // 需要在语言切换时刷新的组件
    private JLabel searchLabel;
    private JButton clearSearchButton;
    private JButton clearHistoryButton;
    private JButton advancedSearchButton;
    private JButton columnControlButton;
    private JScrollPane tableScrollPane;

    /**
     * 创建历史记录面板
     */
    public HistoryPanel() {
        super(new BorderLayout());

        // 初始化记录列表
        historyRecords = new ArrayList<>();

        // 创建搜索面板
        JPanel searchPanel = new JPanel(new BorderLayout());
        searchLabel = new JLabel(I18nManager.tr("history.panel.search"));
        searchField = new JTextField(20);

        // 添加搜索输入框的实时过滤功能
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                filterTable();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                filterTable();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                filterTable();
            }
        });

        searchField.addActionListener(e -> filterTable());

        clearSearchButton = new JButton(I18nManager.tr("history.panel.clear"));
        clearSearchButton.addActionListener(e -> {
            searchField.setText("");
            filterTable();
        });

        clearHistoryButton = new JButton(I18nManager.tr("history.panel.clearAll"));
        clearHistoryButton.addActionListener(e -> clearHistoryWithConfirm());

        advancedSearchButton = new JButton(I18nManager.tr("history.panel.advanced"));
        advancedSearchButton.addActionListener(e -> showAdvancedSearchDialog());

        columnControlButton = new JButton(I18nManager.tr("history.panel.columns"));
        columnControlButton.addActionListener(e -> showColumnControlDialog());

        JPanel searchControlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchControlPanel.add(searchLabel);
        searchControlPanel.add(searchField);
        searchControlPanel.add(clearSearchButton);
        searchControlPanel.add(advancedSearchButton);
        searchControlPanel.add(columnControlButton);

        JPanel controlPanel = new JPanel(new BorderLayout());
        controlPanel.add(searchControlPanel, BorderLayout.WEST);
        controlPanel.add(clearHistoryButton, BorderLayout.EAST);

        searchPanel.add(controlPanel, BorderLayout.CENTER);

        // 创建表格
        createTable();

        // 创建滚动面板
        tableScrollPane = new JScrollPane(historyTable);
        tableScrollPane.setBorder(BorderFactory.createTitledBorder(I18nManager.tr("history.panel.title")));

        // 创建状态栏
        statsBar = new HistoryStatsBar();

        // 添加到面板
        add(searchPanel, BorderLayout.NORTH);
        add(tableScrollPane, BorderLayout.CENTER);
        add(statsBar, BorderLayout.SOUTH);

        // 创建右键菜单工厂（每次右键时动态生成菜单以反映选中数量）
        contextMenu = new HistoryContextMenu(this, historyTable, historyRecords, historyTableModel);
        historyTable.setComponentPopupMenu(new JPopupMenu() {
            @Override
            public void show(Component invoker, int x, int y) {
                // 每次弹出前重新构建菜单项
                removeAll();
                JPopupMenu freshMenu = contextMenu.createPopupMenu();
                for (int i = 0; i < freshMenu.getComponentCount(); i++) {
                    add(freshMenu.getComponent(i));
                }
                super.show(invoker, x, y);
            }
        });

        // 注册语言变更监听
        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);
    }

    /**
     * 语言变更时刷新文本
     */
    private void refreshTexts() {
        searchLabel.setText(I18nManager.tr("history.panel.search"));
        clearSearchButton.setText(I18nManager.tr("history.panel.clear"));
        clearHistoryButton.setText(I18nManager.tr("history.panel.clearAll"));
        advancedSearchButton.setText(I18nManager.tr("history.panel.advanced"));
        columnControlButton.setText(I18nManager.tr("history.panel.columns"));
        tableScrollPane.setBorder(BorderFactory.createTitledBorder(I18nManager.tr("history.panel.title")));
        // 刷新表格列名（保持数据）
        historyTableModel.setColumnIdentifiers(buildColumnNames());
        applyColumnWidths();
        revalidate();
        repaint();
    }

    /**
     * 构建表格列名（从资源读取）
     */
    private static String[] buildColumnNames() {
        return new String[] {
            I18nManager.tr("history.col.index"),
            I18nManager.tr("history.col.time"),
            I18nManager.tr("history.col.api"),
            I18nManager.tr("history.col.method"),
            I18nManager.tr("history.col.protocol"),
            I18nManager.tr("history.col.domain"),
            I18nManager.tr("history.col.path"),
            I18nManager.tr("history.col.query"),
            I18nManager.tr("history.col.status"),
            I18nManager.tr("history.col.length"),
            I18nManager.tr("history.col.elapsed"),
            I18nManager.tr("history.col.user"),
            I18nManager.tr("history.col.judgment"),
            I18nManager.tr("history.col.privilege"),
            I18nManager.tr("history.col.comment")
        };
    }

    /**
     * 创建表格
     */
    private void createTable() {
        // 定义表格列名（v8新增"越权测试"列）
        String[] columnNames = buildColumnNames();

        // 创建表格模型(不允许直接编辑)
        historyTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0 || columnIndex == 8 || columnIndex == 9 || columnIndex == 10) {
                    return Integer.class;
                }
                return String.class;
            }
        };

        // 创建表格
        historyTable = new JTable(historyTableModel);
        historyTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        historyTable.setAutoCreateRowSorter(true);
        historyTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        // 设置列宽度
        applyColumnWidths();

        // 创建排序器
        tableRowSorter = new TableRowSorter<>(historyTableModel);
        historyTable.setRowSorter(tableRowSorter);

        // 添加双击事件
        historyTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    loadSelectedHistoryItem();
                }
            }
        });

        // 添加行选择变化监听，单击切换行时也触发回调以更新请求/响应/状态栏
        historyTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                loadSelectedHistoryItem();
            }
        });

        // 设置状态码列的颜色渲染器
        historyTable.getColumnModel().getColumn(8).setCellRenderer(
            HistoryTableRenderer.createStatusCodeRenderer(historyRecords));

        // 设置越权测试列的渲染器
        historyTable.getColumnModel().getColumn(13).setCellRenderer(
            HistoryTableRenderer.createPrivilegeTestRenderer(historyRecords));

        // 设置表格行背景颜色的渲染器（基于历史记录的颜色标记）
        // 分别注册 Object.class（覆盖 String 列）和 Number.class（覆盖 Integer 列），
        // 因 Swing 的 NumberRenderer 会绕过 Object.class 的默认渲染器
        historyTable.setDefaultRenderer(Object.class,
            HistoryTableRenderer.createRowColorRenderer(historyRecords));
        historyTable.setDefaultRenderer(Number.class,
            HistoryTableRenderer.createRowColorRendererForNumber(historyRecords));
    }

    /**
     * 应用表格列宽设置（语言切换刷新列名后需重新应用）
     */
    private void applyColumnWidths() {
        if (historyTable.getColumnModel().getColumnCount() < 15) {
            return;
        }
        historyTable.getColumnModel().getColumn(0).setPreferredWidth(40);   // 序号列
        historyTable.getColumnModel().getColumn(0).setMaxWidth(50);
        historyTable.getColumnModel().getColumn(1).setPreferredWidth(150);  // 时间列
        historyTable.getColumnModel().getColumn(2).setPreferredWidth(200);  // API列
        historyTable.getColumnModel().getColumn(3).setPreferredWidth(60);   // 方法列
        historyTable.getColumnModel().getColumn(4).setPreferredWidth(60);   // 协议列
        historyTable.getColumnModel().getColumn(5).setPreferredWidth(100);  // 域名列
        historyTable.getColumnModel().getColumn(6).setPreferredWidth(120);  // 路径列
        historyTable.getColumnModel().getColumn(7).setPreferredWidth(100);  // 查询参数列
        historyTable.getColumnModel().getColumn(8).setPreferredWidth(70);   // 状态码列
        historyTable.getColumnModel().getColumn(9).setPreferredWidth(90);   // 响应长度列
        historyTable.getColumnModel().getColumn(10).setPreferredWidth(70);  // 耗时列
        historyTable.getColumnModel().getColumn(11).setPreferredWidth(80);  // 用户列
        historyTable.getColumnModel().getColumn(12).setPreferredWidth(60);  // 判决列
        historyTable.getColumnModel().getColumn(13).setPreferredWidth(70);  // 越权测试列
        historyTable.getColumnModel().getColumn(14).setPreferredWidth(100); // 备注列
    }

    /**
     * 添加历史记录
     */
    public void addHistoryRecord(RequestResponseRecord record) {
        if (record == null) {
            return;
        }

        // 添加到记录列表
        historyRecords.add(record);

        // 添加到表格（对null字段提供默认值，避免表格显示空白）
        String apiValue = record.getApi();
        if (apiValue == null || apiValue.isEmpty()) {
            apiValue = record.getPath() != null ? record.getPath() : "/";
        }
        Object[] rowData = new Object[] {
            historyRecords.size(),                    // 序号
            new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(record.getTimestamp()),  // 时间
            apiValue,                                 // API
            record.getMethod() != null ? record.getMethod() : "",                       // 方法
            record.getProtocol() != null ? record.getProtocol() : "",                   // 协议
            record.getDomain() != null ? record.getDomain() : "",                       // 域名
            record.getPath() != null ? record.getPath() : "/",                          // 路径
            record.getQueryParameters() != null ? record.getQueryParameters() : "",     // 查询参数
            record.getStatusCode(),                   // 状态码
            record.getResponseLength(),               // 响应长度
            record.getResponseTime(),                 // 响应时间
            record.getUserSessionName() != null ? record.getUserSessionName() : "",  // 用户
            record.getJudgment() != null ? JudgmentResult.toDisplayName(record.getJudgment()) : "",                // 判决
            record.getUserSessionName() != null ? I18nManager.tr("history.panel.yes") : I18nManager.tr("history.panel.no"),  // 越权测试
            record.getComment()                       // 备注
        };

        historyTableModel.addRow(rowData);

        // 更新UI
        historyTableModel.fireTableDataChanged();
        historyTable.revalidate();
        historyTable.repaint();

        // 刷新状态栏统计
        if (statsBar != null) {
            statsBar.refreshStats();
        }
    }

    /**
     * 添加历史记录（从 Montoya HttpRequestResponse）
     */
    public void addHistoryRecord(int requestId, burp.api.montoya.http.message.HttpRequestResponse requestResponse) {
        try {
            burp.api.montoya.http.message.requests.HttpRequest httpRequest = requestResponse.request();
            burp.api.montoya.http.message.responses.HttpResponse httpResponse = requestResponse.response();

            byte[] requestData = httpRequest.toByteArray().getBytes();
            byte[] responseData = httpResponse.toByteArray().getBytes();
            int statusCode = httpResponse.statusCode();

            // 从请求URL解析信息
            java.net.URL url = new java.net.URL(httpRequest.url());

            // 创建记录对象
            RequestResponseRecord record = new RequestResponseRecord();
            record.setRequestId(requestId);
            record.setMethod(httpRequest.method());
            record.setProtocol(url.getProtocol());
            record.setDomain(url.getHost());
            record.setPath(url.getPath());
            record.setQueryParameters(url.getQuery() != null ? url.getQuery() : "");
            record.setStatusCode(statusCode);
            record.setResponseLength(responseData.length);
            record.setResponseTime(0);
            record.setTimestamp(new java.util.Date());
            record.setRequestData(requestData);
            record.setResponseData(responseData);

            // 保存到数据库
            HistoryWriteDAO historyWriteDAO = new HistoryWriteDAO();
            int historyId = historyWriteDAO.saveHistory(record);
            record.setId(historyId);

            if (historyId > 0) {
                // 添加到UI
                addHistoryRecord(record);
                LogManager.getInstance().printOutput(I18nManager.tr("log.history.saved", historyId));
            } else {
                LogManager.getInstance().printError(I18nManager.tr("log.history.save.failed"));
            }
        } catch (Exception e) {
            LogManager.getInstance().printError(I18nManager.tr("log.history.add.failed", e.getMessage()));
        }
    }

    /**
     * 加载选中的历史记录项
     */
    void loadSelectedHistoryItem() {
        int selectedRow = historyTable.getSelectedRow();
        if (selectedRow == -1) {
            return;
        }

        int modelRow = historyTable.convertRowIndexToModel(selectedRow);
        if (modelRow >= 0 && modelRow < historyRecords.size()) {
            RequestResponseRecord record = historyRecords.get(modelRow);

            if (onSelectRecord != null) {
                onSelectRecord.accept(record);
            }
        }
    }

    /**
     * 清空所有历史记录（带确认）
     */
    void clearHistoryWithConfirm() {
        if (historyRecords.isEmpty()) {
            return;
        }

        int result = JOptionPane.showConfirmDialog(
            this,
            I18nManager.tr("history.panel.clear.confirm"),
            I18nManager.tr("history.panel.clear.confirm.title"),
            JOptionPane.YES_NO_OPTION
        );

        if (result == JOptionPane.YES_OPTION) {
            clearHistory();
        }
    }

    /**
     * 清空历史记录
     */
    public void clearHistory() {
        historyRecords.clear();
        historyTableModel.setRowCount(0);
        historyTableModel.fireTableDataChanged();
        historyTable.revalidate();
        historyTable.repaint();
        LogManager.getInstance().printOutput(I18nManager.tr("log.history.cleared"));

        // 刷新状态栏统计
        if (statsBar != null) {
            statsBar.refreshStats();
        }
    }

    /**
     * 设置选中记录的回调
     *
     * @param callback 回调函数
     */
    public void setOnSelectRecord(Consumer<RequestResponseRecord> callback) {
        this.onSelectRecord = callback;
    }

    /**
     * 获取历史记录数量
     */
    public int getHistorySize() {
        return historyRecords.size();
    }

    /**
     * 设置边框标题
     */
    public void setBorderTitle(String title) {
        setBorder(BorderFactory.createTitledBorder(title));
    }

    /**
     * 过滤表格
     */
    private void filterTable() {
        String searchText = searchField.getText().toLowerCase().trim();

        if (searchText.isEmpty()) {
            tableRowSorter.setRowFilter(null);
            return;
        }

        try {
            tableRowSorter.setRowFilter(RowFilter.regexFilter("(?i)" + searchText));
        } catch (PatternSyntaxException e) {
            // 如果正则表达式无效，使用包含过滤
            tableRowSorter.setRowFilter(RowFilter.regexFilter("(?i).*" +
                    searchText.replaceAll("[^a-zA-Z0-9]", "") + ".*"));
        }
    }

    /**
     * 显示高级搜索对话框
     */
    void showAdvancedSearchDialog() {
        AdvancedSearchDialog dialog = new AdvancedSearchDialog(this, tableRowSorter);
        dialog.setVisible(true);
    }

    /**
     * 显示列控制对话框
     */
    void showColumnControlDialog() {
        ColumnControlDialog dialog = new ColumnControlDialog(this, historyTable, historyTableModel);
        dialog.setVisible(true);
    }

    /**
     * 获取当前历史记录表中的记录数量
     * @return 历史记录数量
     */
    public int getHistoryCount() {
        return historyTableModel.getRowCount();
    }

    /**
     * 清除所有历史记录
     */
    public void clearAllHistory() {
        // 清空表格数据
        historyTableModel.setRowCount(0);

        // 清空数据映射
        historyRecords.clear();

        LogManager.getInstance().printOutput(I18nManager.tr("log.history.panel.cleared"));
    }

    /**
     * 更新记录序号
     */
    void updateRecordNumbers() {
        for (int i = 0; i < historyTableModel.getRowCount(); i++) {
            historyTableModel.setValueAt(i + 1, i, 0);  // 第一列是序号列
        }
    }

    /**
     * 设置请求调度处理器引用（由 RepeaterManagerUI 在创建 dispatchHandler 后调用）
     */
    public void setDispatchHandler(RequestDispatchHandler dispatchHandler) {
        this.dispatchHandler = dispatchHandler;
    }

    /**
     * 获取请求调度处理器引用
     */
    public RequestDispatchHandler getDispatchHandler() {
        return dispatchHandler;
    }

    /**
     * 设置报文比较面板引用
     */
    public void setComparerPanel(ComparerPanel comparerPanel) {
        this.comparerPanel = comparerPanel;
    }

    /**
     * 获取报文比较面板引用
     */
    public ComparerPanel getComparerPanel() {
        return comparerPanel;
    }

    /**
     * 获取状态栏组件
     */
    public HistoryStatsBar getStatsBar() {
        return statsBar;
    }

    /**
     * 获取所有选中行的历史记录
     * @return 选中的记录列表（可能为空）
     */
    public List<RequestResponseRecord> getSelectedRecords() {
        List<RequestResponseRecord> selected = new ArrayList<>();
        int[] selectedRows = historyTable.getSelectedRows();
        for (int viewRow : selectedRows) {
            int modelRow = historyTable.convertRowIndexToModel(viewRow);
            if (modelRow >= 0 && modelRow < historyRecords.size()) {
                selected.add(historyRecords.get(modelRow));
            }
        }
        return selected;
    }

    /**
     * 删除所有选中的历史记录（UI + 数据库）
     */
    public void deleteSelectedRecords() {
        List<RequestResponseRecord> selected = getSelectedRecords();
        if (selected.isEmpty()) return;

        int result = JOptionPane.showConfirmDialog(
            this,
            I18nManager.tr("history.panel.delete.confirm", selected.size()),
            I18nManager.tr("history.panel.delete.confirm.title"),
            JOptionPane.YES_NO_OPTION
        );

        if (result != JOptionPane.YES_OPTION) return;

        // 从数据库逐条删除
        HistoryUpdateDAO historyUpdateDAO = new HistoryUpdateDAO();
        for (RequestResponseRecord record : selected) {
            if (record.getId() > 0) {
                try {
                    historyUpdateDAO.deleteHistory(record.getId());
                } catch (Exception e) {
                    LogManager.getInstance().printError(I18nManager.tr("log.history.delete.failed", record.getId(), e.getMessage()));
                }
            }
        }

        // 从内存和表格中移除（从后向前删除避免索引偏移）
        int[] selectedRows = historyTable.getSelectedRows();
        List<Integer> modelRows = new ArrayList<>();
        for (int viewRow : selectedRows) {
            modelRows.add(historyTable.convertRowIndexToModel(viewRow));
        }
        // 降序排列，从后向前删除
        modelRows.sort(java.util.Collections.reverseOrder());
        for (int modelRow : modelRows) {
            if (modelRow >= 0 && modelRow < historyRecords.size()) {
                historyRecords.remove(modelRow);
                historyTableModel.removeRow(modelRow);
            }
        }

        updateRecordNumbers();
        LogManager.getInstance().printOutput(I18nManager.tr("log.history.deleted", selected.size()));

        // 刷新状态栏统计
        if (statsBar != null) {
            statsBar.refreshStats();
        }
    }
}
