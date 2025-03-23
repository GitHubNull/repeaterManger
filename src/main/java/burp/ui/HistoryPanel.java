package burp.ui;

import burp.BurpExtender;
import burp.http.RequestResponseRecord;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
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
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.awt.Frame;
import java.awt.Insets;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.util.HashSet;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Set;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import javax.swing.BoxLayout;

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
    
    /**
     * 创建历史记录面板
     */
    public HistoryPanel() {
        super(new BorderLayout());
        
        // 初始化记录列表
        historyRecords = new ArrayList<>();
        
        // 创建搜索面板
        JPanel searchPanel = new JPanel(new BorderLayout());
        JLabel searchLabel = new JLabel("搜索: ");
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
        
        JButton clearSearchButton = new JButton("清除");
        clearSearchButton.addActionListener(e -> {
            searchField.setText("");
            filterTable();
        });
        
        JButton clearHistoryButton = new JButton("清空历史");
        clearHistoryButton.addActionListener(e -> clearHistoryWithConfirm());
        
        JButton advancedSearchButton = new JButton("高级搜索");
        advancedSearchButton.addActionListener(e -> showAdvancedSearchDialog());
        
        JButton columnControlButton = new JButton("显示/隐藏列");
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
        JScrollPane scrollPane = new JScrollPane(historyTable);
        scrollPane.setBorder(BorderFactory.createTitledBorder("重放历史"));
        
        // 添加到面板
        add(searchPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
        
        // 创建右键菜单
        JPopupMenu popupMenu = createPopupMenu();
        historyTable.setComponentPopupMenu(popupMenu);
    }
    
    /**
     * 创建表格
     */
    private void createTable() {
        // 定义表格列名
        String[] columnNames = {
            "#", "时间", "方法", "协议", "域名", "路径", "查询参数", "状态码", "响应长度", "耗时(ms)", "备注"
        };
        
        // 创建表格模型(不允许直接编辑)
        historyTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
            
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0 || columnIndex == 7 || columnIndex == 8 || columnIndex == 9) {
                    return Integer.class;
                }
                return String.class;
            }
        };
        
        // 创建表格
        historyTable = new JTable(historyTableModel);
        historyTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        historyTable.setAutoCreateRowSorter(true);
        
        // 设置列宽度
        historyTable.getColumnModel().getColumn(0).setPreferredWidth(40);   // 序号列
        historyTable.getColumnModel().getColumn(0).setMaxWidth(50);         // 限制最大宽度
        historyTable.getColumnModel().getColumn(1).setPreferredWidth(150);  // 时间列
        historyTable.getColumnModel().getColumn(1).setMaxWidth(180);        // 限制最大宽度
        historyTable.getColumnModel().getColumn(2).setPreferredWidth(60);   // 方法列
        historyTable.getColumnModel().getColumn(2).setMaxWidth(80);         // 限制最大宽度
        historyTable.getColumnModel().getColumn(3).setPreferredWidth(60);   // 协议列
        historyTable.getColumnModel().getColumn(3).setMaxWidth(80);         // 限制最大宽度
        historyTable.getColumnModel().getColumn(4).setPreferredWidth(150);  // 域名列
        historyTable.getColumnModel().getColumn(5).setPreferredWidth(180);  // 路径列
        historyTable.getColumnModel().getColumn(6).setPreferredWidth(150);  // 查询参数列
        historyTable.getColumnModel().getColumn(7).setPreferredWidth(70);   // 状态码列
        historyTable.getColumnModel().getColumn(7).setMaxWidth(90);         // 限制最大宽度
        historyTable.getColumnModel().getColumn(8).setPreferredWidth(90);   // 响应长度列
        historyTable.getColumnModel().getColumn(8).setMaxWidth(110);        // 限制最大宽度
        historyTable.getColumnModel().getColumn(9).setPreferredWidth(70);   // 耗时列
        historyTable.getColumnModel().getColumn(9).setMaxWidth(90);         // 限制最大宽度
        historyTable.getColumnModel().getColumn(10).setPreferredWidth(150); // 备注列
        
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
        
        // 设置状态码列的颜色渲染器
        historyTable.getColumnModel().getColumn(7).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, 
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(
                        table, value, isSelected, hasFocus, row, column);
                
                // 只有未选中时才改变颜色
                if (!isSelected && value instanceof Integer) {
                    int statusCode = (Integer) value;
                    if (statusCode >= 200 && statusCode < 300) {
                        c.setForeground(new Color(0, 130, 0)); // 绿色: 2xx
                    } else if (statusCode >= 300 && statusCode < 400) {
                        c.setForeground(new Color(0, 95, 170)); // 蓝色: 3xx
                    } else if (statusCode >= 400 && statusCode < 500) {
                        c.setForeground(new Color(213, 94, 0)); // 橙色: 4xx
                    } else if (statusCode >= 500) {
                        c.setForeground(new Color(204, 0, 0)); // 红色: 5xx
                    } else {
                        c.setForeground(Color.BLACK); // 其他
                    }
                } else if (isSelected) {
                    c.setForeground(table.getSelectionForeground());
                } else {
                    c.setForeground(Color.BLACK);
                }
                
                return c;
            }
        });
        
        // 设置表格行背景颜色的渲染器（基于历史记录的颜色标记）
        historyTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                                                          boolean isSelected, boolean hasFocus,
                                                          int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                
                if (!isSelected) {
                    int modelRow = table.convertRowIndexToModel(row);
                    if (modelRow >= 0 && modelRow < historyRecords.size()) {
                        RequestResponseRecord record = historyRecords.get(modelRow);
                        Color rowColor = record.getColor();
                        
                        if (rowColor != null) {
                            // 使用单元格选中背景的40%透明度
                            int alpha = 100; // 约40%透明度
                            Color transparentColor = new Color(
                                rowColor.getRed(), 
                                rowColor.getGreen(), 
                                rowColor.getBlue(), 
                                alpha
                            );
                            c.setBackground(transparentColor);
                        } else {
                            c.setBackground(table.getBackground());
                        }
                    }
                } else {
                    c.setBackground(table.getSelectionBackground());
                    c.setForeground(table.getSelectionForeground());
                }
                
                return c;
            }
        });
    }
    
    /**
     * 创建右键菜单
     */
    private JPopupMenu createPopupMenu() {
        JPopupMenu popupMenu = new JPopupMenu();
        
        JMenuItem loadItem = new JMenuItem("加载所选项");
        loadItem.addActionListener(e -> loadSelectedHistoryItem());
        
        JMenuItem deleteItem = new JMenuItem("删除所选项");
        deleteItem.addActionListener(e -> deleteSelectedHistoryItem());
        
        // 添加控制列显示的菜单项
        JMenuItem columnControlItem = new JMenuItem("显示/隐藏列");
        columnControlItem.addActionListener(e -> showColumnControlDialog());
        
        // 添加设置颜色菜单项
        JMenu colorMenu = new JMenu("标记颜色");
        
        // 常用颜色选项
        addColorMenuItem(colorMenu, "红色", new Color(255, 160, 160));
        addColorMenuItem(colorMenu, "橙色", new Color(255, 200, 120));
        addColorMenuItem(colorMenu, "黄色", new Color(255, 255, 150));
        addColorMenuItem(colorMenu, "绿色", new Color(150, 255, 150));
        addColorMenuItem(colorMenu, "蓝色", new Color(150, 200, 255));
        addColorMenuItem(colorMenu, "紫色", new Color(210, 150, 255));
        colorMenu.addSeparator();
        addColorMenuItem(colorMenu, "自定义颜色...", null);
        colorMenu.addSeparator();
        addColorMenuItem(colorMenu, "清除颜色标记", null, true);
        
        // 添加设置备注菜单项
        JMenuItem commentItem = new JMenuItem("编辑备注");
        commentItem.addActionListener(e -> editComment());
        
        JMenuItem clearItem = new JMenuItem("清空所有历史");
        clearItem.addActionListener(e -> clearHistoryWithConfirm());
        
        popupMenu.add(loadItem);
        popupMenu.add(deleteItem);
        popupMenu.addSeparator();
        popupMenu.add(columnControlItem);
        popupMenu.addSeparator();
        popupMenu.add(colorMenu);
        popupMenu.add(commentItem);
        popupMenu.addSeparator();
        popupMenu.add(clearItem);
        
        return popupMenu;
    }
    
    /**
     * 添加颜色菜单项
     */
    private void addColorMenuItem(JMenu parentMenu, String name, Color color) {
        addColorMenuItem(parentMenu, name, color, false);
    }
    
    /**
     * 添加颜色菜单项
     */
    private void addColorMenuItem(JMenu parentMenu, String name, Color color, boolean isClear) {
        JMenuItem item = new JMenuItem(name);
        
        // 为菜单项添加颜色图标
        if (!isClear && color != null) {
            item.setIcon(createColorIcon(color));
        }
        
        item.addActionListener(e -> {
            int selectedRow = historyTable.getSelectedRow();
            if (selectedRow == -1) {
                return;
            }
            
            int modelRow = historyTable.convertRowIndexToModel(selectedRow);
            if (modelRow >= 0 && modelRow < historyRecords.size()) {
                RequestResponseRecord record = historyRecords.get(modelRow);
                
                if (isClear) {
                    // 清除颜色标记
                    record.setColor(null);
                } else if (color == null) {
                    // 打开颜色选择器
                    Color selectedColor = JColorChooser.showDialog(
                        this, "选择标记颜色", Color.YELLOW);
                    if (selectedColor != null) {
                        record.setColor(selectedColor);
                    }
                } else {
                    record.setColor(color);
                }
                
                // 刷新表格显示
                historyTable.repaint();
            }
        });
        
        parentMenu.add(item);
    }
    
    /**
     * 创建颜色图标
     */
    private Icon createColorIcon(Color color) {
        return new Icon() {
            @Override
            public void paintIcon(Component c, Graphics g, int x, int y) {
                Graphics2D g2d = (Graphics2D) g.create();
                g2d.setColor(color);
                g2d.fillRect(x, y, getIconWidth(), getIconHeight());
                g2d.setColor(Color.GRAY);
                g2d.drawRect(x, y, getIconWidth() - 1, getIconHeight() - 1);
                g2d.dispose();
            }

            @Override
            public int getIconWidth() {
                return 16;
            }

            @Override
            public int getIconHeight() {
                return 16;
            }
        };
    }
    
    /**
     * 编辑备注对话框
     */
    private void editComment() {
        int selectedRow = historyTable.getSelectedRow();
        if (selectedRow == -1) {
            return;
        }
        
        int modelRow = historyTable.convertRowIndexToModel(selectedRow);
        if (modelRow >= 0 && modelRow < historyRecords.size()) {
            RequestResponseRecord record = historyRecords.get(modelRow);
            
            // 获取当前备注
            String currentComment = record.getComment();
            
            // 显示编辑对话框
            String newComment = (String) JOptionPane.showInputDialog(
                this,
                "请输入记录备注:",
                "编辑备注",
                JOptionPane.PLAIN_MESSAGE,
                null,
                null,
                currentComment
            );
            
            // 更新备注
            if (newComment != null) {
                record.setComment(newComment.trim());
                
                // 更新表格显示
                int commentColumn = 10; // 备注列索引
                historyTableModel.setValueAt(record.getTruncatedComment(16), modelRow, commentColumn);
            }
        }
    }
    
    /**
     * 添加历史记录
     * 
     * @param record 历史记录项
     */
    public void addHistoryRecord(RequestResponseRecord record) {
        if (record == null) {
            return;
        }
        
        historyRecords.add(0, record); // 添加到列表开头，使最新记录显示在最前面
        
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String timestamp = sdf.format(record.getTimestamp());
        
        // 添加到表格模型的第一行
        historyTableModel.insertRow(0, new Object[]{
            historyRecords.size(),          // 序号
            timestamp,                      // 时间戳
            record.getMethod(),             // 方法
            record.getProtocol(),           // 协议
            record.getDomain(),             // 域名
            record.getPath(),                // 路径
            record.getQueryParameters(),    // 查询参数
            record.getStatusCode(),         // 状态码
            record.getResponseLength(),     // 响应长度
            record.getResponseTime(),       // 响应时间
            record.getTruncatedComment(16)  // 备注
        });
        
        // 更新所有记录的序号
        updateRecordNumbers();
        
        // 自动选择第一行（最新的记录）
        if (historyTable.getRowCount() > 0) {
            historyTable.setRowSelectionInterval(0, 0);
        }
        
        BurpExtender.printOutput("[+] 添加历史记录: " + record.toString());
    }
    
    /**
     * 更新记录序号
     */
    private void updateRecordNumbers() {
        for (int i = 0; i < historyTableModel.getRowCount(); i++) {
            historyTableModel.setValueAt(i + 1, i, 0);
        }
    }
    
    /**
     * 加载选中的历史记录项
     */
    private void loadSelectedHistoryItem() {
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
     * 删除选中的历史记录项
     */
    private void deleteSelectedHistoryItem() {
        int selectedRow = historyTable.getSelectedRow();
        if (selectedRow == -1) {
            return;
        }
        
        int modelRow = historyTable.convertRowIndexToModel(selectedRow);
        
        // 确认删除
        int result = JOptionPane.showConfirmDialog(
            this,
            "确认删除选中的历史记录?",
            "删除确认",
            JOptionPane.YES_NO_OPTION
        );
        
        if (result == JOptionPane.YES_OPTION) {
            // 删除记录
            historyRecords.remove(modelRow);
            historyTableModel.removeRow(modelRow);
            
            // 更新序号
            updateRecordNumbers();
        }
    }
    
    /**
     * 清空所有历史记录（带确认）
     */
    private void clearHistoryWithConfirm() {
        if (historyRecords.isEmpty()) {
            return;
        }
        
        int result = JOptionPane.showConfirmDialog(
            this,
            "确认清空所有历史记录?",
            "清空确认",
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
        BurpExtender.printOutput("[*] 历史记录已清空");
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
    private void showAdvancedSearchDialog() {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "高级搜索", true);
        dialog.setLayout(new BorderLayout());
        
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(5, 5, 5, 5);
        
        // 添加方法过滤器
        c.gridx = 0;
        c.gridy = 0;
        formPanel.add(new JLabel("方法:"), c);
        
        c.gridx = 1;
        c.weightx = 1.0;
        String[] methods = {"所有方法", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"};
        JComboBox<String> methodCombo = new JComboBox<>(methods);
        formPanel.add(methodCombo, c);
        
        // 协议过滤器
        c.gridx = 0;
        c.gridy = 1;
        c.weightx = 0;
        formPanel.add(new JLabel("协议:"), c);
        
        c.gridx = 1;
        JComboBox<String> protocolCombo = new JComboBox<>(new String[] {
            "所有协议", "http", "https"
        });
        formPanel.add(protocolCombo, c);
        
        // 域名过滤器
        c.gridx = 0;
        c.gridy = 2;
        formPanel.add(new JLabel("域名包含:"), c);
        
        c.gridx = 1;
        JTextField hostField = new JTextField(20);
        formPanel.add(hostField, c);
        
        // 路径过滤器
        c.gridx = 0;
        c.gridy = 3;
        formPanel.add(new JLabel("路径包含:"), c);
        
        c.gridx = 1;
        JTextField pathField = new JTextField(20);
        formPanel.add(pathField, c);
        
        // 查询参数过滤器
        c.gridx = 0;
        c.gridy = 4;
        formPanel.add(new JLabel("参数包含:"), c);
        
        c.gridx = 1;
        JTextField queryField = new JTextField(20);
        formPanel.add(queryField, c);
        
        // 状态码过滤器
        c.gridx = 0;
        c.gridy = 5;
        formPanel.add(new JLabel("状态码:"), c);
        
        c.gridx = 1;
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JTextField minStatusField = new JTextField(4);
        JTextField maxStatusField = new JTextField(4);
        statusPanel.add(new JLabel("从:"));
        statusPanel.add(minStatusField);
        statusPanel.add(new JLabel("到:"));
        statusPanel.add(maxStatusField);
        formPanel.add(statusPanel, c);
        
        // 响应长度过滤器
        c.gridx = 0;
        c.gridy = 6;
        formPanel.add(new JLabel("响应长度:"), c);
        
        c.gridx = 1;
        JPanel lengthPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JTextField minLengthField = new JTextField(6);
        JTextField maxLengthField = new JTextField(6);
        lengthPanel.add(new JLabel("从:"));
        lengthPanel.add(minLengthField);
        lengthPanel.add(new JLabel("到:"));
        lengthPanel.add(maxLengthField);
        formPanel.add(lengthPanel, c);
        
        // 备注过滤器
        c.gridx = 0;
        c.gridy = 7;
        formPanel.add(new JLabel("备注包含:"), c);
        
        c.gridx = 1;
        JTextField commentField = new JTextField(20);
        formPanel.add(commentField, c);
        
        // 按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton searchButton = new JButton("搜索");
        JButton cancelButton = new JButton("取消");
        
        buttonPanel.add(searchButton);
        buttonPanel.add(cancelButton);
        
        // 添加到对话框
        dialog.add(formPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        // 设置按钮动作
        searchButton.addActionListener(e -> {
            // 构建高级过滤器
            applyAdvancedFilter(
                (String) methodCombo.getSelectedItem(),
                (String) protocolCombo.getSelectedItem(),
                hostField.getText(),
                pathField.getText(),
                queryField.getText(),
                minStatusField.getText(),
                maxStatusField.getText(),
                minLengthField.getText(),
                maxLengthField.getText(),
                commentField.getText()
            );
            dialog.dispose();
        });
        
        cancelButton.addActionListener(e -> dialog.dispose());
        
        // 显示对话框
        dialog.pack();
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }
    
    /**
     * 应用高级过滤器
     */
    private void applyAdvancedFilter(String method, String protocol, String host, String path, String query,
                                   String minStatus, String maxStatus, String minLength, String maxLength, String comment) {
        // 创建过滤器列表
        List<RowFilter<DefaultTableModel, Object>> filters = new ArrayList<>();
        
        // 方法过滤
        if (method != null && !"所有方法".equals(method)) {
            filters.add(RowFilter.regexFilter("^" + method + "$", 2));
        }
        
        // 协议过滤
        if (protocol != null && !"所有协议".equals(protocol)) {
            filters.add(RowFilter.regexFilter("^" + protocol + "$", 3));
        }
        
        // 域名过滤
        if (host != null && !host.isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(host), 4));
        }
        
        // 路径过滤
        if (path != null && !path.isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(path), 5));
        }
        
        // 查询参数过滤
        if (query != null && !query.isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(query), 6));
        }
        
        // 状态码过滤
        if (!minStatus.isEmpty() || !maxStatus.isEmpty()) {
            try {
                final int min = minStatus.isEmpty() ? 0 : Integer.parseInt(minStatus);
                final int max = maxStatus.isEmpty() ? Integer.MAX_VALUE : Integer.parseInt(maxStatus);
                
                filters.add(new RowFilter<DefaultTableModel, Object>() {
                    @Override
                    public boolean include(Entry<? extends DefaultTableModel, ? extends Object> entry) {
                        // 获取状态码（第7列）
                        Object statusObj = entry.getValue(7);
                        if (!(statusObj instanceof Integer)) {
                            return true;
                        }
                        
                        int status = (Integer) statusObj;
                        return status >= min && status <= max;
                    }
                });
            } catch (NumberFormatException e) {
                JOptionPane.showMessageDialog(this, "状态码必须是数字", "输入错误", JOptionPane.ERROR_MESSAGE);
            }
        }
        
        // 响应长度过滤
        if (!minLength.isEmpty() || !maxLength.isEmpty()) {
            try {
                final int min = minLength.isEmpty() ? 0 : Integer.parseInt(minLength);
                final int max = maxLength.isEmpty() ? Integer.MAX_VALUE : Integer.parseInt(maxLength);
                
                filters.add(new RowFilter<DefaultTableModel, Object>() {
                    @Override
                    public boolean include(Entry<? extends DefaultTableModel, ? extends Object> entry) {
                        // 获取响应长度（第8列）
                        Object lengthObj = entry.getValue(8);
                        if (!(lengthObj instanceof Integer)) {
                            return true;
                        }
                        
                        int length = (Integer) lengthObj;
                        return length >= min && length <= max;
                    }
                });
            } catch (NumberFormatException e) {
                JOptionPane.showMessageDialog(this, "响应长度必须是数字", "输入错误", JOptionPane.ERROR_MESSAGE);
            }
        }
        
        // 备注过滤
        if (comment != null && !comment.isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + comment, 10)); // 备注在第10列
        }
        
        // 应用过滤器
        if (filters.isEmpty()) {
            tableRowSorter.setRowFilter(null);
        } else if (filters.size() == 1) {
            tableRowSorter.setRowFilter(filters.get(0));
        } else {
            tableRowSorter.setRowFilter(RowFilter.andFilter(filters));
        }
    }
    
    /**
     * 显示列控制对话框，用于选择要显示的列
     */
    private void showColumnControlDialog() {
        // 创建对话框
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "列显示控制", true);
        dialog.setLayout(new BorderLayout());
        
        // 创建面板
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 获取所有列
        TableColumnModel columnModel = historyTable.getColumnModel();
        int columnCount = columnModel.getColumnCount();
        
        // 创建复选框数组
        JCheckBox[] checkBoxes = new JCheckBox[columnCount];
        boolean[] initialVisibility = new boolean[columnCount];
        
        // 必须显示的列索引（序号、方法、协议、域名、路径）
        Set<Integer> mandatoryColumns = new HashSet<>(Arrays.asList(0, 2, 3, 4, 5));
        
        for (int i = 0; i < columnCount; i++) {
            TableColumn column = columnModel.getColumn(i);
            String columnName = historyTableModel.getColumnName(column.getModelIndex());
            
            // 检查该列是否可见
            boolean isVisible = true;
            Enumeration<TableColumn> columns = columnModel.getColumns();
            boolean found = false;
            while (columns.hasMoreElements()) {
                if (columns.nextElement() == column) {
                    found = true;
                    break;
                }
            }
            isVisible = found;
            initialVisibility[i] = isVisible;
            
            // 创建复选框
            checkBoxes[i] = new JCheckBox(columnName, isVisible);
            
            // 如果是必须显示的列，则禁用复选框
            if (mandatoryColumns.contains(i)) {
                checkBoxes[i].setEnabled(false);
                checkBoxes[i].setSelected(true);
            }
            
            panel.add(checkBoxes[i]);
        }
        
        // 添加按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton okButton = new JButton("确定");
        JButton cancelButton = new JButton("取消");
        JButton resetButton = new JButton("重置为默认");
        
        buttonPanel.add(resetButton);
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        
        // 设置按钮事件
        okButton.addActionListener(e -> {
            // 应用选择
            for (int i = 0; i < columnCount; i++) {
                if (!mandatoryColumns.contains(i)) {
                    boolean selected = checkBoxes[i].isSelected();
                    if (selected != initialVisibility[i]) {
                        if (selected) {
                            // 显示列
                            TableColumn column = new TableColumn(i);
                            column.setHeaderValue(historyTableModel.getColumnName(i));
                            columnModel.addColumn(column);
                            // 恢复列宽
                            restoreColumnWidth(column, i);
                        } else {
                            // 隐藏列
                            TableColumn column = columnModel.getColumn(i);
                            columnModel.removeColumn(column);
                        }
                    }
                }
            }
            dialog.dispose();
        });
        
        cancelButton.addActionListener(e -> dialog.dispose());
        
        resetButton.addActionListener(e -> {
            // 全部选中
            for (int i = 0; i < columnCount; i++) {
                checkBoxes[i].setSelected(true);
                if (!mandatoryColumns.contains(i)) {
                    checkBoxes[i].setEnabled(true);
                }
            }
        });
        
        // 添加到对话框
        JScrollPane scrollPane = new JScrollPane(panel);
        dialog.add(scrollPane, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        // 显示对话框
        dialog.setSize(300, 400);
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }
    
    /**
     * 恢复列的宽度设置
     */
    private void restoreColumnWidth(TableColumn column, int columnIndex) {
        switch (columnIndex) {
            case 0: // 序号列
                column.setPreferredWidth(40);   
                column.setMaxWidth(50);         
                break;
            case 1: // 时间列
                column.setPreferredWidth(150);  
                column.setMaxWidth(180);        
                break;
            case 2: // 方法列
                column.setPreferredWidth(60);   
                column.setMaxWidth(80);         
                break;
            case 3: // 协议列
                column.setPreferredWidth(60);   
                column.setMaxWidth(80);         
                break;
            case 4: // 域名列
                column.setPreferredWidth(150);  
                break;
            case 5: // 路径列
                column.setPreferredWidth(180);  
                break;
            case 6: // 查询参数列
                column.setPreferredWidth(150);  
                break;
            case 7: // 状态码列
                column.setPreferredWidth(70);   
                column.setMaxWidth(90);         
                break;
            case 8: // 响应长度列
                column.setPreferredWidth(90);   
                column.setMaxWidth(110);        
                break;
            case 9: // 耗时列
                column.setPreferredWidth(70);   
                column.setMaxWidth(90);         
                break;
            case 10: // 备注列
                column.setPreferredWidth(150); 
                break;
        }
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
        
        BurpExtender.printOutput("[*] 已清除所有历史记录数据");
    }
} 