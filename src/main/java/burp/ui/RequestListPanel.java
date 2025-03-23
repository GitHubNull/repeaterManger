package burp.ui;

import burp.BurpExtender;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.regex.PatternSyntaxException;
import java.util.regex.Pattern;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Calendar;
import java.util.HashSet;
import java.util.Arrays;
import java.util.Enumeration;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import java.util.Set;

/**
 * 请求列表面板 - 显示左侧所有的HTTP请求
 */
public class RequestListPanel extends JPanel {
    private static final long serialVersionUID = 1L;
    
    private JTable requestTable;
    private DefaultTableModel requestTableModel;
    private final Map<Integer, byte[]> requestDataMap;
    private TableRowSorter<DefaultTableModel> tableRowSorter;
    private final JTextField searchField;
    private BiConsumer<Integer, byte[]> requestSelectedCallback;
    private int nextRequestId = 1;
    
    // 请求记录的颜色和备注信息
    private final Map<Integer, Color> requestColors = new HashMap<>();
    private final Map<Integer, String> requestComments = new HashMap<>();
    
    /**
     * 创建请求列表面板
     */
    public RequestListPanel() {
        super(new BorderLayout());
        
        // 初始化数据存储
        requestDataMap = new HashMap<>();
        
        // 创建搜索面板
        JPanel searchPanel = new JPanel(new BorderLayout());
        JLabel searchLabel = new JLabel("搜索请求: ");
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
        
        JButton clearSearchButton = new JButton("清除");
        clearSearchButton.addActionListener(e -> {
            searchField.setText("");
            filterTable();
        });
        
        JButton advancedSearchButton = new JButton("高级搜索");
        advancedSearchButton.addActionListener(e -> showAdvancedSearchDialog());
        
        JButton columnControlButton = new JButton("显示/隐藏列");
        columnControlButton.addActionListener(e -> showColumnControlDialog());
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonPanel.add(searchLabel);
        buttonPanel.add(searchField);
        buttonPanel.add(clearSearchButton);
        buttonPanel.add(advancedSearchButton);
        buttonPanel.add(columnControlButton);
        
        searchPanel.add(buttonPanel, BorderLayout.CENTER);
        
        // 创建请求列表表格
        createRequestTable();
        
        // 创建滚动面板
        JScrollPane scrollPane = new JScrollPane(requestTable);
        scrollPane.setBorder(BorderFactory.createTitledBorder("请求列表"));
        
        // 创建右键菜单
        JPopupMenu popupMenu = createPopupMenu();
        requestTable.setComponentPopupMenu(popupMenu);
        
        // 添加到面板
        add(searchPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
    }
    
    /**
     * 创建请求表格
     */
    private void createRequestTable() {
        // 定义表格列名
        String[] columnNames = {
            "#", "协议", "域名", "路径", "查询参数", "方法", "添加时间", "备注"
        };
        
        // 创建表格模型(不允许直接编辑)
        requestTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
            
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0) {
                    return Integer.class;
                }
                return String.class;
            }
        };
        
        // 创建表格
        requestTable = new JTable(requestTableModel);
        requestTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        requestTable.setAutoCreateRowSorter(true);
        
        // 设置列宽度
        requestTable.getColumnModel().getColumn(0).setPreferredWidth(40);   // ID列
        requestTable.getColumnModel().getColumn(0).setMaxWidth(50);         // 限制最大宽度
        requestTable.getColumnModel().getColumn(1).setPreferredWidth(60);   // 协议列
        requestTable.getColumnModel().getColumn(1).setMaxWidth(70);         // 限制最大宽度
        requestTable.getColumnModel().getColumn(2).setPreferredWidth(140);  // 域名列
        requestTable.getColumnModel().getColumn(3).setPreferredWidth(180);  // 路径列
        requestTable.getColumnModel().getColumn(4).setPreferredWidth(180);  // 查询参数列
        requestTable.getColumnModel().getColumn(5).setPreferredWidth(60);   // 方法列
        requestTable.getColumnModel().getColumn(5).setMaxWidth(80);         // 限制最大宽度
        requestTable.getColumnModel().getColumn(6).setPreferredWidth(150);  // 时间列
        requestTable.getColumnModel().getColumn(6).setMaxWidth(180);        // 限制最大宽度
        requestTable.getColumnModel().getColumn(7).setPreferredWidth(150);  // 备注列
        
        // 创建排序器
        tableRowSorter = new TableRowSorter<>(requestTableModel);
        requestTable.setRowSorter(tableRowSorter);
        
        // 添加双击事件
        requestTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    loadSelectedRequest();
                }
            }
        });
        
        // 设置方法列的颜色渲染器
        requestTable.getColumnModel().getColumn(5).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, 
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(
                        table, value, isSelected, hasFocus, row, column);
                
                // 只有未选中时才改变颜色
                if (!isSelected && value instanceof String) {
                    String method = (String) value;
                    if ("GET".equalsIgnoreCase(method)) {
                        c.setForeground(new Color(0, 130, 0)); // 绿色: GET
                    } else if ("POST".equalsIgnoreCase(method)) {
                        c.setForeground(new Color(0, 95, 170)); // 蓝色: POST
                    } else if ("PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method)) {
                        c.setForeground(new Color(170, 85, 0)); // 橙色: PUT/PATCH
                    } else if ("DELETE".equalsIgnoreCase(method)) {
                        c.setForeground(new Color(204, 0, 0)); // 红色: DELETE
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
        
        // 设置表格行背景颜色的渲染器
        requestTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                                                          boolean isSelected, boolean hasFocus,
                                                          int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                
                if (!isSelected) {
                    int modelRow = table.convertRowIndexToModel(row);
                    int requestId = (Integer) requestTableModel.getValueAt(modelRow, 0);
                    Color rowColor = requestColors.get(requestId);
                    
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
        
        JMenuItem loadItem = new JMenuItem("加载请求");
        loadItem.addActionListener(e -> loadSelectedRequest());
        
        JMenuItem deleteItem = new JMenuItem("删除请求");
        deleteItem.addActionListener(e -> deleteSelectedRequest());
        
        JMenuItem duplicateItem = new JMenuItem("复制请求");
        duplicateItem.addActionListener(e -> duplicateSelectedRequest());
        
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
        
        // 添加控制列显示的菜单项
        JMenuItem columnControlItem = new JMenuItem("显示/隐藏列");
        columnControlItem.addActionListener(e -> showColumnControlDialog());
        
        JMenuItem clearAllItem = new JMenuItem("清空所有请求");
        clearAllItem.addActionListener(e -> clearAllRequests());
        
        popupMenu.add(loadItem);
        popupMenu.add(duplicateItem);
        popupMenu.add(deleteItem);
        popupMenu.addSeparator();
        popupMenu.add(columnControlItem);
        popupMenu.addSeparator();
        popupMenu.add(colorMenu);
        popupMenu.add(commentItem);
        popupMenu.addSeparator();
        popupMenu.add(clearAllItem);
        
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
            int selectedRow = requestTable.getSelectedRow();
            if (selectedRow == -1) {
                return;
            }
            
            int modelRow = requestTable.convertRowIndexToModel(selectedRow);
            int requestId = (Integer) requestTableModel.getValueAt(modelRow, 0);
            
            if (isClear) {
                // 清除颜色标记
                requestColors.remove(requestId);
            } else if (color == null) {
                // 打开颜色选择器
                Color selectedColor = JColorChooser.showDialog(
                    this, "选择标记颜色", Color.YELLOW);
                if (selectedColor != null) {
                    requestColors.put(requestId, selectedColor);
                }
            } else {
                requestColors.put(requestId, color);
            }
            
            // 刷新表格显示
            requestTable.repaint();
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
        int selectedRow = requestTable.getSelectedRow();
        if (selectedRow == -1) {
            return;
        }
        
        int modelRow = requestTable.convertRowIndexToModel(selectedRow);
        int requestId = (Integer) requestTableModel.getValueAt(modelRow, 0);
        
        // 获取当前备注
        String currentComment = requestComments.getOrDefault(requestId, "");
        
        // 显示编辑对话框
        String newComment = (String) JOptionPane.showInputDialog(
            this,
            "请输入请求备注:",
            "编辑备注",
            JOptionPane.PLAIN_MESSAGE,
            null,
            null,
            currentComment
        );
        
        // 更新备注
        if (newComment != null) {
            if (newComment.trim().isEmpty()) {
                requestComments.remove(requestId);
            } else {
                requestComments.put(requestId, newComment.trim());
            }
            
            // 更新表格显示
            int commentColumn = 7; // 备注列索引
            requestTableModel.setValueAt(getTruncatedComment(newComment), modelRow, commentColumn);
        }
    }
    
    /**
     * 截断备注文本用于表格显示
     */
    private String getTruncatedComment(String comment) {
        if (comment == null || comment.trim().isEmpty()) {
            return "";
        }
        
        comment = comment.trim();
        if (comment.length() <= 16) {
            return comment;
        }
        
        return comment.substring(0, 16) + "...";
    }
    
    /**
     * 解析URL为各个组件
     * 
     * @param url 完整URL
     * @return 包含协议、域名、路径和查询参数的数组
     */
    private String[] parseUrl(String url) {
        String protocol = "";
        String host = "";
        String path = "";
        String query = "";
        
        try {
            // 处理没有协议的URL
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                url = "http://" + url;
            }
            
            java.net.URL parsedUrl = new java.net.URL(url);
            protocol = parsedUrl.getProtocol();
            host = parsedUrl.getHost();
            
            // 路径部分，如果为空则设为"/"
            path = parsedUrl.getPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            }
            
            // 查询参数部分
            query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";
            
        } catch (Exception e) {
            // 如果URL解析失败，尝试简单拆分
            BurpExtender.printError("[!] URL解析错误: " + e.getMessage());
            int protocolEnd = url.indexOf("://");
            if (protocolEnd > 0) {
                protocol = url.substring(0, protocolEnd);
                url = url.substring(protocolEnd + 3);
            } else {
                protocol = "http";
            }
            
            int pathStart = url.indexOf('/');
            if (pathStart > 0) {
                host = url.substring(0, pathStart);
                String remaining = url.substring(pathStart);
                
                int queryStart = remaining.indexOf('?');
                if (queryStart > 0) {
                    path = remaining.substring(0, queryStart);
                    query = remaining.substring(queryStart + 1);
                } else {
                    path = remaining;
                }
            } else {
                host = url;
                path = "/";
            }
        }
        
        return new String[] {protocol, host, path, query};
    }

    /**
     * 添加新请求
     * 
     * @param url 请求URL
     * @param method 请求方法
     * @param requestData 请求数据
     * @return 请求ID
     */
    public int addNewRequest(String url, String method, byte[] requestData) {
        int requestId = nextRequestId++;
        
        // 保存请求数据
        requestDataMap.put(requestId, requestData);
        
        // 获取当前时间
        java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String timestamp = sdf.format(new java.util.Date());
        
        // 解析URL
        String[] urlParts = parseUrl(url);
        
        // 添加到表格模型
        requestTableModel.addRow(new Object[] {
            requestId,      // 请求ID
            urlParts[0],    // 协议
            urlParts[1],    // 域名
            urlParts[2],    // 路径
            urlParts[3],    // 查询参数
            method,         // 方法
            timestamp,      // 时间
            ""              // 备注（初始为空）
        });
        
        // 自动滚动到最新的记录
        int lastRow = requestTable.convertRowIndexToView(requestTableModel.getRowCount() - 1);
        if (lastRow >= 0) {
            requestTable.scrollRectToVisible(requestTable.getCellRect(lastRow, 0, true));
            requestTable.setRowSelectionInterval(lastRow, lastRow);
        }
        
        return requestId;
    }
    
    /**
     * 添加新请求（简化版）
     * 
     * @param title 请求标题
     * @param method 请求方法
     * @return 请求ID
     */
    public int addNewRequest(String title, String method) {
        // 创建一个空的HTTP请求
        return addNewRequest(title, method, new byte[0]);
    }
    
    /**
     * 更新请求
     */
    public void updateRequest(int requestId, String url, String method, byte[] requestData) {
        // 更新请求数据
        requestDataMap.put(requestId, requestData);
        
        // 解析URL
        String[] urlParts = parseUrl(url);
        
        // 查找对应的表格行
        for (int i = 0; i < requestTableModel.getRowCount(); i++) {
            int rowId = (Integer) requestTableModel.getValueAt(i, 0);
            if (rowId == requestId) {
                // 更新URL各部分和方法
                requestTableModel.setValueAt(urlParts[0], i, 1); // 协议
                requestTableModel.setValueAt(urlParts[1], i, 2); // 域名
                requestTableModel.setValueAt(urlParts[2], i, 3); // 路径
                requestTableModel.setValueAt(urlParts[3], i, 4); // 查询参数
                requestTableModel.setValueAt(method, i, 5);      // 方法
                break;
            }
        }
    }
    
    /**
     * 更新请求的备注
     */
    public void updateRequestComment(int requestId, String comment) {
        if (comment == null || comment.trim().isEmpty()) {
            requestComments.remove(requestId);
        } else {
            requestComments.put(requestId, comment.trim());
        }
        
        // 查找对应的表格行
        for (int i = 0; i < requestTableModel.getRowCount(); i++) {
            int rowId = (Integer) requestTableModel.getValueAt(i, 0);
            if (rowId == requestId) {
                // 更新备注列
                requestTableModel.setValueAt(getTruncatedComment(comment), i, 7);
                break;
            }
        }
    }
    
    /**
     * 获取请求的颜色标记
     */
    public Color getRequestColor(int requestId) {
        return requestColors.get(requestId);
    }
    
    /**
     * 获取请求的备注
     */
    public String getRequestComment(int requestId) {
        return requestComments.getOrDefault(requestId, "");
    }
    
    /**
     * 过滤表格内容
     */
    private void filterTable() {
        String searchText = searchField.getText().toLowerCase().trim();
        
        if (tableRowSorter == null) {
            BurpExtender.printError("[!] 表格排序器未初始化");
            return;
        }
        
        if (searchText.isEmpty()) {
            tableRowSorter.setRowFilter(null);
            return;
        }
        
        try {
            RowFilter<DefaultTableModel, Object> rowFilter = RowFilter.regexFilter("(?i)" + searchText);
            tableRowSorter.setRowFilter(rowFilter);
        } catch (PatternSyntaxException e) {
            BurpExtender.printError("[!] 搜索表达式错误: " + e.getMessage());
            // 使用基本过滤器，不使用正则
            tableRowSorter.setRowFilter(RowFilter.regexFilter(searchText, 1, 2));
        }
    }
    
    /**
     * 显示高级搜索对话框
     */
    private void showAdvancedSearchDialog() {
        // 创建对话框
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "高级搜索", true);
        dialog.setLayout(new BorderLayout());
        
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(5, 5, 5, 5);
        
        // 协议选择
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 0;
        formPanel.add(new JLabel("协议:"), c);
        
        c.gridx = 1;
        c.weightx = 1.0;
        JComboBox<String> protocolCombo = new JComboBox<>(new String[] {
            "所有协议", "http", "https"
        });
        formPanel.add(protocolCombo, c);
        
        // 域名字段
        c.gridx = 0;
        c.gridy = 1;
        c.weightx = 0;
        formPanel.add(new JLabel("域名包含:"), c);
        
        c.gridx = 1;
        c.weightx = 1.0;
        JTextField hostField = new JTextField(20);
        formPanel.add(hostField, c);
        
        // 路径字段
        c.gridx = 0;
        c.gridy = 2;
        formPanel.add(new JLabel("路径包含:"), c);
        
        c.gridx = 1;
        JTextField pathField = new JTextField(20);
        formPanel.add(pathField, c);
        
        // 查询参数字段
        c.gridx = 0;
        c.gridy = 3;
        formPanel.add(new JLabel("参数包含:"), c);
        
        c.gridx = 1;
        JTextField queryField = new JTextField(20);
        formPanel.add(queryField, c);
        
        // 方法字段
        c.gridx = 0;
        c.gridy = 4;
        c.weightx = 0;
        formPanel.add(new JLabel("请求方法:"), c);
        
        c.gridx = 1;
        JComboBox<String> methodCombo = new JComboBox<>(new String[] {
            "所有方法", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"
        });
        formPanel.add(methodCombo, c);
        
        // 添加时间范围字段
        c.gridx = 0;
        c.gridy = 5;
        formPanel.add(new JLabel("添加日期:"), c);
        
        c.gridx = 1;
        JPanel datePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JTextField fromDateField = new JTextField(10);
        JTextField toDateField = new JTextField(10);
        datePanel.add(new JLabel("从:"));
        datePanel.add(fromDateField);
        datePanel.add(new JLabel("到:"));
        datePanel.add(toDateField);
        formPanel.add(datePanel, c);
        
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
                (String) protocolCombo.getSelectedItem(),
                hostField.getText(),
                pathField.getText(),
                queryField.getText(),
                (String) methodCombo.getSelectedItem(),
                fromDateField.getText(),
                toDateField.getText()
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
    private void applyAdvancedFilter(String protocol, String host, String path, String query, String method, String fromDate, String toDate) {
        // 实现高级过滤逻辑
        List<RowFilter<DefaultTableModel, Object>> filters = new ArrayList<>();
        
        // 协议过滤
        if (protocol != null && !"所有协议".equals(protocol)) {
            filters.add(RowFilter.regexFilter("^" + protocol, 1));
        }
        
        // 域名过滤
        if (host != null && !host.isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(host), 2));
        }
        
        // 路径过滤
        if (path != null && !path.isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(path), 3));
        }
        
        // 查询参数过滤
        if (query != null && !query.isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(query), 4));
        }
        
        // 方法过滤
        if (method != null && !"所有方法".equals(method)) {
            filters.add(RowFilter.regexFilter("^" + method + "$", 0));
        }
        
        // 日期过滤
        if (!fromDate.isEmpty() || !toDate.isEmpty()) {
            try {
                SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
                
                Date startDate = fromDate.isEmpty() ? new Date(0) : dateFormat.parse(fromDate);
                // 如果结束日期未指定，设置为当前日期
                Date endDate = toDate.isEmpty() ? new Date() : dateFormat.parse(toDate);
                
                // 将结束日期设置为当天的最后一刻
                if (!toDate.isEmpty()) {
                    Calendar cal = Calendar.getInstance();
                    cal.setTime(endDate);
                    cal.set(Calendar.HOUR_OF_DAY, 23);
                    cal.set(Calendar.MINUTE, 59);
                    cal.set(Calendar.SECOND, 59);
                    endDate = cal.getTime();
                }
                
                final Date finalStartDate = startDate;
                final Date finalEndDate = endDate;
                
                filters.add(new RowFilter<DefaultTableModel, Object>() {
                    @Override
                    public boolean include(Entry<? extends DefaultTableModel, ? extends Object> entry) {
                        try {
                            // 日期列在第8列 (index = 7)
                            String dateStr = (String) entry.getValue(7);
                            Date rowDate = dateFormat.parse(dateStr);
                            return !rowDate.before(finalStartDate) && !rowDate.after(finalEndDate);
                        } catch (Exception e) {
                            BurpExtender.printError("日期过滤错误: " + e.getMessage());
                            return true; // 如果解析出错，默认包含该行
                        }
                    }
                });
            } catch (Exception e) {
                BurpExtender.printError("日期格式错误: " + e.getMessage());
            }
        }
        
        // 应用过滤器
        if (!filters.isEmpty()) {
            RowFilter<DefaultTableModel, Object> compositeFilter = RowFilter.andFilter(filters);
            tableRowSorter.setRowFilter(compositeFilter);
        } else {
            tableRowSorter.setRowFilter(null);
        }
    }
    
    /**
     * 加载选中的请求
     */
    private void loadSelectedRequest() {
        int selectedRow = requestTable.getSelectedRow();
        if (selectedRow == -1) {
            return;
        }
        
        // 转换为模型行索引（考虑排序/过滤器）
        int modelRow = requestTable.convertRowIndexToModel(selectedRow);
        
        // 获取选中行的数据
        int requestId = (Integer) requestTableModel.getValueAt(modelRow, 0);
        
        // 获取请求数据
        byte[] requestData = requestDataMap.get(requestId);
        
        // 如果有回调函数，通知选中的请求
        if (requestSelectedCallback != null) {
            requestSelectedCallback.accept(requestId, requestData);
        }
    }
    
    /**
     * 删除选中的请求
     */
    private void deleteSelectedRequest() {
        int selectedRow = requestTable.getSelectedRow();
        if (selectedRow == -1) {
            return;
        }
        
        // 转换为模型行索引（考虑排序/过滤器）
        int modelRow = requestTable.convertRowIndexToModel(selectedRow);
        
        // 获取选中行的数据
        int requestId = (Integer) requestTableModel.getValueAt(modelRow, 0);
        
        // 从数据映射中删除
        requestDataMap.remove(requestId);
        
        // 从表格中删除
        requestTableModel.removeRow(modelRow);
        
        BurpExtender.printOutput("[+] 已删除请求 #" + requestId);
    }
    
    /**
     * 复制选中的请求
     */
    private void duplicateSelectedRequest() {
        int selectedRow = requestTable.getSelectedRow();
        if (selectedRow == -1) {
            return;
        }
        
        // 转换为模型行索引（考虑排序/过滤器）
        int modelRow = requestTable.convertRowIndexToModel(selectedRow);
        
        // 获取选中行的数据
        int requestId = (Integer) requestTableModel.getValueAt(modelRow, 0);
        String url = (String) requestTableModel.getValueAt(modelRow, 1);
        String method = (String) requestTableModel.getValueAt(modelRow, 5);
        
        // 获取请求数据
        byte[] requestData = requestDataMap.get(requestId);
        
        // 复制并添加为新请求
        if (requestData != null) {
            int newId = addNewRequest(url + " (副本)", method, requestData.clone());
            BurpExtender.printOutput("[+] 已复制请求 #" + requestId + " 到 #" + newId);
        }
    }
    
    /**
     * 清除所有请求数据
     */
    public void clearAllRequests() {
        // 清空表格数据
        while (requestTableModel.getRowCount() > 0) {
            requestTableModel.removeRow(0);
        }
        
        // 清空数据映射
        requestDataMap.clear();
        requestComments.clear();
        requestColors.clear();
        
        // 重置请求ID计数器
        nextRequestId = 1;
        
        BurpExtender.printOutput("[*] 已清除所有请求数据");
    }
    
    /**
     * 设置请求选中回调
     */
    public void setRequestSelectedCallback(BiConsumer<Integer, byte[]> callback) {
        this.requestSelectedCallback = callback;
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
        TableColumnModel columnModel = requestTable.getColumnModel();
        int columnCount = columnModel.getColumnCount();
        
        // 创建复选框数组
        JCheckBox[] checkBoxes = new JCheckBox[columnCount];
        boolean[] initialVisibility = new boolean[columnCount];
        
        // 必须显示的列索引
        Set<Integer> mandatoryColumns = new HashSet<>(Arrays.asList(0, 1, 2, 3, 5)); // 序号、协议、域名、路径、方法
        
        for (int i = 0; i < columnCount; i++) {
            TableColumn column = columnModel.getColumn(i);
            String columnName = requestTableModel.getColumnName(column.getModelIndex());
            
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
                            column.setHeaderValue(requestTableModel.getColumnName(i));
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
            case 1: // 协议列
                column.setPreferredWidth(60);
                column.setMaxWidth(70);
                break;
            case 2: // 域名列
                column.setPreferredWidth(140);
                break;
            case 3: // 路径列
                column.setPreferredWidth(180);
                break;
            case 4: // 查询参数列
                column.setPreferredWidth(180);
                break;
            case 5: // 方法列
                column.setPreferredWidth(60);
                column.setMaxWidth(80);
                break;
            case 6: // 时间列
                column.setPreferredWidth(150);
                column.setMaxWidth(180);
                break;
            case 7: // 备注列
                column.setPreferredWidth(150);
                break;
        }
    }
    
    /**
     * 获取历史记录数量
     */
    public int getHistorySize() {
        return requestComments.size();
    }
    
    /**
     * 获取请求颜色映射
     */
    public Map<Integer, Color> getRequestColors() {
        return requestColors;
    }
    
    /**
     * 获取请求备注映射
     */
    public Map<Integer, String> getRequestComments() {
        return requestComments;
    }
    
    /**
     * 获取当前请求表中的请求数量
     * @return 请求数量
     */
    public int getRequestCount() {
        return requestTableModel.getRowCount();
    }
} 