package oxff.top.ui;

import oxff.top.model.RequestRecord;
import oxff.top.db.RequestDAO;
import burp.BurpExtender;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.PatternSyntaxException;

/**
 * 请求列表面板组件 - 负责显示和管理HTTP请求列表
 */
public class RequestListPanel extends JPanel {
    private static final long serialVersionUID = 1L;
    
    // 请求列表数据
    private final DefaultTableModel tableModel = new DefaultTableModel(
        new Object[]{"ID", "Protocol", "Domain", "Path", "Query", "Method", "Date"}, 0
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
    private final JTextField searchField = new JTextField();
    private int nextRequestId = 1;
    
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
        JPanel searchPanel = new JPanel(new BorderLayout());
        searchPanel.add(new JLabel("搜索: "), BorderLayout.WEST);
        searchPanel.add(searchField, BorderLayout.CENTER);
        add(searchPanel, BorderLayout.NORTH);
        
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
    }
    
    /**
     * 设置搜索功能
     */
    private void setupSearch() {
        tableRowSorter = new TableRowSorter<>(tableModel);
        requestTable.setRowSorter(tableRowSorter);
        
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                search();
            }
            
            @Override
            public void removeUpdate(DocumentEvent e) {
                search();
            }
            
            @Override
            public void changedUpdate(DocumentEvent e) {
                search();
            }
            
            private void search() {
                String text = searchField.getText();
                if (text.trim().length() == 0) {
                    tableRowSorter.setRowFilter(null);
                } else {
                    try {
                        tableRowSorter.setRowFilter(RowFilter.regexFilter("(?i)" + text));
                    } catch (PatternSyntaxException e) {
                        // 忽略无效的正则表达式
                    }
                }
            }
        });
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
     * 更新请求
     */
    public void updateRequest(int requestId, String protocol, String domain, String path, String query, String method) {
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            int rowId = (int) tableModel.getValueAt(i, 0);
            if (rowId == requestId) {
                tableModel.setValueAt(protocol, i, 1);
                tableModel.setValueAt(domain, i, 2);
                tableModel.setValueAt(path, i, 3);
                tableModel.setValueAt(query, i, 4);
                tableModel.setValueAt(method, i, 5);
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
     * 添加请求
     */
    public void addRequest(int id, String protocol, String domain, String path, String query, String method, byte[] requestData) {
        // 添加到表格模型
        tableModel.addRow(new Object[]{
            id,
            protocol,
            domain,
            path,
            query,
            method,
            new Date()
        });
        
        // 保存请求数据到内存映射
        if (requestData != null) {
            requestDataMap.put(id, requestData);
            BurpExtender.printOutput("[+] 请求数据已保存到内存映射，ID: " + id + "，数据大小: " + requestData.length + " 字节");
        }
        
        // 保存到数据库
        try {
            RequestDAO requestDAO = new RequestDAO();
            int savedId = requestDAO.saveRequest(protocol, domain, path, query, method, requestData);
            
            if (savedId > 0) {
                BurpExtender.printOutput("[+] 请求已保存到数据库，ID: " + savedId);
            } else {
                BurpExtender.printError("[!] 保存请求到数据库失败");
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 保存请求到数据库失败: " + e.getMessage());
        }
        
        // 更新颜色和注释映射
        requestColors.put(id, null);
        requestComments.put(id, "");
    }
    
    /**
     * 添加请求记录
     */
    public void addRequestRecord(RequestRecord record) {
        tableModel.addRow(new Object[]{
            record.getId(),
            record.getProtocol(),
            record.getDomain(),
            record.getPath(),
            record.getQuery(),
            record.getMethod(),
            new Date()
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
} 