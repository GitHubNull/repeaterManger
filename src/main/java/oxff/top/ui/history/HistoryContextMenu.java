package oxff.top.ui.history;

import burp.BurpExtender;
import oxff.top.RequestDispatchHandler;
import oxff.top.db.RequestDAO;
import oxff.top.db.history.HistoryReadDAO;
import oxff.top.db.history.HistoryUpdateDAO;
import oxff.top.http.RequestResponseRecord;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.List;
import java.util.Map;

/**
 * 历史记录右键菜单工厂 - 创建和管理历史记录表格的右键菜单
 * 支持多选操作
 */
public class HistoryContextMenu {

    private final HistoryPanel historyPanel;
    private final JTable historyTable;
    private final java.util.List<RequestResponseRecord> historyRecords;
    private final DefaultTableModel historyTableModel;

    /**
     * 创建右键菜单工厂
     *
     * @param historyPanel      历史记录面板（用于对话框父组件和回调）
     * @param historyTable      历史记录表格
     * @param historyRecords    历史记录列表
     * @param historyTableModel 表格模型
     */
    public HistoryContextMenu(HistoryPanel historyPanel, JTable historyTable,
                              java.util.List<RequestResponseRecord> historyRecords,
                              DefaultTableModel historyTableModel) {
        this.historyPanel = historyPanel;
        this.historyTable = historyTable;
        this.historyRecords = historyRecords;
        this.historyTableModel = historyTableModel;
    }

    /**
     * 创建右键菜单（每次右键时重新创建，以反映当前选中数量）
     */
    public JPopupMenu createPopupMenu() {
        JPopupMenu popupMenu = new JPopupMenu();

        int selectedCount = historyTable.getSelectedRows().length;

        // 加载所选项
        JMenuItem loadItem = new JMenuItem("加载所选项");
        loadItem.addActionListener(e -> historyPanel.loadSelectedHistoryItem());

        // 删除所选项
        String deleteText = selectedCount > 1
            ? String.format("删除所选项 (%d条)", selectedCount)
            : "删除所选项";
        JMenuItem deleteItem = new JMenuItem(deleteText);
        deleteItem.addActionListener(e -> historyPanel.deleteSelectedRecords());

        // 添加控制列显示的菜单项
        JMenuItem columnControlItem = new JMenuItem("显示/隐藏列");
        columnControlItem.addActionListener(e -> historyPanel.showColumnControlDialog());

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

        // 编辑备注（多选时禁用）
        JMenuItem commentItem = new JMenuItem("编辑备注");
        commentItem.setEnabled(selectedCount <= 1);
        commentItem.addActionListener(e -> editComment());

        // 批量重放（选中 >= 2 条时显示）
        JMenuItem batchReplayItem = null;
        if (selectedCount >= 2) {
            batchReplayItem = new JMenuItem(String.format("批量重放 (%d条)", selectedCount));
            batchReplayItem.addActionListener(e -> batchReplaySelectedItems());
        }

        // 发送到权限测试
        JMenuItem sendToPrivilegeTestItem = null;
        if (selectedCount >= 1) {
            String privText = selectedCount > 1
                ? String.format("发送到权限测试 (%d条)", selectedCount)
                : "发送到权限测试";
            sendToPrivilegeTestItem = new JMenuItem(privText);
            sendToPrivilegeTestItem.addActionListener(e -> sendSelectedToPrivilegeTest());
        }

        // 比对报文（仅选中1条越权测试记录时显示）
        JMenuItem comparisonItem = null;
        if (selectedCount == 1) {
            int selRow = historyTable.getSelectedRow();
            if (selRow >= 0) {
                int modelRow = historyTable.convertRowIndexToModel(selRow);
                if (modelRow >= 0 && modelRow < historyRecords.size()) {
                    RequestResponseRecord record = historyRecords.get(modelRow);
                    if (record.getUserSessionName() != null && !record.getUserSessionName().isEmpty()) {
                        comparisonItem = new JMenuItem("比对报文");
                        comparisonItem.addActionListener(e -> showComparisonDialog(modelRow));
                    }
                }
            }
        }

        JMenuItem clearItem = new JMenuItem("清空所有历史");
        clearItem.addActionListener(e -> historyPanel.clearHistoryWithConfirm());

        popupMenu.add(loadItem);
        popupMenu.add(deleteItem);
        popupMenu.addSeparator();
        if (batchReplayItem != null) {
            popupMenu.add(batchReplayItem);
        }
        if (sendToPrivilegeTestItem != null) {
            popupMenu.add(sendToPrivilegeTestItem);
        }
        if (comparisonItem != null) {
            popupMenu.add(comparisonItem);
        }
        if (sendToPrivilegeTestItem != null || comparisonItem != null) {
            popupMenu.addSeparator();
        }
        popupMenu.add(columnControlItem);
        popupMenu.addSeparator();
        popupMenu.add(colorMenu);
        popupMenu.add(commentItem);
        popupMenu.addSeparator();
        popupMenu.add(clearItem);

        return popupMenu;
    }

    /**
     * 批量重放选中的历史记录
     */
    private void batchReplaySelectedItems() {
        List<RequestResponseRecord> selectedRecords = historyPanel.getSelectedRecords();
        if (selectedRecords.isEmpty()) return;

        RequestDispatchHandler dispatchHandler = historyPanel.getDispatchHandler();
        if (dispatchHandler == null) {
            BurpExtender.printError("[!] 批量重放：调度处理器未初始化");
            return;
        }

        dispatchHandler.batchSendRequests(selectedRecords);
    }

    /**
     * 将选中的历史记录发送到权限测试
     */
    private void sendSelectedToPrivilegeTest() {
        List<RequestResponseRecord> selectedRecords = historyPanel.getSelectedRecords();
        if (selectedRecords.isEmpty()) return;

        RequestDispatchHandler dispatchHandler = historyPanel.getDispatchHandler();
        if (dispatchHandler == null) {
            BurpExtender.printError("[!] 权限测试：调度处理器未初始化");
            return;
        }

        // 收集所有不重复的 requestId
        java.util.Set<Integer> requestIds = new java.util.LinkedHashSet<>();
        for (RequestResponseRecord record : selectedRecords) {
            if (record.getRequestId() > 0) {
                requestIds.add(record.getRequestId());
            }
        }

        if (requestIds.isEmpty()) {
            BurpExtender.printError("[!] 权限测试：选中的记录没有有效的请求ID");
            return;
        }

        // 标记为越权测试请求
        RequestDAO requestDAO = new RequestDAO();
        for (int requestId : requestIds) {
            requestDAO.markAsPrivilegeTest(requestId);
        }

        // 执行批量权限测试
        dispatchHandler.batchSendPrivilegeTestRequests(new java.util.ArrayList<>(requestIds));
    }

    /**
     * 添加颜色菜单项
     */
    private void addColorMenuItem(JMenu parentMenu, String name, Color color) {
        addColorMenuItem(parentMenu, name, color, false);
    }

    /**
     * 添加颜色菜单项（支持多选批量标记颜色）
     */
    private void addColorMenuItem(JMenu parentMenu, String name, Color color, boolean isClear) {
        JMenuItem item = new JMenuItem(name);

        // 为菜单项添加颜色图标
        if (!isClear && color != null) {
            item.setIcon(createColorIcon(color));
        }

        item.addActionListener((ActionEvent e) -> {
            int[] selectedRows = historyTable.getSelectedRows();
            if (selectedRows.length == 0) {
                return;
            }

            Color finalColor;
            if (isClear) {
                finalColor = null;
            } else if (color == null) {
                Color selectedColor = JColorChooser.showDialog(
                    historyPanel, "选择标记颜色", Color.YELLOW);
                if (selectedColor == null) return;
                finalColor = selectedColor;
            } else {
                finalColor = color;
            }

            // 批量设置所有选中行的颜色
            HistoryUpdateDAO historyUpdateDAO = new HistoryUpdateDAO();
            for (int viewRow : selectedRows) {
                int modelRow = historyTable.convertRowIndexToModel(viewRow);
                if (modelRow >= 0 && modelRow < historyRecords.size()) {
                    RequestResponseRecord record = historyRecords.get(modelRow);
                    record.setColor(finalColor);

                    // 同步更新数据库
                    if (record.getId() > 0) {
                        try {
                            historyUpdateDAO.updateHistoryColor(record.getId(), finalColor);
                        } catch (Exception ex) {
                            BurpExtender.printError("[!] 更新历史记录颜色失败: " + ex.getMessage());
                        }
                    }
                }
            }

            historyTable.repaint();
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
     * 编辑备注（仅支持单条）
     */
    private void editComment() {
        int selectedRow = historyTable.getSelectedRow();
        if (selectedRow == -1) {
            return;
        }

        int modelRow = historyTable.convertRowIndexToModel(selectedRow);
        if (modelRow >= 0 && modelRow < historyRecords.size()) {
            RequestResponseRecord record = historyRecords.get(modelRow);

            String currentComment = record.getComment();

            String newComment = (String) JOptionPane.showInputDialog(
                historyPanel,
                "请输入记录备注:",
                "编辑备注",
                JOptionPane.PLAIN_MESSAGE,
                null,
                null,
                currentComment
            );

            if (newComment != null) {
                record.setComment(newComment.trim());

                int commentColumn = 14; // 备注列索引
                historyTableModel.setValueAt(record.getTruncatedComment(16), modelRow, commentColumn);

                // 同步更新数据库
                if (record.getId() > 0) {
                    HistoryUpdateDAO historyUpdateDAO = new HistoryUpdateDAO();
                    historyUpdateDAO.updateHistoryComment(record.getId(), newComment.trim());
                }
            }
        }
    }

    /**
     * 显示报文比对对话框
     * 获取选中记录的基线记录（原始请求），弹出ComparisonDialog
     *
     * 基线数据来源优先级：
     * 1. history 表中 user_session_name 为 NULL 的记录（正常发送时产生，含请求+响应）
     * 2. requests 表中的原始请求数据（越权测试入口时产生，仅含请求，响应用会话记录的响应代替）
     */
    private void showComparisonDialog(int modelRow) {
        if (modelRow < 0 || modelRow >= historyRecords.size()) return;

        RequestResponseRecord sessionRecord = historyRecords.get(modelRow);
        int requestId = sessionRecord.getRequestId();

        if (requestId <= 0) {
            JOptionPane.showMessageDialog(historyPanel, "选中记录没有有效的请求ID，无法比对", "无法比对", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // 在后台线程查找基线记录（避免UI卡顿）
        new Thread(() -> {
            HistoryReadDAO historyReadDAO = new HistoryReadDAO();
            // 先尝试从 history 表找 user_session_name 为 NULL 的记录（含完整请求+响应）
            RequestResponseRecord baselineRecord = historyReadDAO.getBaselineRecordWithoutFallback(requestId);

            if (baselineRecord == null) {
                // history 表没有基线记录，从 requests 表获取原始请求数据构造基线
                baselineRecord = buildBaselineFromRequestsTable(requestId, historyReadDAO);
            }

            if (baselineRecord == null) {
                SwingUtilities.invokeLater(() ->
                    JOptionPane.showMessageDialog(historyPanel, "未找到原始请求记录，无法比对", "无法比对", JOptionPane.WARNING_MESSAGE));
                return;
            }

            final RequestResponseRecord finalBaseline = baselineRecord;
            SwingUtilities.invokeLater(() -> {
                ComparisonDialog dialog = new ComparisonDialog(historyPanel, finalBaseline, sessionRecord);
                dialog.setVisible(true);
            });
        }).start();
    }

    /**
     * 从 requests 表构造基线记录（用于越权测试直接入口、history 表无原始基线记录的场景）
     *
     * 请求数据：来自 requests 表中存储的原始请求字节（未经令牌替换）
     * 响应数据：从 requests 表的响应字段获取（v10新增），包含发送到插件时携带的原始响应
     *           如果无原始响应（如从 Proxy Intercept 发过来的），则置空
     */
    private RequestResponseRecord buildBaselineFromRequestsTable(int requestId, HistoryReadDAO historyReadDAO) {
        try {
            RequestDAO requestDAO = new RequestDAO();
            Map<String, Object> originalRequest = requestDAO.getRequest(requestId);
            if (originalRequest == null || !originalRequest.containsKey("request_data")) {
                return null;
            }

            byte[] originalRequestData = (byte[]) originalRequest.get("request_data");
            RequestResponseRecord baseline = new RequestResponseRecord();
            baseline.setRequestId(requestId);
            baseline.setRequestData(originalRequestData);
            baseline.setMethod((String) originalRequest.get("method"));
            baseline.setProtocol((String) originalRequest.get("protocol"));
            baseline.setDomain((String) originalRequest.get("domain"));
            baseline.setPath((String) originalRequest.get("path"));
            baseline.setQueryParameters((String) originalRequest.get("query"));

            // 从 requests 表读取原始响应（v10存入的基线响应）
            byte[] originalResponseData = requestDAO.getOriginalResponseData(requestId);
            if (originalResponseData != null && originalResponseData.length > 0) {
                baseline.setResponseData(originalResponseData);
                baseline.setStatusCode(requestDAO.getOriginalResponseStatusCode(requestId));
                baseline.setResponseLength(originalResponseData.length);
            } else {
                // 无基线响应（旧数据或 Intercept 发来的无响应报文）
                baseline.setResponseData(new byte[0]);
                baseline.setStatusCode(0);
                baseline.setResponseLength(0);
            }
            baseline.setResponseTime(0);

            baseline.setTimestamp(new java.util.Date());
            baseline.setUserSessionName(null);
            baseline.setSimilarity(-1);

            return baseline;
        } catch (Exception e) {
            BurpExtender.printError("[!] 从requests表构造基线记录失败: " + e.getMessage());
            return null;
        }
    }
}
