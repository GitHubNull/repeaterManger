package oxff.top.ui;

import burp.BurpExtender;
import oxff.top.db.RequestDAO;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.Map;

/**
 * 请求列表右键菜单 - 支持颜色标记、编辑备注、列控制、删除请求
 */
public class RequestListContextMenu {

    private final JTable requestTable;
    private final Map<Integer, Color> requestColors;
    private final Map<Integer, String> requestComments;
    private final DefaultTableModel requestTableModel;

    public RequestListContextMenu(JTable requestTable, DefaultTableModel requestTableModel,
                                   Map<Integer, Color> requestColors, Map<Integer, String> requestComments) {
        this.requestTable = requestTable;
        this.requestTableModel = requestTableModel;
        this.requestColors = requestColors;
        this.requestComments = requestComments;
    }

    /**
     * 创建右键菜单
     */
    public JPopupMenu createPopupMenu() {
        JPopupMenu popupMenu = new JPopupMenu();

        int selectedCount = requestTable.getSelectedRows().length;

        // 标记颜色菜单
        JMenu colorMenu = new JMenu("标记颜色");
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

        // 列显示控制
        JMenuItem columnControlItem = new JMenuItem("列显示控制");
        columnControlItem.addActionListener(e -> showColumnControlDialog());

        // 删除请求
        String deleteText = selectedCount > 1
            ? String.format("删除请求 (%d条)", selectedCount)
            : "删除请求";
        JMenuItem deleteItem = new JMenuItem(deleteText);
        deleteItem.addActionListener(e -> deleteSelectedRequests());

        popupMenu.add(colorMenu);
        popupMenu.add(commentItem);
        popupMenu.addSeparator();
        popupMenu.add(columnControlItem);
        popupMenu.addSeparator();
        popupMenu.add(deleteItem);

        return popupMenu;
    }

    /**
     * 添加颜色菜单项
     */
    private void addColorMenuItem(JMenu parentMenu, String name, Color color) {
        addColorMenuItem(parentMenu, name, color, false);
    }

    private void addColorMenuItem(JMenu parentMenu, String name, Color color, boolean isClear) {
        JMenuItem item = new JMenuItem(name);

        if (!isClear && color != null) {
            item.setIcon(createColorIcon(color));
        }

        item.addActionListener((ActionEvent e) -> {
            int[] selectedRows = requestTable.getSelectedRows();
            if (selectedRows.length == 0) return;

            Color finalColor;
            if (isClear) {
                finalColor = null;
            } else if (color == null) {
                Color selectedColor = JColorChooser.showDialog(
                    requestTable, "选择标记颜色", Color.YELLOW);
                if (selectedColor == null) return;
                finalColor = selectedColor;
            } else {
                finalColor = color;
            }

            RequestDAO requestDAO = new RequestDAO();
            for (int viewRow : selectedRows) {
                int modelRow = requestTable.convertRowIndexToModel(viewRow);
                if (modelRow >= 0 && modelRow < requestTableModel.getRowCount()) {
                    int requestId = (int) requestTableModel.getValueAt(modelRow, 0);

                    requestColors.put(requestId, finalColor);

                    // 持久化到数据库
                    try {
                        requestDAO.updateRequestColor(requestId, finalColor);
                    } catch (Exception ex) {
                        BurpExtender.printError("[!] 更新请求颜色失败: " + ex.getMessage());
                    }
                }
            }

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
            public int getIconWidth() { return 16; }

            @Override
            public int getIconHeight() { return 16; }
        };
    }

    /**
     * 编辑备注
     */
    private void editComment() {
        int selectedRow = requestTable.getSelectedRow();
        if (selectedRow == -1) return;

        int modelRow = requestTable.convertRowIndexToModel(selectedRow);
        if (modelRow >= 0 && modelRow < requestTableModel.getRowCount()) {
            int requestId = (int) requestTableModel.getValueAt(modelRow, 0);
            String currentComment = requestComments.getOrDefault(requestId, "");

            String newComment = (String) JOptionPane.showInputDialog(
                requestTable,
                "请输入备注:",
                "编辑备注",
                JOptionPane.PLAIN_MESSAGE,
                null,
                null,
                currentComment
            );

            if (newComment != null) {
                String trimmed = newComment.trim();
                requestComments.put(requestId, trimmed);

                // 更新表格备注列
                String displayComment = trimmed.length() > 16
                    ? trimmed.substring(0, 16) + "..." : trimmed;
                requestTableModel.setValueAt(displayComment, modelRow, 9);

                // 持久化到数据库
                RequestDAO requestDAO = new RequestDAO();
                try {
                    requestDAO.updateRequestComment(requestId, trimmed);
                } catch (Exception ex) {
                    BurpExtender.printError("[!] 更新请求备注失败: " + ex.getMessage());
                }
            }
        }
    }

    /**
     * 显示列控制对话框
     */
    private void showColumnControlDialog() {
        RequestColumnControlDialog dialog = new RequestColumnControlDialog(
            requestTable, requestTable, requestTableModel);
        dialog.setVisible(true);
    }

    /**
     * 删除选中的请求
     */
    private void deleteSelectedRequests() {
        int[] selectedRows = requestTable.getSelectedRows();
        if (selectedRows.length == 0) return;

        int confirm = JOptionPane.showConfirmDialog(
            requestTable,
            String.format("确认删除 %d 条请求？", selectedRows.length),
            "删除确认",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE
        );

        if (confirm != JOptionPane.YES_OPTION) return;

        RequestDAO requestDAO = new RequestDAO();
        for (int viewRow : selectedRows) {
            int modelRow = requestTable.convertRowIndexToModel(viewRow);
            if (modelRow >= 0 && modelRow < requestTableModel.getRowCount()) {
                int requestId = (int) requestTableModel.getValueAt(modelRow, 0);

                // 从数据库删除
                try {
                    requestDAO.deleteRequest(requestId);
                } catch (Exception ex) {
                    BurpExtender.printError("[!] 删除请求失败: " + ex.getMessage());
                }

                // 从内存映射删除
                requestColors.remove(requestId);
                requestComments.remove(requestId);
            }
        }

        // 从表格移除行（需从后往前移除以保持索引正确）
        for (int i = selectedRows.length - 1; i >= 0; i--) {
            int modelRow = requestTable.convertRowIndexToModel(selectedRows[i]);
            requestTableModel.removeRow(modelRow);
        }

        requestTable.repaint();
    }
}