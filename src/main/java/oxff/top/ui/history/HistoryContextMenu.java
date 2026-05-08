package oxff.top.ui.history;

import oxff.top.http.RequestResponseRecord;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;

/**
 * 历史记录右键菜单工厂 - 创建和管理历史记录表格的右键菜单
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
     * 创建右键菜单
     */
    public JPopupMenu createPopupMenu() {
        JPopupMenu popupMenu = new JPopupMenu();

        JMenuItem loadItem = new JMenuItem("加载所选项");
        loadItem.addActionListener(e -> historyPanel.loadSelectedHistoryItem());

        JMenuItem deleteItem = new JMenuItem("删除所选项");
        deleteItem.addActionListener(e -> deleteSelectedHistoryItem());

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

        // 添加设置备注菜单项
        JMenuItem commentItem = new JMenuItem("编辑备注");
        commentItem.addActionListener(e -> editComment());

        JMenuItem clearItem = new JMenuItem("清空所有历史");
        clearItem.addActionListener(e -> historyPanel.clearHistoryWithConfirm());

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

        item.addActionListener((ActionEvent e) -> {
            int selectedRow = historyTable.getSelectedRow();
            if (selectedRow == -1) {
                return;
            }

            int modelRow = historyTable.convertRowIndexToModel(selectedRow);
            if (modelRow >= 0 && modelRow < historyRecords.size()) {
                RequestResponseRecord record = historyRecords.get(modelRow);

                if (isClear) {
                    record.setColor(null);
                } else if (color == null) {
                    Color selectedColor = JColorChooser.showDialog(
                        historyPanel, "选择标记颜色", Color.YELLOW);
                    if (selectedColor != null) {
                        record.setColor(selectedColor);
                    }
                } else {
                    record.setColor(color);
                }

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
     * 编辑备注
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

        int result = JOptionPane.showConfirmDialog(
            historyPanel,
            "确认删除选中的历史记录?",
            "删除确认",
            JOptionPane.YES_NO_OPTION
        );

        if (result == JOptionPane.YES_OPTION) {
            historyRecords.remove(modelRow);
            historyTableModel.removeRow(modelRow);
            historyPanel.updateRecordNumbers();
        }
    }
}
