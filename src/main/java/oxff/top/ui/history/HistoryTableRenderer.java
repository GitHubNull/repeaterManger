package oxff.top.ui.history;

import oxff.top.http.RequestResponseRecord;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * 历史记录表格渲染器 - 提供状态码颜色渲染和行颜色标记渲染
 */
public class HistoryTableRenderer {

    /**
     * 创建状态码列的渲染器（根据状态码范围显示不同颜色）
     */
    public static DefaultTableCellRenderer createStatusCodeRenderer() {
        return new DefaultTableCellRenderer() {
            private static final long serialVersionUID = 1L;

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
        };
    }

    /**
     * 创建越权测试列的渲染器（"是"显示绿色，"否"显示默认颜色）
     */
    public static DefaultTableCellRenderer createPrivilegeTestRenderer() {
        return new DefaultTableCellRenderer() {
            private static final long serialVersionUID = 1L;

            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(
                        table, value, isSelected, hasFocus, row, column);

                if (!isSelected && value instanceof String) {
                    String text = (String) value;
                    if ("是".equals(text)) {
                        c.setForeground(new Color(0, 130, 0)); // 绿色
                    } else {
                        c.setForeground(Color.BLACK);
                    }
                } else if (isSelected) {
                    c.setForeground(table.getSelectionForeground());
                } else {
                    c.setForeground(Color.BLACK);
                }

                return c;
            }
        };
    }

    /**
     * 创建行背景颜色渲染器（基于历史记录的颜色标记）
     *
     * @param historyRecords  历史记录列表
     */
    public static DefaultTableCellRenderer createRowColorRenderer(final java.util.List<RequestResponseRecord> historyRecords) {
        return new DefaultTableCellRenderer() {
            private static final long serialVersionUID = 1L;

            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
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
        };
    }
}
