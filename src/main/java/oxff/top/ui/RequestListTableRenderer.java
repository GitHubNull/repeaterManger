package oxff.top.ui;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.util.Map;

/**
 * 请求列表表格渲染器 - 提供行颜色标记渲染
 * 基于requestColors映射为行设置背景颜色
 */
public class RequestListTableRenderer extends DefaultTableCellRenderer {
    private static final long serialVersionUID = 1L;

    private final Map<Integer, Color> requestColors;

    public RequestListTableRenderer(Map<Integer, Color> requestColors) {
        this.requestColors = requestColors;
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
            boolean isSelected, boolean hasFocus, int row, int column) {
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        if (!isSelected) {
            int modelRow = table.convertRowIndexToModel(row);
            if (modelRow >= 0 && modelRow < table.getModel().getRowCount()) {
                int requestId = (int) table.getModel().getValueAt(modelRow, 0);
                Color rowColor = requestColors.get(requestId);

                if (rowColor != null) {
                    // 使用约40%透明度
                    int alpha = 100;
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
}