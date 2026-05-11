package oxff.top.ui.privilege;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * 令牌值摘要列的单元格渲染器
 * 实现自动省略号显示和鼠标悬停tooltip
 */
public class TokenValueCellRenderer extends DefaultTableCellRenderer {

    private static final int MAX_TOOLTIP_LENGTH = 500;

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
            boolean isSelected, boolean hasFocus, int row, int column) {
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        String text = value != null ? value.toString() : "";

        // 检测文本是否超出单元格宽度，设置tooltip
        FontMetrics fm = getFontMetrics(getFont());
        int availableWidth = table.getColumnModel().getColumn(column).getWidth()
                - table.getIntercellSpacing().width
                - getInsets().left - getInsets().right;
        if (fm.stringWidth(text) > availableWidth) {
            String tip = text.length() > MAX_TOOLTIP_LENGTH
                    ? text.substring(0, MAX_TOOLTIP_LENGTH - 3) + "..."
                    : text;
            setToolTipText(tip);
        } else {
            setToolTipText(null);
        }
        return this;
    }
}
