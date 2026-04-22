package oxff.top.ui;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/**
 * 列显示控制对话框 - 允许用户选择要显示/隐藏的表格列
 */
public class ColumnControlDialog extends JDialog {
    private static final long serialVersionUID = 1L;

    private static final Set<Integer> MANDATORY_COLUMNS = new HashSet<>(Arrays.asList(0, 2, 3, 4, 5, 6));

    private final JTable historyTable;
    private final DefaultTableModel historyTableModel;
    private final Component parentComponent;

    // 复选框状态（由 createCheckBoxPanel 初始化）
    private JCheckBox[] checkBoxes;
    private boolean[] initialVisibility;
    private int columnCount;

    /**
     * 创建列控制对话框
     *
     * @param parentComponent  父组件
     * @param historyTable     历史记录表格
     * @param historyTableModel 表格模型
     */
    public ColumnControlDialog(Component parentComponent, JTable historyTable, DefaultTableModel historyTableModel) {
        super((Frame) SwingUtilities.getWindowAncestor(parentComponent), "列显示控制", true);
        this.parentComponent = parentComponent;
        this.historyTable = historyTable;
        this.historyTableModel = historyTableModel;
        initUI();
    }

    /**
     * 初始化界面
     */
    private void initUI() {
        setLayout(new BorderLayout());

        JPanel panel = createCheckBoxPanel();
        JPanel buttonPanel = createButtonPanel();

        add(new JScrollPane(panel), BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        setSize(300, 400);
        setLocationRelativeTo(parentComponent);
    }

    /**
     * 创建复选框面板
     */
    private JPanel createCheckBoxPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        TableColumnModel columnModel = historyTable.getColumnModel();
        columnCount = columnModel.getColumnCount();

        checkBoxes = new JCheckBox[columnCount];
        initialVisibility = new boolean[columnCount];

        for (int i = 0; i < columnCount; i++) {
            TableColumn column = columnModel.getColumn(i);
            String columnName = historyTableModel.getColumnName(column.getModelIndex());

            // 检查该列是否可见
            Enumeration<TableColumn> columns = columnModel.getColumns();
            boolean found = false;
            while (columns.hasMoreElements()) {
                if (columns.nextElement() == column) {
                    found = true;
                    break;
                }
            }
            initialVisibility[i] = found;

            // 创建复选框
            checkBoxes[i] = new JCheckBox(columnName, found);

            // 如果是必须显示的列，则禁用复选框
            if (MANDATORY_COLUMNS.contains(i)) {
                checkBoxes[i].setEnabled(false);
                checkBoxes[i].setSelected(true);
            }

            panel.add(checkBoxes[i]);
        }

        return panel;
    }

    /**
     * 创建按钮面板
     */
    private JPanel createButtonPanel() {
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton okButton = new JButton("确定");
        JButton cancelButton = new JButton("取消");
        JButton resetButton = new JButton("重置为默认");

        okButton.addActionListener(e -> {
            TableColumnModel columnModel = historyTable.getColumnModel();
            for (int i = 0; i < columnCount; i++) {
                if (!MANDATORY_COLUMNS.contains(i)) {
                    boolean selected = checkBoxes[i].isSelected();
                    if (selected != initialVisibility[i]) {
                        if (selected) {
                            TableColumn column = new TableColumn(i);
                            column.setHeaderValue(historyTableModel.getColumnName(i));
                            columnModel.addColumn(column);
                            restoreColumnWidth(column, i);
                        } else {
                            TableColumn column = columnModel.getColumn(i);
                            columnModel.removeColumn(column);
                        }
                    }
                }
            }
            dispose();
        });

        cancelButton.addActionListener(e -> dispose());

        resetButton.addActionListener(e -> {
            for (int i = 0; i < columnCount; i++) {
                checkBoxes[i].setSelected(true);
                if (!MANDATORY_COLUMNS.contains(i)) {
                    checkBoxes[i].setEnabled(true);
                }
            }
        });

        buttonPanel.add(resetButton);
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        return buttonPanel;
    }

    /**
     * 恢复列的宽度设置
     */
    static void restoreColumnWidth(TableColumn column, int columnIndex) {
        switch (columnIndex) {
            case 0: // 序号列
                column.setPreferredWidth(40);
                column.setMaxWidth(50);
                break;
            case 1: // 时间列
                column.setPreferredWidth(150);
                column.setMaxWidth(180);
                break;
            case 2: // API列
                column.setPreferredWidth(200);
                column.setMaxWidth(400);
                break;
            case 3: // 方法列
                column.setPreferredWidth(60);
                column.setMaxWidth(80);
                break;
            case 4: // 协议列
                column.setPreferredWidth(60);
                column.setMaxWidth(80);
                break;
            case 5: // 域名列
                column.setPreferredWidth(150);
                break;
            case 6: // 路径列
                column.setPreferredWidth(180);
                break;
            case 7: // 查询参数列
                column.setPreferredWidth(150);
                break;
            case 8: // 状态码列
                column.setPreferredWidth(70);
                column.setMaxWidth(90);
                break;
            case 9: // 响应长度列
                column.setPreferredWidth(90);
                column.setMaxWidth(110);
                break;
            case 10: // 耗时列
                column.setPreferredWidth(70);
                column.setMaxWidth(90);
                break;
            case 11: // 备注列
                column.setPreferredWidth(150);
                break;
        }
    }
}
