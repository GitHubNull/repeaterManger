package org.oxff.repeater.ui;

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
 * 请求列表列显示控制对话框 - 允许用户选择要显示/隐藏的表格列
 * 必要列（不可隐藏）：ID, Method, Domain, Path
 */
public class RequestColumnControlDialog extends JDialog {
    private static final long serialVersionUID = 1L;

    // 必要列索引：ID(0), Method(2), Domain(4), Path(5)
    private static final Set<Integer> MANDATORY_COLUMNS = new HashSet<>(Arrays.asList(0, 2, 4, 5));

    private final JTable requestTable;
    private final DefaultTableModel requestTableModel;
    private final Component parentComponent;

    private JCheckBox[] checkBoxes;
    private boolean[] initialVisibility;
    private int columnCount;

    public RequestColumnControlDialog(Component parentComponent, JTable requestTable, DefaultTableModel requestTableModel) {
        super((Frame) SwingUtilities.getWindowAncestor(parentComponent), "列显示控制", true);
        this.parentComponent = parentComponent;
        this.requestTable = requestTable;
        this.requestTableModel = requestTableModel;
        initUI();
    }

    private void initUI() {
        setLayout(new BorderLayout());

        JPanel panel = createCheckBoxPanel();
        JPanel buttonPanel = createButtonPanel();

        add(new JScrollPane(panel), BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        setSize(300, 400);
        setLocationRelativeTo(parentComponent);
    }

    private JPanel createCheckBoxPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        TableColumnModel columnModel = requestTable.getColumnModel();
        columnCount = columnModel.getColumnCount();

        checkBoxes = new JCheckBox[columnCount];
        initialVisibility = new boolean[columnCount];

        for (int i = 0; i < columnCount; i++) {
            TableColumn column = columnModel.getColumn(i);
            String columnName = requestTableModel.getColumnName(column.getModelIndex());

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

            checkBoxes[i] = new JCheckBox(columnName, found);

            if (MANDATORY_COLUMNS.contains(i)) {
                checkBoxes[i].setEnabled(false);
                checkBoxes[i].setSelected(true);
            }

            panel.add(checkBoxes[i]);
        }

        return panel;
    }

    private JPanel createButtonPanel() {
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton okButton = new JButton("确定");
        JButton cancelButton = new JButton("取消");
        JButton resetButton = new JButton("重置为默认");

        okButton.addActionListener(e -> {
            TableColumnModel columnModel = requestTable.getColumnModel();
            for (int i = 0; i < columnCount; i++) {
                if (!MANDATORY_COLUMNS.contains(i)) {
                    boolean selected = checkBoxes[i].isSelected();
                    if (selected != initialVisibility[i]) {
                        if (selected) {
                            TableColumn column = new TableColumn(i);
                            column.setHeaderValue(requestTableModel.getColumnName(i));
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
            case 0: // ID列
                column.setPreferredWidth(40);
                column.setMaxWidth(50);
                break;
            case 1: // API列
                column.setPreferredWidth(200);
                column.setMaxWidth(400);
                break;
            case 2: // Method列
                column.setPreferredWidth(60);
                column.setMaxWidth(80);
                break;
            case 3: // Protocol列
                column.setPreferredWidth(60);
                column.setMaxWidth(80);
                break;
            case 4: // Domain列
                column.setPreferredWidth(150);
                break;
            case 5: // Path列
                column.setPreferredWidth(180);
                break;
            case 6: // Query列
                column.setPreferredWidth(150);
                break;
            case 7: // 越权测试列
                column.setPreferredWidth(70);
                column.setMaxWidth(90);
                break;
            case 8: // Date列
                column.setPreferredWidth(150);
                column.setMaxWidth(180);
                break;
            case 9: // 备注列
                column.setPreferredWidth(100);
                break;
        }
    }
}