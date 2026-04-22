package oxff.top.ui.history;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.RowFilter;
import java.awt.*;
import java.awt.Insets;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 高级搜索对话框 - 提供多条件组合过滤历史记录
 */
public class AdvancedSearchDialog extends JDialog {
    private static final long serialVersionUID = 1L;

    private final TableRowSorter<DefaultTableModel> tableRowSorter;
    private final Component parentComponent;

    // 过滤条件输入组件
    private JComboBox<String> methodCombo;
    private JComboBox<String> protocolCombo;
    private JTextField hostField;
    private JTextField pathField;
    private JTextField queryField;
    private JTextField minStatusField;
    private JTextField maxStatusField;
    private JTextField minLengthField;
    private JTextField maxLengthField;
    private JTextField commentField;

    /**
     * 创建高级搜索对话框
     *
     * @param parentComponent  父组件（用于定位对话框）
     * @param tableRowSorter   表格排序器（用于应用过滤器）
     */
    public AdvancedSearchDialog(Component parentComponent, TableRowSorter<DefaultTableModel> tableRowSorter) {
        super((Frame) SwingUtilities.getWindowAncestor(parentComponent), "高级搜索", true);
        this.parentComponent = parentComponent;
        this.tableRowSorter = tableRowSorter;
        initUI();
    }

    /**
     * 初始化界面
     */
    private void initUI() {
        setLayout(new BorderLayout());

        JPanel formPanel = createFormPanel();
        JPanel buttonPanel = createButtonPanel();

        add(formPanel, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        pack();
        setLocationRelativeTo(parentComponent);
    }

    /**
     * 创建表单面板
     */
    private JPanel createFormPanel() {
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(5, 5, 5, 5);

        // 方法过滤器
        c.gridx = 0;
        c.gridy = 0;
        formPanel.add(new JLabel("方法:"), c);

        c.gridx = 1;
        c.weightx = 1.0;
        String[] methods = {"所有方法", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"};
        methodCombo = new JComboBox<>(methods);
        formPanel.add(methodCombo, c);

        // 协议过滤器
        c.gridx = 0;
        c.gridy = 1;
        c.weightx = 0;
        formPanel.add(new JLabel("协议:"), c);

        c.gridx = 1;
        protocolCombo = new JComboBox<>(new String[]{"所有协议", "http", "https"});
        formPanel.add(protocolCombo, c);

        // 域名过滤器
        c.gridx = 0;
        c.gridy = 2;
        formPanel.add(new JLabel("域名包含:"), c);

        c.gridx = 1;
        hostField = new JTextField(20);
        formPanel.add(hostField, c);

        // 路径过滤器
        c.gridx = 0;
        c.gridy = 3;
        formPanel.add(new JLabel("路径包含:"), c);

        c.gridx = 1;
        pathField = new JTextField(20);
        formPanel.add(pathField, c);

        // 查询参数过滤器
        c.gridx = 0;
        c.gridy = 4;
        formPanel.add(new JLabel("参数包含:"), c);

        c.gridx = 1;
        queryField = new JTextField(20);
        formPanel.add(queryField, c);

        // 状态码过滤器
        c.gridx = 0;
        c.gridy = 5;
        formPanel.add(new JLabel("状态码:"), c);

        c.gridx = 1;
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        minStatusField = new JTextField(4);
        maxStatusField = new JTextField(4);
        statusPanel.add(new JLabel("从:"));
        statusPanel.add(minStatusField);
        statusPanel.add(new JLabel("到:"));
        statusPanel.add(maxStatusField);
        formPanel.add(statusPanel, c);

        // 响应长度过滤器
        c.gridx = 0;
        c.gridy = 6;
        formPanel.add(new JLabel("响应长度:"), c);

        c.gridx = 1;
        JPanel lengthPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        minLengthField = new JTextField(6);
        maxLengthField = new JTextField(6);
        lengthPanel.add(new JLabel("从:"));
        lengthPanel.add(minLengthField);
        lengthPanel.add(new JLabel("到:"));
        lengthPanel.add(maxLengthField);
        formPanel.add(lengthPanel, c);

        // 备注过滤器
        c.gridx = 0;
        c.gridy = 7;
        formPanel.add(new JLabel("备注包含:"), c);

        c.gridx = 1;
        commentField = new JTextField(20);
        formPanel.add(commentField, c);

        return formPanel;
    }

    /**
     * 创建按钮面板
     */
    private JPanel createButtonPanel() {
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton searchButton = new JButton("搜索");
        JButton cancelButton = new JButton("取消");

        searchButton.addActionListener(e -> {
            applyAdvancedFilter();
            dispose();
        });

        cancelButton.addActionListener(e -> dispose());

        buttonPanel.add(searchButton);
        buttonPanel.add(cancelButton);
        return buttonPanel;
    }

    /**
     * 应用高级过滤器
     */
    private void applyAdvancedFilter() {
        String method = (String) methodCombo.getSelectedItem();
        String protocol = (String) protocolCombo.getSelectedItem();
        String host = hostField.getText();
        String path = pathField.getText();
        String query = queryField.getText();
        String minStatus = minStatusField.getText();
        String maxStatus = maxStatusField.getText();
        String minLength = minLengthField.getText();
        String maxLength = maxLengthField.getText();
        String comment = commentField.getText();

        List<RowFilter<DefaultTableModel, Object>> filters = new ArrayList<>();

        // 方法过滤
        if (method != null && !"所有方法".equals(method)) {
            filters.add(RowFilter.regexFilter("^" + method + "$", 3));
        }

        // 协议过滤
        if (protocol != null && !"所有协议".equals(protocol)) {
            filters.add(RowFilter.regexFilter("^" + protocol + "$", 4));
        }

        // 域名过滤
        if (host != null && !host.isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(host), 5));
        }

        // 路径过滤
        if (path != null && !path.isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(path), 6));
        }

        // 查询参数过滤
        if (query != null && !query.isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(query), 7));
        }

        // 状态码过滤
        if (!minStatus.isEmpty() || !maxStatus.isEmpty()) {
            try {
                final int min = minStatus.isEmpty() ? 0 : Integer.parseInt(minStatus);
                final int max = maxStatus.isEmpty() ? Integer.MAX_VALUE : Integer.parseInt(maxStatus);

                filters.add(new RowFilter<DefaultTableModel, Object>() {
                    @Override
                    public boolean include(Entry<? extends DefaultTableModel, ? extends Object> entry) {
                        Object statusObj = entry.getValue(8);
                        if (!(statusObj instanceof Integer)) {
                            return true;
                        }
                        int status = (Integer) statusObj;
                        return status >= min && status <= max;
                    }
                });
            } catch (NumberFormatException e) {
                JOptionPane.showMessageDialog(parentComponent, "状态码必须是数字", "输入错误", JOptionPane.ERROR_MESSAGE);
            }
        }

        // 响应长度过滤
        if (!minLength.isEmpty() || !maxLength.isEmpty()) {
            try {
                final int min = minLength.isEmpty() ? 0 : Integer.parseInt(minLength);
                final int max = maxLength.isEmpty() ? Integer.MAX_VALUE : Integer.parseInt(maxLength);

                filters.add(new RowFilter<DefaultTableModel, Object>() {
                    @Override
                    public boolean include(Entry<? extends DefaultTableModel, ? extends Object> entry) {
                        Object lengthObj = entry.getValue(9);
                        if (!(lengthObj instanceof Integer)) {
                            return true;
                        }
                        int length = (Integer) lengthObj;
                        return length >= min && length <= max;
                    }
                });
            } catch (NumberFormatException e) {
                JOptionPane.showMessageDialog(parentComponent, "响应长度必须是数字", "输入错误", JOptionPane.ERROR_MESSAGE);
            }
        }

        // 备注过滤
        if (comment != null && !comment.isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + comment, 11));
        }

        // 应用过滤器
        if (filters.isEmpty()) {
            tableRowSorter.setRowFilter(null);
        } else if (filters.size() == 1) {
            tableRowSorter.setRowFilter(filters.get(0));
        } else {
            tableRowSorter.setRowFilter(RowFilter.andFilter(filters));
        }
    }
}
