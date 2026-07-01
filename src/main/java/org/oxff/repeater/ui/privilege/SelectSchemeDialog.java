package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.model.Scheme;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.List;

/**
 * 方案选择对话框
 * 当没有启用的方案匹配或没有启用任何方案时，让用户选择一个方案
 */
public class SelectSchemeDialog extends JDialog {

    private boolean confirmed = false;
    private Scheme selectedScheme = null;

    private final JList<Scheme> schemeList;
    private final DefaultListModel<Scheme> listModel;

    public SelectSchemeDialog(Frame owner, List<Scheme> allSchemes, String message) {
        super(owner, "选择方案", true);

        setSize(450, 350);
        setLocationRelativeTo(owner);
        setResizable(false);

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(new EmptyBorder(15, 15, 15, 15));

        // 顶部提示信息
        JLabel messageLabel = new JLabel(message);
        messageLabel.setFont(messageLabel.getFont().deriveFont(Font.BOLD));
        messageLabel.setForeground(new Color(180, 100, 0));
        mainPanel.add(messageLabel, BorderLayout.NORTH);

        // 中部方案列表
        listModel = new DefaultListModel<>();
        if (allSchemes != null) {
            for (Scheme scheme : allSchemes) {
                listModel.addElement(scheme);
            }
        }

        schemeList = new JList<>(listModel);
        schemeList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        schemeList.setCellRenderer(new SchemeListCellRenderer());
        schemeList.setVisibleRowCount(8);

        // 默认选中第一个
        if (listModel.getSize() > 0) {
            schemeList.setSelectedIndex(0);
        }

        JScrollPane scrollPane = new JScrollPane(schemeList);
        scrollPane.setBorder(BorderFactory.createTitledBorder("可用方案"));
        mainPanel.add(scrollPane, BorderLayout.CENTER);

        // 底部按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton okBtn = new JButton("确定");
        JButton cancelBtn = new JButton("取消");

        okBtn.addActionListener(e -> {
            selectedScheme = schemeList.getSelectedValue();
            if (selectedScheme == null) {
                JOptionPane.showMessageDialog(this,
                        "请选择一个方案", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            confirmed = true;
            dispose();
        });

        cancelBtn.addActionListener(e -> dispose());

        buttonPanel.add(okBtn);
        buttonPanel.add(cancelBtn);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        getContentPane().add(mainPanel);
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public Scheme getSelectedScheme() {
        return selectedScheme;
    }

    /**
     * 方案列表单元格渲染器
     */
    private static class SchemeListCellRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value,
                                                      int index, boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            if (value instanceof Scheme scheme) {
                String status = scheme.isEnabled() ? "[已启用]" : "[未启用]";
                int locCount = scheme.getFieldCount();
                setText(String.format("%s %s (%d个字段)", scheme.getName(), status, locCount));
                if (!scheme.isEnabled()) {
                    setForeground(isSelected ? list.getSelectionForeground() : Color.GRAY);
                }
            }
            return this;
        }
    }
}
