package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.i18n.I18nManager;

import javax.swing.*;
import java.awt.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * 日期时间范围选择弹窗
 * 提供开始时间和结束时间的 Spinner 选择界面
 */
public class DateTimeRangePickerDialog extends JDialog {

    private static final String DATETIME_PATTERN = "yyyy-MM-dd HH:mm";
    private static final SimpleDateFormat FORMAT = new SimpleDateFormat(DATETIME_PATTERN);

    private boolean confirmed = false;

    private final JSpinner startSpinner;
    private final JSpinner endSpinner;

    private DateTimeRangePickerDialog(Frame owner, String currentRange) {
        super(owner, I18nManager.tr("datetime.title"), true);
        setLayout(new BorderLayout(10, 10));

        // 解析已有时间范围
        Date startDate = new Date();
        Date endDate = new Date();
        if (currentRange != null && !currentRange.trim().isEmpty()) {
            String[] parts = currentRange.split("~");
            if (parts.length == 2) {
                try {
                    startDate = FORMAT.parse(parts[0].trim());
                } catch (ParseException ignored) { }
                try {
                    endDate = FORMAT.parse(parts[1].trim());
                } catch (ParseException ignored) { }
            }
        }

        // 表单面板
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 10, 15));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // 开始时间
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        formPanel.add(new JLabel(I18nManager.tr("datetime.start")), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        startSpinner = new JSpinner(new SpinnerDateModel(startDate, null, null, java.util.Calendar.MINUTE));
        startSpinner.setEditor(new JSpinner.DateEditor(startSpinner, DATETIME_PATTERN));
        formPanel.add(startSpinner, gbc);

        // 结束时间
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        formPanel.add(new JLabel(I18nManager.tr("datetime.end")), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        endSpinner = new JSpinner(new SpinnerDateModel(endDate, null, null, java.util.Calendar.MINUTE));
        endSpinner.setEditor(new JSpinner.DateEditor(endSpinner, DATETIME_PATTERN));
        formPanel.add(endSpinner, gbc);

        add(formPanel, BorderLayout.CENTER);

        // 按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        JButton okButton = new JButton(I18nManager.tr("common.ok"));
        okButton.addActionListener(e -> {
            Date start = (Date) startSpinner.getValue();
            Date end = (Date) endSpinner.getValue();
            if (start.after(end)) {
                JOptionPane.showMessageDialog(this,
                        I18nManager.tr("datetime.invalid"),
                        I18nManager.tr("datetime.validate.failed"), JOptionPane.WARNING_MESSAGE);
                return;
            }
            confirmed = true;
            dispose();
        });
        JButton cancelButton = new JButton(I18nManager.tr("common.cancel"));
        cancelButton.addActionListener(e -> dispose());
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        add(buttonPanel, BorderLayout.SOUTH);

        // ESC 关闭
        getRootPane().registerKeyboardAction(
                e -> dispose(),
                KeyStroke.getKeyStroke("ESCAPE"),
                JComponent.WHEN_IN_FOCUSED_WINDOW);

        pack();
        setLocationRelativeTo(owner);
        setMinimumSize(new Dimension(320, getHeight()));
        setResizable(false);
    }

    /**
     * 获取格式化后的时间范围字符串
     */
    public String getFormattedRange() {
        Date start = (Date) startSpinner.getValue();
        Date end = (Date) endSpinner.getValue();
        return FORMAT.format(start) + " ~ " + FORMAT.format(end);
    }

    /**
     * 显示时间范围选择对话框
     *
     * @param parent       父组件
     * @param currentRange 当前已填写的时间范围字符串（用于回填），可为 null
     * @return 用户确认后的时间范围字符串；取消时返回 null
     */
    public static String showDialog(Component parent, String currentRange) {
        Frame owner = (Frame) SwingUtilities.getWindowAncestor(parent);
        DateTimeRangePickerDialog dialog = new DateTimeRangePickerDialog(owner, currentRange);
        dialog.setVisible(true);
        if (dialog.confirmed) {
            return dialog.getFormattedRange();
        }
        return null;
    }
}
