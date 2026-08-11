package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.i18n.I18nManager;
import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.model.TestInfoConfig;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * 测试信息配置子标签页
 * 用于配置越权测试目标的可选元信息（目标名称、入口、截图、时间段、人员）
 */
public class TestInfoConfigTab extends JPanel {

    private JTextField targetNameField;
    private JTextField targetEntryField;
    private JTextField testTimeRangeField;
    private JTextField testPersonnelField;
    private DefaultListModel<String> screenshotListModel;
    private JList<String> screenshotList;
    private JCheckBox useDefaultTitleCheckBox;
    private JTextField reportTitleField;
    private JTextField reportSubtitleField;

    private JPanel infoPanel;
    private JTextArea infoArea;
    private JPanel formPanel;
    private JLabel targetNameLabel;
    private JLabel targetEntryLabel;
    private JLabel timeRangeLabel;
    private JLabel testerLabel;
    private JLabel reportTitleLabel;
    private JLabel reportSubtitleLabel;
    private JLabel screenshotsLabel;
    private JButton pickTimeRangeBtn;
    private JButton addScreenshotBtn;
    private JButton removeScreenshotBtn;
    private JButton previewScreenshotBtn;
    private JButton saveBtn;
    private JButton clearBtn;

    /** 保存防抖标志，防止快速双击触发并发保存 */
    private volatile boolean saving = false;

    public TestInfoConfigTab() {
        super(new BorderLayout(0, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // ========== 说明面板 ==========
        infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder(I18nManager.tr("testInfo.note")));
        infoArea = new JTextArea(2, 50);
        infoArea.setEditable(false);
        infoArea.setLineWrap(true);
        infoArea.setText(I18nManager.tr("testInfo.info.text"));
        infoPanel.add(infoArea, BorderLayout.CENTER);
        add(infoPanel, BorderLayout.NORTH);

        // ========== 表单面板 ==========
        formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createTitledBorder(I18nManager.tr("testInfo.title")));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 8, 5, 8);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.NORTHWEST;

        int row = 0;

        // 目标名称
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        targetNameLabel = new JLabel(I18nManager.tr("testInfo.targetName"));
        formPanel.add(targetNameLabel, gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1;
        targetNameField = new JTextField(40);
        targetNameField.setToolTipText(I18nManager.tr("testInfo.targetName.tooltip"));
        formPanel.add(targetNameField, gbc);

        // 目标入口
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        targetEntryLabel = new JLabel(I18nManager.tr("testInfo.targetEntry"));
        formPanel.add(targetEntryLabel, gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1;
        targetEntryField = new JTextField(40);
        targetEntryField.setToolTipText(I18nManager.tr("testInfo.targetEntry.tooltip"));
        formPanel.add(targetEntryField, gbc);

        // 测试时间段
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        timeRangeLabel = new JLabel(I18nManager.tr("testInfo.timeRange"));
        formPanel.add(timeRangeLabel, gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1;
        testTimeRangeField = new JTextField(40);
        testTimeRangeField.setEditable(false);
        testTimeRangeField.setToolTipText(I18nManager.tr("testInfo.timeRange.tooltip"));
        pickTimeRangeBtn = new JButton(I18nManager.tr("testInfo.chooseTime"));
        pickTimeRangeBtn.addActionListener(e -> {
            String result = DateTimeRangePickerDialog.showDialog(this, testTimeRangeField.getText());
            if (result != null) {
                testTimeRangeField.setText(result);
            }
        });
        JPanel timeRangePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        timeRangePanel.add(testTimeRangeField);
        timeRangePanel.add(pickTimeRangeBtn);
        formPanel.add(timeRangePanel, gbc);

        // 测试人员
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        testerLabel = new JLabel(I18nManager.tr("testInfo.tester"));
        formPanel.add(testerLabel, gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1;
        testPersonnelField = new JTextField(40);
        testPersonnelField.setToolTipText(I18nManager.tr("testInfo.tester.tooltip"));
        formPanel.add(testPersonnelField, gbc);

        // 报告标题（带复选框切换默认/自定义）
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        reportTitleLabel = new JLabel(I18nManager.tr("testInfo.reportTitle"));
        formPanel.add(reportTitleLabel, gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1;
        JPanel titlePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        useDefaultTitleCheckBox = new JCheckBox(I18nManager.tr("testInfo.defaultTitle"), true);
        useDefaultTitleCheckBox.setToolTipText(I18nManager.tr("testInfo.defaultTitle.tooltip"));
        reportTitleField = new JTextField(40);
        reportTitleField.setText(I18nManager.tr("testInfo.defaultReportTitle"));
        reportTitleField.setToolTipText(I18nManager.tr("testInfo.reportTitle.tooltip"));
        reportTitleField.setEnabled(false);
        useDefaultTitleCheckBox.addActionListener(e -> {
            boolean useDefault = useDefaultTitleCheckBox.isSelected();
            reportTitleField.setEnabled(!useDefault);
            if (useDefault) {
                reportTitleField.setText(I18nManager.tr("testInfo.defaultReportTitle"));
            }
        });
        titlePanel.add(useDefaultTitleCheckBox);
        titlePanel.add(reportTitleField);
        formPanel.add(titlePanel, gbc);

        // 报告副标题
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        reportSubtitleLabel = new JLabel(I18nManager.tr("testInfo.reportSubtitle"));
        formPanel.add(reportSubtitleLabel, gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1;
        reportSubtitleField = new JTextField(40);
        reportSubtitleField.setToolTipText(I18nManager.tr("testInfo.reportSubtitle.tooltip"));
        formPanel.add(reportSubtitleField, gbc);

        // 测试目标截图
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0; gbc.gridwidth = 2;
        screenshotsLabel = new JLabel(I18nManager.tr("testInfo.screenshots"));
        formPanel.add(screenshotsLabel, gbc);
        gbc.gridwidth = 1;

        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2; gbc.weighty = 0;
        screenshotListModel = new DefaultListModel<>();
        screenshotList = new JList<>(screenshotListModel);
        screenshotList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        screenshotList.setVisibleRowCount(4);
        JScrollPane screenshotScroll = new JScrollPane(screenshotList);
        screenshotScroll.setPreferredSize(new Dimension(0, 80));
        formPanel.add(screenshotScroll, gbc);

        // 截图按钮
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2; gbc.weighty = 0;
        JPanel screenshotBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        addScreenshotBtn = new JButton(I18nManager.tr("testInfo.addScreenshot"));
        removeScreenshotBtn = new JButton(I18nManager.tr("testInfo.removeSelected"));
        previewScreenshotBtn = new JButton(I18nManager.tr("testInfo.preview"));
        addScreenshotBtn.addActionListener(e -> addScreenshot());
        removeScreenshotBtn.addActionListener(e -> removeScreenshot());
        previewScreenshotBtn.addActionListener(e -> previewScreenshot());
        screenshotBtnPanel.add(addScreenshotBtn);
        screenshotBtnPanel.add(removeScreenshotBtn);
        screenshotBtnPanel.add(previewScreenshotBtn);
        formPanel.add(screenshotBtnPanel, gbc);

        add(formPanel, BorderLayout.CENTER);

        // ========== 按钮面板 ==========
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        saveBtn = new JButton(I18nManager.tr("testInfo.save"));
        clearBtn = new JButton(I18nManager.tr("testInfo.clear"));
        saveBtn.addActionListener(e -> saveConfig());
        clearBtn.addActionListener(e -> clearConfig());
        buttonPanel.add(saveBtn);
        buttonPanel.add(clearBtn);
        add(buttonPanel, BorderLayout.SOUTH);

        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);

        // 初始加载
        loadConfig();
    }

    /**
     * 语言切换时刷新文本
     */
    private void refreshTexts() {
        ((TitledBorder) infoPanel.getBorder()).setTitle(I18nManager.tr("testInfo.note"));
        infoArea.setText(I18nManager.tr("testInfo.info.text"));
        ((TitledBorder) formPanel.getBorder()).setTitle(I18nManager.tr("testInfo.title"));
        targetNameLabel.setText(I18nManager.tr("testInfo.targetName"));
        targetNameField.setToolTipText(I18nManager.tr("testInfo.targetName.tooltip"));
        targetEntryLabel.setText(I18nManager.tr("testInfo.targetEntry"));
        targetEntryField.setToolTipText(I18nManager.tr("testInfo.targetEntry.tooltip"));
        timeRangeLabel.setText(I18nManager.tr("testInfo.timeRange"));
        testTimeRangeField.setToolTipText(I18nManager.tr("testInfo.timeRange.tooltip"));
        pickTimeRangeBtn.setText(I18nManager.tr("testInfo.chooseTime"));
        testerLabel.setText(I18nManager.tr("testInfo.tester"));
        testPersonnelField.setToolTipText(I18nManager.tr("testInfo.tester.tooltip"));
        reportTitleLabel.setText(I18nManager.tr("testInfo.reportTitle"));
        useDefaultTitleCheckBox.setText(I18nManager.tr("testInfo.defaultTitle"));
        useDefaultTitleCheckBox.setToolTipText(I18nManager.tr("testInfo.defaultTitle.tooltip"));
        reportTitleField.setToolTipText(I18nManager.tr("testInfo.reportTitle.tooltip"));
        if (useDefaultTitleCheckBox.isSelected()) {
            reportTitleField.setText(I18nManager.tr("testInfo.defaultReportTitle"));
        }
        reportSubtitleLabel.setText(I18nManager.tr("testInfo.reportSubtitle"));
        reportSubtitleField.setToolTipText(I18nManager.tr("testInfo.reportSubtitle.tooltip"));
        screenshotsLabel.setText(I18nManager.tr("testInfo.screenshots"));
        addScreenshotBtn.setText(I18nManager.tr("testInfo.addScreenshot"));
        removeScreenshotBtn.setText(I18nManager.tr("testInfo.removeSelected"));
        previewScreenshotBtn.setText(I18nManager.tr("testInfo.preview"));
        saveBtn.setText(I18nManager.tr("testInfo.save"));
        clearBtn.setText(I18nManager.tr("testInfo.clear"));
        repaint();
    }

    /**
     * 从 SessionManager 加载当前配置到表单
     */
    private void loadConfig() {
        TestInfoConfig config = SessionManager.getInstance().getTestInfoConfig();
        if (config == null) {
            config = new TestInfoConfig();
        }
        targetNameField.setText(config.getTargetName());
        targetEntryField.setText(config.getTargetEntry());
        testTimeRangeField.setText(config.getTestTimeRange());
        testPersonnelField.setText(config.getTestPersonnel());

        // 报告标题
        useDefaultTitleCheckBox.setSelected(config.isUseDefaultTitle());
        if (config.isUseDefaultTitle()) {
            reportTitleField.setText(I18nManager.tr("testInfo.defaultReportTitle"));
            reportTitleField.setEnabled(false);
        } else {
            reportTitleField.setText(config.getReportTitle());
            reportTitleField.setEnabled(true);
        }
        // 报告副标题
        reportSubtitleField.setText(config.getReportSubtitle());

        screenshotListModel.clear();
        if (config.getTargetScreenshots() != null) {
            for (String path : config.getTargetScreenshots()) {
                screenshotListModel.addElement(path);
            }
        }
    }

    /**
     * 保存配置到 SessionManager
     */
    private void saveConfig() {
        if (saving) return;
        saving = true;
        try {
            doSaveConfig();
        } finally {
            saving = false;
        }
    }

    private void doSaveConfig() {
        TestInfoConfig config = new TestInfoConfig();
        config.setTargetName(targetNameField.getText().trim());
        config.setTargetEntry(targetEntryField.getText().trim());
        config.setTestTimeRange(testTimeRangeField.getText().trim());
        config.setTestPersonnel(testPersonnelField.getText().trim());
        config.setUseDefaultTitle(useDefaultTitleCheckBox.isSelected());
        config.setReportTitle(reportTitleField.getText().trim());
        config.setReportSubtitle(reportSubtitleField.getText().trim());

        List<String> screenshots = new ArrayList<>();
        List<String> missingFiles = new ArrayList<>();
        for (int i = 0; i < screenshotListModel.size(); i++) {
            String path = screenshotListModel.get(i);
            screenshots.add(path);
            if (!new File(path).exists()) {
                missingFiles.add(path);
            }
        }
        config.setTargetScreenshots(screenshots);

        // 警告不存在的文件
        if (!missingFiles.isEmpty()) {
            StringBuilder sb = new StringBuilder(I18nManager.tr("testInfo.missingFiles"));
            for (String path : missingFiles) {
                sb.append("  • ").append(path).append("\n");
            }
            sb.append(I18nManager.tr("testInfo.missingFiles.continue"));
            int choice = JOptionPane.showConfirmDialog(this, sb.toString(),
                    I18nManager.tr("testInfo.missingFiles.title"), JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice != JOptionPane.YES_OPTION) return;
        }

        boolean success = SessionManager.getInstance().saveTestInfoConfig(config);
        if (success) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("testInfo.save.success"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this, I18nManager.tr("testInfo.save.failed"),
                    I18nManager.tr("common.error"), JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * 清空所有配置
     */
    private void clearConfig() {
        int confirm = JOptionPane.showConfirmDialog(this,
                I18nManager.tr("testInfo.clear.confirm"),
                I18nManager.tr("testInfo.clear.title"), JOptionPane.YES_NO_OPTION);
        if (confirm != JOptionPane.YES_OPTION) return;

        SessionManager.getInstance().deleteTestInfoConfig();
        targetNameField.setText("");
        targetEntryField.setText("");
        testTimeRangeField.setText("");
        testPersonnelField.setText("");
        useDefaultTitleCheckBox.setSelected(true);
        reportTitleField.setText(I18nManager.tr("testInfo.defaultReportTitle"));
        reportTitleField.setEnabled(false);
        reportSubtitleField.setText("");
        screenshotListModel.clear();
        JOptionPane.showMessageDialog(this, I18nManager.tr("testInfo.cleared"),
                I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * 添加截图文件
     */
    private void addScreenshot() {
        JFileChooser chooser = new JFileChooser();
        chooser.setMultiSelectionEnabled(true);
        chooser.setFileFilter(new FileNameExtensionFilter(
                I18nManager.tr("testInfo.image.filter"), "png", "jpg", "jpeg", "gif", "bmp"));
        chooser.setDialogTitle(I18nManager.tr("testInfo.screenshot.dialog"));

        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File[] files = chooser.getSelectedFiles();
            for (File file : files) {
                String path = file.getAbsolutePath();
                // 避免重复添加
                if (!screenshotListModel.contains(path)) {
                    screenshotListModel.addElement(path);
                }
            }
        }
    }

    /**
     * 删除选中的截图
     */
    private void removeScreenshot() {
        int index = screenshotList.getSelectedIndex();
        if (index < 0) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("testInfo.screenshot.select.first"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        screenshotListModel.remove(index);
    }

    /**
     * 预览选中的截图
     */
    private void previewScreenshot() {
        int index = screenshotList.getSelectedIndex();
        if (index < 0) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("testInfo.screenshot.select.first"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String path = screenshotListModel.get(index);
        File file = new File(path);
        if (!file.exists()) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("testInfo.screenshot.notExist", path),
                    I18nManager.tr("common.error"), JOptionPane.ERROR_MESSAGE);
            return;
        }

        // 在对话框中显示图片预览
        try {
            ImageIcon icon = new ImageIcon(path);
            // 限制预览尺寸
            Image image = icon.getImage();
            int maxW = 600, maxH = 450;
            int w = icon.getIconWidth();
            int h = icon.getIconHeight();
            if (w > maxW || h > maxH) {
                double ratio = Math.min((double) maxW / w, (double) maxH / h);
                w = (int) (w * ratio);
                h = (int) (h * ratio);
                image = image.getScaledInstance(w, h, Image.SCALE_SMOOTH);
                icon = new ImageIcon(image);
            }

            JLabel imageLabel = new JLabel(icon);
            JScrollPane scrollPane = new JScrollPane(imageLabel);
            scrollPane.setPreferredSize(new Dimension(maxW + 20, maxH + 20));

            JOptionPane.showMessageDialog(this, scrollPane,
                    I18nManager.tr("testInfo.screenshot.preview", file.getName()), JOptionPane.PLAIN_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("testInfo.screenshot.load.failed", e.getMessage()),
                    I18nManager.tr("common.error"), JOptionPane.ERROR_MESSAGE);
        }
    }
}
