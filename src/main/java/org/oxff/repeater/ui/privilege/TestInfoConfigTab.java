package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.model.TestInfoConfig;

import javax.swing.*;
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

    /** 保存防抖标志，防止快速双击触发并发保存 */
    private volatile boolean saving = false;

    public TestInfoConfigTab() {
        super(new BorderLayout(0, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // ========== 说明面板 ==========
        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder("说明"));
        JTextArea infoArea = new JTextArea(2, 50);
        infoArea.setEditable(false);
        infoArea.setLineWrap(true);
        infoArea.setText(
            "配置测试目标的可选信息。所有字段均为选填，仅当填写后导出报告时才会在报告中展示。\n"
          + "截图文件支持常见图片格式（PNG、JPG、GIF、BMP），将随报告一同导出。"
        );
        infoPanel.add(infoArea, BorderLayout.CENTER);
        add(infoPanel, BorderLayout.NORTH);

        // ========== 表单面板 ==========
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createTitledBorder("测试信息"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 8, 5, 8);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.NORTHWEST;

        int row = 0;

        // 目标名称
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("目标名称:"), gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1;
        targetNameField = new JTextField(40);
        targetNameField.setToolTipText("测试目标的标识名称，如：XX电商平台用户系统");
        formPanel.add(targetNameField, gbc);

        // 目标入口
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("目标入口:"), gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1;
        targetEntryField = new JTextField(40);
        targetEntryField.setToolTipText("目标入口地址，如 URL 地址、APP 下载链接等");
        formPanel.add(targetEntryField, gbc);

        // 测试时间段
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("测试时间段:"), gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1;
        testTimeRangeField = new JTextField(40);
        testTimeRangeField.setToolTipText("测试执行的时间范围，如：2026-07-01 ~ 2026-07-15");
        formPanel.add(testTimeRangeField, gbc);

        // 测试人员
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("测试人员:"), gbc);
        gbc.gridx = 1; gbc.gridy = row; gbc.weightx = 1;
        testPersonnelField = new JTextField(40);
        testPersonnelField.setToolTipText("参与测试的人员信息，如：张三、李四");
        formPanel.add(testPersonnelField, gbc);

        // 测试目标截图
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0; gbc.gridwidth = 2;
        formPanel.add(new JLabel("测试目标截图:"), gbc);
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
        JButton addScreenshotBtn = new JButton("添加截图");
        JButton removeScreenshotBtn = new JButton("删除选中");
        JButton previewScreenshotBtn = new JButton("预览");
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
        JButton saveBtn = new JButton("保存配置");
        JButton clearBtn = new JButton("清空配置");
        saveBtn.addActionListener(e -> saveConfig());
        clearBtn.addActionListener(e -> clearConfig());
        buttonPanel.add(saveBtn);
        buttonPanel.add(clearBtn);
        add(buttonPanel, BorderLayout.SOUTH);

        // 初始加载
        loadConfig();
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
            StringBuilder sb = new StringBuilder("以下截图文件不存在，保存后报告中将无法显示这些截图：\n\n");
            for (String path : missingFiles) {
                sb.append("  • ").append(path).append("\n");
            }
            sb.append("\n是否仍然继续保存？");
            int choice = JOptionPane.showConfirmDialog(this, sb.toString(),
                    "文件不存在警告", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice != JOptionPane.YES_OPTION) return;
        }

        boolean success = SessionManager.getInstance().saveTestInfoConfig(config);
        if (success) {
            JOptionPane.showMessageDialog(this, "配置保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this, "配置保存失败", "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * 清空所有配置
     */
    private void clearConfig() {
        int confirm = JOptionPane.showConfirmDialog(this,
                "确认清空所有测试信息配置？", "清空确认", JOptionPane.YES_NO_OPTION);
        if (confirm != JOptionPane.YES_OPTION) return;

        SessionManager.getInstance().deleteTestInfoConfig();
        targetNameField.setText("");
        targetEntryField.setText("");
        testTimeRangeField.setText("");
        testPersonnelField.setText("");
        screenshotListModel.clear();
        JOptionPane.showMessageDialog(this, "配置已清空", "提示", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * 添加截图文件
     */
    private void addScreenshot() {
        JFileChooser chooser = new JFileChooser();
        chooser.setMultiSelectionEnabled(true);
        chooser.setFileFilter(new FileNameExtensionFilter(
                "图片文件 (*.png, *.jpg, *.jpeg, *.gif, *.bmp)", "png", "jpg", "jpeg", "gif", "bmp"));
        chooser.setDialogTitle("选择测试目标截图");

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
            JOptionPane.showMessageDialog(this, "请先选择一个截图", "提示", JOptionPane.INFORMATION_MESSAGE);
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
            JOptionPane.showMessageDialog(this, "请先选择一个截图", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String path = screenshotListModel.get(index);
        File file = new File(path);
        if (!file.exists()) {
            JOptionPane.showMessageDialog(this, "截图文件不存在: " + path, "错误", JOptionPane.ERROR_MESSAGE);
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
                    "截图预览 - " + file.getName(), JOptionPane.PLAIN_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "无法加载截图: " + e.getMessage(),
                    "错误", JOptionPane.ERROR_MESSAGE);
        }
    }
}
