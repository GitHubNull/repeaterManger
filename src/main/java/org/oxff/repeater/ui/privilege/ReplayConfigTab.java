package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.model.ReplayConfig;

import javax.swing.*;
import java.awt.*;

/**
 * 重放配置子标签页
 * 管理全局重放参数：模式、相似度阈值、超时、并发、重试、延迟等
 */
public class ReplayConfigTab extends JPanel {

    private JRadioButton realtimeRadio;
    private JRadioButton batchRadio;
    private JSpinner thresholdSpinner;
    private JSpinner timeoutSpinner;
    private JSpinner concurrentSpinner;
    private JSpinner retryCountSpinner;
    private JSpinner retryDelaySpinner;
    private JSpinner replayDelaySpinner;

    public ReplayConfigTab() {
        super(new BorderLayout());
        setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        JPanel configPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 10, 5, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;

        int row = 0;

        // 重放模式
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        configPanel.add(new JLabel("重放模式:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JPanel modePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        realtimeRadio = new JRadioButton("实时重放", true);
        batchRadio = new JRadioButton("批量重放");
        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(realtimeRadio);
        modeGroup.add(batchRadio);
        modePanel.add(realtimeRadio);
        modePanel.add(batchRadio);
        configPanel.add(modePanel, gbc);

        // 相似度阈值
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        configPanel.add(new JLabel("相似度阈值:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JPanel thresholdPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        thresholdSpinner = new JSpinner(new SpinnerNumberModel(0.7, 0.0, 1.0, 0.05));
        thresholdSpinner.setPreferredSize(new Dimension(70, 25));
        thresholdPanel.add(thresholdSpinner);
        thresholdPanel.add(new JLabel("(0.0~1.0, 超过此值判定为越权)"));
        configPanel.add(thresholdPanel, gbc);

        // 请求超时
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        configPanel.add(new JLabel("请求超时:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JPanel timeoutPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        timeoutSpinner = new JSpinner(new SpinnerNumberModel(30, 1, 120, 5));
        timeoutSpinner.setPreferredSize(new Dimension(70, 25));
        timeoutPanel.add(timeoutSpinner);
        timeoutPanel.add(new JLabel("秒"));
        configPanel.add(timeoutPanel, gbc);

        // 并发线程数
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        configPanel.add(new JLabel("并发线程数:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JPanel concurrentPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        concurrentSpinner = new JSpinner(new SpinnerNumberModel(1, 1, 10, 1));
        concurrentSpinner.setPreferredSize(new Dimension(70, 25));
        concurrentPanel.add(concurrentSpinner);
        concurrentPanel.add(new JLabel("(1~10)"));
        configPanel.add(concurrentPanel, gbc);

        // 失败重试次数
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        configPanel.add(new JLabel("失败重试次数:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JPanel retryCountPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        retryCountSpinner = new JSpinner(new SpinnerNumberModel(0, 0, 5, 1));
        retryCountSpinner.setPreferredSize(new Dimension(70, 25));
        retryCountPanel.add(retryCountSpinner);
        retryCountPanel.add(new JLabel("(0~5)"));
        configPanel.add(retryCountPanel, gbc);

        // 重试间隔
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        configPanel.add(new JLabel("重试间隔:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JPanel retryDelayPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        retryDelaySpinner = new JSpinner(new SpinnerNumberModel(1000, 100, 10000, 500));
        retryDelaySpinner.setPreferredSize(new Dimension(90, 25));
        retryDelayPanel.add(retryDelaySpinner);
        retryDelayPanel.add(new JLabel("毫秒 (100~10000)"));
        configPanel.add(retryDelayPanel, gbc);

        // 重放间隔延迟
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        configPanel.add(new JLabel("重放间隔延迟:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JPanel replayDelayPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        replayDelaySpinner = new JSpinner(new SpinnerNumberModel(0, 0, 30000, 100));
        replayDelaySpinner.setPreferredSize(new Dimension(90, 25));
        replayDelayPanel.add(replayDelaySpinner);
        replayDelayPanel.add(new JLabel("毫秒 (每次重放前等待)"));
        configPanel.add(replayDelayPanel, gbc);

        // 按钮
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.CENTER;
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 10));

        JButton saveBtn = new JButton("保存配置");
        saveBtn.setPreferredSize(new Dimension(120, 30));
        saveBtn.addActionListener(e -> saveConfig());

        JButton resetBtn = new JButton("恢复默认值");
        resetBtn.setPreferredSize(new Dimension(120, 30));
        resetBtn.addActionListener(e -> resetDefaults());

        buttonPanel.add(saveBtn);
        buttonPanel.add(resetBtn);
        configPanel.add(buttonPanel, gbc);

        add(configPanel, BorderLayout.NORTH);
    }

    /**
     * 刷新配置数据
     */
    public void refreshData() {
        SessionManager sm = SessionManager.getInstance();
        ReplayConfig config = sm.getReplayConfig();
        realtimeRadio.setSelected(config.isRealtimeMode());
        batchRadio.setSelected(!config.isRealtimeMode());
        thresholdSpinner.setValue(config.getSimilarityThreshold());
        timeoutSpinner.setValue(config.getRequestTimeout());
        concurrentSpinner.setValue(config.getMaxConcurrent());
        retryCountSpinner.setValue(config.getRetryCount());
        retryDelaySpinner.setValue(config.getRetryDelay());
        replayDelaySpinner.setValue(config.getReplayDelay());
    }

    private void saveConfig() {
        SessionManager sm = SessionManager.getInstance();
        sm.setRealtimeMode(realtimeRadio.isSelected());
        sm.setSimilarityThreshold((Double) thresholdSpinner.getValue());
        sm.setRequestTimeout((Integer) timeoutSpinner.getValue());
        sm.setMaxConcurrent((Integer) concurrentSpinner.getValue());
        sm.setRetryCount((Integer) retryCountSpinner.getValue());
        sm.setRetryDelay((Integer) retryDelaySpinner.getValue());
        sm.setReplayDelay((Integer) replayDelaySpinner.getValue());
        JOptionPane.showMessageDialog(this, "重放配置已保存", "提示", JOptionPane.INFORMATION_MESSAGE);
    }

    private void resetDefaults() {
        ReplayConfig defaults = new ReplayConfig();
        realtimeRadio.setSelected(defaults.isRealtimeMode());
        batchRadio.setSelected(!defaults.isRealtimeMode());
        thresholdSpinner.setValue(defaults.getSimilarityThreshold());
        timeoutSpinner.setValue(defaults.getRequestTimeout());
        concurrentSpinner.setValue(defaults.getMaxConcurrent());
        retryCountSpinner.setValue(defaults.getRetryCount());
        retryDelaySpinner.setValue(defaults.getRetryDelay());
        replayDelaySpinner.setValue(defaults.getReplayDelay());
    }
}
