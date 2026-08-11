package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.i18n.I18nManager;
import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.model.ReplayConfig;

import javax.swing.*;
import java.awt.*;

/**
 * 重放配置子标签页
 * 管理全局重放参数：模式、超时、并发、重试、延迟等
 */
public class ReplayConfigTab extends JPanel {

    private JRadioButton realtimeRadio;
    private JRadioButton batchRadio;
    private JSpinner timeoutSpinner;
    private JSpinner concurrentSpinner;
    private JSpinner retryCountSpinner;
    private JSpinner retryDelaySpinner;
    private JSpinner replayDelaySpinner;

    private JLabel modeLabel;
    private JLabel timeoutLabel;
    private JLabel timeoutUnitLabel;
    private JLabel threadsLabel;
    private JLabel retryLabel;
    private JLabel retryIntervalLabel;
    private JLabel retryIntervalUnitLabel;
    private JLabel delayLabel;
    private JLabel delayUnitLabel;
    private JButton saveBtn;
    private JButton resetBtn;

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
        modeLabel = new JLabel(I18nManager.tr("replay.mode"));
        configPanel.add(modeLabel, gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JPanel modePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        realtimeRadio = new JRadioButton(I18nManager.tr("replay.mode.realtime"), true);
        batchRadio = new JRadioButton(I18nManager.tr("replay.mode.batch"));
        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(realtimeRadio);
        modeGroup.add(batchRadio);
        modePanel.add(realtimeRadio);
        modePanel.add(batchRadio);
        configPanel.add(modePanel, gbc);

        // 请求超时
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        timeoutLabel = new JLabel(I18nManager.tr("replay.timeout"));
        configPanel.add(timeoutLabel, gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JPanel timeoutPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        timeoutSpinner = new JSpinner(new SpinnerNumberModel(30, 1, 120, 5));
        timeoutSpinner.setPreferredSize(new Dimension(70, 25));
        timeoutPanel.add(timeoutSpinner);
        timeoutUnitLabel = new JLabel(I18nManager.tr("replay.timeout.unit"));
        timeoutPanel.add(timeoutUnitLabel);
        configPanel.add(timeoutPanel, gbc);

        // 并发线程数
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        threadsLabel = new JLabel(I18nManager.tr("replay.threads"));
        configPanel.add(threadsLabel, gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JPanel concurrentPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        concurrentSpinner = new JSpinner(new SpinnerNumberModel(1, 1, 10, 1));
        concurrentSpinner.setPreferredSize(new Dimension(70, 25));
        concurrentPanel.add(concurrentSpinner);
        concurrentPanel.add(new JLabel(I18nManager.tr("replay.threads.range")));
        configPanel.add(concurrentPanel, gbc);

        // 失败重试次数
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        retryLabel = new JLabel(I18nManager.tr("replay.retry"));
        configPanel.add(retryLabel, gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JPanel retryCountPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        retryCountSpinner = new JSpinner(new SpinnerNumberModel(0, 0, 5, 1));
        retryCountSpinner.setPreferredSize(new Dimension(70, 25));
        retryCountPanel.add(retryCountSpinner);
        retryCountPanel.add(new JLabel(I18nManager.tr("replay.retry.range")));
        configPanel.add(retryCountPanel, gbc);

        // 重试间隔
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        retryIntervalLabel = new JLabel(I18nManager.tr("replay.retryInterval"));
        configPanel.add(retryIntervalLabel, gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JPanel retryDelayPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        retryDelaySpinner = new JSpinner(new SpinnerNumberModel(1000, 100, 10000, 500));
        retryDelaySpinner.setPreferredSize(new Dimension(90, 25));
        retryDelayPanel.add(retryDelaySpinner);
        retryIntervalUnitLabel = new JLabel(I18nManager.tr("replay.retryInterval.unit"));
        retryDelayPanel.add(retryIntervalUnitLabel);
        configPanel.add(retryDelayPanel, gbc);

        // 重放间隔延迟
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        delayLabel = new JLabel(I18nManager.tr("replay.delay"));
        configPanel.add(delayLabel, gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JPanel replayDelayPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        replayDelaySpinner = new JSpinner(new SpinnerNumberModel(0, 0, 30000, 100));
        replayDelaySpinner.setPreferredSize(new Dimension(90, 25));
        replayDelayPanel.add(replayDelaySpinner);
        delayUnitLabel = new JLabel(I18nManager.tr("replay.delay.unit"));
        replayDelayPanel.add(delayUnitLabel);
        configPanel.add(replayDelayPanel, gbc);

        // 按钮
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.CENTER;
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 10));

        saveBtn = new JButton(I18nManager.tr("replay.save"));
        saveBtn.setPreferredSize(new Dimension(120, 30));
        saveBtn.addActionListener(e -> saveConfig());

        resetBtn = new JButton(I18nManager.tr("replay.reset"));
        resetBtn.setPreferredSize(new Dimension(120, 30));
        resetBtn.addActionListener(e -> resetDefaults());

        buttonPanel.add(saveBtn);
        buttonPanel.add(resetBtn);
        configPanel.add(buttonPanel, gbc);

        add(configPanel, BorderLayout.NORTH);

        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);
    }

    /**
     * 语言切换时刷新文本
     */
    private void refreshTexts() {
        modeLabel.setText(I18nManager.tr("replay.mode"));
        realtimeRadio.setText(I18nManager.tr("replay.mode.realtime"));
        batchRadio.setText(I18nManager.tr("replay.mode.batch"));
        timeoutLabel.setText(I18nManager.tr("replay.timeout"));
        timeoutUnitLabel.setText(I18nManager.tr("replay.timeout.unit"));
        threadsLabel.setText(I18nManager.tr("replay.threads"));
        retryLabel.setText(I18nManager.tr("replay.retry"));
        retryIntervalLabel.setText(I18nManager.tr("replay.retryInterval"));
        retryIntervalUnitLabel.setText(I18nManager.tr("replay.retryInterval.unit"));
        delayLabel.setText(I18nManager.tr("replay.delay"));
        delayUnitLabel.setText(I18nManager.tr("replay.delay.unit"));
        saveBtn.setText(I18nManager.tr("replay.save"));
        resetBtn.setText(I18nManager.tr("replay.reset"));
    }

    /**
     * 刷新配置数据
     */
    public void refreshData() {
        SessionManager sm = SessionManager.getInstance();
        ReplayConfig config = sm.getReplayConfig();
        realtimeRadio.setSelected(config.isRealtimeMode());
        batchRadio.setSelected(!config.isRealtimeMode());
        timeoutSpinner.setValue(config.getRequestTimeout());
        concurrentSpinner.setValue(config.getMaxConcurrent());
        retryCountSpinner.setValue(config.getRetryCount());
        retryDelaySpinner.setValue(config.getRetryDelay());
        replayDelaySpinner.setValue(config.getReplayDelay());
    }

    private void saveConfig() {
        SessionManager sm = SessionManager.getInstance();
        sm.setRealtimeMode(realtimeRadio.isSelected());
        sm.setRequestTimeout((Integer) timeoutSpinner.getValue());
        sm.setMaxConcurrent((Integer) concurrentSpinner.getValue());
        sm.setRetryCount((Integer) retryCountSpinner.getValue());
        sm.setRetryDelay((Integer) retryDelaySpinner.getValue());
        sm.setReplayDelay((Integer) replayDelaySpinner.getValue());
        JOptionPane.showMessageDialog(this, I18nManager.tr("replay.saved"),
                I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
    }

    private void resetDefaults() {
        ReplayConfig defaults = new ReplayConfig();
        realtimeRadio.setSelected(defaults.isRealtimeMode());
        batchRadio.setSelected(!defaults.isRealtimeMode());
        timeoutSpinner.setValue(defaults.getRequestTimeout());
        concurrentSpinner.setValue(defaults.getMaxConcurrent());
        retryCountSpinner.setValue(defaults.getRetryCount());
        retryDelaySpinner.setValue(defaults.getRetryDelay());
        replayDelaySpinner.setValue(defaults.getReplayDelay());
    }
}
