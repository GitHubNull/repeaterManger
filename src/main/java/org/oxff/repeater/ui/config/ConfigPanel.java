package org.oxff.repeater.ui.config;

import org.oxff.repeater.config.DatabaseConfig;
import org.oxff.repeater.db.DatabaseManager;
import org.oxff.repeater.i18n.I18nManager;
import org.oxff.repeater.logging.LogLevel;
import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.http.ProxyConfig;
import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.File;

/**
 * 配置面板 - 使用子标签页组织不同类别的配置项
 */
public class ConfigPanel extends JPanel {
    private final DatabaseManager dbManager;

    // 存储配置面板（已提取为独立类）
    private StorageConfigTab storageConfigTab;

    // 日志配置UI组件
    private JComboBox<String> logLevelCombo;
    private JCheckBox fileLogCheckbox;
    private JTextField logDirField;
    private JButton browseLogDirButton;
    private JComboBox<String> maxFileSizeCombo;
    private JComboBox<String> maxBackupCombo;
    private JCheckBox uiLogCheckbox;
    private JComboBox<String> maxEntriesCombo;
    private JCheckBox burpConsoleCheckbox;

    // 代理配置UI组件
    private JCheckBox proxyEnabledCheckbox;
    private JTextField proxyHostField;
    private JTextField proxyPortField;

    // API提取规则面板（已提取为独立类）
    private Runnable onDataChanged;

    // 需要随语言切换刷新的组件
    private JTabbedPane configTabbedPane;
    private JPanel loggingPanel;
    private JPanel proxyPanel;
    private JLabel logLevelLabel;
    private JLabel fileLogLabel;
    private JLabel logDirLabel;
    private JLabel maxFileSizeLabel;
    private JLabel maxBackupLabel;
    private JLabel uiLogLabel;
    private JLabel maxEntriesLabel;
    private JLabel burpConsoleLabel;
    private JButton saveLoggingConfigButton;
    private JLabel proxyDescLabel;
    private JLabel proxyLabel;
    private JLabel proxyHostLabel;
    private JLabel proxyPortLabel;
    private JButton saveProxyConfigButton;

    /**
     * 创建配置面板
     */
    public ConfigPanel() {
        super(new BorderLayout());

        dbManager = DatabaseManager.getInstance();

        // ===== 创建子标签页 =====
        configTabbedPane = new JTabbedPane(JTabbedPane.TOP);

        // ----- 存储配置标签页 -----
        storageConfigTab = new StorageConfigTab(onDataChanged);
        configTabbedPane.addTab(I18nManager.tr("config.tab.storage"), storageConfigTab);

        // ----- 日志标签页 -----
        JPanel loggingTab = createLoggingTab();
        configTabbedPane.addTab(I18nManager.tr("config.tab.log"), loggingTab);

        // ----- 代理调试标签页 -----
        JPanel proxyTab = createProxyTab();
        configTabbedPane.addTab(I18nManager.tr("config.tab.proxy"), proxyTab);

        // ----- API提取规则标签页 -----
        JPanel apiRuleTab = new ApiRuleConfigTab(onDataChanged);
        configTabbedPane.addTab(I18nManager.tr("config.tab.apiRule"), apiRuleTab);

        add(configTabbedPane, BorderLayout.CENTER);

        // 注册语言变更监听器
        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);
    }

    /**
     * 语言切换时刷新所有文本
     */
    private void refreshTexts() {
        configTabbedPane.setTitleAt(0, I18nManager.tr("config.tab.storage"));
        configTabbedPane.setTitleAt(1, I18nManager.tr("config.tab.log"));
        configTabbedPane.setTitleAt(2, I18nManager.tr("config.tab.proxy"));
        configTabbedPane.setTitleAt(3, I18nManager.tr("config.tab.apiRule"));

        // 日志配置面板
        ((TitledBorder) loggingPanel.getBorder()).setTitle(I18nManager.tr("log.config.title"));
        logLevelLabel.setText(I18nManager.tr("log.config.level"));
        fileLogLabel.setText(I18nManager.tr("log.config.file"));
        fileLogCheckbox.setText(I18nManager.tr("log.config.enable"));
        logDirLabel.setText(I18nManager.tr("log.config.dir"));
        browseLogDirButton.setText(I18nManager.tr("log.config.browse"));
        maxFileSizeLabel.setText(I18nManager.tr("log.config.maxFileSize"));
        maxBackupLabel.setText(I18nManager.tr("log.config.maxBackup"));
        uiLogLabel.setText(I18nManager.tr("log.config.ui"));
        uiLogCheckbox.setText(I18nManager.tr("log.config.enable"));
        maxEntriesLabel.setText(I18nManager.tr("log.config.maxEntries"));
        burpConsoleLabel.setText(I18nManager.tr("log.config.burpConsole"));
        burpConsoleCheckbox.setText(I18nManager.tr("log.config.burpConsole.enable"));
        saveLoggingConfigButton.setText(I18nManager.tr("log.config.save"));

        // 代理配置面板
        ((TitledBorder) proxyPanel.getBorder()).setTitle(I18nManager.tr("proxy.config.title"));
        proxyDescLabel.setText(I18nManager.tr("proxy.config.desc"));
        proxyLabel.setText(I18nManager.tr("proxy.config.label"));
        proxyEnabledCheckbox.setText(I18nManager.tr("proxy.config.enable"));
        proxyHostLabel.setText(I18nManager.tr("proxy.config.host"));
        proxyPortLabel.setText(I18nManager.tr("proxy.config.port"));
        saveProxyConfigButton.setText(I18nManager.tr("proxy.config.save"));

        revalidate();
        repaint();
    }

    /**
     * 创建日志配置标签页
     */
    private JPanel createLoggingTab() {
        JPanel tab = new JPanel(new BorderLayout());

        loggingPanel = new JPanel(new GridBagLayout());
        loggingPanel.setBorder(BorderFactory.createTitledBorder(I18nManager.tr("log.config.title")));

        GridBagConstraints dc = new GridBagConstraints();
        dc.fill = GridBagConstraints.HORIZONTAL;
        dc.insets = new Insets(5, 5, 5, 5);

        // 日志级别
        dc.gridx = 0; dc.gridy = 0; dc.gridwidth = 1; dc.weightx = 0;
        logLevelLabel = new JLabel(I18nManager.tr("log.config.level"));
        loggingPanel.add(logLevelLabel, dc);

        dc.gridx = 1; dc.gridy = 0; dc.gridwidth = 2; dc.weightx = 1.0;
        logLevelCombo = new JComboBox<>(new String[]{"DEBUG", "INFO", "WARN", "ERROR"});
        String currentLevel = dbManager.getConfig().getLogLevel();
        logLevelCombo.setSelectedItem(currentLevel);
        loggingPanel.add(logLevelCombo, dc);

        // 文件日志开关
        dc.gridx = 0; dc.gridy = 1; dc.gridwidth = 1; dc.weightx = 0;
        fileLogLabel = new JLabel(I18nManager.tr("log.config.file"));
        loggingPanel.add(fileLogLabel, dc);

        dc.gridx = 1; dc.gridy = 1; dc.gridwidth = 1; dc.weightx = 0;
        fileLogCheckbox = new JCheckBox(I18nManager.tr("log.config.enable"), dbManager.getConfig().isLogFileEnabled());
        loggingPanel.add(fileLogCheckbox, dc);

        // 日志目录行
        dc.gridx = 0; dc.gridy = 2; dc.gridwidth = 1; dc.weightx = 0;
        logDirLabel = new JLabel(I18nManager.tr("log.config.dir"));
        loggingPanel.add(logDirLabel, dc);

        dc.gridx = 1; dc.gridy = 2; dc.gridwidth = 1; dc.weightx = 1.0;
        logDirField = new JTextField(20);
        String logDir = dbManager.getConfig().getLogFileDirectory();
        if (logDir != null && !logDir.isEmpty()) {
            logDirField.setText(logDir);
        } else {
            // 默认使用会话目录的 logs/ 子目录
            File sessionLogsDir = dbManager.getLogsDirectory();
            logDirField.setText(sessionLogsDir != null ? sessionLogsDir.getAbsolutePath() :
                System.getProperty("user.dir") + "/repeater_manager/logs");
        }
        loggingPanel.add(logDirField, dc);

        dc.gridx = 2; dc.gridy = 2; dc.gridwidth = 1; dc.weightx = 0;
        browseLogDirButton = new JButton(I18nManager.tr("log.config.browse"));
        browseLogDirButton.addActionListener(e -> browseForLogDirectory());
        loggingPanel.add(browseLogDirButton, dc);

        // 单文件大小限制
        dc.gridx = 0; dc.gridy = 3; dc.gridwidth = 1; dc.weightx = 0;
        maxFileSizeLabel = new JLabel(I18nManager.tr("log.config.maxFileSize"));
        loggingPanel.add(maxFileSizeLabel, dc);

        dc.gridx = 1; dc.gridy = 3; dc.gridwidth = 2; dc.weightx = 1.0;
        maxFileSizeCombo = new JComboBox<>(new String[]{"1 MB", "5 MB", "10 MB", "50 MB"});
        long currentMaxSize = dbManager.getConfig().getLogFileMaxSize();
        if (currentMaxSize <= 1048576) maxFileSizeCombo.setSelectedIndex(0);
        else if (currentMaxSize <= 5242880) maxFileSizeCombo.setSelectedIndex(1);
        else if (currentMaxSize <= 10485760) maxFileSizeCombo.setSelectedIndex(2);
        else maxFileSizeCombo.setSelectedIndex(3);
        loggingPanel.add(maxFileSizeCombo, dc);

        // 最大备份数
        dc.gridx = 0; dc.gridy = 4; dc.gridwidth = 1; dc.weightx = 0;
        maxBackupLabel = new JLabel(I18nManager.tr("log.config.maxBackup"));
        loggingPanel.add(maxBackupLabel, dc);

        dc.gridx = 1; dc.gridy = 4; dc.gridwidth = 2; dc.weightx = 1.0;
        maxBackupCombo = new JComboBox<>(new String[]{"3", "5", "10", "20"});
        int currentBackups = dbManager.getConfig().getLogFileMaxBackups();
        if (currentBackups <= 3) maxBackupCombo.setSelectedIndex(0);
        else if (currentBackups <= 5) maxBackupCombo.setSelectedIndex(1);
        else if (currentBackups <= 10) maxBackupCombo.setSelectedIndex(2);
        else maxBackupCombo.setSelectedIndex(3);
        loggingPanel.add(maxBackupCombo, dc);

        // UI日志开关 + 最大条目数（放在同一行）
        dc.gridx = 0; dc.gridy = 5; dc.gridwidth = 1; dc.weightx = 0;
        uiLogLabel = new JLabel(I18nManager.tr("log.config.ui"));
        loggingPanel.add(uiLogLabel, dc);

        dc.gridx = 1; dc.gridy = 5; dc.gridwidth = 2; dc.weightx = 1.0;
        uiLogCheckbox = new JCheckBox(I18nManager.tr("log.config.enable"), dbManager.getConfig().isLogUIEnabled());
        maxEntriesCombo = new JComboBox<>(new String[]{"128", "256", "512", "1024"});
        int currentMaxEntries = dbManager.getConfig().getLogUIMaxEntries();
        if (currentMaxEntries <= 128) maxEntriesCombo.setSelectedIndex(0);
        else if (currentMaxEntries <= 256) maxEntriesCombo.setSelectedIndex(1);
        else if (currentMaxEntries <= 512) maxEntriesCombo.setSelectedIndex(2);
        else maxEntriesCombo.setSelectedIndex(3);

        JPanel uiLogRowPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        uiLogRowPanel.add(uiLogCheckbox);
        maxEntriesLabel = new JLabel(I18nManager.tr("log.config.maxEntries"));
        uiLogRowPanel.add(maxEntriesLabel);
        uiLogRowPanel.add(maxEntriesCombo);
        loggingPanel.add(uiLogRowPanel, dc);

        // Burp控制台开关
        dc.gridx = 0; dc.gridy = 6; dc.gridwidth = 1; dc.weightx = 0;
        burpConsoleLabel = new JLabel(I18nManager.tr("log.config.burpConsole"));
        loggingPanel.add(burpConsoleLabel, dc);

        dc.gridx = 1; dc.gridy = 6; dc.gridwidth = 2; dc.weightx = 1.0;
        burpConsoleCheckbox = new JCheckBox(I18nManager.tr("log.config.burpConsole.enable"), dbManager.getConfig().isLogBurpConsoleEnabled());
        loggingPanel.add(burpConsoleCheckbox, dc);

        // 保存日志配置按钮
        dc.gridx = 1; dc.gridy = 7; dc.gridwidth = 2; dc.weightx = 0;
        dc.anchor = GridBagConstraints.EAST;
        saveLoggingConfigButton = new JButton(I18nManager.tr("log.config.save"));
        saveLoggingConfigButton.addActionListener(e -> saveLoggingConfig());
        loggingPanel.add(saveLoggingConfigButton, dc);

        tab.add(loggingPanel, BorderLayout.NORTH);

        return tab;
    }

    /**
     * 创建代理调试标签页
     */
    private JPanel createProxyTab() {
        JPanel tab = new JPanel(new BorderLayout());

        proxyPanel = new JPanel(new GridBagLayout());
        proxyPanel.setBorder(BorderFactory.createTitledBorder(I18nManager.tr("proxy.config.title")));

        GridBagConstraints pc = new GridBagConstraints();
        pc.fill = GridBagConstraints.HORIZONTAL;
        pc.insets = new Insets(5, 5, 5, 5);

        // 说明文字
        pc.gridx = 0; pc.gridy = 0; pc.gridwidth = 3; pc.weightx = 1.0;
        proxyDescLabel = new JLabel(I18nManager.tr("proxy.config.desc"));
        proxyDescLabel.setForeground(new Color(100, 100, 100));
        proxyPanel.add(proxyDescLabel, pc);

        // HTTP代理开关
        pc.gridx = 0; pc.gridy = 1; pc.gridwidth = 1; pc.weightx = 0;
        proxyLabel = new JLabel(I18nManager.tr("proxy.config.label"));
        proxyPanel.add(proxyLabel, pc);

        pc.gridx = 1; pc.gridy = 1; pc.gridwidth = 2; pc.weightx = 1.0;
        ProxyConfig proxyConfig = ProxyConfig.getInstance();
        proxyEnabledCheckbox = new JCheckBox(I18nManager.tr("proxy.config.enable"), proxyConfig.isProxyEnabled());
        proxyPanel.add(proxyEnabledCheckbox, pc);

        // 代理主机
        pc.gridx = 0; pc.gridy = 2; pc.gridwidth = 1; pc.weightx = 0;
        proxyHostLabel = new JLabel(I18nManager.tr("proxy.config.host"));
        proxyPanel.add(proxyHostLabel, pc);

        pc.gridx = 1; pc.gridy = 2; pc.gridwidth = 2; pc.weightx = 1.0;
        proxyHostField = new JTextField(proxyConfig.getProxyHost(), 20);
        proxyPanel.add(proxyHostField, pc);

        // 代理端口
        pc.gridx = 0; pc.gridy = 3; pc.gridwidth = 1; pc.weightx = 0;
        proxyPortLabel = new JLabel(I18nManager.tr("proxy.config.port"));
        proxyPanel.add(proxyPortLabel, pc);

        pc.gridx = 1; pc.gridy = 3; pc.gridwidth = 2; pc.weightx = 1.0;
        proxyPortField = new JTextField(String.valueOf(proxyConfig.getProxyPort()), 10);
        proxyPanel.add(proxyPortField, pc);

        // 保存代理配置按钮
        pc.gridx = 1; pc.gridy = 4; pc.gridwidth = 2; pc.weightx = 0;
        pc.anchor = GridBagConstraints.EAST;
        saveProxyConfigButton = new JButton(I18nManager.tr("proxy.config.save"));
        saveProxyConfigButton.addActionListener(e -> saveProxyConfig());
        proxyPanel.add(saveProxyConfigButton, pc);

        tab.add(proxyPanel, BorderLayout.NORTH);

        return tab;
    }

    /**
     * 刷新存储配置标签页中的信息
     */
    public void refreshStorageInfo() {
        storageConfigTab.refreshStorageInfo();
    }

    // ========== 日志配置相关方法 ==========

    /**
     * 保存日志配置
     */
    private void saveLoggingConfig() {
        DatabaseConfig config = dbManager.getConfig();
        LogManager logManager = LogManager.getInstance();

        // 日志级别
        String level = (String) logLevelCombo.getSelectedItem();
        config.setLogLevel(level);
        logManager.setLevel(LogLevel.fromName(level));

        // 文件日志
        boolean fileEnabled = fileLogCheckbox.isSelected();
        config.setLogFileEnabled(fileEnabled);
        logManager.setFileLoggingEnabled(fileEnabled);

        // 日志目录
        String logDir = logDirField.getText().trim();
        config.setLogFileDirectory(logDir);

        // 单文件大小
        int sizeIndex = maxFileSizeCombo.getSelectedIndex();
        long[] sizes = {1048576, 5242880, 10485760, 52428800};
        config.setLogFileMaxSize(sizes[sizeIndex]);

        // 最大备份数
        int backupIndex = maxBackupCombo.getSelectedIndex();
        int[] backups = {3, 5, 10, 20};
        config.setLogFileMaxBackups(backups[backupIndex]);

        // UI日志
        boolean uiEnabled = uiLogCheckbox.isSelected();
        config.setLogUIEnabled(uiEnabled);
        logManager.setUILoggingEnabled(uiEnabled);

        // 最大条目数
        int entriesIndex = maxEntriesCombo.getSelectedIndex();
        int[] entries = {128, 256, 512, 1024};
        config.setLogUIMaxEntries(entries[entriesIndex]);

        // Burp控制台
        boolean burpEnabled = burpConsoleCheckbox.isSelected();
        config.setLogBurpConsoleEnabled(burpEnabled);
        logManager.setBurpConsoleEnabled(burpEnabled);

        if (config.saveConfig()) {
            logManager.success(I18nManager.tr("log.config.saved"));
            JOptionPane.showMessageDialog(this,
                I18nManager.tr("log.config.saved.msg"),
                I18nManager.tr("log.config.save.success.title"), JOptionPane.INFORMATION_MESSAGE);
        } else {
            logManager.error(I18nManager.tr("log.config.save.failed"));
            JOptionPane.showMessageDialog(this,
                I18nManager.tr("log.config.save.failed.msg"),
                I18nManager.tr("log.config.save.failed.title"), JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * 浏览选择日志目录
     */
    private void browseForLogDirectory() {
        // 优先使用当前日志目录路径
        String preferredDir = logDirField.getText().trim();

        File selectedDir = org.oxff.repeater.utils.FileChooserHelper.showDirectoryDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_LOG_DIRECTORY,
                I18nManager.tr("log.config.select.dir"), this,
                preferredDir);

        if (selectedDir != null) {
            logDirField.setText(selectedDir.getAbsolutePath());
        }
    }

    // ========== 代理配置相关方法 ==========

    /**
     * 保存代理配置
     */
    private void saveProxyConfig() {
        DatabaseConfig config = dbManager.getConfig();
        LogManager logManager = LogManager.getInstance();
        ProxyConfig proxyConfig = ProxyConfig.getInstance();

        proxyConfig.setProxyEnabled(proxyEnabledCheckbox.isSelected());
        proxyConfig.setProxyHost(proxyHostField.getText().trim());
        try {
            proxyConfig.setProxyPort(Integer.parseInt(proxyPortField.getText().trim()));
        } catch (NumberFormatException e) {
            proxyConfig.setProxyPort(8080);
            proxyPortField.setText("8080");
        }
        proxyConfig.saveToConfig(config);

        if (config.saveConfig()) {
            logManager.success(I18nManager.tr("proxy.config.saved"));
            JOptionPane.showMessageDialog(this,
                I18nManager.tr("proxy.config.saved.msg"),
                I18nManager.tr("log.config.save.success.title"), JOptionPane.INFORMATION_MESSAGE);
        } else {
            logManager.error(I18nManager.tr("proxy.config.save.failed"));
            JOptionPane.showMessageDialog(this,
                I18nManager.tr("log.config.save.failed.msg"),
                I18nManager.tr("log.config.save.failed.title"), JOptionPane.ERROR_MESSAGE);
        }
    }

    // ========== API提取规则管理 ==========

    /**
     * 设置数据变更回调（用于通知主UI刷新数据）
     */
    public void setOnDataChanged(Runnable callback) {
        this.onDataChanged = callback;
    }
}
