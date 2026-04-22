package oxff.top.ui;

import oxff.top.config.DatabaseConfig;
import oxff.top.db.DatabaseManager;
import oxff.top.io.DataExporter;
import oxff.top.io.DataImporter;
import oxff.top.logging.LogLevel;
import oxff.top.logging.LogManager;
import oxff.top.http.ProxyConfig;
import burp.BurpExtender;

import javax.swing.*;
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

    /**
     * 创建配置面板
     */
    public ConfigPanel() {
        super(new BorderLayout());

        dbManager = DatabaseManager.getInstance();

        // ===== 创建子标签页 =====
        JTabbedPane configTabbedPane = new JTabbedPane(JTabbedPane.TOP);

        // ----- 存储配置标签页 -----
        storageConfigTab = new StorageConfigTab(onDataChanged);
        configTabbedPane.addTab("存储配置", storageConfigTab);

        // ----- 日志标签页 -----
        JPanel loggingTab = createLoggingTab();
        configTabbedPane.addTab("日志", loggingTab);

        // ----- 代理调试标签页 -----
        JPanel proxyTab = createProxyTab();
        configTabbedPane.addTab("代理调试", proxyTab);

        // ----- 数据导入导出标签页 -----
        JPanel ioTab = createDataIOTab();
        configTabbedPane.addTab("数据导入导出", ioTab);

        // ----- API提取规则标签页 -----
        JPanel apiRuleTab = new ApiRuleConfigTab(onDataChanged);
        configTabbedPane.addTab("API提取规则", apiRuleTab);

        add(configTabbedPane, BorderLayout.CENTER);
    }

    /**
     * 创建日志配置标签页
     */
    private JPanel createLoggingTab() {
        JPanel tab = new JPanel(new BorderLayout());

        JPanel loggingPanel = new JPanel(new GridBagLayout());
        loggingPanel.setBorder(BorderFactory.createTitledBorder("日志配置"));

        GridBagConstraints dc = new GridBagConstraints();
        dc.fill = GridBagConstraints.HORIZONTAL;
        dc.insets = new Insets(5, 5, 5, 5);

        // 日志级别
        dc.gridx = 0; dc.gridy = 0; dc.gridwidth = 1; dc.weightx = 0;
        loggingPanel.add(new JLabel("日志级别:"), dc);

        dc.gridx = 1; dc.gridy = 0; dc.gridwidth = 2; dc.weightx = 1.0;
        logLevelCombo = new JComboBox<>(new String[]{"DEBUG", "INFO", "WARN", "ERROR"});
        String currentLevel = dbManager.getConfig().getLogLevel();
        logLevelCombo.setSelectedItem(currentLevel);
        loggingPanel.add(logLevelCombo, dc);

        // 文件日志开关
        dc.gridx = 0; dc.gridy = 1; dc.gridwidth = 1; dc.weightx = 0;
        loggingPanel.add(new JLabel("文件日志:"), dc);

        dc.gridx = 1; dc.gridy = 1; dc.gridwidth = 1; dc.weightx = 0;
        fileLogCheckbox = new JCheckBox("启用", dbManager.getConfig().isLogFileEnabled());
        loggingPanel.add(fileLogCheckbox, dc);

        // 日志目录行
        dc.gridx = 0; dc.gridy = 2; dc.gridwidth = 1; dc.weightx = 0;
        loggingPanel.add(new JLabel("日志目录:"), dc);

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
        browseLogDirButton = new JButton("浏览...");
        browseLogDirButton.addActionListener(e -> browseForLogDirectory());
        loggingPanel.add(browseLogDirButton, dc);

        // 单文件大小限制
        dc.gridx = 0; dc.gridy = 3; dc.gridwidth = 1; dc.weightx = 0;
        loggingPanel.add(new JLabel("单文件大小:"), dc);

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
        loggingPanel.add(new JLabel("最大备份数:"), dc);

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
        loggingPanel.add(new JLabel("UI日志:"), dc);

        dc.gridx = 1; dc.gridy = 5; dc.gridwidth = 2; dc.weightx = 1.0;
        uiLogCheckbox = new JCheckBox("启用", dbManager.getConfig().isLogUIEnabled());
        maxEntriesCombo = new JComboBox<>(new String[]{"128", "256", "512", "1024"});
        int currentMaxEntries = dbManager.getConfig().getLogUIMaxEntries();
        if (currentMaxEntries <= 128) maxEntriesCombo.setSelectedIndex(0);
        else if (currentMaxEntries <= 256) maxEntriesCombo.setSelectedIndex(1);
        else if (currentMaxEntries <= 512) maxEntriesCombo.setSelectedIndex(2);
        else maxEntriesCombo.setSelectedIndex(3);

        JPanel uiLogRowPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        uiLogRowPanel.add(uiLogCheckbox);
        uiLogRowPanel.add(new JLabel("最大条目数:"));
        uiLogRowPanel.add(maxEntriesCombo);
        loggingPanel.add(uiLogRowPanel, dc);

        // Burp控制台开关
        dc.gridx = 0; dc.gridy = 6; dc.gridwidth = 1; dc.weightx = 0;
        loggingPanel.add(new JLabel("Burp控制台:"), dc);

        dc.gridx = 1; dc.gridy = 6; dc.gridwidth = 2; dc.weightx = 1.0;
        burpConsoleCheckbox = new JCheckBox("启用Burp控制台输出", dbManager.getConfig().isLogBurpConsoleEnabled());
        loggingPanel.add(burpConsoleCheckbox, dc);

        // 保存日志配置按钮
        dc.gridx = 1; dc.gridy = 7; dc.gridwidth = 2; dc.weightx = 0;
        dc.anchor = GridBagConstraints.EAST;
        JButton saveLoggingConfigButton = new JButton("保存日志配置");
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

        JPanel proxyPanel = new JPanel(new GridBagLayout());
        proxyPanel.setBorder(BorderFactory.createTitledBorder("HTTP代理配置"));

        GridBagConstraints pc = new GridBagConstraints();
        pc.fill = GridBagConstraints.HORIZONTAL;
        pc.insets = new Insets(5, 5, 5, 5);

        // 说明文字
        pc.gridx = 0; pc.gridy = 0; pc.gridwidth = 3; pc.weightx = 1.0;
        JLabel descLabel = new JLabel("配置HTTP代理用于调试，代理将影响插件发出的所有HTTP请求");
        descLabel.setForeground(new Color(100, 100, 100));
        proxyPanel.add(descLabel, pc);

        // HTTP代理开关
        pc.gridx = 0; pc.gridy = 1; pc.gridwidth = 1; pc.weightx = 0;
        proxyPanel.add(new JLabel("HTTP代理:"), pc);

        pc.gridx = 1; pc.gridy = 1; pc.gridwidth = 2; pc.weightx = 1.0;
        ProxyConfig proxyConfig = ProxyConfig.getInstance();
        proxyEnabledCheckbox = new JCheckBox("启用代理（调试用）", proxyConfig.isProxyEnabled());
        proxyPanel.add(proxyEnabledCheckbox, pc);

        // 代理主机
        pc.gridx = 0; pc.gridy = 2; pc.gridwidth = 1; pc.weightx = 0;
        proxyPanel.add(new JLabel("代理主机:"), pc);

        pc.gridx = 1; pc.gridy = 2; pc.gridwidth = 2; pc.weightx = 1.0;
        proxyHostField = new JTextField(proxyConfig.getProxyHost(), 20);
        proxyPanel.add(proxyHostField, pc);

        // 代理端口
        pc.gridx = 0; pc.gridy = 3; pc.gridwidth = 1; pc.weightx = 0;
        proxyPanel.add(new JLabel("代理端口:"), pc);

        pc.gridx = 1; pc.gridy = 3; pc.gridwidth = 2; pc.weightx = 1.0;
        proxyPortField = new JTextField(String.valueOf(proxyConfig.getProxyPort()), 10);
        proxyPanel.add(proxyPortField, pc);

        // 保存代理配置按钮
        pc.gridx = 1; pc.gridy = 4; pc.gridwidth = 2; pc.weightx = 0;
        pc.anchor = GridBagConstraints.EAST;
        JButton saveProxyConfigButton = new JButton("保存代理配置");
        saveProxyConfigButton.addActionListener(e -> saveProxyConfig());
        proxyPanel.add(saveProxyConfigButton, pc);

        tab.add(proxyPanel, BorderLayout.NORTH);

        return tab;
    }

    /**
     * 创建数据导入导出标签页
     */
    private JPanel createDataIOTab() {
        JPanel tab = new JPanel(new BorderLayout());

        JPanel ioPanel = new JPanel(new BorderLayout());
        ioPanel.setBorder(BorderFactory.createTitledBorder("数据导入导出"));

        JPanel rowsPanel = new JPanel();
        rowsPanel.setLayout(new BoxLayout(rowsPanel, BoxLayout.Y_AXIS));

        // ERM存档行
        JPanel ermRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        ermRow.add(new JLabel("ERM存档 (.erm):"));
        JCheckBox encryptCheckbox = new JCheckBox("加密");
        JButton exportErmButton = new JButton("导出");
        exportErmButton.addActionListener(e -> exportErm(encryptCheckbox.isSelected()));
        ermRow.add(exportErmButton);
        ermRow.add(encryptCheckbox);
        JButton importErmButton = new JButton("导入");
        importErmButton.addActionListener(e -> importErm());
        ermRow.add(importErmButton);
        rowsPanel.add(ermRow);

        // Postman行
        JPanel postmanRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        postmanRow.add(new JLabel("Postman v2.1 (.json):"));
        JButton exportPostmanButton = new JButton("导出");
        exportPostmanButton.addActionListener(e -> exportToPostman());
        postmanRow.add(exportPostmanButton);
        JButton importPostmanButton = new JButton("导入");
        importPostmanButton.addActionListener(e -> importFromPostman());
        postmanRow.add(importPostmanButton);
        rowsPanel.add(postmanRow);

        // 智能导入行
        JPanel smartRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        JButton smartImportButton = new JButton("智能导入 (自动检测格式)");
        smartImportButton.addActionListener(e -> smartImport());
        smartRow.add(smartImportButton);
        rowsPanel.add(smartRow);

        ioPanel.add(rowsPanel, BorderLayout.CENTER);

        tab.add(ioPanel, BorderLayout.NORTH);

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
            logManager.success("[+] 日志配置已保存");
            JOptionPane.showMessageDialog(this,
                "日志配置已保存并生效。\n注意：文件日志目录和大小变更需重启后完全生效。",
                "保存成功", JOptionPane.INFORMATION_MESSAGE);
        } else {
            logManager.error("[!] 保存日志配置失败");
            JOptionPane.showMessageDialog(this,
                "保存配置失败，请检查权限或路径。", "保存失败", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * 浏览选择日志目录
     */
    private void browseForLogDirectory() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("选择日志目录");
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        String currentLogDir = logDirField.getText().trim();
        if (currentLogDir != null && !currentLogDir.isEmpty()) {
            File dir = new File(currentLogDir);
            if (dir.exists()) {
                fileChooser.setCurrentDirectory(dir);
            }
        }

        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            logDirField.setText(fileChooser.getSelectedFile().getAbsolutePath());
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
            logManager.success("[+] 代理配置已保存");
            JOptionPane.showMessageDialog(this,
                "代理配置已保存。",
                "保存成功", JOptionPane.INFORMATION_MESSAGE);
        } else {
            logManager.error("[!] 保存代理配置失败");
            JOptionPane.showMessageDialog(this,
                "保存配置失败，请检查权限或路径。", "保存失败", JOptionPane.ERROR_MESSAGE);
        }
    }

    // ========== 数据导入导出方法 ==========

    private void exportErm(boolean encrypted) {
        try {
            BurpExtender.printOutput("[*] 正在启动ERM存档导出...");
            DataExporter exporter = new DataExporter();
            exporter.exportToErm(this, encrypted);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导出操作发生错误: " + e.getMessage(), "导出错误", JOptionPane.ERROR_MESSAGE);
            BurpExtender.printError("[!] 导出错误: " + e.getMessage());
        }
    }

    private void importErm() {
        try {
            BurpExtender.printOutput("[*] 正在启动ERM存档导入...");
            DataImporter importer = new DataImporter();
            importer.importFromErm(this);
            refreshStorageInfo();
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导入操作发生错误: " + e.getMessage(), "导入错误", JOptionPane.ERROR_MESSAGE);
            BurpExtender.printError("[!] 导入错误: " + e.getMessage());
        }
    }

    private void exportToPostman() {
        try {
            BurpExtender.printOutput("[*] 正在启动Postman Collection导出...");
            DataExporter exporter = new DataExporter();
            exporter.exportToPostman(this);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导出操作发生错误: " + e.getMessage(), "导出错误", JOptionPane.ERROR_MESSAGE);
            BurpExtender.printError("[!] 导出错误: " + e.getMessage());
        }
    }

    private void importFromPostman() {
        try {
            BurpExtender.printOutput("[*] 正在启动Postman Collection导入...");
            DataImporter importer = new DataImporter();
            importer.importFromPostman(this);
            refreshStorageInfo();
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导入操作发生错误: " + e.getMessage(), "导入错误", JOptionPane.ERROR_MESSAGE);
            BurpExtender.printError("[!] 导入错误: " + e.getMessage());
        }
    }

    private void smartImport() {
        try {
            BurpExtender.printOutput("[*] 正在启动智能导入...");
            DataImporter importer = new DataImporter();
            importer.smartImport(this);
            refreshStorageInfo();
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导入操作发生错误: " + e.getMessage(), "导入错误", JOptionPane.ERROR_MESSAGE);
            BurpExtender.printError("[!] 导入错误: " + e.getMessage());
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
