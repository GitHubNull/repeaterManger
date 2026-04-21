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
 * 配置面板 - 用于配置存储和数据导入导出功能
 */
public class ConfigPanel extends JPanel {
    private final DatabaseManager dbManager;

    // 存储配置UI组件
    private final JComboBox<String> storageModeCombo;
    private final JTextField currentDbPathField;
    private final JTextField baseDirField;
    private final JButton browseDirButton;
    private final JButton resetDirButton;
    private final JTextField sessionFileField;
    private final JButton applySessionFileButton;
    private final JCheckBox autoSaveCheckbox;
    private final JComboBox<String> saveIntervalCombo;

    // 日志与调试配置UI组件
    private final JComboBox<String> logLevelCombo;
    private final JCheckBox fileLogCheckbox;
    private final JTextField logDirField;
    private final JButton browseLogDirButton;
    private final JComboBox<String> maxFileSizeCombo;
    private final JComboBox<String> maxBackupCombo;
    private final JCheckBox uiLogCheckbox;
    private final JComboBox<String> maxEntriesCombo;
    private final JCheckBox burpConsoleCheckbox;
    private final JCheckBox proxyEnabledCheckbox;
    private final JTextField proxyHostField;
    private final JTextField proxyPortField;

    /**
     * 创建配置面板
     */
    public ConfigPanel() {
        super(new BorderLayout());

        dbManager = DatabaseManager.getInstance();

        // 创建存储配置区域
        JPanel storagePanel = new JPanel(new GridBagLayout());
        storagePanel.setBorder(BorderFactory.createTitledBorder("存储配置"));

        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(5, 5, 5, 5);

        // 存储模式
        c.gridx = 0; c.gridy = 0; c.gridwidth = 1; c.weightx = 0;
        storagePanel.add(new JLabel("存储模式:"), c);

        c.gridx = 1; c.gridy = 0; c.gridwidth = 2; c.weightx = 1.0;
        String[] modes = {"自动 (默认)", "指定目录", "指定文件"};
        storageModeCombo = new JComboBox<>(modes);
        String currentMode = dbManager.getConfig().getStorageMode();
        if (DatabaseConfig.MODE_DIRECTORY.equals(currentMode)) {
            storageModeCombo.setSelectedIndex(1);
        } else if (DatabaseConfig.MODE_FILE.equals(currentMode)) {
            storageModeCombo.setSelectedIndex(2);
        } else {
            storageModeCombo.setSelectedIndex(0);
        }
        storageModeCombo.addActionListener(e -> onStorageModeChanged());
        storagePanel.add(storageModeCombo, c);

        // 当前数据库文件
        c.gridx = 0; c.gridy = 1; c.gridwidth = 1; c.weightx = 0;
        storagePanel.add(new JLabel("当前数据库:"), c);

        c.gridx = 1; c.gridy = 1; c.gridwidth = 2; c.weightx = 1.0;
        currentDbPathField = new JTextField(30);
        currentDbPathField.setEditable(false);
        currentDbPathField.setBackground(new Color(240, 240, 240));
        updateCurrentDbPathField();
        storagePanel.add(currentDbPathField, c);

        // 存储目录
        c.gridx = 0; c.gridy = 2; c.gridwidth = 1; c.weightx = 0;
        storagePanel.add(new JLabel("存储目录:"), c);

        c.gridx = 1; c.gridy = 2; c.gridwidth = 1; c.weightx = 1.0;
        baseDirField = new JTextField(25);
        baseDirField.setEditable(false);
        baseDirField.setBackground(new Color(240, 240, 240));
        updateBaseDirField();
        storagePanel.add(baseDirField, c);

        c.gridx = 2; c.gridy = 2; c.gridwidth = 1; c.weightx = 0;
        JPanel dirButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        browseDirButton = new JButton("浏览目录...");
        browseDirButton.addActionListener(e -> browseForDirectory());
        resetDirButton = new JButton("重置为默认");
        resetDirButton.addActionListener(e -> resetToDefaultDirectory());
        dirButtonPanel.add(browseDirButton);
        dirButtonPanel.add(resetDirButton);
        storagePanel.add(dirButtonPanel, c);

        // 当前会话文件名
        c.gridx = 0; c.gridy = 3; c.gridwidth = 1; c.weightx = 0;
        storagePanel.add(new JLabel("会话文件名:"), c);

        c.gridx = 1; c.gridy = 3; c.gridwidth = 1; c.weightx = 1.0;
        sessionFileField = new JTextField(25);
        storagePanel.add(sessionFileField, c);

        c.gridx = 2; c.gridy = 3; c.gridwidth = 1; c.weightx = 0;
        applySessionFileButton = new JButton("应用");
        applySessionFileButton.addActionListener(e -> applySessionFile());
        storagePanel.add(applySessionFileButton, c);

        // 自动保存配置
        c.gridx = 0; c.gridy = 4; c.gridwidth = 1; c.weightx = 0;
        storagePanel.add(new JLabel("自动保存:"), c);

        c.gridx = 1; c.gridy = 4; c.gridwidth = 2; c.weightx = 1.0;
        autoSaveCheckbox = new JCheckBox("启用自动保存", dbManager.getConfig().isAutoSaveEnabled());
        storagePanel.add(autoSaveCheckbox, c);

        // 保存间隔
        c.gridx = 0; c.gridy = 5; c.gridwidth = 1; c.weightx = 0;
        storagePanel.add(new JLabel("保存间隔:"), c);

        c.gridx = 1; c.gridy = 5; c.gridwidth = 2; c.weightx = 1.0;
        String[] intervals = {"1分钟", "5分钟", "10分钟", "30分钟", "60分钟"};
        saveIntervalCombo = new JComboBox<>(intervals);
        int currentInterval = dbManager.getConfig().getAutoSaveInterval();
        if (currentInterval <= 1) saveIntervalCombo.setSelectedIndex(0);
        else if (currentInterval <= 5) saveIntervalCombo.setSelectedIndex(1);
        else if (currentInterval <= 10) saveIntervalCombo.setSelectedIndex(2);
        else if (currentInterval <= 30) saveIntervalCombo.setSelectedIndex(3);
        else saveIntervalCombo.setSelectedIndex(4);
        storagePanel.add(saveIntervalCombo, c);

        // 保存配置按钮
        c.gridx = 1; c.gridy = 6; c.gridwidth = 2; c.weightx = 0;
        c.anchor = GridBagConstraints.EAST;
        JButton saveConfigButton = new JButton("保存配置");
        saveConfigButton.addActionListener(e -> saveConfig());
        storagePanel.add(saveConfigButton, c);

        // ===== 日志与调试配置区域 =====
        JPanel debugPanel = new JPanel(new GridBagLayout());
        debugPanel.setBorder(BorderFactory.createTitledBorder("日志与调试配置"));
        GridBagConstraints dc = new GridBagConstraints();
        dc.fill = GridBagConstraints.HORIZONTAL;
        dc.insets = new Insets(5, 5, 5, 5);

        // 日志级别
        dc.gridx = 0; dc.gridy = 0; dc.gridwidth = 1; dc.weightx = 0;
        debugPanel.add(new JLabel("日志级别:"), dc);

        dc.gridx = 1; dc.gridy = 0; dc.gridwidth = 2; dc.weightx = 1.0;
        logLevelCombo = new JComboBox<>(new String[]{"DEBUG", "INFO", "WARN", "ERROR"});
        String currentLevel = dbManager.getConfig().getLogLevel();
        logLevelCombo.setSelectedItem(currentLevel);
        debugPanel.add(logLevelCombo, dc);

        // 文件日志开关
        dc.gridx = 0; dc.gridy = 1; dc.gridwidth = 1; dc.weightx = 0;
        debugPanel.add(new JLabel("文件日志:"), dc);

        dc.gridx = 1; dc.gridy = 1; dc.gridwidth = 1; dc.weightx = 0;
        fileLogCheckbox = new JCheckBox("启用", dbManager.getConfig().isLogFileEnabled());
        debugPanel.add(fileLogCheckbox, dc);

        dc.gridx = 2; dc.gridy = 1; dc.gridwidth = 1; dc.weightx = 1.0;
        // 日志目录行
        dc.gridx = 0; dc.gridy = 2; dc.gridwidth = 1; dc.weightx = 0;
        debugPanel.add(new JLabel("日志目录:"), dc);

        dc.gridx = 1; dc.gridy = 2; dc.gridwidth = 1; dc.weightx = 1.0;
        logDirField = new JTextField(20);
        String logDir = dbManager.getConfig().getLogFileDirectory();
        logDirField.setText(logDir != null && !logDir.isEmpty() ? logDir :
            System.getProperty("user.dir") + "/repeater_manager/logs");
        debugPanel.add(logDirField, dc);

        dc.gridx = 2; dc.gridy = 2; dc.gridwidth = 1; dc.weightx = 0;
        browseLogDirButton = new JButton("浏览...");
        browseLogDirButton.addActionListener(e -> browseForLogDirectory());
        debugPanel.add(browseLogDirButton, dc);

        // 单文件大小限制
        dc.gridx = 0; dc.gridy = 3; dc.gridwidth = 1; dc.weightx = 0;
        debugPanel.add(new JLabel("单文件大小:"), dc);

        dc.gridx = 1; dc.gridy = 3; dc.gridwidth = 2; dc.weightx = 1.0;
        maxFileSizeCombo = new JComboBox<>(new String[]{"1 MB", "5 MB", "10 MB", "50 MB"});
        long currentMaxSize = dbManager.getConfig().getLogFileMaxSize();
        if (currentMaxSize <= 1048576) maxFileSizeCombo.setSelectedIndex(0);
        else if (currentMaxSize <= 5242880) maxFileSizeCombo.setSelectedIndex(1);
        else if (currentMaxSize <= 10485760) maxFileSizeCombo.setSelectedIndex(2);
        else maxFileSizeCombo.setSelectedIndex(3);
        debugPanel.add(maxFileSizeCombo, dc);

        // 最大备份数
        dc.gridx = 0; dc.gridy = 4; dc.gridwidth = 1; dc.weightx = 0;
        debugPanel.add(new JLabel("最大备份数:"), dc);

        dc.gridx = 1; dc.gridy = 4; dc.gridwidth = 2; dc.weightx = 1.0;
        maxBackupCombo = new JComboBox<>(new String[]{"3", "5", "10", "20"});
        int currentBackups = dbManager.getConfig().getLogFileMaxBackups();
        if (currentBackups <= 3) maxBackupCombo.setSelectedIndex(0);
        else if (currentBackups <= 5) maxBackupCombo.setSelectedIndex(1);
        else if (currentBackups <= 10) maxBackupCombo.setSelectedIndex(2);
        else maxBackupCombo.setSelectedIndex(3);
        debugPanel.add(maxBackupCombo, dc);

        // UI日志开关
        dc.gridx = 0; dc.gridy = 5; dc.gridwidth = 1; dc.weightx = 0;
        debugPanel.add(new JLabel("UI日志:"), dc);

        dc.gridx = 1; dc.gridy = 5; dc.gridwidth = 1; dc.weightx = 0;
        uiLogCheckbox = new JCheckBox("启用", dbManager.getConfig().isLogUIEnabled());
        debugPanel.add(uiLogCheckbox, dc);

        dc.gridx = 2; dc.gridy = 5; dc.gridwidth = 1; dc.weightx = 0;
        debugPanel.add(new JLabel("最大条目数:"), dc);

        // 最大条目数（放在同一行）
        JPanel maxEntriesPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        maxEntriesCombo = new JComboBox<>(new String[]{"128", "256", "512", "1024"});
        int currentMaxEntries = dbManager.getConfig().getLogUIMaxEntries();
        if (currentMaxEntries <= 128) maxEntriesCombo.setSelectedIndex(0);
        else if (currentMaxEntries <= 256) maxEntriesCombo.setSelectedIndex(1);
        else if (currentMaxEntries <= 512) maxEntriesCombo.setSelectedIndex(2);
        else maxEntriesCombo.setSelectedIndex(3);
        maxEntriesPanel.add(maxEntriesCombo);

        // 这里将最大条目数放在第5行后面（通过修改gridx）
        dc.gridx = 1; dc.gridy = 5; dc.gridwidth = 2; dc.weightx = 1.0;
        JPanel uiLogRowPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        uiLogRowPanel.add(uiLogCheckbox);
        uiLogRowPanel.add(new JLabel("最大条目数:"));
        uiLogRowPanel.add(maxEntriesCombo);
        debugPanel.add(uiLogRowPanel, dc);

        // Burp控制台开关
        dc.gridx = 0; dc.gridy = 6; dc.gridwidth = 1; dc.weightx = 0;
        debugPanel.add(new JLabel("Burp控制台:"), dc);

        dc.gridx = 1; dc.gridy = 6; dc.gridwidth = 2; dc.weightx = 1.0;
        burpConsoleCheckbox = new JCheckBox("启用Burp控制台输出", dbManager.getConfig().isLogBurpConsoleEnabled());
        debugPanel.add(burpConsoleCheckbox, dc);

        // 代理配置分隔
        dc.gridx = 0; dc.gridy = 7; dc.gridwidth = 3; dc.weightx = 1.0;
        debugPanel.add(new JSeparator(), dc);

        // HTTP代理开关
        dc.gridx = 0; dc.gridy = 8; dc.gridwidth = 1; dc.weightx = 0;
        debugPanel.add(new JLabel("HTTP代理:"), dc);

        dc.gridx = 1; dc.gridy = 8; dc.gridwidth = 2; dc.weightx = 1.0;
        ProxyConfig proxyConfig = ProxyConfig.getInstance();
        proxyEnabledCheckbox = new JCheckBox("启用代理（调试用）", proxyConfig.isProxyEnabled());
        debugPanel.add(proxyEnabledCheckbox, dc);

        // 代理主机
        dc.gridx = 0; dc.gridy = 9; dc.gridwidth = 1; dc.weightx = 0;
        debugPanel.add(new JLabel("代理主机:"), dc);

        dc.gridx = 1; dc.gridy = 9; dc.gridwidth = 2; dc.weightx = 1.0;
        proxyHostField = new JTextField(proxyConfig.getProxyHost(), 20);
        debugPanel.add(proxyHostField, dc);

        // 代理端口
        dc.gridx = 0; dc.gridy = 10; dc.gridwidth = 1; dc.weightx = 0;
        debugPanel.add(new JLabel("代理端口:"), dc);

        dc.gridx = 1; dc.gridy = 10; dc.gridwidth = 2; dc.weightx = 1.0;
        proxyPortField = new JTextField(String.valueOf(proxyConfig.getProxyPort()), 10);
        debugPanel.add(proxyPortField, dc);

        // 保存配置按钮（调试区域）
        dc.gridx = 1; dc.gridy = 11; dc.gridwidth = 2; dc.weightx = 0;
        dc.anchor = GridBagConstraints.EAST;
        JButton saveDebugConfigButton = new JButton("保存日志与调试配置");
        saveDebugConfigButton.addActionListener(e -> saveDebugConfig());
        debugPanel.add(saveDebugConfigButton, dc);

        // 导入导出面板
        JPanel ioPanel = new JPanel(new BorderLayout());
        ioPanel.setBorder(BorderFactory.createTitledBorder("数据导入导出"));

        JPanel rowsPanel = new JPanel();
        rowsPanel.setLayout(new BoxLayout(rowsPanel, BoxLayout.Y_AXIS));

        // SQLite3行
        JPanel sqliteRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        sqliteRow.add(new JLabel("SQLite3 (.sqlite3):"));
        JButton exportDbButton = new JButton("导出");
        exportDbButton.addActionListener(e -> exportDatabase());
        sqliteRow.add(exportDbButton);
        JButton importDbButton = new JButton("导入");
        importDbButton.addActionListener(e -> importDatabase());
        sqliteRow.add(importDbButton);
        rowsPanel.add(sqliteRow);

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

        // 创建顶部面板
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(storagePanel, BorderLayout.NORTH);

        // 中间面板包含日志配置和导入导出
        JPanel middlePanel = new JPanel(new BorderLayout());
        middlePanel.add(debugPanel, BorderLayout.NORTH);
        middlePanel.add(ioPanel, BorderLayout.CENTER);
        topPanel.add(middlePanel, BorderLayout.CENTER);

        add(topPanel, BorderLayout.NORTH);

        // 信息面板
        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder("数据库信息"));

        JTextArea infoArea = new JTextArea(10, 40);
        infoArea.setEditable(false);
        updateInfoArea(infoArea);
        infoPanel.add(new JScrollPane(infoArea), BorderLayout.CENTER);

        add(infoPanel, BorderLayout.CENTER);

        // 初始化UI状态
        onStorageModeChanged();
    }

    private void updateCurrentDbPathField() {
        String path = dbManager.getCurrentDatabasePath();
        if (path == null) {
            path = dbManager.getConfig().getEffectiveDatabasePath();
        }
        currentDbPathField.setText(path);
    }

    private void updateBaseDirField() {
        String mode = dbManager.getConfig().getStorageMode();
        if (DatabaseConfig.MODE_DIRECTORY.equals(mode)) {
            String baseDir = dbManager.getConfig().getBaseDirectory();
            if (baseDir != null && !baseDir.isEmpty()) {
                baseDirField.setText(baseDir);
            } else {
                baseDirField.setText(DatabaseConfig.getDefaultBaseDirectory());
            }
        } else {
            baseDirField.setText(DatabaseConfig.getDefaultBaseDirectory());
        }
    }

    private void updateInfoArea(JTextArea infoArea) {
        String path = dbManager.getCurrentDatabasePath();
        if (path == null) {
            path = dbManager.getConfig().getEffectiveDatabasePath();
        }
        infoArea.setText(
            "当前数据库文件: " + path + "\n" +
            "存储模式: " + getModeDisplayName(dbManager.getConfig().getStorageMode()) + "\n" +
            "自动保存: " + (dbManager.getConfig().isAutoSaveEnabled() ? "启用" : "禁用") + "\n" +
            "保存间隔: " + dbManager.getConfig().getAutoSaveInterval() + "分钟\n\n" +
            "说明:\n" +
            "- 每次加载插件或重启Burp Suite都会自动生成新的数据库文件\n" +
            "- 旧的数据库文件会保留在存储目录中\n" +
            "- 可以配置存储目录，但文件名仍然会自动生成\n" +
            "- 指定文件仅对当前会话有效，重启后会恢复自动命名"
        );
    }

    private String getModeDisplayName(String mode) {
        switch (mode) {
            case DatabaseConfig.MODE_AUTO: return "自动 (默认)";
            case DatabaseConfig.MODE_DIRECTORY: return "指定目录";
            case DatabaseConfig.MODE_FILE: return "指定文件";
            default: return mode;
        }
    }

    private void onStorageModeChanged() {
        int modeIndex = storageModeCombo.getSelectedIndex();

        switch (modeIndex) {
            case 0: // 自动
                browseDirButton.setEnabled(false);
                resetDirButton.setEnabled(false);
                sessionFileField.setEnabled(false);
                applySessionFileButton.setEnabled(false);
                break;
            case 1: // 指定目录
                browseDirButton.setEnabled(true);
                resetDirButton.setEnabled(true);
                sessionFileField.setEnabled(false);
                applySessionFileButton.setEnabled(false);
                break;
            case 2: // 指定文件
                browseDirButton.setEnabled(false);
                resetDirButton.setEnabled(false);
                sessionFileField.setEnabled(true);
                applySessionFileButton.setEnabled(true);
                break;
        }
    }

    private void browseForDirectory() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("选择存储目录");
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        String currentBaseDir = dbManager.getConfig().getBaseDirectory();
        if (currentBaseDir != null && !currentBaseDir.isEmpty()) {
            fileChooser.setCurrentDirectory(new File(currentBaseDir));
        } else {
            fileChooser.setCurrentDirectory(new File(DatabaseConfig.getDefaultBaseDirectory()));
        }

        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedDir = fileChooser.getSelectedFile();
            dbManager.getConfig().setBaseDirectory(selectedDir.getAbsolutePath());
            dbManager.getConfig().setStorageMode(DatabaseConfig.MODE_DIRECTORY);
            baseDirField.setText(selectedDir.getAbsolutePath());

            // 重置并重新初始化以使用新目录
            dbManager.resetForNewSession();
            if (dbManager.initialize()) {
                updateCurrentDbPathField();
                JOptionPane.showMessageDialog(this,
                    "已切换到新存储目录并生成新的数据库文件。\n旧数据在当前会话中不再可用。",
                    "目录已更改", JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    private void resetToDefaultDirectory() {
        dbManager.getConfig().setBaseDirectory("");
        dbManager.getConfig().setStorageMode(DatabaseConfig.MODE_AUTO);
        dbManager.getConfig().setSessionFile(null);
        baseDirField.setText(DatabaseConfig.getDefaultBaseDirectory());

        dbManager.resetForNewSession();
        if (dbManager.initialize()) {
            updateCurrentDbPathField();
            storageModeCombo.setSelectedIndex(0);
            onStorageModeChanged();
            JOptionPane.showMessageDialog(this,
                "已重置为默认存储目录。", "重置成功", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void applySessionFile() {
        String filePath = sessionFileField.getText().trim();
        if (filePath.isEmpty()) {
            JOptionPane.showMessageDialog(this, "请输入文件名", "输入错误", JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (!filePath.toLowerCase().endsWith(".sqlite3") && !filePath.toLowerCase().endsWith(".db")) {
            filePath += ".sqlite3";
        }

        File file = new File(filePath);
        File parentDir = file.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs();
        }

        dbManager.getConfig().setSessionFile(file.getAbsolutePath());
        dbManager.getConfig().setStorageMode(DatabaseConfig.MODE_FILE);

        dbManager.resetForNewSession();
        if (dbManager.initialize()) {
            updateCurrentDbPathField();
            JOptionPane.showMessageDialog(this,
                "已应用会话文件名: " + file.getAbsolutePath() + "\n注意：此设置仅在当前会话有效。",
                "应用成功", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void saveConfig() {
        // 保存存储模式
        int modeIndex = storageModeCombo.getSelectedIndex();
        switch (modeIndex) {
            case 0:
                dbManager.getConfig().setStorageMode(DatabaseConfig.MODE_AUTO);
                break;
            case 1:
                dbManager.getConfig().setStorageMode(DatabaseConfig.MODE_DIRECTORY);
                break;
            case 2:
                dbManager.getConfig().setStorageMode(DatabaseConfig.MODE_FILE);
                break;
        }

        // 清除会话文件（下次启动使用自动命名）
        dbManager.getConfig().setSessionFile(null);

        // 保存自动保存配置
        boolean autoSave = autoSaveCheckbox.isSelected();
        dbManager.getConfig().setProperty(DatabaseConfig.KEY_AUTO_SAVE, String.valueOf(autoSave));

        // 保存间隔时间
        int intervalIndex = saveIntervalCombo.getSelectedIndex();
        int intervalMinutes = 5;
        switch (intervalIndex) {
            case 0: intervalMinutes = 1; break;
            case 1: intervalMinutes = 5; break;
            case 2: intervalMinutes = 10; break;
            case 3: intervalMinutes = 30; break;
            case 4: intervalMinutes = 60; break;
        }
        dbManager.getConfig().setProperty(DatabaseConfig.KEY_SAVE_INTERVAL, String.valueOf(intervalMinutes));

        if (dbManager.getConfig().saveConfig()) {
            JOptionPane.showMessageDialog(this,
                "配置已保存。\n注意：会话文件名设置不会被保存，下次启动将恢复自动命名。",
                "保存成功", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this,
                "保存配置失败，请检查权限或路径。", "保存失败", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * 保存日志与调试配置
     */
    private void saveDebugConfig() {
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

        // 代理配置
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
            logManager.success("[+] 日志与调试配置已保存");
            JOptionPane.showMessageDialog(this,
                "日志与调试配置已保存并生效。\n注意：文件日志目录和大小变更需重启后完全生效。",
                "保存成功", JOptionPane.INFORMATION_MESSAGE);
        } else {
            logManager.error("[!] 保存日志与调试配置失败");
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

    // 导出导入方法
    private void exportDatabase() {
        try {
            BurpExtender.printOutput("[*] 正在启动SQLite数据库导出...");
            DataExporter exporter = new DataExporter();
            exporter.exportToSQLite(this);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导出操作发生错误: " + e.getMessage(), "导出错误", JOptionPane.ERROR_MESSAGE);
            BurpExtender.printError("[!] 导出错误: " + e.getMessage());
        }
    }

    private void importDatabase() {
        try {
            BurpExtender.printOutput("[*] 正在启动SQLite数据库导入...");
            DataImporter importer = new DataImporter();
            importer.importFromSQLite(this);
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
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导入操作发生错误: " + e.getMessage(), "导入错误", JOptionPane.ERROR_MESSAGE);
            BurpExtender.printError("[!] 导入错误: " + e.getMessage());
        }
    }
}
