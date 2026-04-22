package oxff.top.ui;

import oxff.top.config.DatabaseConfig;
import oxff.top.db.DatabaseManager;
import oxff.top.io.DataExporter;
import oxff.top.io.DataImporter;
import oxff.top.logging.LogLevel;
import oxff.top.logging.LogManager;
import oxff.top.http.ProxyConfig;
import oxff.top.api.ApiExtractionRule;
import oxff.top.api.ApiExtractionEngine;
import oxff.top.api.ApiRuleManager;
import oxff.top.api.ApiRuleSource;
import oxff.top.api.ApiRuleMethod;
import oxff.top.api.ApiExtractionRuleDAO;
import oxff.top.db.RequestDAO;
import oxff.top.db.pool.ContentSplitter;
import oxff.top.db.pool.SplitResult;
import burp.BurpExtender;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.RowFilter;
import java.awt.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 配置面板 - 使用子标签页组织不同类别的配置项
 */
public class ConfigPanel extends JPanel {
    private final DatabaseManager dbManager;

    // 存储配置UI组件
    private JComboBox<String> storageModeCombo;
    private JTextField currentDbPathField;
    private JTextField baseDirField;
    private JButton browseDirButton;
    private JButton resetDirButton;
    private JTextField sessionFileField;
    private JButton applySessionFileButton;
    private JCheckBox autoSaveCheckbox;
    private JComboBox<String> saveIntervalCombo;
    private JTextArea infoArea;

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

    // API提取规则UI组件
    private JTable apiRuleTable;
    private ApiRuleTableModel apiRuleTableModel;
    private TableRowSorter<ApiRuleTableModel> apiRuleSorter;
    private JTextField apiSearchField;
    private JPanel advancedSearchPanel;
    private JButton advancedSearchToggleBtn;
    private JComboBox<String> advSourceFilterCombo;
    private JComboBox<String> advMethodFilterCombo;
    private JComboBox<String> advEnabledFilterCombo;
    private JCheckBox advRegexMatchCheckbox;
    private JTextField advExpressionField;
    private JTextField testPathField;
    private JTextField testQueryField;
    private JTextArea testHeadersArea;
    private JTextArea testBodyArea;
    private JTextField testContentTypeField;
    private JTextField testResultField;
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
        JPanel storageTab = createStorageTab();
        configTabbedPane.addTab("存储配置", storageTab);

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
        JPanel apiRuleTab = createApiRuleTab();
        configTabbedPane.addTab("API提取规则", apiRuleTab);

        add(configTabbedPane, BorderLayout.CENTER);

        // 初始化UI状态
        onStorageModeChanged();
    }

    /**
     * 创建存储配置标签页
     */
    private JPanel createStorageTab() {
        JPanel tab = new JPanel(new BorderLayout());

        // 存储设置区域
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

        // 当前会话目录
        c.gridx = 0; c.gridy = 1; c.gridwidth = 1; c.weightx = 0;
        storagePanel.add(new JLabel("当前会话:"), c);

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

        tab.add(storagePanel, BorderLayout.NORTH);

        // 数据库信息区域
        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder("数据库信息"));

        infoArea = new JTextArea(10, 40);
        infoArea.setEditable(false);
        updateInfoArea();
        infoPanel.add(new JScrollPane(infoArea), BorderLayout.CENTER);

        tab.add(infoPanel, BorderLayout.CENTER);

        return tab;
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

    // ========== 存储配置相关方法 ==========

    private void updateCurrentDbPathField() {
        // 显示会话目录路径（比固定名称的数据库文件更有意义）
        oxff.top.config.SessionDirectory sessionDir = dbManager.getConfig().getOrCreateSessionDirectory();
        if (sessionDir != null) {
            currentDbPathField.setText(sessionDir.getAbsolutePath());
        } else {
            // 回退：显示数据库文件路径
            String path = dbManager.getCurrentDatabasePath();
            if (path == null) {
                path = dbManager.getConfig().getEffectiveDatabasePath();
            }
            currentDbPathField.setText(path);
        }
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

    private void updateInfoArea() {
        oxff.top.config.SessionDirectory sessionDir = dbManager.getConfig().getOrCreateSessionDirectory();
        String sessionDirPath = sessionDir != null ? sessionDir.getAbsolutePath() : "未创建";
        String dbPath = dbManager.getCurrentDatabasePath();
        if (dbPath == null) {
            dbPath = dbManager.getConfig().getEffectiveDatabasePath();
        }
        String blobsDir = sessionDir != null ? sessionDir.getBlobsDir().getAbsolutePath() : "-";
        String logsDir = sessionDir != null ? sessionDir.getLogsDir().getAbsolutePath() : "-";

        infoArea.setText(
            "当前会话目录: " + sessionDirPath + "\n" +
            "数据库文件: " + dbPath + "\n" +
            "Body数据目录: " + blobsDir + "\n" +
            "日志目录: " + logsDir + "\n" +
            "存储模式: " + getModeDisplayName(dbManager.getConfig().getStorageMode()) + "\n" +
            "自动保存: " + (dbManager.getConfig().isAutoSaveEnabled() ? "启用" : "禁用") + "\n" +
            "保存间隔: " + dbManager.getConfig().getAutoSaveInterval() + "分钟\n\n" +
            "说明:\n" +
            "- 每次加载插件或重启Burp Suite都会自动生成新的会话目录\n" +
            "- 会话目录以时间戳命名，内含数据库、body数据、日志\n" +
            "- 旧的会话目录会保留在存储目录中\n" +
            "- 可以配置基础存储目录，会话目录名仍然会自动生成\n" +
            "- 指定文件模式不创建时间戳子目录，数据存放在DB文件同目录"
        );
    }

    /**
     * 刷新存储配置标签页中的信息
     */
    public void refreshStorageInfo() {
        updateCurrentDbPathField();
        updateBaseDirField();
        updateInfoArea();
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
                // 重定位日志到新会话目录
                LogManager.getInstance().relocateFileHandler(
                    dbManager.getLogsDirectory().getAbsolutePath());
                refreshStorageInfo();
                JOptionPane.showMessageDialog(this,
                    "已切换到新存储目录并生成新的会话目录。\n旧数据在当前会话中不再可用。",
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
            // 重定位日志到新会话目录
            LogManager.getInstance().relocateFileHandler(
                dbManager.getLogsDirectory().getAbsolutePath());
            refreshStorageInfo();
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
            // 重定位日志到新会话目录
            LogManager.getInstance().relocateFileHandler(
                dbManager.getLogsDirectory().getAbsolutePath());
            refreshStorageInfo();
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

    /**
     * 创建API提取规则管理标签页
     */
    private JPanel createApiRuleTab() {
        JPanel tab = new JPanel(new BorderLayout(5, 5));
        tab.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // ===== 顶部：搜索区域 =====
        JPanel topPanel = new JPanel(new BorderLayout(3, 3));

        // 简单搜索行
        JPanel searchRow = new JPanel(new BorderLayout(5, 0));
        searchRow.add(new JLabel("搜索:"), BorderLayout.WEST);
        apiSearchField = new JTextField(20);
        apiSearchField.setToolTipText("输入关键词搜索规则（匹配来源、方法、表达式）");
        apiSearchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyApiRuleFilter(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyApiRuleFilter(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyApiRuleFilter(); }
        });
        searchRow.add(apiSearchField, BorderLayout.CENTER);

        advancedSearchToggleBtn = new JButton("▶ 高级搜索");
        advancedSearchToggleBtn.setToolTipText("展开/折叠高级搜索条件");
        advancedSearchToggleBtn.addActionListener(e -> toggleAdvancedSearch());
        searchRow.add(advancedSearchToggleBtn, BorderLayout.EAST);

        topPanel.add(searchRow, BorderLayout.NORTH);

        // 高级搜索面板（默认折叠）
        advancedSearchPanel = new JPanel(new GridBagLayout());
        advancedSearchPanel.setBorder(BorderFactory.createTitledBorder("高级搜索"));
        advancedSearchPanel.setVisible(false);

        GridBagConstraints ac = new GridBagConstraints();
        ac.fill = GridBagConstraints.HORIZONTAL;
        ac.insets = new Insets(2, 5, 2, 5);

        // 来源筛选
        ac.gridx = 0; ac.gridy = 0; ac.weightx = 0;
        advancedSearchPanel.add(new JLabel("来源:"), ac);
        ac.gridx = 1; ac.gridy = 0; ac.weightx = 1.0;
        advSourceFilterCombo = new JComboBox<>(new String[]{"全部", "URL路径", "URL参数", "请求头", "请求体"});
        advSourceFilterCombo.addActionListener(e -> applyApiRuleFilter());
        advancedSearchPanel.add(advSourceFilterCombo, ac);

        // 方法筛选
        ac.gridx = 2; ac.gridy = 0; ac.weightx = 0;
        advancedSearchPanel.add(new JLabel("方法:"), ac);
        ac.gridx = 3; ac.gridy = 0; ac.weightx = 1.0;
        advMethodFilterCombo = new JComboBox<>(new String[]{"全部", "正则匹配", "子串截取", "JSON路径", "XPath"});
        advMethodFilterCombo.addActionListener(e -> applyApiRuleFilter());
        advancedSearchPanel.add(advMethodFilterCombo, ac);

        // 启用状态筛选
        ac.gridx = 0; ac.gridy = 1; ac.weightx = 0;
        advancedSearchPanel.add(new JLabel("启用状态:"), ac);
        ac.gridx = 1; ac.gridy = 1; ac.weightx = 1.0;
        advEnabledFilterCombo = new JComboBox<>(new String[]{"全部", "已启用", "已禁用"});
        advEnabledFilterCombo.addActionListener(e -> applyApiRuleFilter());
        advancedSearchPanel.add(advEnabledFilterCombo, ac);

        // 表达式匹配
        ac.gridx = 2; ac.gridy = 1; ac.weightx = 0;
        advancedSearchPanel.add(new JLabel("表达式:"), ac);
        ac.gridx = 3; ac.gridy = 1; ac.weightx = 1.0;
        JPanel exprPanel = new JPanel(new BorderLayout(3, 0));
        advRegexMatchCheckbox = new JCheckBox("正则匹配");
        advExpressionField = new JTextField(15);
        advExpressionField.setToolTipText("表达式搜索内容");
        advExpressionField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyApiRuleFilter(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyApiRuleFilter(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyApiRuleFilter(); }
        });
        advRegexMatchCheckbox.addActionListener(e -> applyApiRuleFilter());
        exprPanel.add(advRegexMatchCheckbox, BorderLayout.WEST);
        exprPanel.add(advExpressionField, BorderLayout.CENTER);
        advancedSearchPanel.add(exprPanel, ac);

        topPanel.add(advancedSearchPanel, BorderLayout.CENTER);
        tab.add(topPanel, BorderLayout.NORTH);

        // ===== 中间：规则表格 =====
        apiRuleTableModel = new ApiRuleTableModel();
        apiRuleTable = new JTable(apiRuleTableModel);
        apiRuleTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        apiRuleTable.setRowHeight(22);
        apiRuleTable.getColumnModel().getColumn(0).setPreferredWidth(50);  // 优先级
        apiRuleTable.getColumnModel().getColumn(1).setPreferredWidth(80);  // 名称
        apiRuleTable.getColumnModel().getColumn(2).setPreferredWidth(70);  // 来源
        apiRuleTable.getColumnModel().getColumn(3).setPreferredWidth(70);  // 方法
        apiRuleTable.getColumnModel().getColumn(4).setPreferredWidth(250); // 表达式
        apiRuleTable.getColumnModel().getColumn(5).setPreferredWidth(50);  // 启用
        apiRuleTable.getColumnModel().getColumn(6).setPreferredWidth(120); // 备注

        // 排序器
        apiRuleSorter = new TableRowSorter<>(apiRuleTableModel);
        apiRuleTable.setRowSorter(apiRuleSorter);

        // 双击编辑
        apiRuleTable.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    editApiRule();
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(apiRuleTable);
        tab.add(tableScroll, BorderLayout.CENTER);

        // ===== 按钮行 =====
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 3));
        JButton addRuleBtn = new JButton("添加规则");
        addRuleBtn.addActionListener(e -> addApiRule());
        JButton editRuleBtn = new JButton("编辑规则");
        editRuleBtn.addActionListener(e -> editApiRule());
        JButton deleteRuleBtn = new JButton("删除规则");
        deleteRuleBtn.addActionListener(e -> deleteApiRule());
        JButton reExtractBtn = new JButton("重新提取所有API");
        reExtractBtn.setToolTipText("使用当前规则重新计算所有请求和历史记录的API值");
        reExtractBtn.addActionListener(e -> reExtractAllApis());

        buttonPanel.add(addRuleBtn);
        buttonPanel.add(editRuleBtn);
        buttonPanel.add(deleteRuleBtn);
        buttonPanel.add(Box.createHorizontalStrut(20));
        buttonPanel.add(reExtractBtn);
        tab.add(buttonPanel, BorderLayout.SOUTH);

        // ===== 右侧：规则测试区域 =====
        JPanel testWrapper = new JPanel(new BorderLayout(5, 5));
        testWrapper.setBorder(BorderFactory.createTitledBorder("规则测试"));

        JPanel testPanel = new JPanel(new GridBagLayout());
        GridBagConstraints tc = new GridBagConstraints();
        tc.fill = GridBagConstraints.HORIZONTAL;
        tc.insets = new Insets(2, 5, 2, 5);

        // URL路径
        tc.gridx = 0; tc.gridy = 0; tc.weightx = 0;
        testPanel.add(new JLabel("URL路径:"), tc);
        tc.gridx = 1; tc.gridy = 0; tc.weightx = 1.0; tc.gridwidth = 2;
        testPathField = new JTextField("/api/v1/users");
        testPanel.add(testPathField, tc);

        // URL参数
        tc.gridx = 0; tc.gridy = 1; tc.weightx = 0; tc.gridwidth = 1;
        testPanel.add(new JLabel("URL参数:"), tc);
        tc.gridx = 1; tc.gridy = 1; tc.weightx = 1.0; tc.gridwidth = 2;
        testQueryField = new JTextField("action=getUser&id=1");
        testPanel.add(testQueryField, tc);

        // 请求头
        tc.gridx = 0; tc.gridy = 2; tc.weightx = 0; tc.gridwidth = 1;
        testPanel.add(new JLabel("请求头:"), tc);
        tc.gridx = 1; tc.gridy = 2; tc.weightx = 1.0; tc.gridwidth = 2;
        testHeadersArea = new JTextArea(3, 30);
        testHeadersArea.setText("Host: example.com\nContent-Type: application/json");
        testHeadersArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        testPanel.add(new JScrollPane(testHeadersArea), tc);

        // 请求体
        tc.gridx = 0; tc.gridy = 3; tc.weightx = 0; tc.gridwidth = 1;
        testPanel.add(new JLabel("请求体:"), tc);
        tc.gridx = 1; tc.gridy = 3; tc.weightx = 1.0; tc.gridwidth = 2;
        testBodyArea = new JTextArea(3, 30);
        testBodyArea.setText("{\"api\": \"login\"}");
        testBodyArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        testPanel.add(new JScrollPane(testBodyArea), tc);

        // Content-Type
        tc.gridx = 0; tc.gridy = 4; tc.weightx = 0; tc.gridwidth = 1;
        testPanel.add(new JLabel("Content-Type:"), tc);
        tc.gridx = 1; tc.gridy = 4; tc.weightx = 1.0; tc.gridwidth = 2;
        testContentTypeField = new JTextField("application/json");
        testPanel.add(testContentTypeField, tc);

        // 测试按钮
        tc.gridx = 0; tc.gridy = 5; tc.weightx = 0; tc.gridwidth = 1;
        JButton testExtractBtn = new JButton("测试提取");
        testExtractBtn.addActionListener(e -> testApiExtraction());
        testPanel.add(testExtractBtn, tc);

        // 测试结果
        tc.gridx = 1; tc.gridy = 5; tc.weightx = 1.0; tc.gridwidth = 2;
        testResultField = new JTextField();
        testResultField.setEditable(false);
        testResultField.setBackground(new Color(240, 240, 240));
        testPanel.add(testResultField, tc);

        // 说明
        tc.gridx = 0; tc.gridy = 6; tc.weightx = 1.0; tc.gridwidth = 3;
        tc.fill = GridBagConstraints.BOTH;
        JTextArea descArea = new JTextArea(
            "说明:\n" +
            "• 规则按优先级执行，首次匹配成功即返回结果\n" +
            "• 若无规则或所有规则未匹配，则使用URL路径作为API\n" +
            "• URL参数来源从URL的query字符串中提取（如 action=getUser）\n" +
            "• substr格式: START,END (END关键字表示到末尾, 负数从末尾计)\n" +
            "• 请求体提取仅对文本类型有效(JSON/XML/表单/纯文本)"
        );
        descArea.setEditable(false);
        descArea.setOpaque(false);
        descArea.setFont(descArea.getFont().deriveFont(Font.PLAIN, 11f));
        testPanel.add(descArea, tc);

        testWrapper.add(testPanel, BorderLayout.NORTH);

        // 使用JSplitPane分割表格和测试区域
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, testWrapper);
        splitPane.setResizeWeight(0.6);
        splitPane.setDividerLocation(300);

        // 替换之前的tableScroll
        tab.remove(tableScroll);
        tab.remove(buttonPanel);
        tab.add(splitPane, BorderLayout.CENTER);
        tab.add(buttonPanel, BorderLayout.SOUTH);

        // 初始化加载数据
        refreshApiRuleTable();

        return tab;
    }

    /**
     * 切换高级搜索面板的显示/隐藏
     */
    private void toggleAdvancedSearch() {
        boolean visible = !advancedSearchPanel.isVisible();
        advancedSearchPanel.setVisible(visible);
        advancedSearchToggleBtn.setText(visible ? "▼ 高级搜索" : "▶ 高级搜索");
        if (!visible) {
            // 折叠时清除高级搜索条件
            advSourceFilterCombo.setSelectedIndex(0);
            advMethodFilterCombo.setSelectedIndex(0);
            advEnabledFilterCombo.setSelectedIndex(0);
            advRegexMatchCheckbox.setSelected(false);
            advExpressionField.setText("");
            applyApiRuleFilter();
        }
    }

    /**
     * 应用搜索过滤
     */
    private void applyApiRuleFilter() {
        String keyword = apiSearchField.getText().trim().toLowerCase();
        boolean advancedVisible = advancedSearchPanel.isVisible();

        // 高级搜索条件
        String sourceFilter = advancedVisible ? (String) advSourceFilterCombo.getSelectedItem() : "全部";
        String methodFilter = advancedVisible ? (String) advMethodFilterCombo.getSelectedItem() : "全部";
        String enabledFilter = advancedVisible ? (String) advEnabledFilterCombo.getSelectedItem() : "全部";
        boolean regexMatch = advancedVisible && advRegexMatchCheckbox.isSelected();
        String exprText = advancedVisible ? advExpressionField.getText().trim() : "";

        RowFilter<ApiRuleTableModel, Integer> filter = new RowFilter<ApiRuleTableModel, Integer>() {
            @Override
            public boolean include(Entry<? extends ApiRuleTableModel, ? extends Integer> entry) {
                ApiExtractionRule rule = apiRuleTableModel.getRule(entry.getIdentifier());

                // 简单关键词搜索
                if (!keyword.isEmpty()) {
                    String allText = (rule.getName() + " " +
                            rule.getSource().getDisplayName() + " " +
                            rule.getMethod().getDisplayName() + " " +
                            rule.getExpression() + " " +
                            rule.getRemark()).toLowerCase();
                    if (!allText.contains(keyword)) {
                        return false;
                    }
                }

                // 高级搜索：来源筛选
                if (!"全部".equals(sourceFilter)) {
                    if (!rule.getSource().getDisplayName().equals(sourceFilter)) {
                        return false;
                    }
                }

                // 高级搜索：方法筛选
                if (!"全部".equals(methodFilter)) {
                    if (!rule.getMethod().getDisplayName().equals(methodFilter)) {
                        return false;
                    }
                }

                // 高级搜索：启用状态筛选
                if ("已启用".equals(enabledFilter) && !rule.isEnabled()) {
                    return false;
                }
                if ("已禁用".equals(enabledFilter) && rule.isEnabled()) {
                    return false;
                }

                // 高级搜索：表达式匹配
                if (!exprText.isEmpty()) {
                    if (regexMatch) {
                        try {
                            if (!Pattern.compile(exprText).matcher(rule.getExpression()).find()) {
                                return false;
                            }
                        } catch (Exception e) {
                            return false;
                        }
                    } else {
                        if (!rule.getExpression().toLowerCase().contains(exprText.toLowerCase())) {
                            return false;
                        }
                    }
                }

                return true;
            }
        };

        apiRuleSorter.setRowFilter(filter);
    }

    /**
     * 刷新规则表格数据
     */
    private void refreshApiRuleTable() {
        ApiExtractionRuleDAO dao = new ApiExtractionRuleDAO();
        List<ApiExtractionRule> rules = dao.getAllRules();
        apiRuleTableModel.setRules(rules);
    }

    /**
     * 添加规则
     */
    private void addApiRule() {
        ApiExtractionRule newRule = new ApiExtractionRule();
        newRule.setPriority(apiRuleTableModel.getRowCount() + 1);
        if (showRuleEditDialog(newRule, true)) {
            ApiExtractionRuleDAO dao = new ApiExtractionRuleDAO();
            int id = dao.saveRule(newRule);
            if (id > 0) {
                ApiRuleManager.getInstance().refreshCache();
                refreshApiRuleTable();
            } else {
                JOptionPane.showMessageDialog(this, "保存规则失败", "错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /**
     * 编辑规则
     */
    private void editApiRule() {
        int viewRow = apiRuleTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一条规则", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = apiRuleTable.convertRowIndexToModel(viewRow);
        ApiExtractionRule rule = apiRuleTableModel.getRule(modelRow);
        if (rule == null) return;

        if (showRuleEditDialog(rule, false)) {
            ApiExtractionRuleDAO dao = new ApiExtractionRuleDAO();
            if (dao.updateRule(rule)) {
                ApiRuleManager.getInstance().refreshCache();
                refreshApiRuleTable();
            } else {
                JOptionPane.showMessageDialog(this, "更新规则失败", "错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /**
     * 删除规则
     */
    private void deleteApiRule() {
        int viewRow = apiRuleTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一条规则", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = apiRuleTable.convertRowIndexToModel(viewRow);
        ApiExtractionRule rule = apiRuleTableModel.getRule(modelRow);
        if (rule == null) return;

        int confirm = JOptionPane.showConfirmDialog(this,
                "确定要删除此规则吗？\n名称: " + rule.getName() +
                "\n来源: " + rule.getSource().getDisplayName() +
                "\n方法: " + rule.getMethod().getDisplayName() +
                "\n表达式: " + rule.getExpression(),
                "确认删除", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm == JOptionPane.YES_OPTION) {
            ApiExtractionRuleDAO dao = new ApiExtractionRuleDAO();
            if (dao.deleteRule(rule.getId())) {
                ApiRuleManager.getInstance().refreshCache();
                refreshApiRuleTable();
            } else {
                JOptionPane.showMessageDialog(this, "删除规则失败", "错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /**
     * 显示规则编辑对话框
     * @return true表示用户点击了确定
     */
    private boolean showRuleEditDialog(ApiExtractionRule rule, boolean isNew) {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this),
                isNew ? "添加API提取规则" : "编辑API提取规则", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        GridBagConstraints fc = new GridBagConstraints();
        fc.fill = GridBagConstraints.HORIZONTAL;
        fc.insets = new Insets(5, 5, 5, 5);

        // 优先级
        fc.gridx = 0; fc.gridy = 0; fc.weightx = 0;
        formPanel.add(new JLabel("优先级:"), fc);
        fc.gridx = 1; fc.gridy = 0; fc.weightx = 1.0; fc.gridwidth = 2;
        JSpinner prioritySpinner = new JSpinner(new SpinnerNumberModel(rule.getPriority(), 1, 999, 1));
        formPanel.add(prioritySpinner, fc);

        // 名称
        fc.gridx = 0; fc.gridy = 1; fc.weightx = 0; fc.gridwidth = 1;
        formPanel.add(new JLabel("名称:"), fc);
        fc.gridx = 1; fc.gridy = 1; fc.weightx = 1.0; fc.gridwidth = 2;
        JTextField nameField = new JTextField(rule.getName(), 30);
        nameField.setToolTipText("规则名称，便于识别和管理");
        formPanel.add(nameField, fc);

        // 来源
        fc.gridx = 0; fc.gridy = 2; fc.weightx = 0; fc.gridwidth = 1;
        formPanel.add(new JLabel("来源:"), fc);
        fc.gridx = 1; fc.gridy = 2; fc.weightx = 1.0; fc.gridwidth = 2;
        JComboBox<ApiRuleSource> sourceCombo = new JComboBox<>(ApiRuleSource.values());
        sourceCombo.setRenderer(new DefaultListCellRenderer() {
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof ApiRuleSource) {
                    setText(((ApiRuleSource) value).getDisplayName());
                }
                return this;
            }
        });
        sourceCombo.setSelectedItem(rule.getSource());
        formPanel.add(sourceCombo, fc);

        // 方法
        fc.gridx = 0; fc.gridy = 3; fc.weightx = 0; fc.gridwidth = 1;
        formPanel.add(new JLabel("方法:"), fc);
        fc.gridx = 1; fc.gridy = 3; fc.weightx = 1.0; fc.gridwidth = 2;
        JComboBox<ApiRuleMethod> methodCombo = new JComboBox<>();
        methodCombo.setRenderer(new DefaultListCellRenderer() {
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof ApiRuleMethod) {
                    setText(((ApiRuleMethod) value).getDisplayName());
                }
                return this;
            }
        });
        // 初始化方法列表
        updateMethodCombo(methodCombo, (ApiRuleSource) sourceCombo.getSelectedItem(), rule.getMethod());
        sourceCombo.addActionListener(e -> {
            ApiRuleSource selected = (ApiRuleSource) sourceCombo.getSelectedItem();
            updateMethodCombo(methodCombo, selected, null);
        });
        formPanel.add(methodCombo, fc);

        // 表达式
        fc.gridx = 0; fc.gridy = 4; fc.weightx = 0; fc.gridwidth = 1;
        formPanel.add(new JLabel("表达式:"), fc);
        fc.gridx = 1; fc.gridy = 4; fc.weightx = 1.0; fc.gridwidth = 2;
        JTextField expressionField = new JTextField(rule.getExpression(), 30);
        formPanel.add(expressionField, fc);

        // 表达式提示
        fc.gridx = 1; fc.gridy = 5; fc.weightx = 1.0; fc.gridwidth = 2;
        JLabel expressionHintLabel = new JLabel(" ");
        expressionHintLabel.setForeground(new Color(120, 120, 120));
        expressionHintLabel.setFont(expressionHintLabel.getFont().deriveFont(Font.PLAIN, 11f));
        formPanel.add(expressionHintLabel, fc);
        methodCombo.addActionListener(e -> {
            ApiRuleMethod selected = (ApiRuleMethod) methodCombo.getSelectedItem();
            updateExpressionHintLabel(expressionHintLabel, selected);
        });
        updateExpressionHintLabel(expressionHintLabel, rule.getMethod());

        // 启用
        fc.gridx = 0; fc.gridy = 6; fc.weightx = 0; fc.gridwidth = 1;
        formPanel.add(new JLabel("启用:"), fc);
        fc.gridx = 1; fc.gridy = 6; fc.weightx = 1.0; fc.gridwidth = 2;
        JCheckBox enabledCheckbox = new JCheckBox("启用此规则", rule.isEnabled());
        formPanel.add(enabledCheckbox, fc);

        // 备注
        fc.gridx = 0; fc.gridy = 7; fc.weightx = 0; fc.gridwidth = 1;
        formPanel.add(new JLabel("备注:"), fc);
        fc.gridx = 1; fc.gridy = 7; fc.weightx = 1.0; fc.gridwidth = 2;
        JTextField remarkField = new JTextField(rule.getRemark(), 30);
        remarkField.setToolTipText("备注信息，用于记录规则用途或注意事项");
        formPanel.add(remarkField, fc);

        // 按钮行
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
        final boolean[] confirmed = {false};
        JButton okBtn = new JButton("确定");
        okBtn.addActionListener(e -> {
            // 校验
            ApiRuleSource source = (ApiRuleSource) sourceCombo.getSelectedItem();
            ApiRuleMethod method = (ApiRuleMethod) methodCombo.getSelectedItem();
            String expression = expressionField.getText().trim();

            if (expression.isEmpty()) {
                JOptionPane.showMessageDialog(dialog, "表达式不能为空", "校验失败", JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (method != null && !ApiRuleMethod.isValidForSource(method, source)) {
                JOptionPane.showMessageDialog(dialog,
                        method.getDisplayName() + " 不适用于 " + source.getDisplayName(),
                        "校验失败", JOptionPane.WARNING_MESSAGE);
                return;
            }
            // 正则预校验
            if (method == ApiRuleMethod.REGEX) {
                try {
                    Pattern.compile(expression);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(dialog,
                            "正则表达式语法错误: " + ex.getMessage(),
                            "校验失败", JOptionPane.WARNING_MESSAGE);
                    return;
                }
            }

            rule.setPriority((Integer) prioritySpinner.getValue());
            rule.setName(nameField.getText().trim());
            rule.setSource(source);
            rule.setMethod(method);
            rule.setExpression(expression);
            rule.setEnabled(enabledCheckbox.isSelected());
            rule.setRemark(remarkField.getText().trim());
            confirmed[0] = true;
            dialog.dispose();
        });
        JButton cancelBtn = new JButton("取消");
        cancelBtn.addActionListener(e -> dialog.dispose());
        btnPanel.add(okBtn);
        btnPanel.add(cancelBtn);

        dialog.add(formPanel, BorderLayout.CENTER);
        dialog.add(btnPanel, BorderLayout.SOUTH);

        dialog.pack();
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);

        return confirmed[0];
    }

    /**
     * 根据来源更新方法下拉框选项
     */
    private void updateMethodCombo(JComboBox<ApiRuleMethod> methodCombo, ApiRuleSource source, ApiRuleMethod currentMethod) {
        methodCombo.removeAllItems();
        List<ApiRuleMethod> methods = ApiRuleMethod.getMethodsForSource(source);
        for (ApiRuleMethod m : methods) {
            methodCombo.addItem(m);
        }
        if (currentMethod != null && methods.contains(currentMethod)) {
            methodCombo.setSelectedItem(currentMethod);
        }
    }

    /**
     * 更新表达式提示标签
     */
    private void updateExpressionHintLabel(JLabel label, ApiRuleMethod method) {
        if (method == null) {
            label.setText(" ");
            return;
        }
        switch (method) {
            case REGEX:
                label.setText("正则表达式（使用捕获组提取，如: /api/v\\d+/(\\w+)）");
                break;
            case SUBSTR:
                label.setText("START,END（如: 0,10 或 5,END 或 4,-3）");
                break;
            case JSON_PATH:
                label.setText("JSON路径（如: $.data.apiName 或 $.items[0].name）");
                break;
            case XPATH:
                label.setText("XPath表达式（如: /root/api/name/text()）");
                break;
            default:
                label.setText(" ");
        }
    }

    /**
     * 判断表达式是否为占位符文本
     */
    private boolean isExpressionPlaceholder(String text) {
        return text.equals("正则表达式") || text.equals("START,END") ||
                text.equals("$.field.name") || text.equals("/root/element");
    }

    /**
     * 测试API提取
     */
    private void testApiExtraction() {
        String path = testPathField.getText().trim();
        String query = testQueryField.getText().trim();
        String headersText = testHeadersArea.getText().trim();
        String bodyText = testBodyArea.getText().trim();
        String contentType = testContentTypeField.getText().trim();

        // 解析请求头
        List<String> headerList = new ArrayList<>();
        if (!headersText.isEmpty()) {
            for (String line : headersText.split("\n")) {
                if (!line.trim().isEmpty()) {
                    headerList.add(line.trim());
                }
            }
        }

        // 解析请求体
        byte[] body = null;
        if (!bodyText.isEmpty()) {
            body = bodyText.getBytes(StandardCharsets.UTF_8);
        }

        // 获取规则并执行提取
        List<ApiExtractionRule> rules = ApiRuleManager.getInstance().getActiveRules();
        String result = ApiExtractionEngine.extractApi(path, query.isEmpty() ? null : query, headerList, body, contentType, rules);

        testResultField.setText(result);
    }

    /**
     * 重新提取所有请求和历史记录的API值
     */
    private void reExtractAllApis() {
        int confirm = JOptionPane.showConfirmDialog(this,
                "确定要使用当前规则重新提取所有请求和历史记录的API值吗？\n" +
                "此操作可能需要一定时间。",
                "确认重新提取", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) return;

        // 在后台线程执行
        final Frame parentFrame = (Frame) SwingUtilities.getWindowAncestor(this);
        final JDialog progressDialog = new JDialog(parentFrame, "重新提取API", true);
        progressDialog.setLayout(new BorderLayout(10, 10));
        progressDialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);

        JProgressBar progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        JLabel statusLabel = new JLabel("正在重新提取所有API值...");

        progressDialog.add(statusLabel, BorderLayout.NORTH);
        progressDialog.add(progressBar, BorderLayout.CENTER);
        progressDialog.setSize(350, 120);
        progressDialog.setLocationRelativeTo(this);

        Thread worker = new Thread(() -> {
            try {
                ApiExtractionRuleDAO ruleDAO = new ApiExtractionRuleDAO();
                List<ApiExtractionRule> rules = ruleDAO.getAllRules();
                oxff.top.db.pool.PoolManager poolMgr = new oxff.top.db.pool.PoolManager();
                ContentSplitter splitter = new ContentSplitter();

                int totalUpdated = 0;

                // ===== 1. 重新提取 requests 表的API =====
                RequestDAO requestDAO = new RequestDAO();
                List<java.util.Map<String, Object>> allRequests = requestDAO.getAllRequests();
                int reqUpdated = 0;

                for (java.util.Map<String, Object> req : allRequests) {
                    try {
                        String path = (String) req.get("path");
                        String reqQuery = (String) req.get("query");
                        byte[] requestData = (byte[]) req.get("request_data");
                        int reqId = (Integer) req.get("id");

                        // 从requestData中解析headers和body
                        List<String> headerList = new ArrayList<>();
                        String contentType = null;
                        byte[] body = null;

                        if (requestData != null && requestData.length > 0) {
                            SplitResult split = splitter.splitRequest(requestData);
                            if (split.getHeaders() != null) {
                                String headersStr = new String(split.getHeaders(), StandardCharsets.UTF_8);
                                for (String line : headersStr.split("\r\n")) {
                                    if (!line.isEmpty()) headerList.add(line);
                                    if (line.toLowerCase().startsWith("content-type:")) {
                                        contentType = line.substring("content-type:".length()).trim();
                                    }
                                }
                            }
                            body = split.hasBody() ? split.getBody() : null;
                        }

                        String apiValue = ApiExtractionEngine.extractApi(path, reqQuery, headerList, body, contentType, rules);

                        // 更新数据库中的api_hash
                        try (java.sql.Connection conn = DatabaseManager.getInstance().getConnection()) {
                            conn.setAutoCommit(false);
                            try {
                                // 读取旧api_hash
                                String oldApiHash = null;
                                String getOldSql = "SELECT api_hash FROM requests WHERE id = ?";
                                try (java.sql.PreparedStatement pstmt = conn.prepareStatement(getOldSql)) {
                                    pstmt.setInt(1, reqId);
                                    try (java.sql.ResultSet rs = pstmt.executeQuery()) {
                                        if (rs.next()) oldApiHash = rs.getString("api_hash");
                                    }
                                }

                                // 确保新api值在string_pool中
                                String newApiHash = (apiValue != null && !apiValue.isEmpty())
                                        ? poolMgr.ensureString(conn, apiValue) : null;

                                // 更新api_hash
                                String updateSql = "UPDATE requests SET api_hash = ? WHERE id = ?";
                                try (java.sql.PreparedStatement pstmt = conn.prepareStatement(updateSql)) {
                                    pstmt.setString(1, newApiHash);
                                    pstmt.setInt(2, reqId);
                                    pstmt.executeUpdate();
                                }

                                // 释放旧引用
                                if (oldApiHash != null) {
                                    poolMgr.releaseString(conn, oldApiHash);
                                }

                                conn.commit();
                                reqUpdated++;
                            } catch (java.sql.SQLException ex) {
                                conn.rollback();
                                BurpExtender.printError("[!] 重新提取API失败(reqId=" + reqId + "): " + ex.getMessage());
                            }
                        }
                    } catch (Exception e) {
                        BurpExtender.printError("[!] 重新提取API处理请求时出错: " + e.getMessage());
                    }
                }

                // ===== 2. 重新提取 history 表的API =====
                oxff.top.db.HistoryDAO historyDAO = new oxff.top.db.HistoryDAO();
                List<oxff.top.http.RequestResponseRecord> allHistory = historyDAO.getAllHistory();
                int histUpdated = 0;

                for (oxff.top.http.RequestResponseRecord record : allHistory) {
                    try {
                        String path = record.getPath();
                        byte[] requestData = record.getRequestData();
                        int histId = record.getId();

                        // 从requestData中解析headers和body
                        List<String> headerList = new ArrayList<>();
                        String contentType = null;
                        byte[] body = null;

                        if (requestData != null && requestData.length > 0) {
                            SplitResult split = splitter.splitRequest(requestData);
                            if (split.getHeaders() != null) {
                                String headersStr = new String(split.getHeaders(), StandardCharsets.UTF_8);
                                for (String line : headersStr.split("\r\n")) {
                                    if (!line.isEmpty()) headerList.add(line);
                                    if (line.toLowerCase().startsWith("content-type:")) {
                                        contentType = line.substring("content-type:".length()).trim();
                                    }
                                }
                            }
                            body = split.hasBody() ? split.getBody() : null;
                        }

                        String apiValue = ApiExtractionEngine.extractApi(path, record.getQueryParameters(), headerList, body, contentType, rules);

                        // 更新数据库中的api_hash
                        try (java.sql.Connection conn = DatabaseManager.getInstance().getConnection()) {
                            conn.setAutoCommit(false);
                            try {
                                // 读取旧api_hash
                                String oldApiHash = null;
                                String getOldSql = "SELECT api_hash FROM history WHERE id = ?";
                                try (java.sql.PreparedStatement pstmt = conn.prepareStatement(getOldSql)) {
                                    pstmt.setInt(1, histId);
                                    try (java.sql.ResultSet rs = pstmt.executeQuery()) {
                                        if (rs.next()) oldApiHash = rs.getString("api_hash");
                                    }
                                }

                                // 确保新api值在string_pool中
                                String newApiHash = (apiValue != null && !apiValue.isEmpty())
                                        ? poolMgr.ensureString(conn, apiValue) : null;

                                // 更新api_hash
                                String updateSql = "UPDATE history SET api_hash = ? WHERE id = ?";
                                try (java.sql.PreparedStatement pstmt = conn.prepareStatement(updateSql)) {
                                    pstmt.setString(1, newApiHash);
                                    pstmt.setInt(2, histId);
                                    pstmt.executeUpdate();
                                }

                                // 释放旧引用
                                if (oldApiHash != null) {
                                    poolMgr.releaseString(conn, oldApiHash);
                                }

                                conn.commit();
                                histUpdated++;
                            } catch (java.sql.SQLException ex) {
                                conn.rollback();
                                BurpExtender.printError("[!] 重新提取历史API失败(histId=" + histId + "): " + ex.getMessage());
                            }
                        }
                    } catch (Exception e) {
                        BurpExtender.printError("[!] 重新提取历史API处理记录时出错: " + e.getMessage());
                    }
                }

                totalUpdated = reqUpdated + histUpdated;
                final int finalReqUpdated = reqUpdated;
                final int finalReqTotal = allRequests.size();
                final int finalHistUpdated = histUpdated;
                final int finalHistTotal = allHistory.size();
                final int finalTotalUpdated = totalUpdated;
                SwingUtilities.invokeLater(() -> {
                    progressDialog.dispose();
                    JOptionPane.showMessageDialog(ConfigPanel.this,
                            "API重新提取完成\n" +
                            "请求: " + finalReqTotal + " 条, 更新 " + finalReqUpdated + " 条\n" +
                            "历史: " + finalHistTotal + " 条, 更新 " + finalHistUpdated + " 条\n" +
                            "合计更新: " + finalTotalUpdated + " 条",
                            "完成", JOptionPane.INFORMATION_MESSAGE);
                    // 通知主UI刷新数据
                    if (onDataChanged != null) {
                        onDataChanged.run();
                    }
                });
            } catch (Exception e) {
                BurpExtender.printError("[!] 重新提取API异常: " + e.getMessage());
                SwingUtilities.invokeLater(() -> {
                    progressDialog.dispose();
                    JOptionPane.showMessageDialog(ConfigPanel.this,
                            "重新提取API时发生错误: " + e.getMessage(),
                            "错误", JOptionPane.ERROR_MESSAGE);
                });
            }
        });
        worker.start();

        progressDialog.setVisible(true);
    }

    // ========== API规则表格模型 ==========

    /**
     * API提取规则表格模型
     */
    private class ApiRuleTableModel extends AbstractTableModel {
        private final String[] COLUMN_NAMES = {"优先级", "名称", "来源", "方法", "表达式", "启用", "备注"};
        private List<ApiExtractionRule> rules = new ArrayList<>();

        public void setRules(List<ApiExtractionRule> rules) {
            this.rules = new ArrayList<>(rules);
            fireTableDataChanged();
        }

        public ApiExtractionRule getRule(int rowIndex) {
            if (rowIndex >= 0 && rowIndex < rules.size()) {
                return rules.get(rowIndex);
            }
            return null;
        }

        @Override
        public int getRowCount() {
            return rules.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMN_NAMES[column];
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            switch (columnIndex) {
                case 0: return Integer.class;
                case 5: return Boolean.class;
                default: return String.class;
            }
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            ApiExtractionRule rule = rules.get(rowIndex);
            switch (columnIndex) {
                case 0: return rule.getPriority();
                case 1: return rule.getName();
                case 2: return rule.getSource().getDisplayName();
                case 3: return rule.getMethod().getDisplayName();
                case 4: return rule.getExpression();
                case 5: return rule.isEnabled();
                case 6: return rule.getRemark();
                default: return null;
            }
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 5; // 仅"启用"列可直接编辑
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (columnIndex == 5 && aValue instanceof Boolean) {
                ApiExtractionRule rule = rules.get(rowIndex);
                rule.setEnabled((Boolean) aValue);
                // 直接保存到数据库
                ApiExtractionRuleDAO dao = new ApiExtractionRuleDAO();
                dao.updateRule(rule);
                ApiRuleManager.getInstance().refreshCache();
                fireTableCellUpdated(rowIndex, columnIndex);
            }
        }
    }
}
