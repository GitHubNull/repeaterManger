package oxff.top.ui.config;

import oxff.top.config.DatabaseConfig;
import oxff.top.config.SessionDirectory;
import oxff.top.db.DatabaseManager;
import oxff.top.logging.LogManager;

import javax.swing.*;
import java.awt.*;
import java.io.File;

/**
 * 存储配置面板 - 管理存储模式、会话目录、自动保存等配置
 */
public class StorageConfigTab extends JPanel {
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

    // 数据变更回调
    private final Runnable onDataChanged;

    /**
     * 创建存储配置面板
     * @param onDataChanged 数据变更后的回调（通知主UI刷新）
     */
    public StorageConfigTab(Runnable onDataChanged) {
        super(new BorderLayout());
        this.dbManager = DatabaseManager.getInstance();
        this.onDataChanged = onDataChanged;
        initUI();
        onStorageModeChanged();
    }

    private void initUI() {
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

        add(storagePanel, BorderLayout.NORTH);

        // 数据库信息区域
        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder("数据库信息"));

        infoArea = new JTextArea(10, 40);
        infoArea.setEditable(false);
        updateInfoArea();
        infoPanel.add(new JScrollPane(infoArea), BorderLayout.CENTER);

        add(infoPanel, BorderLayout.CENTER);
    }

    // ========== 存储配置相关方法 ==========

    private void updateCurrentDbPathField() {
        SessionDirectory sessionDir = dbManager.getConfig().getOrCreateSessionDirectory();
        if (sessionDir != null) {
            currentDbPathField.setText(sessionDir.getAbsolutePath());
        } else {
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
        SessionDirectory sessionDir = dbManager.getConfig().getOrCreateSessionDirectory();
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

    /**
     * 通知主UI数据已变更（安全调用）
     */
    private void notifyDataChanged() {
        if (onDataChanged != null) {
            onDataChanged.run();
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

            dbManager.resetForNewSession();
            if (dbManager.initialize()) {
                LogManager.getInstance().relocateFileHandler(
                    dbManager.getLogsDirectory().getAbsolutePath());
                refreshStorageInfo();
                notifyDataChanged();
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
            LogManager.getInstance().relocateFileHandler(
                dbManager.getLogsDirectory().getAbsolutePath());
            refreshStorageInfo();
            notifyDataChanged();
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
            LogManager.getInstance().relocateFileHandler(
                dbManager.getLogsDirectory().getAbsolutePath());
            refreshStorageInfo();
            notifyDataChanged();
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
}
