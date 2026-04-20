package oxff.top.ui;

import oxff.top.config.DatabaseConfig;
import oxff.top.db.DatabaseManager;
import oxff.top.io.DataExporter;
import oxff.top.io.DataImporter;
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

        // JSON行
        JPanel jsonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        jsonRow.add(new JLabel("JSON (.json):"));
        JButton exportJsonButton = new JButton("导出");
        exportJsonButton.addActionListener(e -> exportToJson());
        jsonRow.add(exportJsonButton);
        JButton importJsonButton = new JButton("导入");
        importJsonButton.addActionListener(e -> importFromJson());
        jsonRow.add(importJsonButton);
        rowsPanel.add(jsonRow);

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
        topPanel.add(ioPanel, BorderLayout.CENTER);

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

    private void exportToJson() {
        try {
            BurpExtender.printOutput("[*] 正在启动JSON数据导出...");
            DataExporter exporter = new DataExporter();
            exporter.exportToJson(this);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导出操作发生错误: " + e.getMessage(), "导出错误", JOptionPane.ERROR_MESSAGE);
            BurpExtender.printError("[!] 导出错误: " + e.getMessage());
        }
    }

    private void importFromJson() {
        try {
            BurpExtender.printOutput("[*] 正在启动JSON数据导入...");
            DataImporter importer = new DataImporter();
            importer.importFromJson(this);
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
