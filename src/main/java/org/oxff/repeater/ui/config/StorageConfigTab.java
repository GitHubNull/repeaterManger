package org.oxff.repeater.ui.config;

import org.oxff.repeater.config.DatabaseConfig;
import org.oxff.repeater.config.SessionDirectory;
import org.oxff.repeater.db.DatabaseManager;
import org.oxff.repeater.i18n.I18nManager;
import org.oxff.repeater.logging.LogManager;

import javax.swing.*;
import javax.swing.border.TitledBorder;
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

    // 需要随语言切换刷新的组件
    private JPanel storagePanel;
    private JPanel infoPanel;
    private JLabel storageModeLabel;
    private JLabel currentSessionLabel;
    private JLabel storageDirLabel;
    private JLabel sessionFileLabel;
    private JLabel autoSaveLabel;
    private JLabel saveIntervalLabel;
    private JButton saveConfigButton;

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
        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);
    }

    /**
     * 语言切换时刷新所有文本
     */
    private void refreshTexts() {
        ((TitledBorder) storagePanel.getBorder()).setTitle(I18nManager.tr("storage.title"));
        ((TitledBorder) infoPanel.getBorder()).setTitle(I18nManager.tr("storage.db.info"));
        storageModeLabel.setText(I18nManager.tr("storage.mode"));
        currentSessionLabel.setText(I18nManager.tr("storage.current.session"));
        storageDirLabel.setText(I18nManager.tr("storage.dir"));
        browseDirButton.setText(I18nManager.tr("storage.browse"));
        resetDirButton.setText(I18nManager.tr("storage.reset"));
        sessionFileLabel.setText(I18nManager.tr("storage.session.file"));
        applySessionFileButton.setText(I18nManager.tr("storage.apply"));
        autoSaveLabel.setText(I18nManager.tr("storage.autoSave"));
        autoSaveCheckbox.setText(I18nManager.tr("storage.autoSave.enable"));
        saveIntervalLabel.setText(I18nManager.tr("storage.interval"));
        saveConfigButton.setText(I18nManager.tr("storage.save.config"));

        // 刷新存储模式下拉项
        int selectedIndex = storageModeCombo.getSelectedIndex();
        storageModeCombo.setModel(new DefaultComboBoxModel<>(new String[]{
            I18nManager.tr("storage.mode.auto"),
            I18nManager.tr("storage.mode.directory"),
            I18nManager.tr("storage.mode.file")
        }));
        storageModeCombo.setSelectedIndex(selectedIndex);

        // 刷新保存间隔下拉项
        int intervalIndex = saveIntervalCombo.getSelectedIndex();
        saveIntervalCombo.setModel(new DefaultComboBoxModel<>(new String[]{
            I18nManager.tr("storage.interval.1"),
            I18nManager.tr("storage.interval.5"),
            I18nManager.tr("storage.interval.10"),
            I18nManager.tr("storage.interval.30"),
            I18nManager.tr("storage.interval.60")
        }));
        saveIntervalCombo.setSelectedIndex(intervalIndex);

        updateInfoArea();
        revalidate();
        repaint();
    }

    private void initUI() {
        // 存储设置区域
        storagePanel = new JPanel(new GridBagLayout());
        storagePanel.setBorder(BorderFactory.createTitledBorder(I18nManager.tr("storage.title")));

        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(5, 5, 5, 5);

        // 存储模式
        c.gridx = 0; c.gridy = 0; c.gridwidth = 1; c.weightx = 0;
        storageModeLabel = new JLabel(I18nManager.tr("storage.mode"));
        storagePanel.add(storageModeLabel, c);

        c.gridx = 1; c.gridy = 0; c.gridwidth = 2; c.weightx = 1.0;
        String[] modes = {
            I18nManager.tr("storage.mode.auto"),
            I18nManager.tr("storage.mode.directory"),
            I18nManager.tr("storage.mode.file")
        };
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
        currentSessionLabel = new JLabel(I18nManager.tr("storage.current.session"));
        storagePanel.add(currentSessionLabel, c);

        c.gridx = 1; c.gridy = 1; c.gridwidth = 2; c.weightx = 1.0;
        currentDbPathField = new JTextField(30);
        currentDbPathField.setEditable(false);
        currentDbPathField.setBackground(new Color(240, 240, 240));
        updateCurrentDbPathField();
        storagePanel.add(currentDbPathField, c);

        // 存储目录
        c.gridx = 0; c.gridy = 2; c.gridwidth = 1; c.weightx = 0;
        storageDirLabel = new JLabel(I18nManager.tr("storage.dir"));
        storagePanel.add(storageDirLabel, c);

        c.gridx = 1; c.gridy = 2; c.gridwidth = 1; c.weightx = 1.0;
        baseDirField = new JTextField(25);
        baseDirField.setEditable(false);
        baseDirField.setBackground(new Color(240, 240, 240));
        updateBaseDirField();
        storagePanel.add(baseDirField, c);

        c.gridx = 2; c.gridy = 2; c.gridwidth = 1; c.weightx = 0;
        JPanel dirButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        browseDirButton = new JButton(I18nManager.tr("storage.browse"));
        browseDirButton.addActionListener(e -> browseForDirectory());
        resetDirButton = new JButton(I18nManager.tr("storage.reset"));
        resetDirButton.addActionListener(e -> resetToDefaultDirectory());
        dirButtonPanel.add(browseDirButton);
        dirButtonPanel.add(resetDirButton);
        storagePanel.add(dirButtonPanel, c);

        // 当前会话文件名
        c.gridx = 0; c.gridy = 3; c.gridwidth = 1; c.weightx = 0;
        sessionFileLabel = new JLabel(I18nManager.tr("storage.session.file"));
        storagePanel.add(sessionFileLabel, c);

        c.gridx = 1; c.gridy = 3; c.gridwidth = 1; c.weightx = 1.0;
        sessionFileField = new JTextField(25);
        storagePanel.add(sessionFileField, c);

        c.gridx = 2; c.gridy = 3; c.gridwidth = 1; c.weightx = 0;
        applySessionFileButton = new JButton(I18nManager.tr("storage.apply"));
        applySessionFileButton.addActionListener(e -> applySessionFile());
        storagePanel.add(applySessionFileButton, c);

        // 自动保存配置
        c.gridx = 0; c.gridy = 4; c.gridwidth = 1; c.weightx = 0;
        autoSaveLabel = new JLabel(I18nManager.tr("storage.autoSave"));
        storagePanel.add(autoSaveLabel, c);

        c.gridx = 1; c.gridy = 4; c.gridwidth = 2; c.weightx = 1.0;
        autoSaveCheckbox = new JCheckBox(I18nManager.tr("storage.autoSave.enable"), dbManager.getConfig().isAutoSaveEnabled());
        storagePanel.add(autoSaveCheckbox, c);

        // 保存间隔
        c.gridx = 0; c.gridy = 5; c.gridwidth = 1; c.weightx = 0;
        saveIntervalLabel = new JLabel(I18nManager.tr("storage.interval"));
        storagePanel.add(saveIntervalLabel, c);

        c.gridx = 1; c.gridy = 5; c.gridwidth = 2; c.weightx = 1.0;
        String[] intervals = {
            I18nManager.tr("storage.interval.1"),
            I18nManager.tr("storage.interval.5"),
            I18nManager.tr("storage.interval.10"),
            I18nManager.tr("storage.interval.30"),
            I18nManager.tr("storage.interval.60")
        };
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
        saveConfigButton = new JButton(I18nManager.tr("storage.save.config"));
        saveConfigButton.addActionListener(e -> saveConfig());
        storagePanel.add(saveConfigButton, c);

        add(storagePanel, BorderLayout.NORTH);

        // 数据库信息区域
        infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder(I18nManager.tr("storage.db.info")));

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
        String sessionDirPath = sessionDir != null ? sessionDir.getAbsolutePath() : I18nManager.tr("storage.info.notCreated");
        String dbPath = dbManager.getCurrentDatabasePath();
        if (dbPath == null) {
            dbPath = dbManager.getConfig().getEffectiveDatabasePath();
        }
        String blobsDir = sessionDir != null ? sessionDir.getBlobsDir().getAbsolutePath() : "-";
        String logsDir = sessionDir != null ? sessionDir.getLogsDir().getAbsolutePath() : "-";

        infoArea.setText(
            I18nManager.tr("storage.info.sessionDir") + " " + sessionDirPath + "\n" +
            I18nManager.tr("storage.info.dbFile") + " " + dbPath + "\n" +
            I18nManager.tr("storage.info.blobsDir") + " " + blobsDir + "\n" +
            I18nManager.tr("storage.info.logsDir") + " " + logsDir + "\n" +
            I18nManager.tr("storage.info.mode") + " " + getModeDisplayName(dbManager.getConfig().getStorageMode()) + "\n" +
            I18nManager.tr("storage.info.autoSave") + " " + (dbManager.getConfig().isAutoSaveEnabled() ? I18nManager.tr("storage.info.enabled") : I18nManager.tr("storage.info.disabled")) + "\n" +
            I18nManager.tr("storage.info.interval") + " " + dbManager.getConfig().getAutoSaveInterval() + I18nManager.tr("storage.info.minute") + "\n\n" +
            I18nManager.tr("storage.info.note") + "\n" +
            I18nManager.tr("storage.info.note1") + "\n" +
            I18nManager.tr("storage.info.note2") + "\n" +
            I18nManager.tr("storage.info.note3") + "\n" +
            I18nManager.tr("storage.info.note4") + "\n" +
            I18nManager.tr("storage.info.note5")
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
            case DatabaseConfig.MODE_AUTO: return I18nManager.tr("storage.mode.auto");
            case DatabaseConfig.MODE_DIRECTORY: return I18nManager.tr("storage.mode.directory");
            case DatabaseConfig.MODE_FILE: return I18nManager.tr("storage.mode.file");
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
        // 优先使用配置中的存储路径，不存在时才用上次浏览记忆
        String preferredDir = dbManager.getConfig().getBaseDirectory();
        if (preferredDir == null || preferredDir.isEmpty()) {
            preferredDir = DatabaseConfig.getDefaultBaseDirectory();
        }

        File selectedDir = org.oxff.repeater.utils.FileChooserHelper.showDirectoryDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_STORAGE_DIRECTORY,
                I18nManager.tr("storage.select.dir"), this,
                preferredDir);

        if (selectedDir != null) {
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
                    I18nManager.tr("storage.dir.changed"),
                    I18nManager.tr("storage.dir.changed.title"), JOptionPane.INFORMATION_MESSAGE);
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
                I18nManager.tr("storage.reset.success"),
                I18nManager.tr("storage.reset.success.title"), JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void applySessionFile() {
        String filePath = sessionFileField.getText().trim();
        if (filePath.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                I18nManager.tr("storage.file.empty"),
                I18nManager.tr("storage.file.empty.title"), JOptionPane.WARNING_MESSAGE);
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
                I18nManager.tr("storage.file.applied", file.getAbsolutePath()),
                I18nManager.tr("storage.file.applied.title"), JOptionPane.INFORMATION_MESSAGE);
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
                I18nManager.tr("storage.save.success"),
                I18nManager.tr("storage.save.success.title"), JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this,
                I18nManager.tr("storage.save.failed"),
                I18nManager.tr("storage.save.failed.title"), JOptionPane.ERROR_MESSAGE);
        }
    }
}
