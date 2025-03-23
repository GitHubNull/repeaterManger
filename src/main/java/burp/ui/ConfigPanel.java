package burp.ui;

import burp.config.DatabaseConfig;
import burp.db.DatabaseManager;
import burp.io.DataExporter;
import burp.io.DataImporter;
import burp.BurpExtender;

import javax.swing.*;
import java.awt.*;
import java.io.File;

/**
 * 配置面板 - 用于配置数据库和导入导出功能
 */
public class ConfigPanel extends JPanel {
    private final DatabaseManager dbManager;
    private final JTextField dbPathField;
    private final JCheckBox autoSaveCheckbox;
    private final JComboBox<String> saveIntervalCombo;
    
    /**
     * 创建配置面板
     */
    public ConfigPanel() {
        super(new BorderLayout());
        
        dbManager = DatabaseManager.getInstance();
        
        // 创建配置区域
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(BorderFactory.createTitledBorder("数据库配置"));
        
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(5, 5, 5, 5);
        
        // 数据库路径配置
        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 1;
        configPanel.add(new JLabel("数据库文件:"), c);
        
        c.gridx = 1;
        c.gridy = 0;
        c.weightx = 1.0;
        dbPathField = new JTextField(dbManager.getConfig().getDatabasePath(), 30);
        dbPathField.setEditable(false);
        configPanel.add(dbPathField, c);
        
        c.gridx = 2;
        c.gridy = 0;
        c.weightx = 0;
        JButton browseButton = new JButton("浏览...");
        browseButton.addActionListener(e -> browseForDbFile());
        configPanel.add(browseButton, c);
        
        // 自动保存配置
        c.gridx = 0;
        c.gridy = 1;
        c.gridwidth = 1;
        configPanel.add(new JLabel("自动保存:"), c);
        
        c.gridx = 1;
        c.gridy = 1;
        c.gridwidth = 2;
        autoSaveCheckbox = new JCheckBox("启用自动保存", dbManager.getConfig().isAutoSaveEnabled());
        configPanel.add(autoSaveCheckbox, c);
        
        // 保存间隔
        c.gridx = 0;
        c.gridy = 2;
        c.gridwidth = 1;
        configPanel.add(new JLabel("保存间隔:"), c);
        
        c.gridx = 1;
        c.gridy = 2;
        c.gridwidth = 2;
        String[] intervals = {"1分钟", "5分钟", "10分钟", "30分钟", "60分钟"};
        saveIntervalCombo = new JComboBox<>(intervals);
        int currentInterval = dbManager.getConfig().getAutoSaveInterval();
        
        // 根据当前配置设置选中项
        if (currentInterval <= 1) {
            saveIntervalCombo.setSelectedIndex(0);
        } else if (currentInterval <= 5) {
            saveIntervalCombo.setSelectedIndex(1);
        } else if (currentInterval <= 10) {
            saveIntervalCombo.setSelectedIndex(2);
        } else if (currentInterval <= 30) {
            saveIntervalCombo.setSelectedIndex(3);
        } else {
            saveIntervalCombo.setSelectedIndex(4);
        }
        
        configPanel.add(saveIntervalCombo, c);
        
        // 保存按钮
        c.gridx = 1;
        c.gridy = 3;
        c.gridwidth = 2;
        c.anchor = GridBagConstraints.EAST;
        JButton saveConfigButton = new JButton("保存配置");
        saveConfigButton.addActionListener(e -> saveConfig());
        configPanel.add(saveConfigButton, c);
        
        // 导入导出面板 - 使用紧凑的设计，每行一个FlowLayout
        JPanel ioPanel = new JPanel(new BorderLayout());
        ioPanel.setBorder(BorderFactory.createTitledBorder("数据导入导出"));
        
        // 使用垂直布局的面板容纳两行
        JPanel rowsPanel = new JPanel();
        rowsPanel.setLayout(new BoxLayout(rowsPanel, BoxLayout.Y_AXIS));
        
        // 第一行 - SQLite格式
        JPanel sqliteRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        sqliteRow.add(new JLabel("SQLite格式:"));
        JButton exportDbButton = new JButton("导出");
        exportDbButton.addActionListener(e -> exportDatabase());
        sqliteRow.add(exportDbButton);
        
        JButton importDbButton = new JButton("导入");
        importDbButton.addActionListener(e -> importDatabase());
        sqliteRow.add(importDbButton);
        
        rowsPanel.add(sqliteRow);
        
        // 第二行 - JSON格式
        JPanel jsonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        jsonRow.add(new JLabel("JSON格式:"));
        JButton exportJsonButton = new JButton("导出");
        exportJsonButton.addActionListener(e -> exportToJson());
        jsonRow.add(exportJsonButton);
        
        JButton importJsonButton = new JButton("导入");
        importJsonButton.addActionListener(e -> importFromJson());
        jsonRow.add(importJsonButton);
        
        rowsPanel.add(jsonRow);
        
        // 添加行面板到IO面板
        ioPanel.add(rowsPanel, BorderLayout.CENTER);
        
        // 创建顶部面板容纳配置和导入导出
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(configPanel, BorderLayout.NORTH);
        topPanel.add(ioPanel, BorderLayout.CENTER);
        
        // 添加顶部面板到NORTH位置
        add(topPanel, BorderLayout.NORTH);
        
        // 添加信息面板 - 占据大部分空间
        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder("数据库信息"));
        
        JTextArea infoArea = new JTextArea(10, 40); // 增加了行数，让它占据更多空间
        infoArea.setEditable(false);
        infoArea.setText("SQLite数据库文件: " + dbManager.getConfig().getDatabasePath() + "\n" +
                       "自动保存: " + (dbManager.getConfig().isAutoSaveEnabled() ? "启用" : "禁用") + "\n" +
                       "保存间隔: " + dbManager.getConfig().getAutoSaveInterval() + "分钟\n\n" +
                       "数据持久化使您的请求和历史记录在Burp Suite重新启动后仍然可用。");
        
        infoPanel.add(new JScrollPane(infoArea), BorderLayout.CENTER);
        
        // 将信息面板添加到CENTER，使其占据剩余所有空间
        add(infoPanel, BorderLayout.CENTER);
    }
    
    /**
     * 浏览数据库文件位置
     */
    private void browseForDbFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("选择数据库文件");
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
            "SQLite数据库文件 (*.db)", "db"));
        
        // 设置默认目录为当前数据库文件所在目录
        File currentDbFile = new File(dbManager.getConfig().getDatabasePath());
        if (currentDbFile.getParentFile() != null && currentDbFile.getParentFile().exists()) {
            fileChooser.setCurrentDirectory(currentDbFile.getParentFile());
        }
        
        int result = fileChooser.showSaveDialog(this);
        
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            String filePath = selectedFile.getAbsolutePath();
            
            // 确保文件以.db结尾
            if (!filePath.toLowerCase().endsWith(".db")) {
                filePath += ".db";
            }
            
            dbPathField.setText(filePath);
        }
    }
    
    /**
     * 保存配置
     */
    private void saveConfig() {
        // 保存数据库路径配置
        String dbPath = dbPathField.getText().trim();
        if (!dbPath.isEmpty()) {
            dbManager.getConfig().setDatabasePath(dbPath);
        }
        
        // 保存自动保存配置
        boolean autoSave = autoSaveCheckbox.isSelected();
        dbManager.getConfig().setProperty(DatabaseConfig.KEY_AUTO_SAVE, String.valueOf(autoSave));
        
        // 保存间隔时间
        int intervalIndex = saveIntervalCombo.getSelectedIndex();
        int intervalMinutes = 5; // 默认5分钟
        
        switch (intervalIndex) {
            case 0: intervalMinutes = 1; break;
            case 1: intervalMinutes = 5; break;
            case 2: intervalMinutes = 10; break;
            case 3: intervalMinutes = 30; break;
            case 4: intervalMinutes = 60; break;
        }
        
        dbManager.getConfig().setProperty(DatabaseConfig.KEY_SAVE_INTERVAL, String.valueOf(intervalMinutes));
        
        // 保存配置到文件
        if (dbManager.getConfig().saveConfig()) {
            JOptionPane.showMessageDialog(this, 
                "配置已保存。\n下次启动Burp Suite时生效。", 
                "保存成功", 
                JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this, 
                "保存配置失败，请检查权限或路径。", 
                "保存失败", 
                JOptionPane.ERROR_MESSAGE);
        }
    }
    
    /**
     * 导出数据库
     */
    private void exportDatabase() {
        try {
            BurpExtender.printOutput("[*] 正在启动SQLite数据库导出...");
            
            // 显示操作提示
            JOptionPane.showMessageDialog(
                this,
                "即将打开导出对话框，请选择SQLite数据库文件保存位置。",
                "数据库导出",
                JOptionPane.INFORMATION_MESSAGE
            );
            
            DataExporter exporter = new DataExporter();
            boolean started = exporter.exportToSQLite(this);
            
            if (!started) {
                JOptionPane.showMessageDialog(
                    this,
                    "启动导出操作失败，请查看输出面板获取详细信息。",
                    "导出错误",
                    JOptionPane.ERROR_MESSAGE
                );
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(
                this,
                "导出操作发生错误: " + e.getMessage(),
                "导出错误",
                JOptionPane.ERROR_MESSAGE
            );
            BurpExtender.printError("[!] 导出错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 导入数据库
     */
    private void importDatabase() {
        try {
            BurpExtender.printOutput("[*] 正在启动SQLite数据库导入...");
            
            // 显示操作提示
            JOptionPane.showMessageDialog(
                this,
                "即将打开导入对话框，请选择要导入的SQLite数据库文件。",
                "数据库导入",
                JOptionPane.INFORMATION_MESSAGE
            );
            
            DataImporter importer = new DataImporter();
            boolean started = importer.importFromSQLite(this);
            
            if (!started) {
                BurpExtender.printOutput("[!] 导入操作已取消或发生错误");
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(
                this,
                "导入操作发生错误: " + e.getMessage(),
                "导入错误",
                JOptionPane.ERROR_MESSAGE
            );
            BurpExtender.printError("[!] 导入错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 导出为JSON
     */
    private void exportToJson() {
        try {
            BurpExtender.printOutput("[*] 正在启动JSON数据导出...");
            
            // 显示操作提示
            JOptionPane.showMessageDialog(
                this,
                "即将打开导出对话框，请选择JSON文件保存位置。",
                "JSON导出",
                JOptionPane.INFORMATION_MESSAGE
            );
            
            DataExporter exporter = new DataExporter();
            boolean started = exporter.exportToJson(this);
            
            if (!started) {
                JOptionPane.showMessageDialog(
                    this,
                    "启动导出操作失败，请查看输出面板获取详细信息。",
                    "导出错误",
                    JOptionPane.ERROR_MESSAGE
                );
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(
                this,
                "导出操作发生错误: " + e.getMessage(),
                "导出错误",
                JOptionPane.ERROR_MESSAGE
            );
            BurpExtender.printError("[!] 导出错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 从JSON导入
     */
    private void importFromJson() {
        try {
            BurpExtender.printOutput("[*] 正在启动JSON数据导入...");
            
            // 显示操作提示
            JOptionPane.showMessageDialog(
                this,
                "即将打开导入对话框，请选择要导入的JSON文件。",
                "JSON导入",
                JOptionPane.INFORMATION_MESSAGE
            );
            
            DataImporter importer = new DataImporter();
            boolean started = importer.importFromJson(this);
            
            if (!started) {
                BurpExtender.printOutput("[!] 导入操作已取消或发生错误");
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(
                this,
                "导入操作发生错误: " + e.getMessage(),
                "导入错误",
                JOptionPane.ERROR_MESSAGE
            );
            BurpExtender.printError("[!] 导入错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
} 