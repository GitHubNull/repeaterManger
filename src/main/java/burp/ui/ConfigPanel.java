package burp.ui;

import burp.config.DatabaseConfig;
import burp.db.DatabaseManager;
import burp.io.DataExporter;
import burp.io.DataImporter;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
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
        browseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                browseForDbFile();
            }
        });
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
        saveConfigButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                saveConfig();
            }
        });
        configPanel.add(saveConfigButton, c);
        
        // 导入导出面板
        JPanel ioPanel = new JPanel(new GridLayout(1, 4, 10, 0));
        ioPanel.setBorder(BorderFactory.createTitledBorder("数据导入导出"));
        
        JButton exportDbButton = new JButton("导出数据库");
        exportDbButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                exportDatabase();
            }
        });
        ioPanel.add(exportDbButton);
        
        JButton importDbButton = new JButton("导入数据库");
        importDbButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                importDatabase();
            }
        });
        ioPanel.add(importDbButton);
        
        JButton exportJsonButton = new JButton("导出为JSON");
        exportJsonButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                exportToJson();
            }
        });
        ioPanel.add(exportJsonButton);
        
        JButton importJsonButton = new JButton("从JSON导入");
        importJsonButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                importFromJson();
            }
        });
        ioPanel.add(importJsonButton);
        
        // 添加到主面板
        add(configPanel, BorderLayout.NORTH);
        add(ioPanel, BorderLayout.CENTER);
        
        // 添加信息面板
        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder("数据库信息"));
        
        JTextArea infoArea = new JTextArea(5, 40);
        infoArea.setEditable(false);
        infoArea.setText("SQLite数据库文件: " + dbManager.getConfig().getDatabasePath() + "\n" +
                       "自动保存: " + (dbManager.getConfig().isAutoSaveEnabled() ? "启用" : "禁用") + "\n" +
                       "保存间隔: " + dbManager.getConfig().getAutoSaveInterval() + "分钟\n\n" +
                       "数据持久化使您的请求和历史记录在Burp Suite重新启动后仍然可用。");
        
        infoPanel.add(new JScrollPane(infoArea), BorderLayout.CENTER);
        
        add(infoPanel, BorderLayout.SOUTH);
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
        DataExporter exporter = new DataExporter();
        exporter.exportToSQLite(this);
    }
    
    /**
     * 导入数据库
     */
    private void importDatabase() {
        DataImporter importer = new DataImporter();
        importer.importFromSQLite(this);
    }
    
    /**
     * 导出为JSON
     */
    private void exportToJson() {
        DataExporter exporter = new DataExporter();
        exporter.exportToJson(this);
    }
    
    /**
     * 从JSON导入
     */
    private void importFromJson() {
        DataImporter importer = new DataImporter();
        importer.importFromJson(this);
    }
} 