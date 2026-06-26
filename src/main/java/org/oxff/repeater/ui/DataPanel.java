package org.oxff.repeater.ui;

import org.oxff.repeater.io.DataExporter;
import org.oxff.repeater.io.DataImporter;
import org.oxff.repeater.logging.LogManager;

import javax.swing.*;
import java.awt.*;

/**
 * 数据面板 - 顶级标签页
 * 提供数据导入导出功能
 */
public class DataPanel extends JPanel {

    private Runnable onDataChanged;

    public DataPanel() {
        super(new BorderLayout());

        // ===== 创建子标签页 =====
        JTabbedPane dataTabbedPane = new JTabbedPane(JTabbedPane.TOP);

        // ----- 数据导入导出标签页 -----
        JPanel ioTab = createDataIOTab();
        dataTabbedPane.addTab("数据导入导出", ioTab);

        add(dataTabbedPane, BorderLayout.CENTER);
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

    // ========== 数据导入导出方法 ==========

    private void exportErm(boolean encrypted) {
        try {
            LogManager.getInstance().printOutput("[*] 正在启动ERM存档导出...");
            DataExporter exporter = new DataExporter();
            exporter.exportToErm(this, encrypted);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导出操作发生错误: " + e.getMessage(), "导出错误", JOptionPane.ERROR_MESSAGE);
            LogManager.getInstance().printError("[!] 导出错误: " + e.getMessage());
        }
    }

    private void importErm() {
        try {
            LogManager.getInstance().printOutput("[*] 正在启动ERM存档导入...");
            DataImporter importer = new DataImporter();
            importer.importFromErm(this);
            notifyDataChanged();
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导入操作发生错误: " + e.getMessage(), "导入错误", JOptionPane.ERROR_MESSAGE);
            LogManager.getInstance().printError("[!] 导入错误: " + e.getMessage());
        }
    }

    private void exportToPostman() {
        try {
            LogManager.getInstance().printOutput("[*] 正在启动Postman Collection导出...");
            DataExporter exporter = new DataExporter();
            exporter.exportToPostman(this);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导出操作发生错误: " + e.getMessage(), "导出错误", JOptionPane.ERROR_MESSAGE);
            LogManager.getInstance().printError("[!] 导出错误: " + e.getMessage());
        }
    }

    private void importFromPostman() {
        try {
            LogManager.getInstance().printOutput("[*] 正在启动Postman Collection导入...");
            DataImporter importer = new DataImporter();
            importer.importFromPostman(this);
            notifyDataChanged();
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导入操作发生错误: " + e.getMessage(), "导入错误", JOptionPane.ERROR_MESSAGE);
            LogManager.getInstance().printError("[!] 导入错误: " + e.getMessage());
        }
    }

    private void smartImport() {
        try {
            LogManager.getInstance().printOutput("[*] 正在启动智能导入...");
            DataImporter importer = new DataImporter();
            importer.smartImport(this);
            notifyDataChanged();
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导入操作发生错误: " + e.getMessage(), "导入错误", JOptionPane.ERROR_MESSAGE);
            LogManager.getInstance().printError("[!] 导入错误: " + e.getMessage());
        }
    }

    /**
     * 通知数据变更
     */
    private void notifyDataChanged() {
        if (onDataChanged != null) {
            onDataChanged.run();
        }
    }

    /**
     * 设置数据变更回调（用于通知主UI刷新数据）
     */
    public void setOnDataChanged(Runnable callback) {
        this.onDataChanged = callback;
    }
}
