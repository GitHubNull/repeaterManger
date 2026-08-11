package org.oxff.repeater.ui;

import org.oxff.repeater.i18n.I18nManager;
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

    // 需要在语言切换时刷新的组件
    private JTabbedPane dataTabbedPane;
    private JPanel ioPanel;
    private JLabel ermLabel;
    private JLabel postmanLabel;
    private JCheckBox encryptCheckbox;
    private JButton exportErmButton;
    private JButton importErmButton;
    private JButton exportPostmanButton;
    private JButton importPostmanButton;
    private JButton smartImportButton;

    public DataPanel() {
        super(new BorderLayout());

        // ===== 创建子标签页 =====
        dataTabbedPane = new JTabbedPane(JTabbedPane.TOP);

        // ----- 数据导入导出标签页 -----
        JPanel ioTab = createDataIOTab();
        dataTabbedPane.addTab(I18nManager.tr("data.panel.title"), ioTab);

        add(dataTabbedPane, BorderLayout.CENTER);

        // 注册语言变更监听
        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);
    }

    /**
     * 创建数据导入导出标签页
     */
    private JPanel createDataIOTab() {
        JPanel tab = new JPanel(new BorderLayout());

        ioPanel = new JPanel(new BorderLayout());
        ioPanel.setBorder(BorderFactory.createTitledBorder(I18nManager.tr("data.panel.title")));

        JPanel rowsPanel = new JPanel();
        rowsPanel.setLayout(new BoxLayout(rowsPanel, BoxLayout.Y_AXIS));

        // ERM存档行
        JPanel ermRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        ermLabel = new JLabel(I18nManager.tr("data.panel.erm"));
        ermRow.add(ermLabel);
        encryptCheckbox = new JCheckBox(I18nManager.tr("data.panel.encrypt"));
        exportErmButton = new JButton(I18nManager.tr("data.panel.export"));
        exportErmButton.addActionListener(e -> exportErm(encryptCheckbox.isSelected()));
        ermRow.add(exportErmButton);
        ermRow.add(encryptCheckbox);
        importErmButton = new JButton(I18nManager.tr("data.panel.import"));
        importErmButton.addActionListener(e -> importErm());
        ermRow.add(importErmButton);
        rowsPanel.add(ermRow);

        // Postman行
        JPanel postmanRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        postmanLabel = new JLabel(I18nManager.tr("data.panel.postman"));
        postmanRow.add(postmanLabel);
        exportPostmanButton = new JButton(I18nManager.tr("data.panel.export"));
        exportPostmanButton.addActionListener(e -> exportToPostman());
        postmanRow.add(exportPostmanButton);
        importPostmanButton = new JButton(I18nManager.tr("data.panel.import"));
        importPostmanButton.addActionListener(e -> importFromPostman());
        postmanRow.add(importPostmanButton);
        rowsPanel.add(postmanRow);

        // 智能导入行
        JPanel smartRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        smartImportButton = new JButton(I18nManager.tr("data.panel.smartImport"));
        smartImportButton.addActionListener(e -> smartImport());
        smartRow.add(smartImportButton);
        rowsPanel.add(smartRow);

        ioPanel.add(rowsPanel, BorderLayout.CENTER);

        tab.add(ioPanel, BorderLayout.NORTH);

        return tab;
    }

    /**
     * 语言变更时刷新文本
     */
    private void refreshTexts() {
        if (dataTabbedPane.getTabCount() >= 1) {
            dataTabbedPane.setTitleAt(0, I18nManager.tr("data.panel.title"));
        }
        ioPanel.setBorder(BorderFactory.createTitledBorder(I18nManager.tr("data.panel.title")));
        ermLabel.setText(I18nManager.tr("data.panel.erm"));
        postmanLabel.setText(I18nManager.tr("data.panel.postman"));
        encryptCheckbox.setText(I18nManager.tr("data.panel.encrypt"));
        exportErmButton.setText(I18nManager.tr("data.panel.export"));
        importErmButton.setText(I18nManager.tr("data.panel.import"));
        exportPostmanButton.setText(I18nManager.tr("data.panel.export"));
        importPostmanButton.setText(I18nManager.tr("data.panel.import"));
        smartImportButton.setText(I18nManager.tr("data.panel.smartImport"));
        revalidate();
        repaint();
    }

    // ========== 数据导入导出方法 ==========

    private void exportErm(boolean encrypted) {
        try {
            LogManager.getInstance().printOutput(I18nManager.tr("data.io.exportErm.start"));
            DataExporter exporter = new DataExporter();
            exporter.exportToErm(this, encrypted);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                I18nManager.tr("data.io.error", e.getMessage()),
                I18nManager.tr("common.error"), JOptionPane.ERROR_MESSAGE);
            LogManager.getInstance().printError(I18nManager.tr("data.io.export.error", e.getMessage()));
        }
    }

    private void importErm() {
        try {
            LogManager.getInstance().printOutput(I18nManager.tr("data.io.importErm.start"));
            DataImporter importer = new DataImporter();
            importer.importFromErm(this);
            notifyDataChanged();
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                I18nManager.tr("data.io.error", e.getMessage()),
                I18nManager.tr("common.error"), JOptionPane.ERROR_MESSAGE);
            LogManager.getInstance().printError(I18nManager.tr("data.io.import.error", e.getMessage()));
        }
    }

    private void exportToPostman() {
        try {
            LogManager.getInstance().printOutput(I18nManager.tr("data.io.exportPostman.start"));
            DataExporter exporter = new DataExporter();
            exporter.exportToPostman(this);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                I18nManager.tr("data.io.error", e.getMessage()),
                I18nManager.tr("common.error"), JOptionPane.ERROR_MESSAGE);
            LogManager.getInstance().printError(I18nManager.tr("data.io.export.error", e.getMessage()));
        }
    }

    private void importFromPostman() {
        try {
            LogManager.getInstance().printOutput(I18nManager.tr("data.io.importPostman.start"));
            DataImporter importer = new DataImporter();
            importer.importFromPostman(this);
            notifyDataChanged();
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                I18nManager.tr("data.io.error", e.getMessage()),
                I18nManager.tr("common.error"), JOptionPane.ERROR_MESSAGE);
            LogManager.getInstance().printError(I18nManager.tr("data.io.import.error", e.getMessage()));
        }
    }

    private void smartImport() {
        try {
            LogManager.getInstance().printOutput(I18nManager.tr("data.io.smartImport.start"));
            DataImporter importer = new DataImporter();
            importer.smartImport(this);
            notifyDataChanged();
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                I18nManager.tr("data.io.error", e.getMessage()),
                I18nManager.tr("common.error"), JOptionPane.ERROR_MESSAGE);
            LogManager.getInstance().printError(I18nManager.tr("data.io.import.error", e.getMessage()));
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
