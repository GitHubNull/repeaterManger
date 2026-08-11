package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.i18n.I18nManager;
import org.oxff.repeater.privilege.JudgmentRuleManager;
import org.oxff.repeater.privilege.JudgmentRuleYamlIO;
import org.oxff.repeater.privilege.model.JudgmentRule;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.util.List;

/**
 * 判决规则配置子Tab
 * 包含：规则列表 + CRUD按钮 + 搜索过滤 + 导入导出
 */
public class JudgmentRuleConfigTab extends JPanel {

    private final JTable ruleTable;
    private final JudgmentRuleTableModel ruleModel;
    private final JTextField searchField;

    private JLabel searchLabel;
    private JButton clearSearchBtn;
    private JPanel tablePanel;
    private JPanel infoPanel;
    private JTextArea infoArea;
    private JButton addBtn;
    private JButton editBtn;
    private JButton deleteBtn;
    private JButton toggleBtn;
    private JButton exportBtn;
    private JButton importBtn;

    public JudgmentRuleConfigTab() {
        super(new BorderLayout(0, 5));

        // ========== 搜索面板 ==========
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchLabel = new JLabel(I18nManager.tr("judgment.search"));
        searchPanel.add(searchLabel);
        searchField = new JTextField(20);
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { filterRules(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { filterRules(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { filterRules(); }
        });
        searchPanel.add(searchField);
        clearSearchBtn = new JButton(I18nManager.tr("judgment.clear"));
        clearSearchBtn.addActionListener(e -> { searchField.setText(""); filterRules(); });
        searchPanel.add(clearSearchBtn);

        // ========== 规则表格 ==========
        tablePanel = new JPanel(new BorderLayout());
        tablePanel.setBorder(BorderFactory.createTitledBorder(I18nManager.tr("judgment.title")));

        ruleModel = new JudgmentRuleTableModel();
        ruleTable = new JTable(ruleModel);
        ruleTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        ruleTable.getColumnModel().getColumn(0).setPreferredWidth(40);   // 活跃
        ruleTable.getColumnModel().getColumn(1).setPreferredWidth(120);  // 名称
        ruleTable.getColumnModel().getColumn(2).setPreferredWidth(50);   // 条件数
        ruleTable.getColumnModel().getColumn(3).setPreferredWidth(280);  // 条件摘要
        ruleTable.getColumnModel().getColumn(4).setPreferredWidth(40);   // 启用
        ruleTable.getColumnModel().getColumn(5).setPreferredWidth(50);   // 持久化

        JScrollPane scrollPane = new JScrollPane(ruleTable);
        scrollPane.setPreferredSize(new Dimension(0, 200));
        tablePanel.add(scrollPane, BorderLayout.CENTER);

        // ========== 按钮面板 ==========
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        addBtn = new JButton(I18nManager.tr("judgment.add"));
        editBtn = new JButton(I18nManager.tr("judgment.edit"));
        deleteBtn = new JButton(I18nManager.tr("judgment.delete"));
        toggleBtn = new JButton(I18nManager.tr("judgment.toggle"));

        addBtn.addActionListener(e -> addRule());
        editBtn.addActionListener(e -> editRule());
        deleteBtn.addActionListener(e -> deleteRule());
        toggleBtn.addActionListener(e -> toggleRule());

        buttonPanel.add(addBtn);
        buttonPanel.add(editBtn);
        buttonPanel.add(deleteBtn);
        buttonPanel.add(toggleBtn);
        buttonPanel.add(Box.createHorizontalStrut(20));

        // 导入导出按钮
        exportBtn = new JButton(I18nManager.tr("judgment.export"));
        importBtn = new JButton(I18nManager.tr("judgment.import"));
        exportBtn.addActionListener(e -> exportRules());
        importBtn.addActionListener(e -> importRules());
        buttonPanel.add(exportBtn);
        buttonPanel.add(importBtn);

        tablePanel.add(buttonPanel, BorderLayout.SOUTH);

        // ========== 说明面板 ==========
        infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder(I18nManager.tr("judgment.logic.title")));
        infoArea = new JTextArea(4, 50);
        infoArea.setEditable(false);
        infoArea.setLineWrap(true);
        infoArea.setText(I18nManager.tr("judgment.info.text"));
        infoPanel.add(new JScrollPane(infoArea), BorderLayout.CENTER);

        // ========== 组装 ==========
        add(searchPanel, BorderLayout.NORTH);
        add(tablePanel, BorderLayout.CENTER);
        add(infoPanel, BorderLayout.SOUTH);

        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);

        // 初始加载
        refreshData();
    }

    /**
     * 语言切换时刷新文本
     */
    private void refreshTexts() {
        searchLabel.setText(I18nManager.tr("judgment.search"));
        clearSearchBtn.setText(I18nManager.tr("judgment.clear"));
        ((TitledBorder) tablePanel.getBorder()).setTitle(I18nManager.tr("judgment.title"));
        ((TitledBorder) infoPanel.getBorder()).setTitle(I18nManager.tr("judgment.logic.title"));
        infoArea.setText(I18nManager.tr("judgment.info.text"));
        addBtn.setText(I18nManager.tr("judgment.add"));
        editBtn.setText(I18nManager.tr("judgment.edit"));
        deleteBtn.setText(I18nManager.tr("judgment.delete"));
        toggleBtn.setText(I18nManager.tr("judgment.toggle"));
        exportBtn.setText(I18nManager.tr("judgment.export"));
        importBtn.setText(I18nManager.tr("judgment.import"));
        ruleModel.refreshColumnNames();
        repaint();
    }

    /**
     * 刷新数据
     */
    public void refreshData() {
        JudgmentRuleManager manager = JudgmentRuleManager.getInstance();
        ruleModel.setData(manager.getAllRules());
    }

    private void addRule() {
        JudgmentRuleEditDialog dialog = new JudgmentRuleEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), I18nManager.tr("judgment.add.title"), null);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            JudgmentRule rule = dialog.toRule();
            JudgmentRuleManager.getInstance().addRule(rule);
            refreshData();
        }
    }

    private void editRule() {
        int row = ruleTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("judgment.select.first"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JudgmentRule selected = ruleModel.getRule(row);
        JudgmentRuleEditDialog dialog = new JudgmentRuleEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), I18nManager.tr("judgment.edit.title"), selected);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            JudgmentRule updated = dialog.toRule();
            JudgmentRuleManager.getInstance().updateRule(updated);
            refreshData();
        }
    }

    private void deleteRule() {
        int row = ruleTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("judgment.select.first"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JudgmentRule selected = ruleModel.getRule(row);
        int confirm = JOptionPane.showConfirmDialog(this,
                I18nManager.tr("judgment.delete.confirm", selected.getName()),
                I18nManager.tr("judgment.delete.confirm.title"), JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            JudgmentRuleManager.getInstance().deleteRule(selected.getId());
            refreshData();
        }
    }

    private void toggleRule() {
        int row = ruleTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("judgment.select.first"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JudgmentRule selected = ruleModel.getRule(row);
        JudgmentRuleManager.getInstance().toggleRuleEnabled(selected.getId(), !selected.isEnabled());
        refreshData();
    }

    private void exportRules() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showSaveDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_YAML_RULE_EXPORT,
                I18nManager.tr("judgment.export.dialog"), this,
                new File("judgment_rules.yml"),
                new FileNameExtensionFilter(I18nManager.tr("judgment.yaml.filter"), "yml", "yaml"));

        if (selectedFile == null) {
            return;
        }

        String filePath = selectedFile.getAbsolutePath();
        if (!filePath.endsWith(".yml") && !filePath.endsWith(".yaml")) {
            filePath += ".yml";
        }
        if (JudgmentRuleYamlIO.writeToFile(
                JudgmentRuleManager.getInstance().getAllRules(), filePath)) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("judgment.export.success", filePath),
                    I18nManager.tr("judgment.export.success.title"), JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this, I18nManager.tr("judgment.export.failed"),
                    I18nManager.tr("judgment.export.failed.title"), JOptionPane.ERROR_MESSAGE);
        }
    }

    private void importRules() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showOpenDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_YAML_RULE_IMPORT,
                I18nManager.tr("judgment.import.dialog"), this,
                new FileNameExtensionFilter(I18nManager.tr("judgment.yaml.filter"), "yml", "yaml"));

        if (selectedFile == null) {
            return;
        }

        String filePath = selectedFile.getAbsolutePath();
        List<JudgmentRule> importedRules = JudgmentRuleYamlIO.readFromFile(filePath);
        if (importedRules.isEmpty()) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("judgment.import.empty"),
                    I18nManager.tr("judgment.import.failed.title"), JOptionPane.WARNING_MESSAGE);
            return;
        }

        String[] options = {I18nManager.tr("judgment.import.merge"),
                I18nManager.tr("judgment.import.replace"), I18nManager.tr("judgment.import.cancel")};
        int choice = JOptionPane.showOptionDialog(this,
                I18nManager.tr("judgment.import.choice.msg", importedRules.size()),
                I18nManager.tr("judgment.import.choice.title"), 0, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);

        if (choice == 0) {
            int added = JudgmentRuleManager.getInstance().importRulesMerge(importedRules);
            JOptionPane.showMessageDialog(this,
                    I18nManager.tr("judgment.import.merge.done", added),
                    I18nManager.tr("judgment.import.success.title"), JOptionPane.INFORMATION_MESSAGE);
        } else if (choice == 1) {
            JudgmentRuleManager.getInstance().importRulesReplace(importedRules);
            JOptionPane.showMessageDialog(this,
                    I18nManager.tr("judgment.import.replace.done", importedRules.size()),
                    I18nManager.tr("judgment.import.success.title"), JOptionPane.INFORMATION_MESSAGE);
        }
        refreshData();
    }

    private void filterRules() {
        String searchText = searchField.getText().trim().toLowerCase();
        if (searchText.isEmpty()) {
            ruleModel.setData(JudgmentRuleManager.getInstance().getAllRules());
            return;
        }
        List<JudgmentRule> allRules = JudgmentRuleManager.getInstance().getAllRules();
        List<JudgmentRule> filtered = new java.util.ArrayList<>();
        for (JudgmentRule rule : allRules) {
            if (matchRule(rule, searchText)) {
                filtered.add(rule);
            }
        }
        ruleModel.setData(filtered);
    }

    private boolean matchRule(JudgmentRule rule, String searchText) {
        if (rule.getName() != null && rule.getName().toLowerCase().contains(searchText)) return true;
        if (rule.getExpression() != null && rule.getExpression().toLowerCase().contains(searchText)) return true;
        if (rule.getTarget() != null && rule.getTarget().getDisplayName().contains(searchText)) return true;
        if (rule.getMethod() != null && rule.getMethod().getDisplayName().contains(searchText)) return true;
        if (rule.getRemark() != null && rule.getRemark().toLowerCase().contains(searchText)) return true;
        return false;
    }
}
