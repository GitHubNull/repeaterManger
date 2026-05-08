package oxff.top.ui.privilege;

import oxff.top.privilege.JudgmentRuleManager;
import oxff.top.privilege.JudgmentRuleYamlIO;
import oxff.top.privilege.model.JudgmentRule;

import javax.swing.*;
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

    public JudgmentRuleConfigTab() {
        super(new BorderLayout(0, 5));

        // ========== 搜索面板 ==========
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchPanel.add(new JLabel("搜索:"));
        searchField = new JTextField(20);
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { filterRules(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { filterRules(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { filterRules(); }
        });
        searchPanel.add(searchField);
        JButton clearSearchBtn = new JButton("清除");
        clearSearchBtn.addActionListener(e -> { searchField.setText(""); filterRules(); });
        searchPanel.add(clearSearchBtn);

        // ========== 规则表格 ==========
        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.setBorder(BorderFactory.createTitledBorder("判决规则"));

        ruleModel = new JudgmentRuleTableModel();
        ruleTable = new JTable(ruleModel);
        ruleTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        ruleTable.getColumnModel().getColumn(0).setPreferredWidth(100);  // 名称
        ruleTable.getColumnModel().getColumn(1).setPreferredWidth(70);   // 目标
        ruleTable.getColumnModel().getColumn(2).setPreferredWidth(70);   // 方法
        ruleTable.getColumnModel().getColumn(3).setPreferredWidth(250);  // 表达式
        ruleTable.getColumnModel().getColumn(4).setPreferredWidth(40);   // 启用
        ruleTable.getColumnModel().getColumn(5).setPreferredWidth(50);   // 优先级

        JScrollPane scrollPane = new JScrollPane(ruleTable);
        scrollPane.setPreferredSize(new Dimension(0, 200));
        tablePanel.add(scrollPane, BorderLayout.CENTER);

        // ========== 按钮面板 ==========
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton addBtn = new JButton("添加规则");
        JButton editBtn = new JButton("编辑规则");
        JButton deleteBtn = new JButton("删除规则");
        JButton toggleBtn = new JButton("启用/禁用");

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
        JButton exportBtn = new JButton("导出规则");
        JButton importBtn = new JButton("导入规则");
        exportBtn.addActionListener(e -> exportRules());
        importBtn.addActionListener(e -> importRules());
        buttonPanel.add(exportBtn);
        buttonPanel.add(importBtn);

        tablePanel.add(buttonPanel, BorderLayout.SOUTH);

        // ========== 说明面板 ==========
        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder("判决逻辑说明"));
        JTextArea infoArea = new JTextArea(3, 50);
        infoArea.setEditable(false);
        infoArea.setLineWrap(true);
        infoArea.setText(
            "• 规则按优先级升序匹配，匹配到第一条规则即决定判决结果\n" +
            "• 规则匹配成功 → 标记为越权（红色），匹配失败 → 标记为安全（绿色）\n" +
            "• 无规则时使用默认判决：状态码不同或响应相似度低于阈值则判定为越权"
        );
        infoPanel.add(new JScrollPane(infoArea), BorderLayout.CENTER);

        // ========== 组装 ==========
        add(searchPanel, BorderLayout.NORTH);
        add(tablePanel, BorderLayout.CENTER);
        add(infoPanel, BorderLayout.SOUTH);

        // 初始加载
        refreshData();
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
                (Frame) SwingUtilities.getWindowAncestor(this), "添加判决规则", null);
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
            JOptionPane.showMessageDialog(this, "请先选择一条规则", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JudgmentRule selected = ruleModel.getRule(row);
        JudgmentRuleEditDialog dialog = new JudgmentRuleEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), "编辑判决规则", selected);
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
            JOptionPane.showMessageDialog(this, "请先选择一条规则", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JudgmentRule selected = ruleModel.getRule(row);
        int confirm = JOptionPane.showConfirmDialog(this,
                "确认删除判决规则: " + selected.getName() + "?",
                "删除确认", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            JudgmentRuleManager.getInstance().deleteRule(selected.getId());
            refreshData();
        }
    }

    private void toggleRule() {
        int row = ruleTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一条规则", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JudgmentRule selected = ruleModel.getRule(row);
        JudgmentRuleManager.getInstance().toggleRuleEnabled(selected.getId(), !selected.isEnabled());
        refreshData();
    }

    private void exportRules() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导出判决规则");
        fileChooser.setFileFilter(new FileNameExtensionFilter("YAML文件 (*.yml, *.yaml)", "yml", "yaml"));
        fileChooser.setSelectedFile(new File("judgment_rules.yml"));
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            String filePath = fileChooser.getSelectedFile().getAbsolutePath();
            if (!filePath.endsWith(".yml") && !filePath.endsWith(".yaml")) {
                filePath += ".yml";
            }
            if (JudgmentRuleYamlIO.writeToFile(
                    JudgmentRuleManager.getInstance().getAllRules(), filePath)) {
                JOptionPane.showMessageDialog(this, "规则导出成功: " + filePath,
                        "导出成功", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, "规则导出失败", "导出失败", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void importRules() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导入判决规则");
        fileChooser.setFileFilter(new FileNameExtensionFilter("YAML文件 (*.yml, *.yaml)", "yml", "yaml"));
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            String filePath = fileChooser.getSelectedFile().getAbsolutePath();
            List<JudgmentRule> importedRules = JudgmentRuleYamlIO.readFromFile(filePath);
            if (importedRules.isEmpty()) {
                JOptionPane.showMessageDialog(this, "未找到有效的判决规则", "导入失败", JOptionPane.WARNING_MESSAGE);
                return;
            }

            String[] options = {"合并导入", "替换导入", "取消"};
            int choice = JOptionPane.showOptionDialog(this,
                    "发现 " + importedRules.size() + " 条规则，请选择导入方式",
                    "导入方式", 0, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);

            if (choice == 0) {
                int added = JudgmentRuleManager.getInstance().importRulesMerge(importedRules);
                JOptionPane.showMessageDialog(this,
                        "合并导入完成，新增 " + added + " 条规则", "导入成功", JOptionPane.INFORMATION_MESSAGE);
            } else if (choice == 1) {
                JudgmentRuleManager.getInstance().importRulesReplace(importedRules);
                JOptionPane.showMessageDialog(this,
                        "替换导入完成，共 " + importedRules.size() + " 条规则", "导入成功", JOptionPane.INFORMATION_MESSAGE);
            }
            refreshData();
        }
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
