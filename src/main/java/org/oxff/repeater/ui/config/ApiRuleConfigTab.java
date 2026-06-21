package org.oxff.repeater.ui.config;

import org.oxff.repeater.api.ApiExtractionEngine;
import org.oxff.repeater.api.ApiExtractionRule;
import org.oxff.repeater.api.ApiRuleManager;
import org.oxff.repeater.api.ApiRuleYamlIO;
import javax.swing.*;
import javax.swing.table.TableRowSorter;
import javax.swing.RowFilter;
import java.awt.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * API提取规则配置面板 - 管理API提取规则的搜索、增删改、测试和导入导出
 */
public class ApiRuleConfigTab extends JPanel {
    private static final long serialVersionUID = 1L;

    private final Runnable onDataChanged;

    // 表格组件
    private JTable apiRuleTable;
    private ApiRuleTableModel apiRuleTableModel;
    private TableRowSorter<ApiRuleTableModel> apiRuleSorter;

    // 搜索组件
    private JTextField apiSearchField;
    private JPanel advancedSearchPanel;
    private JButton advancedSearchToggleBtn;
    private JComboBox<String> advSourceFilterCombo;
    private JComboBox<String> advMethodFilterCombo;
    private JComboBox<String> advEnabledFilterCombo;
    private JCheckBox advRegexMatchCheckbox;
    private JTextField advExpressionField;

    // 测试组件
    private JTextField testPathField;
    private JTextField testQueryField;
    private JTextArea testHeadersArea;
    private JTextArea testBodyArea;
    private JTextField testContentTypeField;
    private JTextField testResultField;

    /**
     * 创建API提取规则配置面板
     *
     * @param onDataChanged 数据变更回调
     */
    public ApiRuleConfigTab(Runnable onDataChanged) {
        super(new BorderLayout(5, 5));
        this.onDataChanged = onDataChanged;
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        initUI();
    }

    /**
     * 刷新规则表格数据
     */
    public void refreshApiRuleTable() {
        apiRuleTableModel.setRules(ApiRuleManager.getInstance().getAllRulesForDisplay());
    }

    private void initUI() {
        // ===== 顶部：搜索区域 =====
        add(createSearchPanel(), BorderLayout.NORTH);

        // ===== 中间和底部由splitPane和buttonPanel组成 =====
        createTableAndButtons();
    }

    private JPanel createSearchPanel() {
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

        // 高级搜索面板
        advancedSearchPanel = new JPanel(new GridBagLayout());
        advancedSearchPanel.setBorder(BorderFactory.createTitledBorder("高级搜索"));
        advancedSearchPanel.setVisible(false);

        GridBagConstraints ac = new GridBagConstraints();
        ac.fill = GridBagConstraints.HORIZONTAL;
        ac.insets = new Insets(2, 5, 2, 5);

        ac.gridx = 0; ac.gridy = 0; ac.weightx = 0;
        advancedSearchPanel.add(new JLabel("来源:"), ac);
        ac.gridx = 1; ac.gridy = 0; ac.weightx = 1.0;
        advSourceFilterCombo = new JComboBox<>(new String[]{"全部", "URL路径", "URL参数", "请求头", "请求体"});
        advSourceFilterCombo.addActionListener(e -> applyApiRuleFilter());
        advancedSearchPanel.add(advSourceFilterCombo, ac);

        ac.gridx = 2; ac.gridy = 0; ac.weightx = 0;
        advancedSearchPanel.add(new JLabel("方法:"), ac);
        ac.gridx = 3; ac.gridy = 0; ac.weightx = 1.0;
        advMethodFilterCombo = new JComboBox<>(new String[]{"全部", "正则匹配", "子串截取", "JSON路径", "XPath"});
        advMethodFilterCombo.addActionListener(e -> applyApiRuleFilter());
        advancedSearchPanel.add(advMethodFilterCombo, ac);

        ac.gridx = 0; ac.gridy = 1; ac.weightx = 0;
        advancedSearchPanel.add(new JLabel("启用状态:"), ac);
        ac.gridx = 1; ac.gridy = 1; ac.weightx = 1.0;
        advEnabledFilterCombo = new JComboBox<>(new String[]{"全部", "已启用", "已禁用"});
        advEnabledFilterCombo.addActionListener(e -> applyApiRuleFilter());
        advancedSearchPanel.add(advEnabledFilterCombo, ac);

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
        return topPanel;
    }

    private void createTableAndButtons() {
        // 规则表格
        apiRuleTableModel = new ApiRuleTableModel();
        apiRuleTableModel.setOnRuleChanged(() -> ApiReExtractWorker.reExtractSilently(onDataChanged));
        apiRuleTable = new JTable(apiRuleTableModel);
        apiRuleTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        apiRuleTable.setRowHeight(22);
        apiRuleTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        apiRuleTable.getColumnModel().getColumn(1).setPreferredWidth(80);
        apiRuleTable.getColumnModel().getColumn(2).setPreferredWidth(70);
        apiRuleTable.getColumnModel().getColumn(3).setPreferredWidth(70);
        apiRuleTable.getColumnModel().getColumn(4).setPreferredWidth(250);
        apiRuleTable.getColumnModel().getColumn(5).setPreferredWidth(50);
        apiRuleTable.getColumnModel().getColumn(6).setPreferredWidth(120);
        apiRuleTable.getColumnModel().getColumn(7).setPreferredWidth(80);

        apiRuleSorter = new TableRowSorter<>(apiRuleTableModel);
        apiRuleTable.setRowSorter(apiRuleSorter);

        apiRuleTable.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    editApiRule();
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(apiRuleTable);

        // 按钮行
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 3));
        JButton addRuleBtn = new JButton("添加规则");
        addRuleBtn.addActionListener(e -> addApiRule());
        JButton editRuleBtn = new JButton("编辑规则");
        editRuleBtn.addActionListener(e -> editApiRule());
        JButton deleteRuleBtn = new JButton("删除规则");
        deleteRuleBtn.addActionListener(e -> deleteApiRule());
        JButton reExtractBtn = new JButton("重新提取所有API");
        reExtractBtn.setToolTipText("使用当前规则重新计算所有请求和历史记录的API值");
        reExtractBtn.addActionListener(e -> ApiReExtractWorker.reExtractWithProgress(this, onDataChanged));
        JButton exportYamlBtn = new JButton("导出YAML");
        exportYamlBtn.setToolTipText("将所有规则导出为YAML格式文件");
        exportYamlBtn.addActionListener(e -> exportRulesToYaml());
        JButton importYamlBtn = new JButton("导入YAML");
        importYamlBtn.setToolTipText("从YAML格式文件导入规则");
        importYamlBtn.addActionListener(e -> importRulesFromYaml());

        buttonPanel.add(addRuleBtn);
        buttonPanel.add(editRuleBtn);
        buttonPanel.add(deleteRuleBtn);
        buttonPanel.add(Box.createHorizontalStrut(20));
        buttonPanel.add(exportYamlBtn);
        buttonPanel.add(importYamlBtn);
        buttonPanel.add(Box.createHorizontalStrut(20));
        buttonPanel.add(reExtractBtn);

        // 规则测试区域
        JPanel testWrapper = createTestPanel();

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, testWrapper);
        splitPane.setResizeWeight(0.6);
        splitPane.setDividerLocation(300);

        add(splitPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        // 初始化加载数据
        refreshApiRuleTable();
    }

    private JPanel createTestPanel() {
        JPanel testWrapper = new JPanel(new BorderLayout(5, 5));
        testWrapper.setBorder(BorderFactory.createTitledBorder("规则测试"));

        JPanel testPanel = new JPanel(new GridBagLayout());
        GridBagConstraints tc = new GridBagConstraints();
        tc.fill = GridBagConstraints.HORIZONTAL;
        tc.insets = new Insets(2, 5, 2, 5);

        tc.gridx = 0; tc.gridy = 0; tc.weightx = 0;
        testPanel.add(new JLabel("URL路径:"), tc);
        tc.gridx = 1; tc.gridy = 0; tc.weightx = 1.0; tc.gridwidth = 2;
        testPathField = new JTextField("/api/v1/users");
        testPanel.add(testPathField, tc);

        tc.gridx = 0; tc.gridy = 1; tc.weightx = 0; tc.gridwidth = 1;
        testPanel.add(new JLabel("URL参数:"), tc);
        tc.gridx = 1; tc.gridy = 1; tc.weightx = 1.0; tc.gridwidth = 2;
        testQueryField = new JTextField("action=getUser&id=1");
        testPanel.add(testQueryField, tc);

        tc.gridx = 0; tc.gridy = 2; tc.weightx = 0; tc.gridwidth = 1;
        testPanel.add(new JLabel("请求头:"), tc);
        tc.gridx = 1; tc.gridy = 2; tc.weightx = 1.0; tc.gridwidth = 2;
        testHeadersArea = new JTextArea(3, 30);
        testHeadersArea.setText("Host: example.com\nContent-Type: application/json");
        testHeadersArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        testPanel.add(new JScrollPane(testHeadersArea), tc);

        tc.gridx = 0; tc.gridy = 3; tc.weightx = 0; tc.gridwidth = 1;
        testPanel.add(new JLabel("请求体:"), tc);
        tc.gridx = 1; tc.gridy = 3; tc.weightx = 1.0; tc.gridwidth = 2;
        testBodyArea = new JTextArea(3, 30);
        testBodyArea.setText("{\"api\": \"login\"}");
        testBodyArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        testPanel.add(new JScrollPane(testBodyArea), tc);

        tc.gridx = 0; tc.gridy = 4; tc.weightx = 0; tc.gridwidth = 1;
        testPanel.add(new JLabel("Content-Type:"), tc);
        tc.gridx = 1; tc.gridy = 4; tc.weightx = 1.0; tc.gridwidth = 2;
        testContentTypeField = new JTextField("application/json");
        testPanel.add(testContentTypeField, tc);

        tc.gridx = 0; tc.gridy = 5; tc.weightx = 0; tc.gridwidth = 1;
        JButton testExtractBtn = new JButton("测试提取");
        testExtractBtn.addActionListener(e -> testApiExtraction());
        testPanel.add(testExtractBtn, tc);

        tc.gridx = 1; tc.gridy = 5; tc.weightx = 1.0; tc.gridwidth = 2;
        testResultField = new JTextField();
        testResultField.setEditable(false);
        testResultField.setBackground(new Color(240, 240, 240));
        testPanel.add(testResultField, tc);

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
        return testWrapper;
    }

    private void toggleAdvancedSearch() {
        boolean visible = !advancedSearchPanel.isVisible();
        advancedSearchPanel.setVisible(visible);
        advancedSearchToggleBtn.setText(visible ? "▼ 高级搜索" : "▶ 高级搜索");
    }

    private void applyApiRuleFilter() {
        String searchText = apiSearchField.getText().trim().toLowerCase();
        String sourceFilter = (String) advSourceFilterCombo.getSelectedItem();
        String methodFilter = (String) advMethodFilterCombo.getSelectedItem();
        String enabledFilter = (String) advEnabledFilterCombo.getSelectedItem();
        boolean regexMode = advRegexMatchCheckbox.isSelected();
        String exprFilter = advExpressionField.getText().trim();

        List<RowFilter<ApiRuleTableModel, Integer>> filters = new ArrayList<>();

        // 简单搜索
        if (!searchText.isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(searchText)));
        }

        // 来源过滤
        if (sourceFilter != null && !"全部".equals(sourceFilter)) {
            filters.add(RowFilter.regexFilter("^" + Pattern.quote(sourceFilter) + "$", 2));
        }

        // 方法过滤
        if (methodFilter != null && !"全部".equals(methodFilter)) {
            filters.add(RowFilter.regexFilter("^" + Pattern.quote(methodFilter) + "$", 3));
        }

        // 启用状态过滤
        if (enabledFilter != null && !"全部".equals(enabledFilter)) {
            if ("已启用".equals(enabledFilter)) {
                filters.add(new RowFilter<ApiRuleTableModel, Integer>() {
                    public boolean include(Entry<? extends ApiRuleTableModel, ? extends Integer> entry) {
                        return Boolean.TRUE.equals(entry.getValue(5));
                    }
                });
            } else if ("已禁用".equals(enabledFilter)) {
                filters.add(new RowFilter<ApiRuleTableModel, Integer>() {
                    public boolean include(Entry<? extends ApiRuleTableModel, ? extends Integer> entry) {
                        return Boolean.FALSE.equals(entry.getValue(5));
                    }
                });
            }
        }

        // 表达式过滤
        if (!exprFilter.isEmpty()) {
            if (regexMode) {
                try {
                    filters.add(RowFilter.regexFilter(exprFilter, 4));
                } catch (PatternSyntaxException e) {
                    // 无效正则，跳过
                }
            } else {
                filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(exprFilter), 4));
            }
        }

        // 应用
        if (filters.isEmpty()) {
            apiRuleSorter.setRowFilter(null);
        } else if (filters.size() == 1) {
            apiRuleSorter.setRowFilter(filters.get(0));
        } else {
            apiRuleSorter.setRowFilter(RowFilter.andFilter(filters));
        }
    }

    private void addApiRule() {
        ApiExtractionRule newRule = new ApiExtractionRule();
        newRule.setPriority(apiRuleTableModel.getRowCount() + 1);
        if (ApiRuleEditDialog.showDialog(this, newRule, true)) {
            int id = ApiRuleManager.getInstance().addRule(newRule);
            if (id != -1) {
                refreshApiRuleTable();
                ApiReExtractWorker.reExtractSilently(onDataChanged);
            } else {
                JOptionPane.showMessageDialog(this, "保存规则失败", "错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void editApiRule() {
        int selectedRow = apiRuleTable.getSelectedRow();
        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(this, "请先选择要编辑的规则", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = apiRuleTable.convertRowIndexToModel(selectedRow);
        ApiExtractionRule rule = apiRuleTableModel.getRule(modelRow);
        if (rule == null) return;

        ApiExtractionRule oldRule = ApiRuleTableModel.copyRule(rule);
        if (ApiRuleEditDialog.showDialog(this, rule, false)) {
            if (ApiRuleManager.getInstance().updateRule(oldRule, rule)) {
                refreshApiRuleTable();
                ApiReExtractWorker.reExtractSilently(onDataChanged);
            } else {
                JOptionPane.showMessageDialog(this, "更新规则失败", "错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void deleteApiRule() {
        int selectedRow = apiRuleTable.getSelectedRow();
        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(this, "请先选择要删除的规则", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = apiRuleTable.convertRowIndexToModel(selectedRow);
        ApiExtractionRule rule = apiRuleTableModel.getRule(modelRow);
        if (rule == null) return;

        int confirm = JOptionPane.showConfirmDialog(this,
                "确定要删除规则 \"" + rule.getName() + "\" 吗？",
                "确认删除", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm == JOptionPane.YES_OPTION) {
            if (ApiRuleManager.getInstance().deleteRule(rule.getId())) {
                refreshApiRuleTable();
                ApiReExtractWorker.reExtractSilently(onDataChanged);
            } else {
                JOptionPane.showMessageDialog(this, "删除规则失败", "错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportRulesToYaml() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showSaveDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_YAML_RULE_EXPORT, "导出API提取规则", this,
                new File("api_extraction_rules.yaml"),
                new javax.swing.filechooser.FileNameExtensionFilter("YAML文件 (*.yaml, *.yml)", "yaml", "yml"));

        if (selectedFile == null) {
            return;
        }

        if (!selectedFile.getName().endsWith(".yaml") && !selectedFile.getName().endsWith(".yml")) {
            selectedFile = new File(selectedFile.getAbsolutePath() + ".yaml");
        }
        List<ApiExtractionRule> rules = ApiRuleManager.getInstance().getAllRulesForDisplay();
        if (rules.isEmpty()) {
            JOptionPane.showMessageDialog(this, "没有规则可导出", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        if (ApiRuleYamlIO.writeToFile(rules, selectedFile.getAbsolutePath())) {
            JOptionPane.showMessageDialog(this,
                    "已导出 " + rules.size() + " 条规则到:\n" + selectedFile.getAbsolutePath(),
                    "导出成功", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this, "导出规则失败", "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void importRulesFromYaml() {
        File file = org.oxff.repeater.utils.FileChooserHelper.showOpenDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_YAML_RULE_IMPORT, "导入API提取规则", this,
                new javax.swing.filechooser.FileNameExtensionFilter("YAML文件 (*.yaml, *.yml)", "yaml", "yml"));

        if (file == null) {
            return;
        }

        List<ApiExtractionRule> importedRules = ApiRuleYamlIO.readFromFile(file.getAbsolutePath());
        if (importedRules.isEmpty()) {
            JOptionPane.showMessageDialog(this, "文件中没有找到有效规则", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String[] options = {"合并（保留现有规则）", "替换（清除现有规则）", "取消"};
        int choice = JOptionPane.showOptionDialog(this,
                "检测到 " + importedRules.size() + " 条规则\n请选择导入模式:",
                "导入模式", JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE,
                null, options, options[0]);

        if (choice == 0) {
            int added = ApiRuleManager.getInstance().importRulesMerge(importedRules);
            refreshApiRuleTable();
            ApiReExtractWorker.reExtractSilently(onDataChanged);
            JOptionPane.showMessageDialog(this,
                    "合并导入完成\n新增 " + added + " 条规则（去重后）",
                    "导入成功", JOptionPane.INFORMATION_MESSAGE);
        } else if (choice == 1) {
            int confirm = JOptionPane.showConfirmDialog(this,
                    "替换模式将删除所有现有规则，确定继续吗？",
                    "确认替换", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirm == JOptionPane.YES_OPTION) {
                ApiRuleManager.getInstance().importRulesReplace(importedRules);
                refreshApiRuleTable();
                ApiReExtractWorker.reExtractSilently(onDataChanged);
                JOptionPane.showMessageDialog(this,
                        "替换导入完成，共导入 " + importedRules.size() + " 条规则",
                        "导入成功", JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    private void testApiExtraction() {
        String path = testPathField.getText().trim();
        String query = testQueryField.getText().trim();
        String headersText = testHeadersArea.getText().trim();
        String bodyText = testBodyArea.getText().trim();
        String contentType = testContentTypeField.getText().trim();

        List<String> headerList = new ArrayList<>();
        if (!headersText.isEmpty()) {
            for (String line : headersText.split("\n")) {
                if (!line.trim().isEmpty()) {
                    headerList.add(line.trim());
                }
            }
        }

        byte[] body = null;
        if (!bodyText.isEmpty()) {
            body = bodyText.getBytes(StandardCharsets.UTF_8);
        }

        List<ApiExtractionRule> rules = ApiRuleManager.getInstance().getActiveRules();
        String result = ApiExtractionEngine.extractApi(path, query.isEmpty() ? null : query, headerList, body, contentType, rules);

        testResultField.setText(result);
    }
}
