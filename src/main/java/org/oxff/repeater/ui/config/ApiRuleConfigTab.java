package org.oxff.repeater.ui.config;

import org.oxff.repeater.api.ApiExtractionEngine;
import org.oxff.repeater.api.ApiExtractionRule;
import org.oxff.repeater.api.ApiRuleManager;
import org.oxff.repeater.api.ApiRuleYamlIO;
import org.oxff.repeater.i18n.I18nManager;
import javax.swing.*;
import javax.swing.border.TitledBorder;
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

    // 需要随语言切换刷新的组件
    private JLabel searchLabel;
    private JLabel advSourceLabel;
    private JLabel advMethodLabel;
    private JLabel advStatusLabel;
    private JLabel advExprLabel;
    private JButton addRuleBtn;
    private JButton editRuleBtn;
    private JButton deleteRuleBtn;
    private JButton reExtractBtn;
    private JButton exportYamlBtn;
    private JButton importYamlBtn;
    private JPanel testWrapper;
    private JLabel testPathLabel;
    private JLabel testQueryLabel;
    private JLabel testHeadersLabel;
    private JLabel testBodyLabel;
    private JLabel testContentTypeLabel;
    private JButton testExtractBtn;
    private JTextArea descArea;

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
        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);
    }

    /**
     * 语言切换时刷新所有文本
     */
    private void refreshTexts() {
        searchLabel.setText(I18nManager.tr("api.rule.search"));
        apiSearchField.setToolTipText(I18nManager.tr("api.rule.search.tooltip"));
        advancedSearchToggleBtn.setText(advancedSearchPanel.isVisible()
            ? I18nManager.tr("api.rule.advanced.hide") : I18nManager.tr("api.rule.advanced.show"));
        advancedSearchToggleBtn.setToolTipText(I18nManager.tr("api.rule.advanced.tooltip"));
        ((TitledBorder) advancedSearchPanel.getBorder()).setTitle(I18nManager.tr("api.rule.advanced.title"));
        advSourceLabel.setText(I18nManager.tr("api.rule.advanced.source"));
        advMethodLabel.setText(I18nManager.tr("api.rule.advanced.method"));
        advStatusLabel.setText(I18nManager.tr("api.rule.advanced.status"));
        advExprLabel.setText(I18nManager.tr("api.rule.advanced.expression"));
        advRegexMatchCheckbox.setText(I18nManager.tr("api.rule.regex"));
        advExpressionField.setToolTipText(I18nManager.tr("api.rule.advanced.expr.tooltip"));

        // 刷新高级搜索下拉项
        int srcIdx = advSourceFilterCombo.getSelectedIndex();
        advSourceFilterCombo.setModel(new DefaultComboBoxModel<>(new String[]{
            I18nManager.tr("api.rule.source.all"), I18nManager.tr("api.rule.source.urlPath"),
            I18nManager.tr("api.rule.source.urlParam"), I18nManager.tr("api.rule.source.header"),
            I18nManager.tr("api.rule.source.body")
        }));
        advSourceFilterCombo.setSelectedIndex(srcIdx);

        int mthIdx = advMethodFilterCombo.getSelectedIndex();
        advMethodFilterCombo.setModel(new DefaultComboBoxModel<>(new String[]{
            I18nManager.tr("api.rule.method.all"), I18nManager.tr("api.rule.method.regex"),
            I18nManager.tr("api.rule.method.substring"), I18nManager.tr("api.rule.method.jsonPath"),
            I18nManager.tr("api.rule.method.xpath")
        }));
        advMethodFilterCombo.setSelectedIndex(mthIdx);

        int stIdx = advEnabledFilterCombo.getSelectedIndex();
        advEnabledFilterCombo.setModel(new DefaultComboBoxModel<>(new String[]{
            I18nManager.tr("api.rule.status.all"), I18nManager.tr("api.rule.status.enabled"),
            I18nManager.tr("api.rule.status.disabled")
        }));
        advEnabledFilterCombo.setSelectedIndex(stIdx);

        addRuleBtn.setText(I18nManager.tr("api.rule.add"));
        editRuleBtn.setText(I18nManager.tr("api.rule.edit"));
        deleteRuleBtn.setText(I18nManager.tr("api.rule.delete"));
        reExtractBtn.setText(I18nManager.tr("api.rule.reextract"));
        reExtractBtn.setToolTipText(I18nManager.tr("api.rule.reextract.tooltip"));
        exportYamlBtn.setText(I18nManager.tr("api.rule.exportYaml"));
        exportYamlBtn.setToolTipText(I18nManager.tr("api.rule.exportYaml.tooltip"));
        importYamlBtn.setText(I18nManager.tr("api.rule.importYaml"));
        importYamlBtn.setToolTipText(I18nManager.tr("api.rule.importYaml.tooltip"));

        ((TitledBorder) testWrapper.getBorder()).setTitle(I18nManager.tr("api.rule.test.title"));
        testPathLabel.setText(I18nManager.tr("api.rule.test.urlPath"));
        testQueryLabel.setText(I18nManager.tr("api.rule.test.urlParam"));
        testHeadersLabel.setText(I18nManager.tr("api.rule.test.header"));
        testBodyLabel.setText(I18nManager.tr("api.rule.test.body"));
        testContentTypeLabel.setText(I18nManager.tr("api.rule.test.contentType"));
        testExtractBtn.setText(I18nManager.tr("api.rule.test.run"));
        descArea.setText(I18nManager.tr("api.rule.test.desc"));

        // 刷新表格列名
        apiRuleTableModel.refreshColumnNames();
        applyColumnWidths();

        revalidate();
        repaint();
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
        searchLabel = new JLabel(I18nManager.tr("api.rule.search"));
        searchRow.add(searchLabel, BorderLayout.WEST);
        apiSearchField = new JTextField(20);
        apiSearchField.setToolTipText(I18nManager.tr("api.rule.search.tooltip"));
        apiSearchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyApiRuleFilter(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyApiRuleFilter(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyApiRuleFilter(); }
        });
        searchRow.add(apiSearchField, BorderLayout.CENTER);

        advancedSearchToggleBtn = new JButton(I18nManager.tr("api.rule.advanced.show"));
        advancedSearchToggleBtn.setToolTipText(I18nManager.tr("api.rule.advanced.tooltip"));
        advancedSearchToggleBtn.addActionListener(e -> toggleAdvancedSearch());
        searchRow.add(advancedSearchToggleBtn, BorderLayout.EAST);

        topPanel.add(searchRow, BorderLayout.NORTH);

        // 高级搜索面板
        advancedSearchPanel = new JPanel(new GridBagLayout());
        advancedSearchPanel.setBorder(BorderFactory.createTitledBorder(I18nManager.tr("api.rule.advanced.title")));
        advancedSearchPanel.setVisible(false);

        GridBagConstraints ac = new GridBagConstraints();
        ac.fill = GridBagConstraints.HORIZONTAL;
        ac.insets = new Insets(2, 5, 2, 5);

        ac.gridx = 0; ac.gridy = 0; ac.weightx = 0;
        advSourceLabel = new JLabel(I18nManager.tr("api.rule.advanced.source"));
        advancedSearchPanel.add(advSourceLabel, ac);
        ac.gridx = 1; ac.gridy = 0; ac.weightx = 1.0;
        advSourceFilterCombo = new JComboBox<>(new String[]{
            I18nManager.tr("api.rule.source.all"), I18nManager.tr("api.rule.source.urlPath"),
            I18nManager.tr("api.rule.source.urlParam"), I18nManager.tr("api.rule.source.header"),
            I18nManager.tr("api.rule.source.body")
        });
        advSourceFilterCombo.addActionListener(e -> applyApiRuleFilter());
        advancedSearchPanel.add(advSourceFilterCombo, ac);

        ac.gridx = 2; ac.gridy = 0; ac.weightx = 0;
        advMethodLabel = new JLabel(I18nManager.tr("api.rule.advanced.method"));
        advancedSearchPanel.add(advMethodLabel, ac);
        ac.gridx = 3; ac.gridy = 0; ac.weightx = 1.0;
        advMethodFilterCombo = new JComboBox<>(new String[]{
            I18nManager.tr("api.rule.method.all"), I18nManager.tr("api.rule.method.regex"),
            I18nManager.tr("api.rule.method.substring"), I18nManager.tr("api.rule.method.jsonPath"),
            I18nManager.tr("api.rule.method.xpath")
        });
        advMethodFilterCombo.addActionListener(e -> applyApiRuleFilter());
        advancedSearchPanel.add(advMethodFilterCombo, ac);

        ac.gridx = 0; ac.gridy = 1; ac.weightx = 0;
        advStatusLabel = new JLabel(I18nManager.tr("api.rule.advanced.status"));
        advancedSearchPanel.add(advStatusLabel, ac);
        ac.gridx = 1; ac.gridy = 1; ac.weightx = 1.0;
        advEnabledFilterCombo = new JComboBox<>(new String[]{
            I18nManager.tr("api.rule.status.all"), I18nManager.tr("api.rule.status.enabled"),
            I18nManager.tr("api.rule.status.disabled")
        });
        advEnabledFilterCombo.addActionListener(e -> applyApiRuleFilter());
        advancedSearchPanel.add(advEnabledFilterCombo, ac);

        ac.gridx = 2; ac.gridy = 1; ac.weightx = 0;
        advExprLabel = new JLabel(I18nManager.tr("api.rule.advanced.expression"));
        advancedSearchPanel.add(advExprLabel, ac);
        ac.gridx = 3; ac.gridy = 1; ac.weightx = 1.0;
        JPanel exprPanel = new JPanel(new BorderLayout(3, 0));
        advRegexMatchCheckbox = new JCheckBox(I18nManager.tr("api.rule.regex"));
        advExpressionField = new JTextField(15);
        advExpressionField.setToolTipText(I18nManager.tr("api.rule.advanced.expr.tooltip"));
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
        applyColumnWidths();

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
        addRuleBtn = new JButton(I18nManager.tr("api.rule.add"));
        addRuleBtn.addActionListener(e -> addApiRule());
        editRuleBtn = new JButton(I18nManager.tr("api.rule.edit"));
        editRuleBtn.addActionListener(e -> editApiRule());
        deleteRuleBtn = new JButton(I18nManager.tr("api.rule.delete"));
        deleteRuleBtn.addActionListener(e -> deleteApiRule());
        reExtractBtn = new JButton(I18nManager.tr("api.rule.reextract"));
        reExtractBtn.setToolTipText(I18nManager.tr("api.rule.reextract.tooltip"));
        reExtractBtn.addActionListener(e -> ApiReExtractWorker.reExtractWithProgress(this, onDataChanged));
        exportYamlBtn = new JButton(I18nManager.tr("api.rule.exportYaml"));
        exportYamlBtn.setToolTipText(I18nManager.tr("api.rule.exportYaml.tooltip"));
        exportYamlBtn.addActionListener(e -> exportRulesToYaml());
        importYamlBtn = new JButton(I18nManager.tr("api.rule.importYaml"));
        importYamlBtn.setToolTipText(I18nManager.tr("api.rule.importYaml.tooltip"));
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
        testWrapper = createTestPanel();

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, testWrapper);
        splitPane.setResizeWeight(0.6);
        splitPane.setDividerLocation(300);

        add(splitPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        // 初始化加载数据
        refreshApiRuleTable();
    }

    /**
     * 应用表格列宽
     */
    private void applyColumnWidths() {
        if (apiRuleTable.getColumnModel().getColumnCount() < 8) return;
        apiRuleTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        apiRuleTable.getColumnModel().getColumn(1).setPreferredWidth(80);
        apiRuleTable.getColumnModel().getColumn(2).setPreferredWidth(70);
        apiRuleTable.getColumnModel().getColumn(3).setPreferredWidth(70);
        apiRuleTable.getColumnModel().getColumn(4).setPreferredWidth(250);
        apiRuleTable.getColumnModel().getColumn(5).setPreferredWidth(50);
        apiRuleTable.getColumnModel().getColumn(6).setPreferredWidth(120);
        apiRuleTable.getColumnModel().getColumn(7).setPreferredWidth(80);
    }

    private JPanel createTestPanel() {
        testWrapper = new JPanel(new BorderLayout(5, 5));
        testWrapper.setBorder(BorderFactory.createTitledBorder(I18nManager.tr("api.rule.test.title")));

        JPanel testPanel = new JPanel(new GridBagLayout());
        GridBagConstraints tc = new GridBagConstraints();
        tc.fill = GridBagConstraints.HORIZONTAL;
        tc.insets = new Insets(2, 5, 2, 5);

        tc.gridx = 0; tc.gridy = 0; tc.weightx = 0;
        testPathLabel = new JLabel(I18nManager.tr("api.rule.test.urlPath"));
        testPanel.add(testPathLabel, tc);
        tc.gridx = 1; tc.gridy = 0; tc.weightx = 1.0; tc.gridwidth = 2;
        testPathField = new JTextField("/api/v1/users");
        testPanel.add(testPathField, tc);

        tc.gridx = 0; tc.gridy = 1; tc.weightx = 0; tc.gridwidth = 1;
        testQueryLabel = new JLabel(I18nManager.tr("api.rule.test.urlParam"));
        testPanel.add(testQueryLabel, tc);
        tc.gridx = 1; tc.gridy = 1; tc.weightx = 1.0; tc.gridwidth = 2;
        testQueryField = new JTextField("action=getUser&id=1");
        testPanel.add(testQueryField, tc);

        tc.gridx = 0; tc.gridy = 2; tc.weightx = 0; tc.gridwidth = 1;
        testHeadersLabel = new JLabel(I18nManager.tr("api.rule.test.header"));
        testPanel.add(testHeadersLabel, tc);
        tc.gridx = 1; tc.gridy = 2; tc.weightx = 1.0; tc.gridwidth = 2;
        testHeadersArea = new JTextArea(3, 30);
        testHeadersArea.setText("Host: example.com\nContent-Type: application/json");
        testHeadersArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        testPanel.add(new JScrollPane(testHeadersArea), tc);

        tc.gridx = 0; tc.gridy = 3; tc.weightx = 0; tc.gridwidth = 1;
        testBodyLabel = new JLabel(I18nManager.tr("api.rule.test.body"));
        testPanel.add(testBodyLabel, tc);
        tc.gridx = 1; tc.gridy = 3; tc.weightx = 1.0; tc.gridwidth = 2;
        testBodyArea = new JTextArea(3, 30);
        testBodyArea.setText("{\"api\": \"login\"}");
        testBodyArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        testPanel.add(new JScrollPane(testBodyArea), tc);

        tc.gridx = 0; tc.gridy = 4; tc.weightx = 0; tc.gridwidth = 1;
        testContentTypeLabel = new JLabel(I18nManager.tr("api.rule.test.contentType"));
        testPanel.add(testContentTypeLabel, tc);
        tc.gridx = 1; tc.gridy = 4; tc.weightx = 1.0; tc.gridwidth = 2;
        testContentTypeField = new JTextField("application/json");
        testPanel.add(testContentTypeField, tc);

        tc.gridx = 0; tc.gridy = 5; tc.weightx = 0; tc.gridwidth = 1;
        testExtractBtn = new JButton(I18nManager.tr("api.rule.test.run"));
        testExtractBtn.addActionListener(e -> testApiExtraction());
        testPanel.add(testExtractBtn, tc);

        tc.gridx = 1; tc.gridy = 5; tc.weightx = 1.0; tc.gridwidth = 2;
        testResultField = new JTextField();
        testResultField.setEditable(false);
        testResultField.setBackground(new Color(240, 240, 240));
        testPanel.add(testResultField, tc);

        tc.gridx = 0; tc.gridy = 6; tc.weightx = 1.0; tc.gridwidth = 3;
        tc.fill = GridBagConstraints.BOTH;
        descArea = new JTextArea(I18nManager.tr("api.rule.test.desc"));
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
        advancedSearchToggleBtn.setText(visible
            ? I18nManager.tr("api.rule.advanced.hide") : I18nManager.tr("api.rule.advanced.show"));
    }

    private void applyApiRuleFilter() {
        String searchText = apiSearchField.getText().trim().toLowerCase();
        int sourceFilterIndex = advSourceFilterCombo.getSelectedIndex();
        int methodFilterIndex = advMethodFilterCombo.getSelectedIndex();
        int enabledFilterIndex = advEnabledFilterCombo.getSelectedIndex();
        boolean regexMode = advRegexMatchCheckbox.isSelected();
        String exprFilter = advExpressionField.getText().trim();

        List<RowFilter<ApiRuleTableModel, Integer>> filters = new ArrayList<>();

        // 简单搜索
        if (!searchText.isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(searchText)));
        }

        // 来源过滤（按索引，0=全部）
        if (sourceFilterIndex > 0) {
            String sourceValue = (String) advSourceFilterCombo.getSelectedItem();
            if (sourceValue != null) {
                filters.add(RowFilter.regexFilter("^" + Pattern.quote(sourceValue) + "$", 2));
            }
        }

        // 方法过滤（按索引，0=全部）
        if (methodFilterIndex > 0) {
            String methodValue = (String) advMethodFilterCombo.getSelectedItem();
            if (methodValue != null) {
                filters.add(RowFilter.regexFilter("^" + Pattern.quote(methodValue) + "$", 3));
            }
        }

        // 启用状态过滤（按索引，0=全部，1=已启用，2=已禁用）
        if (enabledFilterIndex == 1) {
            filters.add(new RowFilter<ApiRuleTableModel, Integer>() {
                public boolean include(Entry<? extends ApiRuleTableModel, ? extends Integer> entry) {
                    return Boolean.TRUE.equals(entry.getValue(5));
                }
            });
        } else if (enabledFilterIndex == 2) {
            filters.add(new RowFilter<ApiRuleTableModel, Integer>() {
                public boolean include(Entry<? extends ApiRuleTableModel, ? extends Integer> entry) {
                    return Boolean.FALSE.equals(entry.getValue(5));
                }
            });
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
                JOptionPane.showMessageDialog(this, I18nManager.tr("api.rule.save.failed"),
                    I18nManager.tr("common.error"), JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void editApiRule() {
        int selectedRow = apiRuleTable.getSelectedRow();
        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("api.rule.select.edit"),
                I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
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
                JOptionPane.showMessageDialog(this, I18nManager.tr("api.rule.update.failed"),
                    I18nManager.tr("common.error"), JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void deleteApiRule() {
        int selectedRow = apiRuleTable.getSelectedRow();
        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("api.rule.select.delete"),
                I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = apiRuleTable.convertRowIndexToModel(selectedRow);
        ApiExtractionRule rule = apiRuleTableModel.getRule(modelRow);
        if (rule == null) return;

        int confirm = JOptionPane.showConfirmDialog(this,
                I18nManager.tr("api.rule.delete.confirm", rule.getName()),
                I18nManager.tr("api.rule.delete.confirm.title"), JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm == JOptionPane.YES_OPTION) {
            if (ApiRuleManager.getInstance().deleteRule(rule.getId())) {
                refreshApiRuleTable();
                ApiReExtractWorker.reExtractSilently(onDataChanged);
            } else {
                JOptionPane.showMessageDialog(this, I18nManager.tr("api.rule.delete.failed"),
                    I18nManager.tr("common.error"), JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportRulesToYaml() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showSaveDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_YAML_RULE_EXPORT,
                I18nManager.tr("api.rule.export.dialog"), this,
                new File("api_extraction_rules.yaml"),
                new javax.swing.filechooser.FileNameExtensionFilter(
                    I18nManager.tr("api.rule.yaml.filter"), "yaml", "yml"));

        if (selectedFile == null) {
            return;
        }

        if (!selectedFile.getName().endsWith(".yaml") && !selectedFile.getName().endsWith(".yml")) {
            selectedFile = new File(selectedFile.getAbsolutePath() + ".yaml");
        }
        List<ApiExtractionRule> rules = ApiRuleManager.getInstance().getAllRulesForDisplay();
        if (rules.isEmpty()) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("api.rule.export.empty"),
                I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        if (ApiRuleYamlIO.writeToFile(rules, selectedFile.getAbsolutePath())) {
            JOptionPane.showMessageDialog(this,
                    I18nManager.tr("api.rule.export.success", rules.size(), selectedFile.getAbsolutePath()),
                    I18nManager.tr("api.rule.export.success.title"), JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this, I18nManager.tr("api.rule.export.failed"),
                I18nManager.tr("common.error"), JOptionPane.ERROR_MESSAGE);
        }
    }

    private void importRulesFromYaml() {
        File file = org.oxff.repeater.utils.FileChooserHelper.showOpenDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_YAML_RULE_IMPORT,
                I18nManager.tr("api.rule.import.dialog"), this,
                new javax.swing.filechooser.FileNameExtensionFilter(
                    I18nManager.tr("api.rule.yaml.filter"), "yaml", "yml"));

        if (file == null) {
            return;
        }

        List<ApiExtractionRule> importedRules = ApiRuleYamlIO.readFromFile(file.getAbsolutePath());
        if (importedRules.isEmpty()) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("api.rule.import.empty"),
                I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String[] options = {
            I18nManager.tr("api.rule.import.mode.merge"),
            I18nManager.tr("api.rule.import.mode.replace"),
            I18nManager.tr("api.rule.import.mode.cancel")
        };
        int choice = JOptionPane.showOptionDialog(this,
                I18nManager.tr("api.rule.import.mode.msg", importedRules.size()),
                I18nManager.tr("api.rule.import.mode.title"), JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE,
                null, options, options[0]);

        if (choice == 0) {
            int added = ApiRuleManager.getInstance().importRulesMerge(importedRules);
            refreshApiRuleTable();
            ApiReExtractWorker.reExtractSilently(onDataChanged);
            JOptionPane.showMessageDialog(this,
                    I18nManager.tr("api.rule.import.merge.success", added),
                    I18nManager.tr("api.rule.import.success.title"), JOptionPane.INFORMATION_MESSAGE);
        } else if (choice == 1) {
            int confirm = JOptionPane.showConfirmDialog(this,
                    I18nManager.tr("api.rule.import.replace.confirm"),
                    I18nManager.tr("api.rule.import.replace.confirm.title"), JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirm == JOptionPane.YES_OPTION) {
                ApiRuleManager.getInstance().importRulesReplace(importedRules);
                refreshApiRuleTable();
                ApiReExtractWorker.reExtractSilently(onDataChanged);
                JOptionPane.showMessageDialog(this,
                        I18nManager.tr("api.rule.import.replace.success", importedRules.size()),
                        I18nManager.tr("api.rule.import.success.title"), JOptionPane.INFORMATION_MESSAGE);
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
