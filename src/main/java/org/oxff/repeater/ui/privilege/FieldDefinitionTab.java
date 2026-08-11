package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.i18n.I18nManager;
import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.model.FieldDefinition;
import org.oxff.repeater.privilege.model.FieldType;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.TableRowSorter;
import javax.swing.RowFilter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 字段定义管理子标签页
 * 从原有 SessionConfigTab 的字段定义区域抽取
 */
public class FieldDefinitionTab extends JPanel {

    private final JTable fieldTable;
    private final FieldDefinitionTableModel fieldModel;
    private TableRowSorter<FieldDefinitionTableModel> fieldSorter;
    private JTextField searchField;
    private JCheckBox caseSensitiveCheckbox;
    private JCheckBox regexCheckbox;

    private JLabel searchLabel;
    private JButton clearSearchBtn;
    private JMenuItem editItem;
    private JMenuItem deleteItem;
    private JButton addBtn;
    private JButton editBtn;
    private JButton deleteBtn;
    private JButton importBtn;
    private JButton exportBtn;

    public FieldDefinitionTab() {
        super(new BorderLayout(0, 5));

        // ========== 字段搜索面板 ==========
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        searchLabel = new JLabel(I18nManager.tr("field.search"));
        searchPanel.add(searchLabel);
        searchField = new JTextField(15);
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilter(); }
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilter(); }
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyFilter(); }
        });
        searchPanel.add(searchField);

        caseSensitiveCheckbox = new JCheckBox("Aa");
        caseSensitiveCheckbox.setToolTipText(I18nManager.tr("field.search.case.tooltip"));
        caseSensitiveCheckbox.addActionListener(e -> applyFilter());
        searchPanel.add(caseSensitiveCheckbox);

        regexCheckbox = new JCheckBox(".*");
        regexCheckbox.setToolTipText(I18nManager.tr("field.search.regex.tooltip"));
        regexCheckbox.addActionListener(e -> applyFilter());
        searchPanel.add(regexCheckbox);

        clearSearchBtn = new JButton(I18nManager.tr("field.clear"));
        clearSearchBtn.addActionListener(e -> {
            searchField.setText("");
            applyFilter();
        });
        searchPanel.add(clearSearchBtn);

        add(searchPanel, BorderLayout.NORTH);

        // ========== 字段表格 ==========
        fieldModel = new FieldDefinitionTableModel();
        fieldTable = new JTable(fieldModel);
        fieldTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        fieldTable.getColumnModel().getColumn(0).setPreferredWidth(60);   // 类型
        fieldTable.getColumnModel().getColumn(1).setPreferredWidth(150);  // 表达式
        fieldTable.getColumnModel().getColumn(2).setPreferredWidth(150);  // 描述
        fieldTable.getColumnModel().getColumn(3).setPreferredWidth(80);   // 持久化到全局
        fieldTable.getColumnModel().getColumn(4).setPreferredWidth(50);   // 启用

        // 设置 TableRowSorter 启用列头排序
        fieldSorter = new TableRowSorter<>(fieldModel);
        fieldTable.setRowSorter(fieldSorter);

        // 双击编辑 + 右键行选择 + 右键菜单
        fieldTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
                    int row = fieldTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        editField();
                    }
                }
            }
            @Override
            public void mousePressed(MouseEvent e) {
                selectRowOnRightClick(e, fieldTable);
            }
            @Override
            public void mouseReleased(MouseEvent e) {
                selectRowOnRightClick(e, fieldTable);
            }
        });

        // 右键菜单
        JPopupMenu popupMenu = new JPopupMenu();
        editItem = new JMenuItem(I18nManager.tr("field.edit"));
        editItem.addActionListener(e -> editField());
        deleteItem = new JMenuItem(I18nManager.tr("field.delete"));
        deleteItem.addActionListener(e -> deleteField());
        popupMenu.add(editItem);
        popupMenu.add(deleteItem);
        fieldTable.setComponentPopupMenu(popupMenu);

        JScrollPane scrollPane = new JScrollPane(fieldTable);
        add(scrollPane, BorderLayout.CENTER);

        // ========== 按钮面板 ==========
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addBtn = new JButton(I18nManager.tr("field.add"));
        editBtn = new JButton(I18nManager.tr("field.edit.title"));
        deleteBtn = new JButton(I18nManager.tr("field.delete.title"));
        importBtn = new JButton(I18nManager.tr("field.import"));
        exportBtn = new JButton(I18nManager.tr("field.export"));

        addBtn.addActionListener(e -> addField());
        editBtn.addActionListener(e -> editField());
        deleteBtn.addActionListener(e -> deleteField());
        importBtn.addActionListener(e -> importFields());
        exportBtn.addActionListener(e -> exportFields());

        buttonPanel.add(addBtn);
        buttonPanel.add(editBtn);
        buttonPanel.add(deleteBtn);
        buttonPanel.add(importBtn);
        buttonPanel.add(exportBtn);

        add(buttonPanel, BorderLayout.SOUTH);

        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);
    }

    /**
     * 语言切换时刷新文本
     */
    private void refreshTexts() {
        searchLabel.setText(I18nManager.tr("field.search"));
        caseSensitiveCheckbox.setToolTipText(I18nManager.tr("field.search.case.tooltip"));
        regexCheckbox.setToolTipText(I18nManager.tr("field.search.regex.tooltip"));
        clearSearchBtn.setText(I18nManager.tr("field.clear"));
        editItem.setText(I18nManager.tr("field.edit"));
        deleteItem.setText(I18nManager.tr("field.delete"));
        addBtn.setText(I18nManager.tr("field.add"));
        editBtn.setText(I18nManager.tr("field.edit.title"));
        deleteBtn.setText(I18nManager.tr("field.delete.title"));
        importBtn.setText(I18nManager.tr("field.import"));
        exportBtn.setText(I18nManager.tr("field.export"));
        fieldModel.refreshColumnNames();
    }

    private void selectRowOnRightClick(MouseEvent e, JTable table) {
        if (SwingUtilities.isRightMouseButton(e)) {
            int row = table.rowAtPoint(e.getPoint());
            if (row >= 0) {
                table.setRowSelectionInterval(row, row);
            }
        }
    }

    public void refreshData() {
        SessionManager sessionManager = SessionManager.getInstance();
        fieldModel.setData(sessionManager.getFieldDefinitions());
    }

    private void applyFilter() {
        String text = searchField.getText().trim();
        if (text.isEmpty()) {
            fieldSorter.setRowFilter(null);
            return;
        }

        boolean caseSensitive = caseSensitiveCheckbox.isSelected();
        boolean regexMode = regexCheckbox.isSelected();

        String pattern;
        if (regexMode) {
            pattern = caseSensitive ? text : "(?i)" + text;
        } else {
            pattern = caseSensitive ? Pattern.quote(text) : "(?i)" + Pattern.quote(text);
        }

        try {
            fieldSorter.setRowFilter(RowFilter.regexFilter(pattern));
        } catch (PatternSyntaxException e) {
            // 正则表达式无效时静默忽略
        }
    }

    private void addField() {
        FieldDefinitionEditDialog dialog = new FieldDefinitionEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), I18nManager.tr("field.add.title"), null);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            SessionManager.getInstance().addFieldDefinition(
                    dialog.getFieldType(), dialog.getExpression(), dialog.getDescription(),
                    dialog.isPersistToGlobal(), dialog.isFieldEnabled());
            refreshData();
        }
    }

    private void editField() {
        int viewRow = fieldTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("field.select.first"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = fieldTable.convertRowIndexToModel(viewRow);
        FieldDefinition selected = fieldModel.getFieldDefinition(modelRow);
        FieldDefinitionEditDialog dialog = new FieldDefinitionEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), I18nManager.tr("field.edit.title"), selected);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            SessionManager.getInstance().updateFieldDefinition(
                    selected.getId(), dialog.getFieldType(), dialog.getExpression(), dialog.getDescription(),
                    dialog.isPersistToGlobal(), dialog.isFieldEnabled());
            refreshData();
        }
    }

    private void deleteField() {
        int viewRow = fieldTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("field.select.first"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = fieldTable.convertRowIndexToModel(viewRow);
        FieldDefinition selected = fieldModel.getFieldDefinition(modelRow);

        // 查询引用方案数
        int refCount = SessionManager.getInstance().getSchemeReferenceCountByField(selected.getId());
        String refMsg = refCount > 0 ? I18nManager.tr("field.delete.ref", refCount) : "";

        int confirm = JOptionPane.showConfirmDialog(this,
                I18nManager.tr("field.delete.confirm", selected.getExpression()) + refMsg,
                I18nManager.tr("field.delete.title"), JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            SessionManager.getInstance().deleteFieldDefinition(selected.getId());
            refreshData();
        }
    }

    private void exportFields() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showSaveDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_SESSION_YAML_EXPORT,
                I18nManager.tr("field.export.dialog"), this,
                new File("field_definitions.yaml"),
                new FileNameExtensionFilter(I18nManager.tr("field.yaml.filter"), "yaml"));

        if (selectedFile == null) return;

        File file = selectedFile;
        if (!file.getName().endsWith(".yaml") && !file.getName().endsWith(".yml")) {
            file = new File(file.getAbsolutePath() + ".yaml");
        }

        try {
            List<FieldDefinition> fields = SessionManager.getInstance().getFieldDefinitions();
            List<Map<String, Object>> exportList = new ArrayList<>();
            for (FieldDefinition field : fields) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("type", field.getType().name());
                entry.put("expression", field.getExpression());
                entry.put("description", field.getDescription());
                entry.put("persistToGlobal", field.isPersistToGlobal());
                entry.put("enabled", field.isEnabled());
                exportList.add(entry);
            }

            org.yaml.snakeyaml.DumperOptions options = new org.yaml.snakeyaml.DumperOptions();
            options.setDefaultFlowStyle(org.yaml.snakeyaml.DumperOptions.FlowStyle.BLOCK);
            options.setPrettyFlow(true);
            org.yaml.snakeyaml.Yaml yaml = new org.yaml.snakeyaml.Yaml(options);
            try (FileWriter writer = new FileWriter(file)) {
                yaml.dump(exportList, writer);
            }

            JOptionPane.showMessageDialog(this,
                I18nManager.tr("field.export.success", exportList.size(), file.getAbsolutePath()),
                I18nManager.tr("field.export.success.title"), JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                I18nManager.tr("field.export.failed", e.getMessage()),
                I18nManager.tr("field.export.failed.title"), JOptionPane.ERROR_MESSAGE);
        }
    }

    private void importFields() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showOpenDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_SESSION_YAML_IMPORT,
                I18nManager.tr("field.import.dialog"), this,
                new FileNameExtensionFilter(I18nManager.tr("field.yaml.filter.all"), "yaml", "yml"));

        if (selectedFile == null) return;

        try {
            org.yaml.snakeyaml.Yaml yaml = new org.yaml.snakeyaml.Yaml();
            List<Map<String, Object>> importList;

            try (FileInputStream fis = new FileInputStream(selectedFile)) {
                Iterable<Object> objects = yaml.loadAll(fis);
                List<Map<String, Object>> merged = new ArrayList<>();
                for (Object obj : objects) {
                    if (obj instanceof List) {
                        for (Object item : (List<?>) obj) {
                            if (item instanceof Map) {
                                merged.add(castToMap((Map<?, ?>) item));
                            }
                        }
                    } else if (obj instanceof Map) {
                        merged.add(castToMap((Map<?, ?>) obj));
                    }
                }
                importList = merged;
            }

            if (importList.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                    I18nManager.tr("field.import.empty"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            int imported = 0;
            SessionManager sm = SessionManager.getInstance();
            for (Map<String, Object> entry : importList) {
                try {
                    String typeStr = String.valueOf(entry.get("type"));
                    FieldType type = FieldType.fromString(typeStr);
                    String expression = String.valueOf(entry.getOrDefault("expression", ""));
                    String description = String.valueOf(entry.getOrDefault("description", ""));
                    boolean persistToGlobal = toBoolean(entry.getOrDefault("persistToGlobal", true));
                    boolean enabled = toBoolean(entry.getOrDefault("enabled", true));
                    sm.addFieldDefinition(type, expression, description, persistToGlobal, enabled);
                    imported++;
                } catch (Exception e) {
                    // 跳过无效条目
                }
            }

            refreshData();
            JOptionPane.showMessageDialog(this,
                I18nManager.tr("field.import.success", imported),
                I18nManager.tr("field.import.success.title"), JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                I18nManager.tr("field.import.failed", e.getMessage()),
                I18nManager.tr("field.import.failed.title"), JOptionPane.ERROR_MESSAGE);
        }
    }

    private static Map<String, Object> castToMap(Map<?, ?> map) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            result.put(String.valueOf(entry.getKey()), entry.getValue());
        }
        return result;
    }

    private static boolean toBoolean(Object value) {
        if (value == null) return true;
        if (value instanceof Boolean) return (Boolean) value;
        String str = String.valueOf(value).trim().toLowerCase();
        return "true".equals(str) || "1".equals(str) || "yes".equals(str);
    }
}
