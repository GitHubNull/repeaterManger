package org.oxff.repeater.ui.privilege;

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

    public FieldDefinitionTab() {
        super(new BorderLayout(0, 5));

        // ========== 字段搜索面板 ==========
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        searchPanel.add(new JLabel("搜索:"));
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
        caseSensitiveCheckbox.setToolTipText("区分大小写");
        caseSensitiveCheckbox.addActionListener(e -> applyFilter());
        searchPanel.add(caseSensitiveCheckbox);

        regexCheckbox = new JCheckBox(".*");
        regexCheckbox.setToolTipText("启用正则表达式匹配");
        regexCheckbox.addActionListener(e -> applyFilter());
        searchPanel.add(regexCheckbox);

        JButton clearSearchBtn = new JButton("清除");
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
        JMenuItem editItem = new JMenuItem("编辑");
        editItem.addActionListener(e -> editField());
        JMenuItem deleteItem = new JMenuItem("删除");
        deleteItem.addActionListener(e -> deleteField());
        popupMenu.add(editItem);
        popupMenu.add(deleteItem);
        fieldTable.setComponentPopupMenu(popupMenu);

        JScrollPane scrollPane = new JScrollPane(fieldTable);
        add(scrollPane, BorderLayout.CENTER);

        // ========== 按钮面板 ==========
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addBtn = new JButton("添加字段");
        JButton editBtn = new JButton("编辑字段");
        JButton deleteBtn = new JButton("删除字段");
        JButton importBtn = new JButton("导入");
        JButton exportBtn = new JButton("导出");

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
                (Frame) SwingUtilities.getWindowAncestor(this), "添加字段定义", null);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            SessionManager.getInstance().addFieldDefinition(
                    dialog.getFieldType(), dialog.getExpression(), dialog.getDescription(),
                    dialog.isPersistToGlobal(), dialog.isEnabled());
            refreshData();
        }
    }

    private void editField() {
        int viewRow = fieldTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个字段定义", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = fieldTable.convertRowIndexToModel(viewRow);
        FieldDefinition selected = fieldModel.getFieldDefinition(modelRow);
        FieldDefinitionEditDialog dialog = new FieldDefinitionEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), "编辑字段定义", selected);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            SessionManager.getInstance().updateFieldDefinition(
                    selected.getId(), dialog.getFieldType(), dialog.getExpression(), dialog.getDescription(),
                    dialog.isPersistToGlobal(), dialog.isEnabled());
            refreshData();
        }
    }

    private void deleteField() {
        int viewRow = fieldTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个字段定义", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = fieldTable.convertRowIndexToModel(viewRow);
        FieldDefinition selected = fieldModel.getFieldDefinition(modelRow);

        // 查询引用方案数
        int refCount = SessionManager.getInstance().getSchemeReferenceCountByField(selected.getId());
        String refMsg = refCount > 0 ? "\n该字段被 " + refCount + " 个方案引用，删除后将从方案中移除。" : "";

        int confirm = JOptionPane.showConfirmDialog(this,
                "确认删除字段定义: " + selected.getExpression() + "?\n关联的所有用户字段值也会被删除。" + refMsg,
                "删除确认", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            SessionManager.getInstance().deleteFieldDefinition(selected.getId());
            refreshData();
        }
    }

    private void exportFields() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showSaveDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_SESSION_YAML_EXPORT, "导出字段定义", this,
                new File("field_definitions.yaml"),
                new FileNameExtensionFilter("YAML文件 (*.yaml)", "yaml"));

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
                "成功导出 " + exportList.size() + " 条字段定义到:\n" + file.getAbsolutePath(),
                "导出成功", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导出失败: " + e.getMessage(), "导出错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void importFields() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showOpenDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_SESSION_YAML_IMPORT, "导入字段定义", this,
                new FileNameExtensionFilter("YAML文件 (*.yaml, *.yml)", "yaml", "yml"));

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
                    "文件中没有找到字段定义数据", "导入提示", JOptionPane.INFORMATION_MESSAGE);
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
                "成功导入 " + imported + " 条字段定义",
                "导入成功", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导入失败: " + e.getMessage(), "导入错误", JOptionPane.ERROR_MESSAGE);
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
