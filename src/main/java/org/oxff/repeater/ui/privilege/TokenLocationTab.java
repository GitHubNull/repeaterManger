package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.model.TokenLocation;
import org.oxff.repeater.privilege.model.TokenLocationType;

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
 * 令牌位置管理子标签页
 * 从原有 SessionConfigTab 的令牌位置区域抽取
 */
public class TokenLocationTab extends JPanel {

    private final JTable tokenLocationTable;
    private final TokenLocationTableModel tokenLocationModel;
    private TableRowSorter<TokenLocationTableModel> tokenLocationSorter;
    private JTextField tokenSearchField;
    private JCheckBox tokenCaseSensitiveCheckbox;
    private JCheckBox tokenRegexCheckbox;

    public TokenLocationTab() {
        super(new BorderLayout(0, 5));

        // ========== 令牌位置搜索面板 ==========
        JPanel tokenSearchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        tokenSearchPanel.add(new JLabel("搜索:"));
        tokenSearchField = new JTextField(15);
        tokenSearchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyTokenLocationFilter(); }
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyTokenLocationFilter(); }
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyTokenLocationFilter(); }
        });
        tokenSearchPanel.add(tokenSearchField);

        tokenCaseSensitiveCheckbox = new JCheckBox("Aa");
        tokenCaseSensitiveCheckbox.setToolTipText("区分大小写");
        tokenCaseSensitiveCheckbox.addActionListener(e -> applyTokenLocationFilter());
        tokenSearchPanel.add(tokenCaseSensitiveCheckbox);

        tokenRegexCheckbox = new JCheckBox(".*");
        tokenRegexCheckbox.setToolTipText("启用正则表达式匹配");
        tokenRegexCheckbox.addActionListener(e -> applyTokenLocationFilter());
        tokenSearchPanel.add(tokenRegexCheckbox);

        JButton clearTokenSearchBtn = new JButton("清除");
        clearTokenSearchBtn.addActionListener(e -> {
            tokenSearchField.setText("");
            applyTokenLocationFilter();
        });
        tokenSearchPanel.add(clearTokenSearchBtn);

        add(tokenSearchPanel, BorderLayout.NORTH);

        // ========== 令牌位置表格 ==========
        tokenLocationModel = new TokenLocationTableModel();
        tokenLocationTable = new JTable(tokenLocationModel);
        tokenLocationTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        tokenLocationTable.getColumnModel().getColumn(0).setPreferredWidth(60);   // 类型
        tokenLocationTable.getColumnModel().getColumn(1).setPreferredWidth(150);  // 表达式
        tokenLocationTable.getColumnModel().getColumn(2).setPreferredWidth(150);  // 描述
        tokenLocationTable.getColumnModel().getColumn(3).setPreferredWidth(80);   // 持久化到全局
        tokenLocationTable.getColumnModel().getColumn(4).setPreferredWidth(50);   // 启用

        // 设置 TableRowSorter 启用列头排序
        tokenLocationSorter = new TableRowSorter<>(tokenLocationModel);
        tokenLocationTable.setRowSorter(tokenLocationSorter);

        // 双击编辑 + 右键行选择 + 右键菜单
        tokenLocationTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
                    int row = tokenLocationTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        editTokenLocation();
                    }
                }
            }
            @Override
            public void mousePressed(MouseEvent e) {
                selectRowOnRightClick(e, tokenLocationTable);
            }
            @Override
            public void mouseReleased(MouseEvent e) {
                selectRowOnRightClick(e, tokenLocationTable);
            }
        });

        // 右键菜单
        JPopupMenu tokenLocationPopupMenu = new JPopupMenu();
        JMenuItem editTokenLocItem = new JMenuItem("编辑");
        editTokenLocItem.addActionListener(e -> editTokenLocation());
        JMenuItem deleteTokenLocItem = new JMenuItem("删除");
        deleteTokenLocItem.addActionListener(e -> deleteTokenLocation());
        tokenLocationPopupMenu.add(editTokenLocItem);
        tokenLocationPopupMenu.add(deleteTokenLocItem);
        tokenLocationTable.setComponentPopupMenu(tokenLocationPopupMenu);

        JScrollPane tokenScroll = new JScrollPane(tokenLocationTable);
        add(tokenScroll, BorderLayout.CENTER);

        // ========== 按钮面板 ==========
        JPanel tokenButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addTokenBtn = new JButton("添加位置");
        JButton editTokenBtn = new JButton("编辑位置");
        JButton deleteTokenBtn = new JButton("删除位置");
        JButton importTokenBtn = new JButton("导入");
        JButton exportTokenBtn = new JButton("导出");

        addTokenBtn.addActionListener(e -> addTokenLocation());
        editTokenBtn.addActionListener(e -> editTokenLocation());
        deleteTokenBtn.addActionListener(e -> deleteTokenLocation());
        importTokenBtn.addActionListener(e -> importTokenLocations());
        exportTokenBtn.addActionListener(e -> exportTokenLocations());

        tokenButtonPanel.add(addTokenBtn);
        tokenButtonPanel.add(editTokenBtn);
        tokenButtonPanel.add(deleteTokenBtn);
        tokenButtonPanel.add(importTokenBtn);
        tokenButtonPanel.add(exportTokenBtn);

        add(tokenButtonPanel, BorderLayout.SOUTH);
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
        tokenLocationModel.setData(sessionManager.getTokenLocations());
    }

    private void applyTokenLocationFilter() {
        String text = tokenSearchField.getText().trim();
        if (text.isEmpty()) {
            tokenLocationSorter.setRowFilter(null);
            return;
        }

        boolean caseSensitive = tokenCaseSensitiveCheckbox.isSelected();
        boolean regexMode = tokenRegexCheckbox.isSelected();

        String pattern;
        if (regexMode) {
            pattern = caseSensitive ? text : "(?i)" + text;
        } else {
            pattern = caseSensitive ? Pattern.quote(text) : "(?i)" + Pattern.quote(text);
        }

        try {
            tokenLocationSorter.setRowFilter(RowFilter.regexFilter(pattern));
        } catch (PatternSyntaxException e) {
            // 正则表达式无效时静默忽略
        }
    }

    private void addTokenLocation() {
        TokenLocationEditDialog dialog = new TokenLocationEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), "添加令牌位置", null);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            SessionManager.getInstance().addTokenLocation(
                    dialog.getLocationType(), dialog.getExpression(), dialog.getDescription(),
                    dialog.isPersistToGlobal(), dialog.isEnabled());
            refreshData();
        }
    }

    private void editTokenLocation() {
        int viewRow = tokenLocationTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个令牌位置", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = tokenLocationTable.convertRowIndexToModel(viewRow);
        TokenLocation selected = tokenLocationModel.getTokenLocation(modelRow);
        TokenLocationEditDialog dialog = new TokenLocationEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), "编辑令牌位置", selected);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            SessionManager.getInstance().updateTokenLocation(
                    selected.getId(), dialog.getLocationType(), dialog.getExpression(), dialog.getDescription(),
                    dialog.isPersistToGlobal(), dialog.isEnabled());
            refreshData();
        }
    }

    private void deleteTokenLocation() {
        int viewRow = tokenLocationTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个令牌位置", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = tokenLocationTable.convertRowIndexToModel(viewRow);
        TokenLocation selected = tokenLocationModel.getTokenLocation(modelRow);

        // 查询引用方案数
        int refCount = SessionManager.getInstance().getSchemeReferenceCountByTokenLocation(selected.getId());
        String refMsg = refCount > 0 ? "\n该位置被 " + refCount + " 个令牌方案引用，删除后将从方案中移除。" : "";

        int confirm = JOptionPane.showConfirmDialog(this,
                "确认删除令牌位置: " + selected.getExpression() + "?\n关联的所有用户令牌值也会被删除。" + refMsg,
                "删除确认", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            SessionManager.getInstance().deleteTokenLocation(selected.getId());
            refreshData();
        }
    }

    private void exportTokenLocations() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showSaveDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_SESSION_YAML_EXPORT, "导出令牌位置", this,
                new File("token_locations.yaml"),
                new FileNameExtensionFilter("YAML文件 (*.yaml)", "yaml"));

        if (selectedFile == null) return;

        File file = selectedFile;
        if (!file.getName().endsWith(".yaml") && !file.getName().endsWith(".yml")) {
            file = new File(file.getAbsolutePath() + ".yaml");
        }

        try {
            List<TokenLocation> locations = SessionManager.getInstance().getTokenLocations();
            List<Map<String, Object>> exportList = new ArrayList<>();
            for (TokenLocation loc : locations) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("type", loc.getType().name());
                entry.put("expression", loc.getExpression());
                entry.put("description", loc.getDescription());
                entry.put("persistToGlobal", loc.isPersistToGlobal());
                entry.put("enabled", loc.isEnabled());
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
                "成功导出 " + exportList.size() + " 条令牌位置到:\n" + file.getAbsolutePath(),
                "导出成功", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导出失败: " + e.getMessage(), "导出错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void importTokenLocations() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showOpenDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_SESSION_YAML_IMPORT, "导入令牌位置", this,
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
                    "文件中没有找到令牌位置数据", "导入提示", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            int imported = 0;
            SessionManager sm = SessionManager.getInstance();
            for (Map<String, Object> entry : importList) {
                try {
                    String typeStr = String.valueOf(entry.get("type"));
                    TokenLocationType type = TokenLocationType.fromString(typeStr);
                    String expression = String.valueOf(entry.getOrDefault("expression", ""));
                    String description = String.valueOf(entry.getOrDefault("description", ""));
                    boolean persistToGlobal = toBoolean(entry.getOrDefault("persistToGlobal", true));
                    boolean enabled = toBoolean(entry.getOrDefault("enabled", true));
                    sm.addTokenLocation(type, expression, description, persistToGlobal, enabled);
                    imported++;
                } catch (Exception e) {
                    // 跳过无效条目
                }
            }

            refreshData();
            JOptionPane.showMessageDialog(this,
                "成功导入 " + imported + " 条令牌位置",
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
