package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.TokenSchemeYamlIO;
import org.oxff.repeater.privilege.model.TokenLocation;
import org.oxff.repeater.privilege.model.TokenScheme;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.List;

/**
 * 令牌方案管理子标签页
 * 管理令牌方案的CRUD操作，方案为令牌位置的组合
 */
public class TokenSchemeTab extends JPanel {

    private final JTable schemeTable;
    private final TokenSchemeTableModel schemeModel;
    private TableRowSorter<TokenSchemeTableModel> schemeSorter;
    private JTextField searchField;

    public TokenSchemeTab() {
        super(new BorderLayout(0, 5));

        // ========== 搜索面板 ==========
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

        JButton clearSearchBtn = new JButton("清除");
        clearSearchBtn.addActionListener(e -> {
            searchField.setText("");
            applyFilter();
        });
        searchPanel.add(clearSearchBtn);

        add(searchPanel, BorderLayout.NORTH);

        // ========== 方案表格 ==========
        schemeModel = new TokenSchemeTableModel();
        schemeTable = new JTable(schemeModel);
        schemeTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        schemeTable.getColumnModel().getColumn(0).setPreferredWidth(150);  // 名称
        schemeTable.getColumnModel().getColumn(1).setPreferredWidth(200);  // 描述
        schemeTable.getColumnModel().getColumn(2).setPreferredWidth(80);   // 令牌位置数
        schemeTable.getColumnModel().getColumn(3).setPreferredWidth(50);   // 全局
        schemeTable.getColumnModel().getColumn(4).setPreferredWidth(50);   // 启用

        schemeSorter = new TableRowSorter<>(schemeModel);
        schemeTable.setRowSorter(schemeSorter);

        // 双击编辑 + 右键菜单
        schemeTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
                    int row = schemeTable.rowAtPoint(e.getPoint());
                    if (row >= 0) editScheme();
                }
            }
            @Override
            public void mousePressed(MouseEvent e) { selectRowOnRightClick(e); }
            @Override
            public void mouseReleased(MouseEvent e) { selectRowOnRightClick(e); }
        });

        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem editItem = new JMenuItem("编辑");
        editItem.addActionListener(e -> editScheme());
        JMenuItem deleteItem = new JMenuItem("删除");
        deleteItem.addActionListener(e -> deleteScheme());
        popupMenu.add(editItem);
        popupMenu.add(deleteItem);
        schemeTable.setComponentPopupMenu(popupMenu);

        JScrollPane scrollPane = new JScrollPane(schemeTable);
        add(scrollPane, BorderLayout.CENTER);

        // ========== 按钮面板 ==========
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addBtn = new JButton("添加方案");
        JButton editBtn = new JButton("编辑方案");
        JButton deleteBtn = new JButton("删除方案");
        JButton toggleBtn = new JButton("启用/禁用");
        JButton importBtn = new JButton("导入");
        JButton exportBtn = new JButton("导出");

        addBtn.addActionListener(e -> addScheme());
        editBtn.addActionListener(e -> editScheme());
        deleteBtn.addActionListener(e -> deleteScheme());
        toggleBtn.addActionListener(e -> toggleSchemeEnabled());
        importBtn.addActionListener(e -> importSchemes());
        exportBtn.addActionListener(e -> exportSchemes());

        buttonPanel.add(addBtn);
        buttonPanel.add(editBtn);
        buttonPanel.add(deleteBtn);
        buttonPanel.add(toggleBtn);
        buttonPanel.add(importBtn);
        buttonPanel.add(exportBtn);

        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void selectRowOnRightClick(MouseEvent e) {
        if (SwingUtilities.isRightMouseButton(e)) {
            int row = schemeTable.rowAtPoint(e.getPoint());
            if (row >= 0) schemeTable.setRowSelectionInterval(row, row);
        }
    }

    public void refreshData() {
        schemeModel.setData(SessionManager.getInstance().getTokenSchemes());
    }

    private void applyFilter() {
        String text = searchField.getText().trim();
        if (text.isEmpty()) {
            schemeSorter.setRowFilter(null);
            return;
        }
        try {
            schemeSorter.setRowFilter(javax.swing.RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(text)));
        } catch (java.util.regex.PatternSyntaxException e) {
            // 忽略
        }
    }

    private void addScheme() {
        TokenSchemeEditDialog dialog = new TokenSchemeEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), "添加令牌方案", null);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            SessionManager.getInstance().addTokenScheme(
                    dialog.getSchemeName(), dialog.getDescription(),
                    dialog.isEnabled(), dialog.isPersistToGlobal(), dialog.getSelectedTokenLocationIds());
            refreshData();
        }
    }

    private void editScheme() {
        int viewRow = schemeTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个令牌方案", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = schemeTable.convertRowIndexToModel(viewRow);
        TokenScheme selected = schemeModel.getTokenScheme(modelRow);
        TokenSchemeEditDialog dialog = new TokenSchemeEditDialog(
                (Frame) SwingUtilities.getWindowAncestor(this), "编辑令牌方案", selected);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            SessionManager sm = SessionManager.getInstance();
            sm.updateTokenScheme(selected.getId(), dialog.getSchemeName(), dialog.getDescription(),
                    dialog.isEnabled(), dialog.isPersistToGlobal());
            sm.saveSchemeTokenLocations(selected.getId(), dialog.getSelectedTokenLocationIds());
            refreshData();
        }
    }

    private void deleteScheme() {
        int viewRow = schemeTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个令牌方案", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = schemeTable.convertRowIndexToModel(viewRow);
        TokenScheme selected = schemeModel.getTokenScheme(modelRow);

        int refCount = SessionManager.getInstance().getSessionReferenceCountByScheme(selected.getId());
        String refMsg = refCount > 0 ? "\n该方案被 " + refCount + " 个用户会话引用，删除后这些会话将不再关联任何方案。" : "";

        int confirm = JOptionPane.showConfirmDialog(this,
                "确认删除令牌方案: " + selected.getName() + "?" + refMsg,
                "删除确认", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            SessionManager.getInstance().deleteTokenScheme(selected.getId());
            refreshData();
        }
    }

    private void toggleSchemeEnabled() {
        int viewRow = schemeTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "请先选择一个令牌方案", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = schemeTable.convertRowIndexToModel(viewRow);
        TokenScheme selected = schemeModel.getTokenScheme(modelRow);
        SessionManager.getInstance().updateTokenScheme(
                selected.getId(), selected.getName(), selected.getDescription(), selected.isPersistToGlobal(), !selected.isEnabled());
        refreshData();
    }

    private void exportSchemes() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showSaveDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_SESSION_YAML_EXPORT, "导出令牌方案", this,
                new File("token_schemes.yaml"),
                new FileNameExtensionFilter("YAML文件 (*.yaml)", "yaml"));
        if (selectedFile == null) return;

        File file = selectedFile;
        if (!file.getName().endsWith(".yaml") && !file.getName().endsWith(".yml")) {
            file = new File(file.getAbsolutePath() + ".yaml");
        }

        try {
            SessionManager sm = SessionManager.getInstance();
            List<TokenScheme> schemes = sm.getTokenSchemes();
            List<TokenLocation> locations = sm.getTokenLocations();
            boolean success = TokenSchemeYamlIO.writeToFile(schemes, locations, file.getAbsolutePath());
            if (success) {
                JOptionPane.showMessageDialog(this,
                    "成功导出 " + schemes.size() + " 个令牌方案到:\n" + file.getAbsolutePath(),
                    "导出成功", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, "导出失败", "导出错误", JOptionPane.ERROR_MESSAGE);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导出失败: " + e.getMessage(), "导出错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void importSchemes() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showOpenDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_SESSION_YAML_IMPORT, "导入令牌方案", this,
                new FileNameExtensionFilter("YAML文件 (*.yaml, *.yml)", "yaml", "yml"));
        if (selectedFile == null) return;

        try {
            SessionManager sm = SessionManager.getInstance();
            List<TokenLocation> locations = sm.getTokenLocations();
            List<TokenScheme> importedSchemes = TokenSchemeYamlIO.readFromFile(selectedFile.getAbsolutePath(), locations);

            if (importedSchemes.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                    "文件中没有找到令牌方案数据", "导入提示", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            int imported = 0;
            for (TokenScheme scheme : importedSchemes) {
                int id = sm.addTokenScheme(scheme.getName(), scheme.getDescription(),
                        scheme.isEnabled(), scheme.isPersistToGlobal(), scheme.getTokenLocationIds());
                if (id > 0) imported++;
            }

            refreshData();
            JOptionPane.showMessageDialog(this,
                "成功导入 " + imported + " 个令牌方案",
                "导入成功", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "导入失败: " + e.getMessage(), "导入错误", JOptionPane.ERROR_MESSAGE);
        }
    }
}
