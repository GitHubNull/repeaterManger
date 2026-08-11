package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.i18n.I18nManager;
import org.oxff.repeater.privilege.SessionManager;
import org.oxff.repeater.privilege.SchemeYamlIO;
import org.oxff.repeater.privilege.model.FieldDefinition;
import org.oxff.repeater.privilege.model.Scheme;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.List;

/**
 * 方案管理子标签页
 * 管理方案的CRUD操作，方案为字段定义的组合
 */
public class SchemeTab extends JPanel {

    private final JTable schemeTable;
    private final SchemeTableModel schemeModel;
    private TableRowSorter<SchemeTableModel> schemeSorter;
    private JTextField searchField;

    private JLabel searchLabel;
    private JButton clearSearchBtn;
    private JMenuItem editItem;
    private JMenuItem deleteItem;
    private JButton addBtn;
    private JButton editBtn;
    private JButton deleteBtn;
    private JButton toggleBtn;
    private JButton importBtn;
    private JButton exportBtn;

    public SchemeTab() {
        super(new BorderLayout(0, 5));

        // ========== 搜索面板 ==========
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        searchLabel = new JLabel(I18nManager.tr("scheme.search"));
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

        clearSearchBtn = new JButton(I18nManager.tr("scheme.clear"));
        clearSearchBtn.addActionListener(e -> {
            searchField.setText("");
            applyFilter();
        });
        searchPanel.add(clearSearchBtn);

        add(searchPanel, BorderLayout.NORTH);

        // ========== 方案表格 ==========
        schemeModel = new SchemeTableModel();
        schemeTable = new JTable(schemeModel);
        schemeTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        schemeTable.getColumnModel().getColumn(0).setPreferredWidth(150);  // 名称
        schemeTable.getColumnModel().getColumn(1).setPreferredWidth(200);  // 描述
        schemeTable.getColumnModel().getColumn(2).setPreferredWidth(80);   // 关联字段数
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
                    if (row >= 0) {
                        SwingUtilities.invokeLater(() -> editScheme());
                    }
                }
            }
            @Override
            public void mousePressed(MouseEvent e) { selectRowOnRightClick(e); }
            @Override
            public void mouseReleased(MouseEvent e) { selectRowOnRightClick(e); }
        });

        JPopupMenu popupMenu = new JPopupMenu();
        editItem = new JMenuItem(I18nManager.tr("scheme.edit"));
        editItem.addActionListener(e -> editScheme());
        deleteItem = new JMenuItem(I18nManager.tr("scheme.delete"));
        deleteItem.addActionListener(e -> deleteScheme());
        popupMenu.add(editItem);
        popupMenu.add(deleteItem);
        schemeTable.setComponentPopupMenu(popupMenu);

        JScrollPane scrollPane = new JScrollPane(schemeTable);
        add(scrollPane, BorderLayout.CENTER);

        // ========== 按钮面板 ==========
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addBtn = new JButton(I18nManager.tr("scheme.add"));
        editBtn = new JButton(I18nManager.tr("scheme.edit.title"));
        deleteBtn = new JButton(I18nManager.tr("scheme.delete.title"));
        toggleBtn = new JButton(I18nManager.tr("scheme.toggle"));
        importBtn = new JButton(I18nManager.tr("scheme.import"));
        exportBtn = new JButton(I18nManager.tr("scheme.export"));

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

        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);
    }

    /**
     * 语言切换时刷新文本
     */
    private void refreshTexts() {
        searchLabel.setText(I18nManager.tr("scheme.search"));
        clearSearchBtn.setText(I18nManager.tr("scheme.clear"));
        editItem.setText(I18nManager.tr("scheme.edit"));
        deleteItem.setText(I18nManager.tr("scheme.delete"));
        addBtn.setText(I18nManager.tr("scheme.add"));
        editBtn.setText(I18nManager.tr("scheme.edit.title"));
        deleteBtn.setText(I18nManager.tr("scheme.delete.title"));
        toggleBtn.setText(I18nManager.tr("scheme.toggle"));
        importBtn.setText(I18nManager.tr("scheme.import"));
        exportBtn.setText(I18nManager.tr("scheme.export"));
        schemeModel.refreshColumnNames();
    }

    private void selectRowOnRightClick(MouseEvent e) {
        if (SwingUtilities.isRightMouseButton(e)) {
            int row = schemeTable.rowAtPoint(e.getPoint());
            if (row >= 0) schemeTable.setRowSelectionInterval(row, row);
        }
    }

    public void refreshData() {
        schemeModel.setData(SessionManager.getInstance().getSchemes());
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
        SchemeEditDialog dialog = new SchemeEditDialog(
                SwingUtilities.getWindowAncestor(this), I18nManager.tr("scheme.add"), null);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            SessionManager.getInstance().addScheme(
                    dialog.getSchemeName(), dialog.getDescription(),
                    dialog.isSchemeEnabled(), dialog.isPersistToGlobal(), dialog.getSelectedFieldIds());
            refreshData();
        }
    }

    private void editScheme() {
        int viewRow = schemeTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("scheme.select.first"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = schemeTable.convertRowIndexToModel(viewRow);
        Scheme selected = schemeModel.getScheme(modelRow);
        SchemeEditDialog dialog = new SchemeEditDialog(
                SwingUtilities.getWindowAncestor(this), I18nManager.tr("scheme.edit.title"), selected);
        dialog.setVisible(true);
        if (dialog.isConfirmed()) {
            SessionManager sm = SessionManager.getInstance();
            sm.updateScheme(selected.getId(), dialog.getSchemeName(), dialog.getDescription(),
                    dialog.isSchemeEnabled(), dialog.isPersistToGlobal());
            sm.saveSchemeFields(selected.getId(), dialog.getSelectedFieldIds());
            refreshData();
        }
    }

    private void deleteScheme() {
        int viewRow = schemeTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("scheme.select.first"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = schemeTable.convertRowIndexToModel(viewRow);
        Scheme selected = schemeModel.getScheme(modelRow);

        int refCount = SessionManager.getInstance().getSessionReferenceCountByScheme(selected.getId());
        String refMsg = refCount > 0 ? I18nManager.tr("scheme.delete.ref", refCount) : "";

        int confirm = JOptionPane.showConfirmDialog(this,
                I18nManager.tr("scheme.delete.confirm", selected.getName()) + refMsg,
                I18nManager.tr("scheme.delete.title"), JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            SessionManager.getInstance().deleteScheme(selected.getId());
            refreshData();
        }
    }

    private void toggleSchemeEnabled() {
        int viewRow = schemeTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, I18nManager.tr("scheme.select.first"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = schemeTable.convertRowIndexToModel(viewRow);
        Scheme selected = schemeModel.getScheme(modelRow);
        SessionManager.getInstance().updateScheme(
                selected.getId(), selected.getName(), selected.getDescription(), !selected.isEnabled(), selected.isPersistToGlobal());
        refreshData();
    }

    private void exportSchemes() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showSaveDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_SESSION_YAML_EXPORT,
                I18nManager.tr("scheme.export.dialog"), this,
                new File("schemes.yaml"),
                new FileNameExtensionFilter(I18nManager.tr("field.yaml.filter"), "yaml"));
        if (selectedFile == null) return;

        File file = selectedFile;
        if (!file.getName().endsWith(".yaml") && !file.getName().endsWith(".yml")) {
            file = new File(file.getAbsolutePath() + ".yaml");
        }

        try {
            SessionManager sm = SessionManager.getInstance();
            List<Scheme> schemes = sm.getSchemes();
            List<FieldDefinition> fields = sm.getFieldDefinitions();
            boolean success = SchemeYamlIO.writeToFile(schemes, fields, file.getAbsolutePath());
            if (success) {
                JOptionPane.showMessageDialog(this,
                    I18nManager.tr("scheme.export.success", schemes.size(), file.getAbsolutePath()),
                    I18nManager.tr("scheme.export.success.title"), JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, I18nManager.tr("scheme.export.failed"),
                        I18nManager.tr("scheme.export.failed.title"), JOptionPane.ERROR_MESSAGE);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                I18nManager.tr("scheme.export.failed.msg", e.getMessage()),
                I18nManager.tr("scheme.export.failed.title"), JOptionPane.ERROR_MESSAGE);
        }
    }

    private void importSchemes() {
        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showOpenDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_SESSION_YAML_IMPORT,
                I18nManager.tr("scheme.import.dialog"), this,
                new FileNameExtensionFilter(I18nManager.tr("field.yaml.filter.all"), "yaml", "yml"));
        if (selectedFile == null) return;

        try {
            SessionManager sm = SessionManager.getInstance();
            List<FieldDefinition> fields = sm.getFieldDefinitions();
            List<Scheme> importedSchemes = SchemeYamlIO.readFromFile(selectedFile.getAbsolutePath(), fields);

            if (importedSchemes.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                    I18nManager.tr("scheme.import.empty"),
                    I18nManager.tr("common.hint"), JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            int imported = 0;
            for (Scheme scheme : importedSchemes) {
                int id = sm.addScheme(scheme.getName(), scheme.getDescription(),
                        scheme.isEnabled(), scheme.isPersistToGlobal(), scheme.getFieldIds());
                if (id > 0) imported++;
            }

            refreshData();
            JOptionPane.showMessageDialog(this,
                I18nManager.tr("scheme.import.success", imported),
                I18nManager.tr("scheme.import.success.title"), JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                I18nManager.tr("scheme.import.failed", e.getMessage()),
                I18nManager.tr("scheme.import.failed.title"), JOptionPane.ERROR_MESSAGE);
        }
    }
}
