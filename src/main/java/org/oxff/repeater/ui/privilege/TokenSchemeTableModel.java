package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.model.TokenScheme;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * 令牌方案表格模型
 * 列：名称、描述、令牌位置数、全局、启用
 */
public class TokenSchemeTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {"名称", "描述", "令牌位置数", "全局", "启用"};

    private List<TokenScheme> schemes = new ArrayList<>();

    public void setData(List<TokenScheme> schemes) {
        this.schemes = schemes != null ? schemes : new ArrayList<>();
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return schemes.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 2: return Integer.class;
            case 3: return Boolean.class;  // 全局
            case 4: return Boolean.class;  // 启用
            default: return String.class;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        TokenScheme scheme = schemes.get(rowIndex);
        switch (columnIndex) {
            case 0: return scheme.getName();
            case 1: return scheme.getDescription();
            case 2: return scheme.getTokenLocationCount();
            case 3: return scheme.isPersistToGlobal();
            case 4: return scheme.isEnabled();
            default: return null;
        }
    }

    public TokenScheme getTokenScheme(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < schemes.size()) {
            return schemes.get(rowIndex);
        }
        return null;
    }
}
