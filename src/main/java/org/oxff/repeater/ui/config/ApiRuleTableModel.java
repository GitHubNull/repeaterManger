package org.oxff.repeater.ui.config;

import org.oxff.repeater.api.ApiExtractionRule;
import org.oxff.repeater.api.ApiRuleManager;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * API提取规则表格模型 - 管理规则数据的表格展示
 */
public class ApiRuleTableModel extends AbstractTableModel {
    private static final long serialVersionUID = 1L;

    private final String[] COLUMN_NAMES = {"优先级", "名称", "来源", "方法", "表达式", "启用", "备注", "存储类型"};
    private List<ApiExtractionRule> rules = new ArrayList<>();
    private Runnable onRuleChanged;

    /**
     * 设置规则变更回调（当启用状态变更时触发）
     */
    public void setOnRuleChanged(Runnable callback) {
        this.onRuleChanged = callback;
    }

    public void setRules(List<ApiExtractionRule> rules) {
        this.rules = new ArrayList<>(rules);
        fireTableDataChanged();
    }

    public ApiExtractionRule getRule(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < rules.size()) {
            return rules.get(rowIndex);
        }
        return null;
    }

    @Override
    public int getRowCount() {
        return rules.size();
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
            case 0: return Integer.class;
            case 5: return Boolean.class;
            default: return String.class;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ApiExtractionRule rule = rules.get(rowIndex);
        switch (columnIndex) {
            case 0: return rule.getPriority();
            case 1: return rule.getName();
            case 2: return rule.getSource().getDisplayName();
            case 3: return rule.getMethod().getDisplayName();
            case 4: return rule.getExpression();
            case 5: return rule.isEnabled();
            case 6: return rule.getRemark();
            case 7: return rule.getStorageTypeDisplay();
            default: return null;
        }
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 5; // 仅"启用"列可直接编辑
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex == 5 && aValue instanceof Boolean) {
            ApiExtractionRule rule = rules.get(rowIndex);
            boolean newEnabled = (Boolean) aValue;
            ApiExtractionRule oldRule = copyRule(rule);
            rule.setEnabled(newEnabled);
            ApiRuleManager.getInstance().updateRule(oldRule, rule);
            fireTableCellUpdated(rowIndex, columnIndex);
            if (onRuleChanged != null) {
                onRuleChanged.run();
            }
        }
    }

    /**
     * 复制规则对象（用于保存编辑前状态）
     */
    static ApiExtractionRule copyRule(ApiExtractionRule source) {
        return new ApiExtractionRule(
                source.getId(), source.getName(), source.getSource(), source.getMethod(),
                source.getExpression(), source.isEnabled(), source.getPriority(), source.getRemark(),
                source.isPersistent(), source.isGlobal()
        );
    }
}
