package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.model.JudgmentRule;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * 判决规则表格模型
 */
public class JudgmentRuleTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {"名称", "目标", "方法", "表达式", "启用", "优先级"};

    private List<JudgmentRule> rules = new ArrayList<>();

    public void setData(List<JudgmentRule> rules) {
        this.rules = rules != null ? rules : new ArrayList<>();
        fireTableDataChanged();
    }

    public JudgmentRule getRule(int row) {
        if (row >= 0 && row < rules.size()) {
            return rules.get(row);
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
    public Object getValueAt(int rowIndex, int columnIndex) {
        JudgmentRule rule = rules.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> rule.getName() != null ? rule.getName() : "";
            case 1 -> rule.getTarget() != null ? rule.getTarget().getDisplayName() : "";
            case 2 -> rule.getMethod() != null ? rule.getMethod().getDisplayName() : "";
            case 3 -> rule.getExpression() != null ? rule.getExpression() : "";
            case 4 -> rule.isEnabled() ? "是" : "否";
            case 5 -> rule.getPriority();
            default -> "";
        };
    }
}
