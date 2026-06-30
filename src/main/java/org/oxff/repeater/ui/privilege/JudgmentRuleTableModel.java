package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.JudgmentRuleManager;
import org.oxff.repeater.privilege.model.JudgmentRule;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * 判决规则表格模型（v13：单活跃规则集模式）
 */
public class JudgmentRuleTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {"活跃", "名称", "条件数", "条件摘要", "启用"};

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
    public Class<?> getColumnClass(int columnIndex) {
        return switch (columnIndex) {
            case 0 -> Boolean.class;   // 活跃（复选框）
            case 4 -> Boolean.class;   // 启用（复选框）
            default -> String.class;
        };
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 0 || columnIndex == 4;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        JudgmentRule rule = rules.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> rule.isActive();
            case 1 -> rule.getName() != null ? rule.getName() : "";
            case 2 -> rule.getEffectiveConditions().size();
            case 3 -> rule.getConditionSummary();
            case 4 -> rule.isEnabled();
            default -> "";
        };
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        JudgmentRule rule = rules.get(rowIndex);
        if (rule == null) return;

        if (columnIndex == 0) {
            // 活跃列：设为活跃时调用 manager 保证互斥，然后重新拉取数据
            boolean active = Boolean.TRUE.equals(aValue);
            if (active && !rule.isActive()) {
                JudgmentRuleManager manager = JudgmentRuleManager.getInstance();
                manager.setActiveRule(rule.getId());
                setData(manager.getAllRules());
            }
        } else if (columnIndex == 4) {
            // 启用列
            boolean enabled = Boolean.TRUE.equals(aValue);
            JudgmentRuleManager manager = JudgmentRuleManager.getInstance();
            manager.toggleRuleEnabled(rule.getId(), enabled);
            setData(manager.getAllRules());
        }
    }
}
