package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.model.RuleCondition;
import org.oxff.repeater.privilege.model.RuleMethod;
import org.oxff.repeater.privilege.model.RuleTarget;

import javax.swing.*;

/**
 * 每行条件的组件持有者（v19：添加 operator 支持）
 */
class ConditionRow {
    final JPanel rowPanel;
    final JComboBox<RuleCondition.LogicalOperator> operatorCombo;
    final JCheckBox negateCheckbox;
    final JComboBox<RuleTarget> targetCombo;
    final JComboBox<RuleMethod> methodCombo;
    final JTextField expressionField;

    ConditionRow(int index, JPanel rowPanel,
                 JComboBox<RuleCondition.LogicalOperator> operatorCombo,
                 JCheckBox negateCheckbox,
                 JComboBox<RuleTarget> targetCombo,
                 JComboBox<RuleMethod> methodCombo,
                 JTextField expressionField,
                 JButton deleteButton) {
        this.rowPanel = rowPanel;
        this.operatorCombo = operatorCombo;
        this.negateCheckbox = negateCheckbox;
        this.targetCombo = targetCombo;
        this.methodCombo = methodCombo;
        this.expressionField = expressionField;
    }

    RuleCondition toCondition() {
        RuleCondition cond = new RuleCondition();
        cond.setTarget((RuleTarget) targetCombo.getSelectedItem());
        cond.setMethod((RuleMethod) methodCombo.getSelectedItem());
        cond.setExpression(expressionField.getText().trim());
        cond.setNegate(negateCheckbox.isSelected());
        cond.setOperator((RuleCondition.LogicalOperator) operatorCombo.getSelectedItem());
        return cond;
    }
}
