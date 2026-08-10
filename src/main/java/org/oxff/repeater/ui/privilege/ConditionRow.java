package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.model.RuleCondition;
import org.oxff.repeater.privilege.model.RuleMethod;
import org.oxff.repeater.privilege.model.RuleTarget;

import javax.swing.*;
import java.awt.*;

/**
 * 每行条件的组件持有者（v19：添加 operator 支持）
 *
 * v20：首行不显示 AND/OR 连接符（第一条条件之前没有可连接的条件）。
 * 通过 opCardPanel（CardLayout）在 "operator" 卡片与 "blank" 占位卡片之间切换，
 * 保证首行隐藏连接符的同时列宽不抖动。
 */
class ConditionRow {

    /** operator 卡片名：显示 AND/OR 下拉框 */
    static final String CARD_OPERATOR = "operator";
    /** 空白占位卡片名：首行使用 */
    static final String CARD_BLANK = "blank";

    final JPanel rowPanel;
    /** gridx=0 位置的卡片容器，内部含 operatorCombo 与空白占位两张卡 */
    final JPanel opCardPanel;
    final JComboBox<RuleCondition.LogicalOperator> operatorCombo;
    final JCheckBox negateCheckbox;
    final JComboBox<RuleTarget> targetCombo;
    final JComboBox<RuleMethod> methodCombo;
    final JTextField expressionField;

    ConditionRow(int index, JPanel rowPanel,
                 JPanel opCardPanel,
                 JComboBox<RuleCondition.LogicalOperator> operatorCombo,
                 JCheckBox negateCheckbox,
                 JComboBox<RuleTarget> targetCombo,
                 JComboBox<RuleMethod> methodCombo,
                 JTextField expressionField,
                 JButton deleteButton) {
        this.rowPanel = rowPanel;
        this.opCardPanel = opCardPanel;
        this.operatorCombo = operatorCombo;
        this.negateCheckbox = negateCheckbox;
        this.targetCombo = targetCombo;
        this.methodCombo = methodCombo;
        this.expressionField = expressionField;
    }

    /**
     * 根据是否为首行切换 operator 下拉框的显示。
     * 首行显示空白占位卡片，其余行显示 AND/OR 下拉框。
     */
    void showOperator(boolean show) {
        CardLayout cl = (CardLayout) opCardPanel.getLayout();
        cl.show(opCardPanel, show ? CARD_OPERATOR : CARD_BLANK);
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
