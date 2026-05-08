package oxff.top.ui.privilege;

import javax.swing.*;
import java.awt.*;

/**
 * 权限测试配置面板（第4个Tab）
 * 仅包含配置项，报文重放和结果查看复用"请求管理"Tab
 */
public class PrivilegeTestPanel extends JPanel {

    private final JTabbedPane innerTabbedPane;

    public PrivilegeTestPanel() {
        super(new BorderLayout());

        innerTabbedPane = new JTabbedPane();

        // 会话配置子Tab
        SessionConfigTab sessionConfigTab = new SessionConfigTab();
        innerTabbedPane.addTab("会话配置", sessionConfigTab);

        // 判决规则子Tab（Phase 2）
        JudgmentRuleConfigTab judgmentRuleConfigTab = new JudgmentRuleConfigTab();
        innerTabbedPane.addTab("判决规则", judgmentRuleConfigTab);

        // Scope子Tab
        ScopeConfigTab scopeConfigTab = new ScopeConfigTab();
        innerTabbedPane.addTab("Scope", scopeConfigTab);

        add(innerTabbedPane, BorderLayout.CENTER);
    }
}
