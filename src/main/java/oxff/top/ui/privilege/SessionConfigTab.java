package oxff.top.ui.privilege;

import javax.swing.*;
import java.awt.*;

/**
 * 会话配置子Tab - 容器
 * 使用 JTabbedPane 承载四个独立子标签页：
 * 1. 令牌位置管理
 * 2. 令牌方案管理
 * 3. 用户会话管理
 * 4. 重放配置
 */
public class SessionConfigTab extends JPanel {

    private final JTabbedPane innerTabbedPane;
    private final TokenLocationTab tokenLocationTab;
    private final TokenSchemeTab tokenSchemeTab;
    private final UserSessionTab userSessionTab;
    private final ReplayConfigTab replayConfigTab;

    public SessionConfigTab() {
        super(new BorderLayout());

        innerTabbedPane = new JTabbedPane(JTabbedPane.TOP);

        tokenLocationTab = new TokenLocationTab();
        tokenSchemeTab = new TokenSchemeTab();
        userSessionTab = new UserSessionTab();
        replayConfigTab = new ReplayConfigTab();

        innerTabbedPane.addTab("令牌位置", tokenLocationTab);
        innerTabbedPane.addTab("令牌方案", tokenSchemeTab);
        innerTabbedPane.addTab("用户会话", userSessionTab);
        innerTabbedPane.addTab("重放配置", replayConfigTab);

        add(innerTabbedPane, BorderLayout.CENTER);

        // 初始加载数据
        refreshData();
    }

    /**
     * 刷新所有子标签页数据
     */
    public void refreshData() {
        tokenLocationTab.refreshData();
        tokenSchemeTab.refreshData();
        userSessionTab.refreshData();
        replayConfigTab.refreshData();
    }
}
