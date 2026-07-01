package org.oxff.repeater.ui.privilege;

import javax.swing.*;
import java.awt.*;

/**
 * 会话配置子Tab - 容器
 * 使用 JTabbedPane 承载四个独立子标签页：
 * 1. 字段定义管理
 * 2. 方案管理
 * 3. 用户会话管理
 * 4. 重放配置
 */
public class SessionConfigTab extends JPanel {

    private final JTabbedPane innerTabbedPane;
    private final FieldDefinitionTab fieldDefinitionTab;
    private final SchemeTab schemeTab;
    private final UserSessionTab userSessionTab;
    private final ReplayConfigTab replayConfigTab;

    public SessionConfigTab() {
        super(new BorderLayout());

        innerTabbedPane = new JTabbedPane(JTabbedPane.TOP);

        fieldDefinitionTab = new FieldDefinitionTab();
        schemeTab = new SchemeTab();
        userSessionTab = new UserSessionTab();
        replayConfigTab = new ReplayConfigTab();

        innerTabbedPane.addTab("字段管理", fieldDefinitionTab);
        innerTabbedPane.addTab("方案管理", schemeTab);
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
        fieldDefinitionTab.refreshData();
        schemeTab.refreshData();
        userSessionTab.refreshData();
        replayConfigTab.refreshData();
    }
}
