package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.i18n.I18nManager;

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

        innerTabbedPane.addTab(I18nManager.tr("session.tab.field"), fieldDefinitionTab);
        innerTabbedPane.addTab(I18nManager.tr("session.tab.scheme"), schemeTab);
        innerTabbedPane.addTab(I18nManager.tr("session.tab.user"), userSessionTab);
        innerTabbedPane.addTab(I18nManager.tr("session.tab.replay"), replayConfigTab);

        add(innerTabbedPane, BorderLayout.CENTER);

        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);

        // 初始加载数据
        refreshData();
    }

    /**
     * 语言切换时刷新Tab标题
     */
    private void refreshTexts() {
        innerTabbedPane.setTitleAt(0, I18nManager.tr("session.tab.field"));
        innerTabbedPane.setTitleAt(1, I18nManager.tr("session.tab.scheme"));
        innerTabbedPane.setTitleAt(2, I18nManager.tr("session.tab.user"));
        innerTabbedPane.setTitleAt(3, I18nManager.tr("session.tab.replay"));
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
