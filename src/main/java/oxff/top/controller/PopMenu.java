package oxff.top.controller;

import burp.BurpExtender;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.*;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

public class PopMenu implements ContextMenuItemsProvider {
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // 检查是否有请求被选中
        List<HttpRequestResponse> selectedResponses = event.selectedRequestResponses();
        if (selectedResponses != null && !selectedResponses.isEmpty()) {
            final HttpRequestResponse requestResponse = selectedResponses.get(0);

            if (requestResponse != null && requestResponse.request() != null) {
                // 创建菜单项
                JMenuItem sendToRepeater = new JMenuItem("发送到 Repeater Manager");
                sendToRepeater.addActionListener(e -> {
                    // 调用 RepeaterManagerUI 的方法处理所选请求
                    BurpExtender.setRepeaterUIRequest(requestResponse);
                });

                // 创建权限测试菜单项
                JMenuItem sendToPrivilegeTest = new JMenuItem("发送到权限测试");
                sendToPrivilegeTest.addActionListener(e -> {
                    // 调用权限测试方法，自动加载请求并启动重放
                    BurpExtender.setPrivilegeTestRequest(requestResponse);
                });

                menuItems.add(sendToRepeater);
                menuItems.add(sendToPrivilegeTest);
            }
        }

        return menuItems;
    }
}
