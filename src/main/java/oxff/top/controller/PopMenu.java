package oxff.top.controller;

import burp.BurpExtender;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.*;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class PopMenu implements ContextMenuItemsProvider {
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // 检查是否有请求被选中
        List<HttpRequestResponse> selectedResponses = event.selectedRequestResponses();
        if (selectedResponses != null && !selectedResponses.isEmpty()) {
            // 过滤掉无效的请求（null 或 request 为 null）
            List<HttpRequestResponse> validResponses = selectedResponses.stream()
                .filter(rr -> rr != null && rr.request() != null)
                .collect(Collectors.toList());

            if (validResponses.isEmpty()) {
                return menuItems;
            }

            int count = validResponses.size();

            if (count == 1) {
                // 单条选中：保持原有行为
                final HttpRequestResponse requestResponse = validResponses.get(0);

                JMenuItem sendToRepeater = new JMenuItem("发送到 Repeater Manager");
                sendToRepeater.addActionListener(e -> {
                    BurpExtender.setRepeaterUIRequest(requestResponse);
                });

                JMenuItem sendToPrivilegeTest = new JMenuItem("发送到权限测试");
                sendToPrivilegeTest.addActionListener(e -> {
                    BurpExtender.setPrivilegeTestRequest(requestResponse);
                });

                menuItems.add(sendToRepeater);
                menuItems.add(sendToPrivilegeTest);
            } else {
                // 多条选中：使用批量方法，菜单文案附带数量
                JMenuItem sendToRepeater = new JMenuItem(String.format("发送到 Repeater Manager (%d条)", count));
                sendToRepeater.addActionListener(e -> {
                    BurpExtender.setRepeaterUIRequests(validResponses);
                });

                JMenuItem sendToPrivilegeTest = new JMenuItem(String.format("发送到权限测试 (%d条)", count));
                sendToPrivilegeTest.addActionListener(e -> {
                    BurpExtender.setPrivilegeTestRequests(validResponses);
                });

                menuItems.add(sendToRepeater);
                menuItems.add(sendToPrivilegeTest);
            }
        }

        return menuItems;
    }
}
