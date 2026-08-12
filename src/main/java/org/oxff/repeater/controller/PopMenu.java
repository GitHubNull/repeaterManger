package org.oxff.repeater.controller;

import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.http.message.HttpRequestResponse;

import org.oxff.repeater.UIRequestDispatcher;
import org.oxff.repeater.privilege.SessionManager;

import javax.swing.*;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class PopMenu implements ContextMenuItemsProvider {
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // 检查是否有请求被选中（列表/表格场景）
        List<HttpRequestResponse> selectedResponses = event.selectedRequestResponses();

        // 报文查看器（请求/响应编辑器）右键场景回退：
        // 当焦点在 MESSAGE_EDITOR_REQUEST/RESPONSE 或 MESSAGE_VIEWER_REQUEST/RESPONSE 时，
        // selectedRequestResponses() 返回空列表，需通过 messageEditorRequestResponse() 获取当前显示的报文
        if (selectedResponses == null || selectedResponses.isEmpty()) {
            var editorRR = event.messageEditorRequestResponse();
            if (editorRR.isPresent() && editorRR.get().requestResponse() != null
                    && editorRR.get().requestResponse().request() != null) {
                selectedResponses = List.of(editorRR.get().requestResponse());
            }
        }

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
                    UIRequestDispatcher.getInstance().setRepeaterUIRequest(requestResponse);
                });

                JMenuItem sendToPrivilegeTest = new JMenuItem("发送到权限测试");
                sendToPrivilegeTest.addActionListener(e -> {
                    UIRequestDispatcher.getInstance().setPrivilegeTestRequest(requestResponse);
                });

                JMenuItem parseSessionItem = new JMenuItem("解析为用户会话");
                boolean hasSchemes = !SessionManager.getInstance().getSchemes().isEmpty();
                parseSessionItem.setEnabled(hasSchemes);
                if (!hasSchemes) {
                    parseSessionItem.setToolTipText("请先配置方案");
                }
                parseSessionItem.addActionListener(e -> {
                    UIRequestDispatcher.getInstance().parseSessionFromRequest(requestResponse.request());
                });

                menuItems.add(sendToRepeater);
                menuItems.add(sendToPrivilegeTest);
                menuItems.add(parseSessionItem);
            } else {
                // 多条选中：使用批量方法，菜单文案附带数量
                JMenuItem sendToRepeater = new JMenuItem(String.format("发送到 Repeater Manager (%d条)", count));
                sendToRepeater.addActionListener(e -> {
                    UIRequestDispatcher.getInstance().setRepeaterUIRequests(validResponses);
                });

                JMenuItem sendToPrivilegeTest = new JMenuItem(String.format("发送到权限测试 (%d条)", count));
                sendToPrivilegeTest.addActionListener(e -> {
                    UIRequestDispatcher.getInstance().setPrivilegeTestRequests(validResponses);
                });

                menuItems.add(sendToRepeater);
                menuItems.add(sendToPrivilegeTest);
            }
        }

        return menuItems;
    }
}
