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
                JMenuItem sendToEnhancedRepeater = new JMenuItem("发送到增强型Repeater");
                sendToEnhancedRepeater.addActionListener(e -> {
                    // 调用EnhancedRepeaterUI的方法处理所选请求
                    BurpExtender.setRepeaterUIRequest(requestResponse);
                });

                menuItems.add(sendToEnhancedRepeater);
            }
        }

        return menuItems;
    }
}
