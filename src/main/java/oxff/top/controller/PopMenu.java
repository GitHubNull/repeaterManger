package oxff.top.controller;

import burp.BurpExtender;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class PopMenu implements IContextMenuFactory {
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();

        // 检查是否有请求被选中
        IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
        if (selectedMessages != null && selectedMessages.length > 0) {
            final IHttpRequestResponse requestResponse = selectedMessages[0];

            if (requestResponse != null && requestResponse.getRequest() != null) {
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
