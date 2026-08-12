package org.oxff.repeater.ui.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.oxff.repeater.i18n.I18nManager;
import org.oxff.repeater.ui.comparer.ComparerPanel;

import javax.swing.*;
import javax.swing.plaf.LayerUI;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * 基于Burp原生编辑器的响应面板（使用Montoya SDK HttpResponseEditor）
 */
public class BurpResponsePanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private final HttpResponseEditor responseEditor;
    private byte[] currentResponse;

    // 需要在语言切换时刷新的组件
    private JButton saveButton;

    // 报文比较面板引用
    private ComparerPanel comparerPanel;

    /**
     * 创建响应面板
     *
     * @param api MontoyaApi实例
     */
    public BurpResponsePanel(MontoyaApi api) {
        super(new BorderLayout());

        // 创建Montoya响应编辑器
        responseEditor = api.userInterface().createHttpResponseEditor();

        // 创建保存按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        saveButton = new JButton(I18nManager.tr("burp.response.save"));
        saveButton.addActionListener(e -> saveResponseToFile());
        buttonPanel.add(saveButton);

        // 添加到面板
        add(buttonPanel, BorderLayout.NORTH);
        add(wrapWithContextMenu(responseEditor.uiComponent()), BorderLayout.CENTER);

        // 注册语言变更监听
        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);
    }

    /**
     * 语言变更时刷新文本
     */
    private void refreshTexts() {
        saveButton.setText(I18nManager.tr("burp.response.save"));
        revalidate();
        repaint();
    }

    /**
     * 将响应内容保存到文件
     */
    private void saveResponseToFile() {
        if (currentResponse == null || currentResponse.length == 0) {
            JOptionPane.showMessageDialog(this,
                I18nManager.tr("burp.response.save.empty"),
                I18nManager.tr("common.error"), JOptionPane.ERROR_MESSAGE);
            return;
        }

        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showSaveDialog(
            org.oxff.repeater.utils.FileChooserHelper.OP_RESPONSE_SAVE, I18nManager.tr("burp.response.save.dialog"), this, null);

        if (selectedFile != null) {
            try (FileOutputStream fos = new FileOutputStream(selectedFile)) {
                fos.write(currentResponse);
                JOptionPane.showMessageDialog(this,
                    I18nManager.tr("burp.response.save.success", selectedFile.getAbsolutePath()),
                    I18nManager.tr("burp.response.save.success.title"), JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this,
                    I18nManager.tr("burp.response.save.failed", ex.getMessage()),
                    I18nManager.tr("common.error"), JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /**
     * 设置响应数据
     */
    public void setResponse(byte[] response) {
        if (response != null) {
            responseEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(response)));
            currentResponse = response.clone();
        }
    }

    /**
     * 获取响应数据
     */
    public byte[] getResponse() {
        return responseEditor.getResponse().toByteArray().getBytes();
    }

    /**
     * 用 JLayer 包装编辑器组件，拦截编辑器子树内的右键事件
     * （Swing 鼠标事件只会分发给最深层子组件，外层容器加 MouseListener
     *   无法捕获编辑区内部的右键，因此必须通过 JLayer 在事件分发前拦截）
     */
    private JLayer<Component> wrapWithContextMenu(Component editorComponent) {
        LayerUI<Component> layerUI = new LayerUI<Component>() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void processMouseEvent(MouseEvent e, JLayer<? extends Component> l) {
                if (e.isPopupTrigger() && comparerPanel != null) {
                    // 消费事件，避免与Burp编辑器自带右键菜单叠加显示
                    e.consume();
                    showSendToComparerPopup(e);
                }
            }
        };
        JLayer<Component> layer = new JLayer<>(editorComponent, layerUI);
        // 订阅鼠标事件，使 LayerUI 能收到编辑器子树内的鼠标事件
        layer.setLayerEventMask(AWTEvent.MOUSE_EVENT_MASK);
        return layer;
    }

    /**
     * 显示"发送到报文比较"右键菜单
     */
    private void showSendToComparerPopup(MouseEvent e) {
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem sendToComparerItem = new JMenuItem(I18nManager.tr("editor.sendToComparer"));
        sendToComparerItem.addActionListener(ev -> {
            byte[] responseData = getResponse();
            if (responseData != null && responseData.length > 0) {
                comparerPanel.addItem(responseData, "响应编辑器");
            }
        });
        popupMenu.add(sendToComparerItem);
        popupMenu.show(e.getComponent(), e.getX(), e.getY());
    }

    /**
     * 设置报文比较面板引用
     */
    public void setComparerPanel(ComparerPanel comparerPanel) {
        this.comparerPanel = comparerPanel;
    }

    /**
     * 获取响应编辑器
     */
    public HttpResponseEditor getResponseEditor() {
        return responseEditor;
    }

    /**
     * 清空响应内容
     */
    public void clear() {
        responseEditor.setResponse(HttpResponse.httpResponse());
        currentResponse = null;
    }
}
