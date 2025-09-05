package oxff.top.ui;

import oxff.top.ui.viewer.HttpViewerPanel;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;

/**
 * 增强型请求面板 - 支持美化、原始和十六进制视图模式
 */
public class EnhancedRequestPanel extends JPanel {
    private static final long serialVersionUID = 1L;
    
    private final HttpViewerPanel requestViewer;
    private final JButton sendButton;
    private final JSpinner timeoutSpinner;
    
    /**
     * 创建增强型请求面板
     */
    public EnhancedRequestPanel() {
        super(new BorderLayout());
        
        // 创建请求查看器
        requestViewer = new HttpViewerPanel("请求", true);
        requestViewer.setupContextMenu();
        
        // 创建控制面板
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        // 超时设置
        JLabel timeoutLabel = new JLabel("请求超时(秒):");
        timeoutSpinner = new JSpinner(new SpinnerNumberModel(30, 0, 60, 1));
        timeoutSpinner.setPreferredSize(new Dimension(60, 25));
        controlPanel.add(timeoutLabel);
        controlPanel.add(timeoutSpinner);
        
        // 发送按钮
        sendButton = new JButton("发送请求");
        sendButton.setToolTipText("发送请求 (Ctrl+Enter)");
        controlPanel.add(sendButton);
        
        // 添加到面板
        add(controlPanel, BorderLayout.NORTH);
        add(requestViewer, BorderLayout.CENTER);
        
        // 添加快捷键支持
        registerKeyboardShortcuts();
    }
    
    /**
     * 注册键盘快捷键
     */
    private void registerKeyboardShortcuts() {
        // 使用InputMap和ActionMap代替KeyListener，更加灵活和可靠
        InputMap inputMap = getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        ActionMap actionMap = getActionMap();
        
        // 注册Ctrl+Enter快捷键发送请求
        KeyStroke ctrlEnter = KeyStroke.getKeyStroke("ctrl ENTER");
        inputMap.put(ctrlEnter, "sendRequest");
        actionMap.put("sendRequest", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                sendButton.doClick();
            }
        });
    }
    
    /**
     * 设置发送按钮监听器
     * 
     * @param listener 点击监听器
     */
    public void setSendButtonListener(ActionListener listener) {
        // 移除现有监听器
        for (ActionListener al : sendButton.getActionListeners()) {
            sendButton.removeActionListener(al);
        }
        
        // 添加新监听器
        sendButton.addActionListener(listener);
    }
    
    /**
     * 获取请求文本
     * 
     * @return 请求文本
     */
    public String getRequestText() {
        return requestViewer.getText();
    }
    
    /**
     * 设置请求文本
     * 
     * @param text 请求文本
     */
    public void setRequestText(String text) {
        requestViewer.setText(text);
    }
    
    /**
     * 设置请求数据
     * 
     * @param request 请求字节数组
     */
    public void setRequestText(byte[] request) {
        if (request != null) {
            requestViewer.setData(request);
        }
    }
    
    /**
     * 获取超时设置(秒)
     * 
     * @return 超时秒数
     */
    public int getTimeout() {
        return (Integer) timeoutSpinner.getValue();
    }
    
    /**
     * 获取请求查看器组件
     * 
     * @return HttpViewerPanel实例
     */
    public HttpViewerPanel getRequestViewer() {
        return requestViewer;
    }
    
    /**
     * 清空请求内容
     */
    public void clear() {
        requestViewer.clear();
    }
} 