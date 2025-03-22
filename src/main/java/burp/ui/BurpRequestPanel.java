package burp.ui;

import burp.BurpExtender;
import burp.IMessageEditor;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;

/**
 * 基于Burp原生编辑器的请求面板
 */
public class BurpRequestPanel extends JPanel {
    private static final long serialVersionUID = 1L;
    
    private final IMessageEditor requestEditor;
    private final JButton sendButton;
    private final JSpinner timeoutSpinner;
    
    /**
     * 创建请求面板
     */
    public BurpRequestPanel() {
        super(new BorderLayout());
        
        // 创建Burp原生请求编辑器
        requestEditor = BurpExtender.callbacks.createMessageEditor(null, true);
        
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
        add(requestEditor.getComponent(), BorderLayout.CENTER);
        
        // 添加快捷键支持
        registerKeyboardShortcuts();
    }
    
    /**
     * 注册键盘快捷键
     */
    private void registerKeyboardShortcuts() {
        // 使用InputMap和ActionMap进行快捷键绑定
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
     * 获取请求数据
     * 
     * @return 请求字节数组
     */
    public byte[] getRequest() {
        return requestEditor.getMessage();
    }
    
    /**
     * 设置请求数据
     * 
     * @param request 请求字节数组
     */
    public void setRequest(byte[] request) {
        if (request != null) {
            requestEditor.setMessage(request, true);
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
     * 获取原生请求编辑器
     * 
     * @return Burp的IMessageEditor接口
     */
    public IMessageEditor getRequestEditor() {
        return requestEditor;
    }
    
    /**
     * 清空请求内容
     */
    public void clear() {
        requestEditor.setMessage(new byte[0], true);
    }
} 