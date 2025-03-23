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
     * 设置请求内容
     */
    public void setRequest(byte[] request) {
        if (request == null) {
            BurpExtender.printError("[!] 设置请求失败：请求为空");
            return;
        }
        
        try {
            // 尝试修复可能损坏的请求数据
            byte[] fixedRequest = validateAndFixRequest(request);
            // 设置请求到编辑器
            requestEditor.setMessage(fixedRequest, true);
            BurpExtender.printOutput("[*] 已加载请求数据到Burp编辑器，大小: " + request.length + " 字节");
        } catch (Exception e) {
            BurpExtender.printError("[!] 设置请求到Burp编辑器失败: " + e.getMessage());
            
            // 异常处理：尝试创建一个最基本的HTTP请求
            try {
                String basicRequest = createBasicHttpRequest(request);
                requestEditor.setMessage(basicRequest.getBytes(), true);
                BurpExtender.printOutput("[*] 已创建基本HTTP请求作为替代");
            } catch (Exception ex) {
                BurpExtender.printError("[!] 无法创建替代请求: " + ex.getMessage());
            }
        }
    }
    
    /**
     * 验证并修复请求数据
     */
    private byte[] validateAndFixRequest(byte[] request) {
        if (request == null || request.length == 0) {
            return "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".getBytes();
        }
        
        // 检查是否为有效的HTTP请求
        String requestStr = new String(request, java.nio.charset.StandardCharsets.ISO_8859_1);
        
        // 简单检查是否包含HTTP方法和版本
        boolean isValidHttp = false;
        String[] lines = requestStr.split("\r\n|\n", 2);
        if (lines.length > 0) {
            String firstLine = lines[0].trim();
            isValidHttp = firstLine.matches("(?i)(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE)\\s+.+\\s+HTTP/.+");
        }
        
        if (isValidHttp) {
            return request;
        }
        
        // 如果不是有效的HTTP请求，尝试修复
        BurpExtender.printOutput("[*] 请求数据格式无效，尝试修复...");
        
        // 检查是否只是缺少HTTP头
        if (!requestStr.contains("HTTP/1.") && !requestStr.contains("Host:")) {
            // 可能是纯粹的请求体数据，尝试添加一个基本的HTTP头
            String method = "POST";  // 默认使用POST方法
            StringBuilder fixedRequest = new StringBuilder();
            fixedRequest.append(method).append(" / HTTP/1.1\r\n");
            fixedRequest.append("Host: example.com\r\n");
            fixedRequest.append("Content-Type: application/x-www-form-urlencoded\r\n");
            fixedRequest.append("Content-Length: ").append(request.length).append("\r\n");
            fixedRequest.append("\r\n");
            fixedRequest.append(requestStr);
            
            BurpExtender.printOutput("[+] 已添加基本HTTP头到请求数据");
            return fixedRequest.toString().getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        }
        
        // 如果包含二进制数据，可能需要更特殊的处理
        boolean containsBinary = false;
        for (byte b : request) {
            if (b == 0 || (b < 32 && b != '\r' && b != '\n' && b != '\t')) {
                containsBinary = true;
                break;
            }
        }
        
        if (containsBinary) {
            // 二进制数据，创建一个带有适当Content-Type的POST请求
            StringBuilder fixedRequest = new StringBuilder();
            fixedRequest.append("POST / HTTP/1.1\r\n");
            fixedRequest.append("Host: example.com\r\n");
            fixedRequest.append("Content-Type: application/octet-stream\r\n");
            fixedRequest.append("Content-Length: ").append(request.length).append("\r\n");
            fixedRequest.append("\r\n");
            
            // 将二进制数据作为请求体
            byte[] header = fixedRequest.toString().getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
            byte[] fixed = new byte[header.length + request.length];
            System.arraycopy(header, 0, fixed, 0, header.length);
            System.arraycopy(request, 0, fixed, header.length, request.length);
            
            BurpExtender.printOutput("[+] 已创建包含二进制数据的HTTP请求");
            return fixed;
        }
        
        // 如果以上都不适用，返回原始请求
        return request;
    }
    
    /**
     * 创建基本的HTTP请求作为后备选项
     */
    private String createBasicHttpRequest(byte[] originalData) {
        StringBuilder sb = new StringBuilder();
        sb.append("GET / HTTP/1.1\r\n");
        sb.append("Host: example.com\r\n");
        sb.append("User-Agent: Mozilla/5.0\r\n");
        sb.append("Accept: */*\r\n");
        sb.append("\r\n");
        
        // 如果有原始数据，添加注释
        if (originalData != null && originalData.length > 0) {
            sb.append("<!-- 原始数据长度: ").append(originalData.length).append(" 字节 -->\r\n");
        }
        
        return sb.toString();
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