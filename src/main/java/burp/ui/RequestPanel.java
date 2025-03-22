package burp.ui;

import burp.BurpExtender;
import burp.IRequestInfo;
import burp.ITextEditor;
import burp.utils.TextLineNumber;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 请求面板组件 - 负责显示和编辑HTTP请求
 */
public class RequestPanel extends JPanel {
    private static final long serialVersionUID = 1L;
    
    // 基本组件
    private final JTextArea requestTextArea;
    private final JButton sendButton;
    private final JSpinner timeoutSpinner;
    
    // HTTP请求编辑器组件
    private ITextEditor requestEditor;  // Burp的文本编辑器接口
    
    // HTTP请求参数输入字段
    private JTextField methodField;     // 请求方法
    private JTextField hostField;       // 主机名
    private JTextField portField;       // 端口号
    private JCheckBox httpsCheckbox;    // HTTPS开关
    private JTextField contentTypeField; // 内容类型
    
    /**
     * 创建请求面板
     */
    public RequestPanel() {
        super(new BorderLayout());
        
        // 创建请求文本区域
        requestTextArea = new JTextArea();
        requestTextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        requestTextArea.setTabSize(4);
        requestTextArea.setLineWrap(true);
        requestTextArea.setWrapStyleWord(true);
        
        // 添加自动缩进功能
        requestTextArea.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    addIndent();
                } else if (e.getKeyCode() == KeyEvent.VK_ENTER && e.isControlDown()) {
                    // 允许Ctrl+Enter发送请求
                    if (sendButton != null) {
                        sendButton.doClick();
                    }
                }
            }
        });
        
        // 创建右键菜单
        JPopupMenu requestPopupMenu = createContextMenu();
        requestTextArea.setComponentPopupMenu(requestPopupMenu);
        
        // 创建滚动面板
        JScrollPane requestScrollPane = new JScrollPane(requestTextArea);
        requestScrollPane.setBorder(BorderFactory.createTitledBorder("请求"));
        
        // 添加行号
        TextLineNumber requestLineNumber = new TextLineNumber(requestTextArea);
        requestLineNumber.setCurrentLineForeground(new Color(44, 121, 217)); // 蓝色高亮当前行
        requestLineNumber.setForeground(Color.GRAY);
        requestLineNumber.setBackground(new Color(245, 245, 245)); // 浅灰色背景
        requestLineNumber.setFont(new Font("Monospaced", Font.PLAIN, 12));
        requestScrollPane.setRowHeaderView(requestLineNumber);
        
        // 创建控制面板
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        // 创建HTTP请求参数输入字段
        methodField = new JTextField("GET", 5);
        hostField = new JTextField(20);
        portField = new JTextField("80", 5);
        httpsCheckbox = new JCheckBox("HTTPS", false);
        httpsCheckbox.addActionListener(e -> {
            if (httpsCheckbox.isSelected() && portField.getText().equals("80")) {
                portField.setText("443");
            } else if (!httpsCheckbox.isSelected() && portField.getText().equals("443")) {
                portField.setText("80");
            }
        });
        contentTypeField = new JTextField("application/x-www-form-urlencoded", 20);
        
        // 添加HTTP请求参数字段到面板
        JPanel httpParamsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        httpParamsPanel.add(new JLabel("方法:"));
        httpParamsPanel.add(methodField);
        httpParamsPanel.add(new JLabel("主机:"));
        httpParamsPanel.add(hostField);
        httpParamsPanel.add(new JLabel("端口:"));
        httpParamsPanel.add(portField);
        httpParamsPanel.add(httpsCheckbox);
        httpParamsPanel.add(new JLabel("内容类型:"));
        httpParamsPanel.add(contentTypeField);
        
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
        
        // 将HTTP参数面板添加到主面板
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(httpParamsPanel, BorderLayout.NORTH);
        topPanel.add(controlPanel, BorderLayout.SOUTH);
        
        // 添加到面板
        add(topPanel, BorderLayout.NORTH);
        add(requestScrollPane, BorderLayout.CENTER);
        
        // 初始化Burp编辑器
        initBurpEditor();
    }
    
    /**
     * 初始化Burp编辑器
     */
    private void initBurpEditor() {
        try {
            // 通过BurpExtender获取requestEditor，如果可用
            if (BurpExtender.callbacks != null) {
                requestEditor = BurpExtender.callbacks.createTextEditor();
            }
        } catch (Exception e) {
            // 如果无法创建Burp编辑器，则使用标准文本区域
            BurpExtender.printError("[!] 无法创建Burp编辑器: " + e.getMessage());
        }
    }
    
    /**
     * 创建右键菜单
     */
    private JPopupMenu createContextMenu() {
        JPopupMenu popupMenu = new JPopupMenu();
        
        JMenuItem copyItem = new JMenuItem("复制");
        copyItem.addActionListener(e -> requestTextArea.copy());
        copyItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_C, KeyEvent.CTRL_DOWN_MASK));
        
        JMenuItem pasteItem = new JMenuItem("粘贴");
        pasteItem.addActionListener(e -> requestTextArea.paste());
        pasteItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_V, KeyEvent.CTRL_DOWN_MASK));
        
        JMenuItem cutItem = new JMenuItem("剪切");
        cutItem.addActionListener(e -> requestTextArea.cut());
        cutItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_X, KeyEvent.CTRL_DOWN_MASK));
        
        JMenuItem selectAllItem = new JMenuItem("全选");
        selectAllItem.addActionListener(e -> requestTextArea.selectAll());
        selectAllItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_A, KeyEvent.CTRL_DOWN_MASK));
        
        JMenuItem clearItem = new JMenuItem("清空");
        clearItem.addActionListener(e -> requestTextArea.setText(""));
        
        JMenuItem sendMenuItem = new JMenuItem("发送请求");
        sendMenuItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, KeyEvent.CTRL_DOWN_MASK));
        
        popupMenu.add(copyItem);
        popupMenu.add(pasteItem);
        popupMenu.add(cutItem);
        popupMenu.addSeparator();
        popupMenu.add(selectAllItem);
        popupMenu.add(clearItem);
        popupMenu.addSeparator();
        popupMenu.add(sendMenuItem);
        
        return popupMenu;
    }
    
    /**
     * 添加缩进功能
     */
    private void addIndent() {
        try {
            int caretPos = requestTextArea.getCaretPosition();
            int lineNum = requestTextArea.getDocument().getDefaultRootElement().getElementIndex(caretPos);
            int lineStart = requestTextArea.getLineStartOffset(lineNum);
            String line = requestTextArea.getText(lineStart, caretPos - lineStart);
            
            // 计算前导空格
            StringBuilder indent = new StringBuilder();
            for (char c : line.toCharArray()) {
                if (c == ' ' || c == '\t') {
                    indent.append(c);
                } else {
                    break;
                }
            }
            
            // 在下一行添加相同的缩进
            SwingUtilities.invokeLater(() -> {
                try {
                    requestTextArea.getDocument().insertString(
                        requestTextArea.getCaretPosition(), 
                        indent.toString(), 
                        null
                    );
                } catch (BadLocationException ex) {
                    BurpExtender.printError("[!] 添加缩进失败: " + ex.getMessage());
                }
            });
        } catch (BadLocationException ex) {
            BurpExtender.printError("[!] 添加缩进失败: " + ex.getMessage());
        }
    }
    
    /**
     * 设置发送请求的监听器
     */
    public void setSendButtonListener(java.awt.event.ActionListener listener) {
        sendButton.addActionListener(listener);
        // 同时为菜单项也添加相同的监听器
        for (Component item : requestTextArea.getComponentPopupMenu().getComponents()) {
            if (item instanceof JMenuItem && "发送请求".equals(((JMenuItem)item).getText())) {
                ((JMenuItem)item).addActionListener(listener);
            }
        }
    }
    
    /**
     * 获取请求文本
     */
    public String getRequestText() {
        return requestTextArea.getText();
    }
    
    /**
     * 设置请求文本
     */
    public void setRequestText(String text) {
        requestTextArea.setText(text);
        requestTextArea.setCaretPosition(0);
    }
    
    /**
     * 设置请求文本
     */
    public void setRequestText(byte[] request) {
        if (request != null) {
            setRequestText(new String(request));
        }
    }
    
    /**
     * 获取超时设置(秒)
     */
    public int getTimeout() {
        return (Integer) timeoutSpinner.getValue();
    }
    
    /**
     * 获取请求文本组件
     */
    public JTextArea getRequestTextArea() {
        return requestTextArea;
    }
    
    /**
     * 清空请求内容
     */
    public void clear() {
        requestTextArea.setText("");
        if (requestEditor != null) {
            requestEditor.setText("".getBytes());
        }
    }
    
    /**
     * 检查请求参数是否被修改
     */
    public boolean isRequestModified() {
        // 检查请求参数是否被用户修改，需要与原始参数比较
        // 简化实现：只要有任何字段有内容就认为已修改
        return !hostField.getText().trim().isEmpty() ||
               !methodField.getText().trim().isEmpty() ||
               !portField.getText().trim().isEmpty() ||
               !contentTypeField.getText().trim().isEmpty();
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
            // 先清空已有内容
            clear();
            
            // 设置请求内容到编辑器
            if (requestEditor != null) {
                requestEditor.setText(request);
            } else {
                setRequestText(request);
            }
            
            // 分析请求信息
            IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(request);
            List<String> headers = requestInfo.getHeaders();
            
            // 更新请求方法和URL信息
            if (!headers.isEmpty()) {
                String firstLine = headers.get(0);
                String[] parts = firstLine.split(" ", 3);
                if (parts.length >= 2) {
                    String method = parts[0];
                    methodField.setText(method);
                }
            }
            
            // 设置主机和端口
            String host = "";
            String port = "";
            boolean isHttps = false;
            
            for (String header : headers) {
                if (header.toLowerCase().startsWith("host:")) {
                    host = header.substring(5).trim();
                    // 如果主机包含端口号，则分离出来
                    if (host.contains(":")) {
                        String[] parts = host.split(":", 2);
                        host = parts[0];
                        port = parts[1];
                    } else {
                        // 默认端口
                        port = "80";
                    }
                    break;
                }
            }
            
            // 检查是否为HTTPS
            for (String header : headers) {
                if (header.toLowerCase().startsWith("referer: https://") ||
                    (port.equals("443"))) {
                    isHttps = true;
                    if (port.equals("80")) {
                        port = "443";
                    }
                    break;
                }
            }
            
            // 设置到界面
            hostField.setText(host);
            portField.setText(port);
            httpsCheckbox.setSelected(isHttps);
            
            // 设置Content-Type
            String contentType = "";
            for (String header : headers) {
                if (header.toLowerCase().startsWith("content-type:")) {
                    contentType = header.substring(13).trim();
                    break;
                }
            }
            contentTypeField.setText(contentType);
            
            BurpExtender.printOutput("[+] 请求已加载: " + (isHttps ? "https://" : "http://") + host + ":" + port);
        } catch (Exception e) {
            BurpExtender.printError("[!] 设置请求时出错: " + e.getMessage());
        }
    }

    public byte[] getRequest() {
        try {
            // 从编辑器获取请求
            byte[] request;
            if (requestEditor != null) {
                request = requestEditor.getText();
            } else {
                request = requestTextArea.getText().getBytes();
            }
            
            // 如果需要修改主机、端口或协议
            if (isRequestModified()) {
                BurpExtender.printOutput("[*] 检测到请求参数已修改，正在更新请求...");
                
                // 分析请求
                IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(request);
                List<String> headers = new ArrayList<>(requestInfo.getHeaders());
                byte[] body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
                
                // 更新Host头
                String newHost = hostField.getText().trim();
                if (!newHost.isEmpty()) {
                    boolean foundHost = false;
                    for (int i = 0; i < headers.size(); i++) {
                        if (headers.get(i).toLowerCase().startsWith("host:")) {
                            String newHostHeader = "Host: " + newHost;
                            if (!portField.getText().trim().isEmpty() && 
                                !portField.getText().equals("80") && 
                                !portField.getText().equals("443")) {
                                newHostHeader += ":" + portField.getText().trim();
                            }
                            headers.set(i, newHostHeader);
                            foundHost = true;
                            break;
                        }
                    }
                    
                    // 如果没有找到Host头，添加一个
                    if (!foundHost) {
                        String newHostHeader = "Host: " + newHost;
                        if (!portField.getText().trim().isEmpty() && 
                            !portField.getText().equals("80") && 
                            !portField.getText().equals("443")) {
                            newHostHeader += ":" + portField.getText().trim();
                        }
                        headers.add(1, newHostHeader);
                    }
                }
                
                // 更新Content-Type头
                String newContentType = contentTypeField.getText().trim();
                if (!newContentType.isEmpty()) {
                    boolean foundContentType = false;
                    for (int i = 0; i < headers.size(); i++) {
                        if (headers.get(i).toLowerCase().startsWith("content-type:")) {
                            headers.set(i, "Content-Type: " + newContentType);
                            foundContentType = true;
                            break;
                        }
                    }
                    
                    // 如果没有找到Content-Type头，但有输入值，则添加一个
                    if (!foundContentType && !newContentType.isEmpty() && body.length > 0) {
                        headers.add("Content-Type: " + newContentType);
                    }
                }
                
                // 更新请求方法
                String newMethod = methodField.getText().trim();
                if (!newMethod.isEmpty()) {
                    String firstLine = headers.get(0);
                    String[] parts = firstLine.split(" ", 3);
                    if (parts.length >= 3) {
                        headers.set(0, newMethod + " " + parts[1] + " " + parts[2]);
                    } else if (parts.length == 2) {
                        headers.set(0, newMethod + " " + parts[1] + " HTTP/1.1");
                    }
                }
                
                // 重建请求
                request = BurpExtender.helpers.buildHttpMessage(headers, body);
                
                BurpExtender.printOutput("[+] 请求已更新: " +
                                       (httpsCheckbox.isSelected() ? "https://" : "http://") +
                                       hostField.getText() + ":" + portField.getText());
            }
            
            return request;
        } catch (Exception e) {
            BurpExtender.printError("[!] 获取请求时出错: " + e.getMessage());
            return null;
        }
    }
} 