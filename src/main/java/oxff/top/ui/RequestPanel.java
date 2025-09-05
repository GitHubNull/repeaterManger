package oxff.top.ui;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import oxff.top.db.HistoryDAO;
import oxff.top.db.RequestDAO;
import burp.ITextEditor;
import oxff.top.utils.TextLineNumber;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.net.URL;
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
    private ITextEditor responseEditor;
    
    // HTTP请求参数输入字段
    private JTextField methodField;     // 请求方法
    private JTextField hostField;       // 主机名
    private JTextField portField;       // 端口号
    private JCheckBox httpsCheckbox;    // HTTPS开关
    private JTextField contentTypeField; // 内容类型
    
    private final MainUI mainUI;
    
    /**
     * 创建请求面板
     */
    public RequestPanel(MainUI mainUI) {
        super(new BorderLayout());
        
        this.mainUI = mainUI;
        
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
        sendButton.addActionListener(e -> sendRequest());
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
                requestEditor.setEditable(true);
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
        if (request == null || request.length == 0) {
            BurpExtender.printError("[!] 设置请求失败：请求数据为空");
            return;
        }
        
        try {
            // 尝试不同的解码方式来处理请求数据
            String requestText = null;
            boolean isBinary = false;
            
            // 检查是否包含二进制数据
            for (byte b : request) {
                if (b == 0 || (b < 32 && b != '\r' && b != '\n' && b != '\t')) {
                    isBinary = true;
                    break;
                }
            }
            
            if (isBinary) {
                // 对于二进制数据，使用Base64编码显示
                requestText = "HTTP/1.1 二进制数据\r\n";
                requestText += "Content-Type: application/octet-stream\r\n";
                requestText += "Content-Length: " + request.length + "\r\n\r\n";
                requestText += "[二进制数据，长度: " + request.length + " 字节]\n";
                requestText += java.util.Base64.getEncoder().encodeToString(request);
            } else {
                // 尝试UTF-8解码
                try {
                    requestText = new String(request, java.nio.charset.StandardCharsets.UTF_8);
                    if (!isValidHttpRequest(requestText)) {
                        // 如果UTF-8解码后不是有效的HTTP请求，尝试ISO-8859-1
                        requestText = new String(request, java.nio.charset.StandardCharsets.ISO_8859_1);
                    }
                } catch (Exception e) {
                    // UTF-8解码失败，使用ISO-8859-1
                    requestText = new String(request, java.nio.charset.StandardCharsets.ISO_8859_1);
                }
            }
            
            // 验证请求格式
            if (!isValidHttpRequest(requestText)) {
                BurpExtender.printError("[!] 请求格式无效，尝试修复...");
                requestText = repairBinaryData(request);
            }
            
            // 设置文本到UI
            setRequestText(requestText);
            BurpExtender.printOutput("[*] 已加载请求数据，大小: " + request.length + " 字节");
            
        } catch (Exception e) {
            BurpExtender.printError("[!] 设置请求文本时出错: " + e.getMessage());
            // 创建基本请求作为后备方案
            setRequestText(createBasicRequest());
        }
    }
    
    /**
     * 检查文本是否为有效的HTTP请求
     */
    private boolean isValidHttpRequest(String text) {
        if (text == null || text.isEmpty()) {
            return false;
        }
        
        try {
            // 简单检查是否包含HTTP方法和HTTP版本
            String[] firstLines = text.split("\r\n|\n", 2);
            if (firstLines.length == 0) {
                return false;
            }
            
            String firstLine = firstLines[0].trim();
            boolean isValidMethod = firstLine.matches("(?i)(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE)\\s+.+\\s+HTTP/.+");
            boolean isValidResponse = firstLine.matches("HTTP/.+\\s+\\d+\\s+.*");
            
            if (!isValidMethod && !isValidResponse) {
                return false;
            }
            
            // 检查是否包含必要的头部
            boolean hasHost = false;
            boolean hasContentLength = false;
            String[] lines = text.split("\r\n|\n");
            
            for (String line : lines) {
                if (line.toLowerCase().startsWith("host:")) {
                    hasHost = true;
                }
                if (line.toLowerCase().startsWith("content-length:")) {
                    hasContentLength = true;
                }
                // 如果同时找到Host和Content-Length，可以提前返回
                if (hasHost && hasContentLength) {
                    return true;
                }
            }
            
            // 对于GET请求，不需要Content-Length
            if (firstLine.toUpperCase().startsWith("GET") && hasHost) {
                return true;
            }
            
            // 对于其他请求，需要Content-Length
            return hasHost && hasContentLength;
            
        } catch (Exception e) {
            BurpExtender.printError("[!] 验证HTTP请求时出错: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 尝试修复损坏的二进制数据
     */
    private String repairBinaryData(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        
        // 记录原始数据用于调试
        BurpExtender.printOutput("[*] 尝试修复请求数据，大小: " + data.length + " 字节");
        
        StringBuilder sb = new StringBuilder();
        
        // 尝试识别HTTP头部和正文的分隔符
        int bodyStart = -1;
        for (int i = 0; i < data.length - 3; i++) {
            // 查找\r\n\r\n序列，这通常用于分隔HTTP头部和正文
            if (data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n') {
                bodyStart = i + 4;
                break;
            }
        }
        
        // 如果找到了分隔符
        if (bodyStart > 0) {
            // 分别处理头部和正文
            String headers = new String(Arrays.copyOfRange(data, 0, bodyStart), 
                                      java.nio.charset.StandardCharsets.ISO_8859_1);
            sb.append(headers);
            
            // 检查是否为多部分表单数据
            if (headers.toLowerCase().contains("content-type: multipart/form-data")) {
                // 对于多部分表单数据，使用ISO-8859-1编码处理整个请求
                return new String(data, java.nio.charset.StandardCharsets.ISO_8859_1);
            }
            
            // 对于正文部分，尝试智能选择编码
            if (bodyStart < data.length) {
                byte[] body = Arrays.copyOfRange(data, bodyStart, data.length);
                
                // 尝试检测正文是否包含二进制数据
                boolean isBinary = false;
                for (byte b : body) {
                    if (b == 0 || (b < 32 && b != '\r' && b != '\n' && b != '\t')) {
                        isBinary = true;
                        break;
                    }
                }
                
                if (isBinary) {
                    // 对于二进制数据，使用Base64编码显示
                    sb.append("[二进制数据，长度: ").append(body.length).append(" 字节]\n");
                    sb.append(java.util.Base64.getEncoder().encodeToString(body));
                } else {
                    // 对于文本数据，尝试使用UTF-8解码
                    try {
                        sb.append(new String(body, java.nio.charset.StandardCharsets.UTF_8));
                    } catch (Exception e) {
                        // 如果UTF-8解码失败，回退到ISO-8859-1
                        sb.append(new String(body, java.nio.charset.StandardCharsets.ISO_8859_1));
                    }
                }
            }
            
            return sb.toString();
        } else {
            // 如果找不到分隔符，尝试检测数据是否为纯二进制
            boolean isBinary = false;
            for (byte b : data) {
                if (b == 0 || (b < 32 && b != '\r' && b != '\n' && b != '\t')) {
                    isBinary = true;
                    break;
                }
            }
            
            if (isBinary) {
                // 对于二进制数据，以可读形式展示
                sb.append("HTTP/1.1 自动生成的请求头\r\n");
                sb.append("Content-Type: application/octet-stream\r\n");
                sb.append("Content-Length: ").append(data.length).append("\r\n\r\n");
                sb.append("[二进制数据，长度: ").append(data.length).append(" 字节]\n");
                sb.append(java.util.Base64.getEncoder().encodeToString(data));
            } else {
                // 对于可能的文本数据，尝试UTF-8和ISO-8859-1
                try {
                    return new String(data, java.nio.charset.StandardCharsets.UTF_8);
                } catch (Exception e) {
                    return new String(data, java.nio.charset.StandardCharsets.ISO_8859_1);
                }
            }
            
            return sb.toString();
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
        if (request == null || request.length == 0) {
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
            
            if (headers.isEmpty()) {
                BurpExtender.printError("[!] 请求头为空，使用默认值");
                setDefaultRequestParams();
                return;
            }
            
            // 更新请求方法和URL信息
            String firstLine = headers.get(0);
            String[] parts = firstLine.split(" ", 3);
            if (parts.length >= 2) {
                methodField.setText(parts[0]);
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
                        String[] hostParts = host.split(":", 2);
                        host = hostParts[0];
                        port = hostParts[1];
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
            setDefaultRequestParams();
        }
    }

    /**
     * 设置默认请求参数
     */
    private void setDefaultRequestParams() {
        methodField.setText("GET");
        hostField.setText("example.com");
        portField.setText("80");
        httpsCheckbox.setSelected(false);
        contentTypeField.setText("application/x-www-form-urlencoded");
    }

    /**
     * 创建基本请求
     */
    private String createBasicRequest() {
        StringBuilder sb = new StringBuilder();
        sb.append("GET / HTTP/1.1\r\n");
        sb.append("Host: example.com\r\n");
        sb.append("User-Agent: Mozilla/5.0\r\n");
        sb.append("Accept: */*\r\n");
        sb.append("Connection: close\r\n");
        sb.append("\r\n");
        return sb.toString();
    }

    /**
     * 获取请求数据
     */
    public byte[] getRequest() {
        try {
            // 从编辑器获取请求
            byte[] request;
            if (requestEditor != null) {
                request = requestEditor.getText();
            } else {
                request = requestTextArea.getText().getBytes();
            }
            
            // 验证请求数据
            if (request == null || request.length == 0) {
                BurpExtender.printError("[!] 请求数据为空，使用默认请求");
                return createBasicRequest().getBytes();
            }
            
            // 如果需要修改主机、端口或协议
            if (isRequestModified()) {
                BurpExtender.printOutput("[*] 检测到请求参数已修改，正在更新请求...");
                
                try {
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
                    
                    // 验证重建后的请求
                    if (!isValidHttpRequest(new String(request))) {
                        BurpExtender.printError("[!] 重建的请求格式无效，使用原始请求");
                        return request;
                    }
                    
                    BurpExtender.printOutput("[+] 请求已更新: " +
                                           (httpsCheckbox.isSelected() ? "https://" : "http://") +
                                           hostField.getText() + ":" + portField.getText());
                    
                } catch (Exception e) {
                    BurpExtender.printError("[!] 更新请求时出错: " + e.getMessage());
                    // 返回原始请求
                    return request;
                }
            }
            
            return request;
            
        } catch (Exception e) {
            BurpExtender.printError("[!] 获取请求时出错: " + e.getMessage());
            return createBasicRequest().getBytes();
        }
    }

    /**
     * 发送请求并处理响应
     */
    private void sendRequest() {
        try {
            // 获取请求数据
            byte[] request = getRequest();
            if (request == null || request.length == 0) {
                BurpExtender.printError("[!] 请求数据为空");
                return;
            }
            
            // 解析请求信息
            IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(request);
            String url = requestInfo.getUrl().toString();
            
            BurpExtender.printOutput("[*] 正在发送请求到 " + url + " (超时时间: " + getTimeout() + "秒)");
            
            // 创建HTTP服务
            URL urlObj = new URL(url);
            String host = urlObj.getHost();
            int port = urlObj.getPort() == -1 ? urlObj.getDefaultPort() : urlObj.getPort();
            boolean useHttps = urlObj.getProtocol().equalsIgnoreCase("https");
            
            // 发送请求
            IHttpService httpService = BurpExtender.helpers.buildHttpService(host, port, useHttps);
            IHttpRequestResponse response = BurpExtender.callbacks.makeHttpRequest(httpService, request);
            
            if (response != null && response.getResponse() != null) {
                try {
                    // 解析URL组件
                    URL parsedUrl = requestInfo.getUrl();
                    String protocol = parsedUrl.getProtocol();
                    String domain = parsedUrl.getHost();
                    String path = parsedUrl.getPath();
                    String query = parsedUrl.getQuery() != null ? parsedUrl.getQuery() : "";
                    String method = requestInfo.getMethod();
                    
                    // 保存请求到数据库
                    RequestDAO requestDAO = new RequestDAO();
                    int requestId = requestDAO.saveRequest(protocol, domain, path, query, method, request);
                    
                    if (requestId > 0) {
                        // 保存响应到数据库
                        HistoryDAO historyDAO = new HistoryDAO();
                        int historyId = historyDAO.saveHistory(requestId, requestInfo, request, response.getResponse());
                        
                        if (historyId > 0) {
                            // 更新UI
                            if (responseEditor != null) {
                                responseEditor.setText(response.getResponse());
                            }
                            
                            // 更新历史记录面板
                            if (mainUI != null && mainUI.getHistoryPanel() != null) {
                                mainUI.getHistoryPanel().addHistoryRecord(requestId, response);
                            }
                            
                            BurpExtender.printOutput("[+] 请求和响应已保存到数据库，请求ID: " + requestId + ", 历史ID: " + historyId);
                        } else {
                            BurpExtender.printError("[!] 保存响应到数据库失败");
                            throw new Exception("保存响应到数据库失败");
                        }
                    } else {
                        BurpExtender.printError("[!] 保存请求到数据库失败");
                        throw new Exception("保存请求到数据库失败");
                    }
                } catch (Exception e) {
                    BurpExtender.printError("[!] 数据库操作失败: " + e.getMessage());
                    throw e;
                }
            } else {
                BurpExtender.printError("[!] 请求发送失败");
                throw new Exception("请求发送失败，未收到响应");
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 发送请求时出错: " + e.getMessage());
            // 显示错误对话框
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(
                    this,
                    "发送请求失败: " + e.getMessage(),
                    "错误",
                    JOptionPane.ERROR_MESSAGE
                );
            });
        }
    }
} 