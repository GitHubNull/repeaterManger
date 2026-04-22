package oxff.top.ui.editor;

import burp.BurpExtender;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;

/**
 * 基于Burp原生编辑器的请求面板（使用Montoya SDK HttpRequestEditor）
 */
public class BurpRequestPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private final HttpRequestEditor requestEditor;
    private final JButton sendButton;
    private final JSpinner timeoutSpinner;

    /**
     * 创建请求面板
     *
     * @param api MontoyaApi实例
     */
    public BurpRequestPanel(MontoyaApi api) {
        super(new BorderLayout());

        // 创建Montoya请求编辑器
        requestEditor = api.userInterface().createHttpRequestEditor();

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
        add(requestEditor.uiComponent(), BorderLayout.CENTER);

        // 添加快捷键支持
        registerKeyboardShortcuts();
    }

    /**
     * 注册键盘快捷键
     */
    private void registerKeyboardShortcuts() {
        InputMap inputMap = getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        ActionMap actionMap = getActionMap();

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
     */
    public void setSendButtonListener(ActionListener listener) {
        for (ActionListener al : sendButton.getActionListeners()) {
            sendButton.removeActionListener(al);
        }
        sendButton.addActionListener(listener);
    }

    /**
     * 获取请求数据
     */
    public byte[] getRequest() {
        return requestEditor.getRequest().toByteArray().getBytes();
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
            byte[] fixedRequest = validateAndFixRequest(request);
            requestEditor.setRequest(HttpRequest.httpRequest(ByteArray.byteArray(fixedRequest)));
            BurpExtender.printOutput("[*] 已加载请求数据到Burp编辑器，大小: " + request.length + " 字节");
        } catch (Exception e) {
            BurpExtender.printError("[!] 设置请求到Burp编辑器失败: " + e.getMessage());

            try {
                String basicRequest = createBasicHttpRequest(request);
                requestEditor.setRequest(HttpRequest.httpRequest(ByteArray.byteArray(basicRequest.getBytes())));
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

        String requestStr = new String(request, java.nio.charset.StandardCharsets.ISO_8859_1);

        boolean isValidHttp = false;
        String[] lines = requestStr.split("\r\n|\n", 2);
        if (lines.length > 0) {
            String firstLine = lines[0].trim();
            isValidHttp = firstLine.matches("(?i)(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE)\\s+.+\\s+HTTP/.+");
        }

        if (isValidHttp) {
            return request;
        }

        BurpExtender.printOutput("[*] 请求数据格式无效，尝试修复...");

        if (!requestStr.contains("HTTP/1.") && !requestStr.contains("Host:")) {
            String method = "POST";
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

        boolean containsBinary = false;
        for (byte b : request) {
            if (b == 0 || (b < 32 && b != '\r' && b != '\n' && b != '\t')) {
                containsBinary = true;
                break;
            }
        }

        if (containsBinary) {
            StringBuilder fixedRequest = new StringBuilder();
            fixedRequest.append("POST / HTTP/1.1\r\n");
            fixedRequest.append("Host: example.com\r\n");
            fixedRequest.append("Content-Type: application/octet-stream\r\n");
            fixedRequest.append("Content-Length: ").append(request.length).append("\r\n");
            fixedRequest.append("\r\n");

            byte[] header = fixedRequest.toString().getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
            byte[] fixed = new byte[header.length + request.length];
            System.arraycopy(header, 0, fixed, 0, header.length);
            System.arraycopy(request, 0, fixed, header.length, request.length);

            BurpExtender.printOutput("[+] 已创建包含二进制数据的HTTP请求");
            return fixed;
        }

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

        if (originalData != null && originalData.length > 0) {
            sb.append("<!-- 原始数据长度: ").append(originalData.length).append(" 字节 -->\r\n");
        }

        return sb.toString();
    }

    /**
     * 获取超时设置(秒)
     */
    public int getTimeout() {
        return (Integer) timeoutSpinner.getValue();
    }

    /**
     * 获取请求编辑器
     */
    public HttpRequestEditor getRequestEditor() {
        return requestEditor;
    }

    /**
     * 清空请求内容
     */
    public void clear() {
        requestEditor.setRequest(HttpRequest.httpRequest());
    }
}
