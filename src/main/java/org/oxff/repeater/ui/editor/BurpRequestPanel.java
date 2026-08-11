package org.oxff.repeater.ui.editor;

import org.oxff.repeater.i18n.I18nManager;
import org.oxff.repeater.logging.LogManager;
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

    // 需要在语言切换时刷新的组件
    private JButton newRequestButton;
    private JButton clearButton;
    private JLabel timeoutLabel;

    // 回调函数
    private Runnable onNewRequest;
    private Runnable onClear;

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

        // 新建请求按钮
        newRequestButton = new JButton(I18nManager.tr("burp.request.new"));
        newRequestButton.setToolTipText(I18nManager.tr("burp.request.new.tooltip"));
        newRequestButton.addActionListener(e -> {
            if (onNewRequest != null) {
                onNewRequest.run();
            }
        });
        controlPanel.add(newRequestButton);

        // 清空按钮
        clearButton = new JButton(I18nManager.tr("burp.request.clear"));
        clearButton.setToolTipText(I18nManager.tr("burp.request.clear.tooltip"));
        clearButton.addActionListener(e -> {
            if (onClear != null) {
                onClear.run();
            }
        });
        controlPanel.add(clearButton);

        // 分隔符
        controlPanel.add(new JSeparator(SwingConstants.VERTICAL));

        // 超时设置
        timeoutLabel = new JLabel(I18nManager.tr("burp.request.timeout"));
        timeoutSpinner = new JSpinner(new SpinnerNumberModel(30, 0, 60, 1));
        timeoutSpinner.setPreferredSize(new Dimension(60, 25));
        controlPanel.add(timeoutLabel);
        controlPanel.add(timeoutSpinner);

        // 发送按钮
        sendButton = new JButton(I18nManager.tr("burp.request.send"));
        sendButton.setToolTipText(I18nManager.tr("burp.request.send.tooltip"));
        controlPanel.add(sendButton);

        // 添加到面板
        add(controlPanel, BorderLayout.NORTH);
        add(requestEditor.uiComponent(), BorderLayout.CENTER);

        // 添加快捷键支持
        registerKeyboardShortcuts();

        // 注册语言变更监听
        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);
    }

    /**
     * 语言变更时刷新文本
     */
    private void refreshTexts() {
        newRequestButton.setText(I18nManager.tr("burp.request.new"));
        newRequestButton.setToolTipText(I18nManager.tr("burp.request.new.tooltip"));
        clearButton.setText(I18nManager.tr("burp.request.clear"));
        clearButton.setToolTipText(I18nManager.tr("burp.request.clear.tooltip"));
        timeoutLabel.setText(I18nManager.tr("burp.request.timeout"));
        sendButton.setText(I18nManager.tr("burp.request.send"));
        sendButton.setToolTipText(I18nManager.tr("burp.request.send.tooltip"));
        revalidate();
        repaint();
    }

    /**
     * 设置新建请求回调
     */
    public void setOnNewRequest(Runnable callback) {
        this.onNewRequest = callback;
    }

    /**
     * 设置清空回调
     */
    public void setOnClear(Runnable callback) {
        this.onClear = callback;
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
            LogManager.getInstance().printError(I18nManager.tr("burp.request.set.null"));
            return;
        }

        try {
            byte[] fixedRequest = validateAndFixRequest(request);
            requestEditor.setRequest(HttpRequest.httpRequest(ByteArray.byteArray(fixedRequest)));
            LogManager.getInstance().printOutput(I18nManager.tr("burp.request.loaded", request.length));
        } catch (Exception e) {
            LogManager.getInstance().printError(I18nManager.tr("burp.request.set.failed", e.getMessage()));

            try {
                String basicRequest = createBasicHttpRequest(request);
                requestEditor.setRequest(HttpRequest.httpRequest(ByteArray.byteArray(basicRequest.getBytes())));
                LogManager.getInstance().printOutput(I18nManager.tr("burp.request.basic.created"));
            } catch (Exception ex) {
                LogManager.getInstance().printError(I18nManager.tr("burp.request.basic.failed", ex.getMessage()));
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

        LogManager.getInstance().printOutput(I18nManager.tr("burp.request.fixing"));

        if (!requestStr.contains("HTTP/1.") && !requestStr.contains("Host:")) {
            String method = "POST";
            StringBuilder fixedRequest = new StringBuilder();
            fixedRequest.append(method).append(" / HTTP/1.1\r\n");
            fixedRequest.append("Host: example.com\r\n");
            fixedRequest.append("Content-Type: application/x-www-form-urlencoded\r\n");
            fixedRequest.append("Content-Length: ").append(request.length).append("\r\n");
            fixedRequest.append("\r\n");
            fixedRequest.append(requestStr);

            LogManager.getInstance().printOutput(I18nManager.tr("burp.request.header.added"));
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

            LogManager.getInstance().printOutput(I18nManager.tr("burp.request.binary.created"));
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
            sb.append(I18nManager.tr("burp.request.originalLength", originalData.length)).append("\r\n");
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
