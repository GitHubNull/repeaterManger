package oxff.top.ui;

import burp.BurpExtender;
import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.nio.charset.StandardCharsets;

/**
 * HTTP数据查看器面板 - 用于查看和编辑HTTP请求/响应
 */
public class HttpViewerPanel extends JPanel {
    
    private static final long serialVersionUID = 1L;
    
    // 界面组件
    private final JTextComponent textEditor;
    
    // 数据
    private byte[] data;
    
    // 当前视图模式
    private Mode currentMode = Mode.TEXT;
    
    /**
     * 视图模式枚举
     */
    public enum Mode {
        TEXT,   // 文本视图
        HEX     // 十六进制视图
    }
    
    /**
     * 创建HTTP查看器面板
     */
    public HttpViewerPanel(JTextComponent editor) {
        super(new BorderLayout());
        this.textEditor = editor;
    }
    
    /**
     * 设置数据
     */
    public void setData(byte[] data) {
        this.data = data;
        
        // 根据当前模式显示数据
        if (currentMode == Mode.TEXT) {
            showRawData();
        } else {
            showHexView();
        }
    }
    
    /**
     * 设置当前视图模式
     */
    public void setMode(Mode mode) {
        this.currentMode = mode;
    }
    
    /**
     * 获取当前数据
     */
    public byte[] getData() {
        return this.data;
    }
    
    /**
     * 查看请求/响应的原始数据
     */
    private void showRawData() {
        if (this.data == null || this.data.length == 0) {
            BurpExtender.printError("[!] 没有数据可显示");
            return;
        }
        
        // 将字节转换为字符串
        String rawText = new String(data, StandardCharsets.UTF_8);
        
        // 设置到编辑器
        textEditor.setText(rawText);
        
        // 将模式设置为文本
        setMode(Mode.TEXT);
        
        BurpExtender.printOutput("[*] 已切换到原始文本视图");
    }
    
    /**
     * 查看十六进制
     */
    private void showHexView() {
        if (data == null || data.length == 0) {
            BurpExtender.printError("[!] 没有数据可显示");
            return;
        }
        
        // 从 byte[] 创建十六进制文本
        StringBuilder hexText = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            if (i > 0 && i % 16 == 0) {
                hexText.append("\n");
            } else if (i > 0) {
                hexText.append(" ");
            }
            hexText.append(String.format("%02X", data[i] & 0xFF));
        }
        
        // 设置到编辑器
        textEditor.setText(hexText.toString());
        
        // 将模式设置为十六进制
        setMode(Mode.HEX);
        
        BurpExtender.printOutput("[*] 已切换到十六进制视图");
    }
} 