package burp.ui;

import burp.BurpExtender;
import org.fife.ui.rsyntaxtextarea.*;
import org.fife.ui.rtextarea.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.ActionListener;
import java.io.IOException;

/**
 * HTTP编辑器面板 - 使用RSyntaxTextArea提供语法高亮
 * 可以在未来版本中替代RequestPanel和ResponsePanel中的JTextArea
 */
public class HttpEditorPanel extends JPanel {
    private static final long serialVersionUID = 1L;
    
    private final RSyntaxTextArea textArea;
    private final RTextScrollPane scrollPane;
    private final boolean editable;
    
    /**
     * 创建HTTP编辑器面板
     * 
     * @param title 面板标题
     * @param editable 是否可编辑
     */
    public HttpEditorPanel(String title, boolean editable) {
        super(new BorderLayout());
        this.editable = editable;
        
        // 创建语法高亮文本区域
        textArea = createTextArea();
        
        // 创建滚动面板
        scrollPane = new RTextScrollPane(textArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder(title));
        scrollPane.setLineNumbersEnabled(true);
        
        // 设置行号区域颜色
        scrollPane.getGutter().setBackground(new Color(245, 245, 245));
        scrollPane.getGutter().setLineNumberColor(Color.GRAY);
        
        // 添加到面板
        add(scrollPane, BorderLayout.CENTER);
    }
    
    /**
     * 创建语法高亮文本区域
     */
    private RSyntaxTextArea createTextArea() {
        RSyntaxTextArea textArea = new RSyntaxTextArea();
        
        // 基本设置
        textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML);
        textArea.setCodeFoldingEnabled(true);
        textArea.setAntiAliasingEnabled(true);
        textArea.setEditable(editable);
        textArea.setTabSize(4);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        
        // 设置自动缩进
        textArea.setAutoIndentEnabled(true);
        textArea.setBracketMatchingEnabled(true);
        
        // 设置主题
        try {
            Theme theme = Theme.load(
                getClass().getResourceAsStream("/org/fife/ui/rsyntaxtextarea/themes/default.xml")
            );
            theme.apply(textArea);
        } catch (IOException e) {
            BurpExtender.callbacks.printError("[!] 无法加载编辑器主题: " + e.getMessage());
        }
        
        // 添加按键监听器，用于快捷键和缩进处理
        if (editable) {
            textArea.addKeyListener(new KeyAdapter() {
                @Override
                public void keyPressed(KeyEvent e) {
                    // 处理特殊键盘事件
                    if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                        handleEnterKey(e);
                    }
                }
            });
        }
        
        // 添加右键菜单
        configurePopupMenu(textArea);
        
        return textArea;
    }
    
    /**
     * 处理回车键，添加自定义缩进逻辑
     */
    private void handleEnterKey(KeyEvent e) {
        if (!e.isControlDown()) { // 避免和Ctrl+Enter冲突
            // 让RSyntaxTextArea处理基本的缩进
            // 这里可以添加额外的自定义缩进逻辑
        }
    }
    
    /**
     * 配置右键菜单
     */
    private void configurePopupMenu(RSyntaxTextArea textArea) {
        JPopupMenu popup = new JPopupMenu();
        
        // 添加基本编辑选项
        popup.add(createMenuItem("复制", null, e -> textArea.copy()));
        
        if (editable) {
            popup.add(createMenuItem("粘贴", null, e -> textArea.paste()));
            popup.add(createMenuItem("剪切", null, e -> textArea.cut()));
        }
        
        popup.addSeparator();
        
        popup.add(createMenuItem("全选", null, e -> textArea.selectAll()));
        
        if (editable) {
            popup.add(createMenuItem("清空", null, e -> textArea.setText("")));
        }
        
        // 设置右键菜单
        textArea.setPopupMenu(popup);
    }
    
    /**
     * 创建具有图标的菜单项
     * 
     * @param text 菜单文本
     * @param icon 菜单图标
     * @param action 点击动作
     * @return 菜单项
     */
    private JMenuItem createMenuItem(String text, Icon icon, ActionListener action) {
        JMenuItem menuItem = new JMenuItem(text);
        if (icon != null) {
            menuItem.setIcon(icon);
        }
        menuItem.addActionListener(action);
        return menuItem;
    }
    
    /**
     * 设置文本内容
     */
    public void setText(String text) {
        textArea.setText(text);
        textArea.setCaretPosition(0);
        
        // 尝试检测内容类型并设置适当的语法高亮
        detectAndSetSyntaxStyle(text);
    }
    
    /**
     * 设置内容(字节数组)
     */
    public void setData(byte[] data) {
        if (data != null) {
            setText(new String(data));
        } else {
            textArea.setText("");
        }
    }
    
    /**
     * 检测内容类型并设置语法高亮
     */
    private void detectAndSetSyntaxStyle(String text) {
        try {
            // 基本检测逻辑
            if (text.startsWith("{") || text.startsWith("[")) {
                // 可能是JSON
                textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
            } else if (text.contains("<html") || text.contains("<!DOCTYPE")) {
                // 可能是HTML
                textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML);
            } else if (text.contains("<?xml")) {
                // 可能是XML
                textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_XML);
            } else if (text.matches("(?s)^HTTP/[0-9.]+\\s+\\d+.*")) {
                // 可能是HTTP响应
                textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML);
            } else if (text.matches("(?s)^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\\s+.*")) {
                // 可能是HTTP请求
                textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML);
            } else {
                // 默认为普通文本
                textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
            }
        } catch (Exception e) {
            // 出错时使用默认样式
            textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
        }
    }
    
    /**
     * 获取文本内容
     */
    public String getText() {
        return textArea.getText();
    }
    
    /**
     * 获取文本区域组件
     */
    public RSyntaxTextArea getTextArea() {
        return textArea;
    }
    
    /**
     * 清空内容
     */
    public void clear() {
        textArea.setText("");
    }
} 