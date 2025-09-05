package oxff.top.ui.viewer;

import burp.BurpExtender;
import oxff.top.utils.TextLineNumber;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.Theme;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * HTTP查看器面板 - 实现HttpViewer接口，支持多种视图模式
 */
public class HttpViewerPanel extends JPanel implements HttpViewer {
    private static final long serialVersionUID = 1L;
    
    // 当前视图模式
    private ViewMode currentViewMode = ViewMode.PRETTY;
    
    // 是否可编辑
    private final boolean editable;
    
    // 各种显示组件
    private final RSyntaxTextArea prettyTextArea;
    private final JTextArea rawTextArea;
    private final JTextArea hexTextArea;
    
    // 当前显示的内容
    private byte[] currentData;
    
    // 切换模式的选项卡
    private final JTabbedPane modeTabbedPane;
    
    // 模式切换监听器
    private final List<ChangeListener> modeChangeListeners = new ArrayList<>();
    
    /**
     * 创建HTTP查看器面板
     * 
     * @param title 面板标题
     * @param editable 是否可编辑
     */
    public HttpViewerPanel(String title, boolean editable) {
        super(new BorderLayout());
        this.editable = editable;
        
        // 创建模式选择按钮组
        JPanel modePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        ButtonGroup modeGroup = new ButtonGroup();
        
        JToggleButton prettyButton = new JToggleButton(ViewMode.PRETTY.getDisplayName());
        JToggleButton rawButton = new JToggleButton(ViewMode.RAW.getDisplayName());
        JToggleButton hexButton = new JToggleButton(ViewMode.HEX.getDisplayName());
        
        // 设置按钮样式为扁平透明
        for (JToggleButton btn : new JToggleButton[]{prettyButton, rawButton, hexButton}) {
            btn.setFocusPainted(false);
            btn.setBorderPainted(true);
            btn.setContentAreaFilled(false);
            btn.setMargin(new Insets(2, 5, 2, 5));
            modeGroup.add(btn);
            modePanel.add(btn);
        }
        
        // 默认选择美化模式
        prettyButton.setSelected(true);
        
        // 创建带标题的面板
        JPanel titledPanel = new JPanel(new BorderLayout());
        JLabel titleLabel = new JLabel(title);
        titleLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        // 创建标题和模式切换面板
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.add(titleLabel, BorderLayout.WEST);
        headerPanel.add(modePanel, BorderLayout.EAST);
        
        titledPanel.add(headerPanel, BorderLayout.NORTH);
        
        // 创建各种模式的文本区域
        prettyTextArea = createPrettyTextArea();
        rawTextArea = createRawTextArea();
        hexTextArea = createHexTextArea();
        
        // 创建选项卡面板
        modeTabbedPane = new JTabbedPane(JTabbedPane.TOP, JTabbedPane.SCROLL_TAB_LAYOUT);
        modeTabbedPane.setTabPlacement(JTabbedPane.TOP);
        
        // 美化模式选项卡
        RTextScrollPane prettyScrollPane = new RTextScrollPane(prettyTextArea);
        prettyScrollPane.setLineNumbersEnabled(true);
        prettyScrollPane.getGutter().setBackground(new Color(245, 245, 245));
        prettyScrollPane.getGutter().setLineNumberColor(Color.GRAY);
        
        // 原始模式选项卡
        JScrollPane rawScrollPane = new JScrollPane(rawTextArea);
        TextLineNumber rawLineNumber = new TextLineNumber(rawTextArea);
        rawLineNumber.setCurrentLineForeground(new Color(44, 121, 217));
        rawLineNumber.setForeground(Color.GRAY);
        rawLineNumber.setBackground(new Color(245, 245, 245));
        rawScrollPane.setRowHeaderView(rawLineNumber);
        
        // Hex模式选项卡
        JScrollPane hexScrollPane = new JScrollPane(hexTextArea);
        
        // 添加选项卡
        modeTabbedPane.addTab(ViewMode.PRETTY.getDisplayName(), prettyScrollPane);
        modeTabbedPane.addTab(ViewMode.RAW.getDisplayName(), rawScrollPane);
        modeTabbedPane.addTab(ViewMode.HEX.getDisplayName(), hexScrollPane);
        
        // 隐藏选项卡标题
        modeTabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        modeTabbedPane.setVisible(true);
        
        // 添加选项卡切换监听器
        modeTabbedPane.addChangeListener(e -> {
            int selectedIndex = modeTabbedPane.getSelectedIndex();
            if (selectedIndex == 0) {
                prettyButton.setSelected(true);
                currentViewMode = ViewMode.PRETTY;
            } else if (selectedIndex == 1) {
                rawButton.setSelected(true);
                currentViewMode = ViewMode.RAW;
            } else if (selectedIndex == 2) {
                hexButton.setSelected(true);
                currentViewMode = ViewMode.HEX;
            }
            
            // 通知监听器
            notifyModeChangeListeners();
        });
        
        // 按钮点击事件
        prettyButton.addActionListener(e -> setViewMode(ViewMode.PRETTY));
        rawButton.addActionListener(e -> setViewMode(ViewMode.RAW));
        hexButton.addActionListener(e -> setViewMode(ViewMode.HEX));
        
        titledPanel.add(modeTabbedPane, BorderLayout.CENTER);
        
        // 添加到面板
        add(titledPanel, BorderLayout.CENTER);
    }
    
    /**
     * 创建美化模式文本区域
     */
    private RSyntaxTextArea createPrettyTextArea() {
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
        
        return textArea;
    }
    
    /**
     * 创建原始模式文本区域
     */
    private JTextArea createRawTextArea() {
        JTextArea textArea = new JTextArea();
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        textArea.setEditable(editable);
        textArea.setTabSize(4);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        
        return textArea;
    }
    
    /**
     * 创建十六进制模式文本区域
     */
    private JTextArea createHexTextArea() {
        JTextArea textArea = new JTextArea();
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        textArea.setEditable(false); // Hex模式通常不编辑
        textArea.setTabSize(4);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        
        return textArea;
    }
    
    /**
     * 添加模式切换监听器
     */
    public void addModeChangeListener(ChangeListener listener) {
        if (!modeChangeListeners.contains(listener)) {
            modeChangeListeners.add(listener);
        }
    }
    
    /**
     * 移除模式切换监听器
     */
    public void removeModeChangeListener(ChangeListener listener) {
        modeChangeListeners.remove(listener);
    }
    
    /**
     * 通知所有监听器
     */
    private void notifyModeChangeListeners() {
        ChangeEvent event = new ChangeEvent(this);
        for (ChangeListener listener : modeChangeListeners) {
            listener.stateChanged(event);
        }
    }
    
    @Override
    public void setViewMode(ViewMode mode) {
        if (mode == currentViewMode) {
            return;
        }
        
        currentViewMode = mode;
        
        // 更新选项卡选择
        switch (mode) {
            case PRETTY:
                modeTabbedPane.setSelectedIndex(0);
                break;
            case RAW:
                modeTabbedPane.setSelectedIndex(1);
                break;
            case HEX:
                modeTabbedPane.setSelectedIndex(2);
                break;
        }
        
        // 通知监听器
        notifyModeChangeListeners();
    }
    
    @Override
    public ViewMode getViewMode() {
        return currentViewMode;
    }
    
    @Override
    public void setData(byte[] data) {
        if (data == null) {
            clear();
            return;
        }
        
        currentData = data.clone();
        
        // 更新各种视图
        String text = new String(data);
        
        // 设置美化视图
        prettyTextArea.setText(text);
        prettyTextArea.setCaretPosition(0);
        
        // 尝试检测内容类型并设置语法高亮
        detectAndSetSyntaxStyle(text);
        
        // 设置原始视图
        rawTextArea.setText(text);
        rawTextArea.setCaretPosition(0);
        
        // 设置十六进制视图
        hexTextArea.setText(bytesToHexDump(data));
        hexTextArea.setCaretPosition(0);
    }
    
    @Override
    public void setText(String text) {
        if (text == null) {
            clear();
            return;
        }
        
        // 保存当前数据
        currentData = text.getBytes();
        
        // 更新各种视图
        prettyTextArea.setText(text);
        prettyTextArea.setCaretPosition(0);
        
        // 尝试检测内容类型并设置语法高亮
        detectAndSetSyntaxStyle(text);
        
        // 设置原始视图
        rawTextArea.setText(text);
        rawTextArea.setCaretPosition(0);
        
        // 设置十六进制视图
        hexTextArea.setText(bytesToHexDump(text.getBytes()));
        hexTextArea.setCaretPosition(0);
    }
    
    /**
     * 检测内容类型并设置语法高亮
     */
    private void detectAndSetSyntaxStyle(String text) {
        try {
            // 基本检测逻辑
            if (text.startsWith("{") || text.startsWith("[")) {
                // 可能是JSON
                prettyTextArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
            } else if (text.contains("<html") || text.contains("<!DOCTYPE")) {
                // 可能是HTML
                prettyTextArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML);
            } else if (text.contains("<?xml")) {
                // 可能是XML
                prettyTextArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_XML);
            } else if (text.matches("(?s)^HTTP/[0-9.]+\\s+\\d+.*")) {
                // 可能是HTTP响应
                prettyTextArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML);
            } else if (text.matches("(?s)^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\\s+.*")) {
                // 可能是HTTP请求
                prettyTextArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML);
            } else {
                // 默认为普通文本
                prettyTextArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
            }
        } catch (Exception e) {
            // 出错时使用默认样式
            prettyTextArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
        }
    }
    
    /**
     * 将字节数组转换为十六进制转储格式
     * 例如:
     * 00000000: 4745 5420 2f20 4854 5450 2f31 2e31 0d0a  GET / HTTP/1.1..
     */
    private String bytesToHexDump(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        StringBuilder asciiLine = new StringBuilder();
        
        // 每16个字节一行
        for (int i = 0; i < bytes.length; i++) {
            // 每行开头显示偏移量
            if (i % 16 == 0) {
                if (i > 0) {
                    // 添加前一行的ASCII表示
                    result.append("  ").append(asciiLine).append("\n");
                    asciiLine = new StringBuilder();
                }
                result.append(String.format("%08x: ", i));
            }
            
            // 添加十六进制值
            result.append(String.format("%02x", bytes[i] & 0xff));
            
            // 每两个字节添加空格
            if (i % 2 == 1) {
                result.append(" ");
            }
            
            // 添加ASCII表示
            if (bytes[i] >= 32 && bytes[i] < 127) {
                asciiLine.append((char) bytes[i]);
            } else {
                asciiLine.append(".");
            }
        }
        
        // 补全最后一行
        int remaining = 16 - (bytes.length % 16);
        if (remaining < 16) {
            for (int i = 0; i < remaining; i++) {
                result.append("  ");
                if (i % 2 == 1) {
                    result.append(" ");
                }
            }
        }
        
        // 添加最后一行的ASCII表示
        result.append("  ").append(asciiLine);
        
        return result.toString();
    }
    
    @Override
    public String getText() {
        switch (currentViewMode) {
            case PRETTY:
                return prettyTextArea.getText();
            case RAW:
                return rawTextArea.getText();
            case HEX:
                // Hex视图不直接返回文本内容，而是返回原始数据的字符串表示
                return new String(currentData);
            default:
                return "";
        }
    }
    
    @Override
    public void clear() {
        prettyTextArea.setText("");
        rawTextArea.setText("");
        hexTextArea.setText("");
        currentData = null;
    }
    
    /**
     * 配置右键菜单
     */
    public void setupContextMenu() {
        // 为不同视图配置右键菜单
        JPopupMenu prettyPopup = createContextMenu(prettyTextArea);
        prettyTextArea.setPopupMenu(prettyPopup);
        
        JPopupMenu rawPopup = createContextMenu(rawTextArea);
        rawTextArea.setComponentPopupMenu(rawPopup);
        
        JPopupMenu hexPopup = createContextMenu(hexTextArea);
        hexTextArea.setComponentPopupMenu(hexPopup);
    }
    
    /**
     * 创建上下文菜单
     */
    private JPopupMenu createContextMenu(JTextComponent textComponent) {
        JPopupMenu popup = new JPopupMenu();
        
        // 添加基本编辑选项
        JMenuItem copyItem = new JMenuItem("复制");
        copyItem.addActionListener(e -> textComponent.copy());
        popup.add(copyItem);
        
        if (editable && textComponent != hexTextArea) {
            JMenuItem pasteItem = new JMenuItem("粘贴");
            pasteItem.addActionListener(e -> textComponent.paste());
            popup.add(pasteItem);
            
            JMenuItem cutItem = new JMenuItem("剪切");
            cutItem.addActionListener(e -> textComponent.cut());
            popup.add(cutItem);
        }
        
        popup.addSeparator();
        
        JMenuItem selectAllItem = new JMenuItem("全选");
        selectAllItem.addActionListener(e -> textComponent.selectAll());
        popup.add(selectAllItem);
        
        if (editable && textComponent != hexTextArea) {
            JMenuItem clearItem = new JMenuItem("清空");
            clearItem.addActionListener(e -> textComponent.setText(""));
            popup.add(clearItem);
        }
        
        return popup;
    }
} 