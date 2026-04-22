package oxff.top.ui;

import burp.BurpExtender;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.responses.HttpResponse;
import oxff.top.utils.TextLineNumber;
import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * 响应面板组件 - 负责显示HTTP响应信息
 */
public class ResponsePanel extends JPanel {
    private static final long serialVersionUID = 1L;
    
    // 基本组件
    private final JTextArea responseTextArea;
    
    // 响应信息字段
    private JTextField statusCodeField;     // 状态码
    private JTextField contentTypeField;    // 内容类型
    private JTextField responseLengthField; // 响应长度
    
    /**
     * 创建响应面板
     */
    public ResponsePanel() {
        super(new BorderLayout());
        
        // 创建响应文本区域
        responseTextArea = new JTextArea();
        responseTextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        responseTextArea.setEditable(false);
        responseTextArea.setTabSize(4);
        responseTextArea.setLineWrap(true);
        responseTextArea.setWrapStyleWord(true);
        
        // 创建右键菜单
        JPopupMenu responsePopupMenu = createContextMenu();
        responseTextArea.setComponentPopupMenu(responsePopupMenu);
        
        // 创建响应信息面板
        JPanel responseInfoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        // 初始化响应信息字段
        statusCodeField = new JTextField(4);
        statusCodeField.setEditable(false);
        
        contentTypeField = new JTextField(20);
        contentTypeField.setEditable(false);
        
        responseLengthField = new JTextField(8);
        responseLengthField.setEditable(false);
        
        // 添加字段到面板
        responseInfoPanel.add(new JLabel("状态码:"));
        responseInfoPanel.add(statusCodeField);
        responseInfoPanel.add(new JLabel("内容类型:"));
        responseInfoPanel.add(contentTypeField);
        responseInfoPanel.add(new JLabel("响应长度:"));
        responseInfoPanel.add(responseLengthField);
        
        // 创建滚动面板
        JScrollPane responseScrollPane = new JScrollPane(responseTextArea);
        responseScrollPane.setBorder(BorderFactory.createTitledBorder("响应"));
        
        // 添加行号
        TextLineNumber responseLineNumber = new TextLineNumber(responseTextArea);
        responseLineNumber.setCurrentLineForeground(new Color(44, 121, 217)); // 蓝色高亮当前行
        responseLineNumber.setForeground(Color.GRAY);
        responseLineNumber.setBackground(new Color(245, 245, 245)); // 浅灰色背景
        responseLineNumber.setFont(new Font("Monospaced", Font.PLAIN, 12));
        responseScrollPane.setRowHeaderView(responseLineNumber);
        
        // 添加到主面板
        add(responseInfoPanel, BorderLayout.NORTH);
        add(responseScrollPane, BorderLayout.CENTER);
    }
    
    /**
     * 创建右键菜单
     */
    private JPopupMenu createContextMenu() {
        JPopupMenu popupMenu = new JPopupMenu();
        
        JMenuItem copyItem = new JMenuItem("复制");
        copyItem.addActionListener(e -> responseTextArea.copy());
        
        JMenuItem selectAllItem = new JMenuItem("全选");
        selectAllItem.addActionListener(e -> responseTextArea.selectAll());
        
        JMenuItem clearItem = new JMenuItem("清空");
        clearItem.addActionListener(e -> responseTextArea.setText(""));
        
        JMenuItem saveItem = new JMenuItem("另存为文件");
        saveItem.addActionListener(e -> saveResponseToFile());
        
        popupMenu.add(copyItem);
        popupMenu.addSeparator();
        popupMenu.add(selectAllItem);
        popupMenu.add(clearItem);
        popupMenu.addSeparator();
        popupMenu.add(saveItem);
        
        return popupMenu;
    }
    
    /**
     * 将响应内容保存到文件
     */
    private void saveResponseToFile() {
        String responseText = responseTextArea.getText();
        if (responseText == null || responseText.isEmpty()) {
            JOptionPane.showMessageDialog(this, "没有响应内容可保存", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("保存响应内容");
        
        int userSelection = fileChooser.showSaveDialog(this);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();
            
            try (FileOutputStream fos = new FileOutputStream(fileToSave)) {
                fos.write(responseText.getBytes());
                JOptionPane.showMessageDialog(this, 
                    "文件已保存到: " + fileToSave.getAbsolutePath(), 
                    "保存成功", 
                    JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, 
                    "保存文件失败: " + ex.getMessage(), 
                    "错误", 
                    JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    /**
     * 设置响应文本内容
     */
    public void setResponseText(String text) {
        responseTextArea.setText(text);
        responseTextArea.setCaretPosition(0);
    }
    
    /**
     * 设置响应内容(字节数组)
     */
    public void setResponseData(byte[] response) {
        if (response != null) {
            setResponseText(new String(response));
        } else {
            responseTextArea.setText("");
        }
    }
    
    /**
     * 清空响应内容
     */
    public void clear() {
        responseTextArea.setText("");
        statusCodeField.setText("");
        contentTypeField.setText("");
        responseLengthField.setText("");
    }
    
    /**
     * 获取响应文本
     */
    public String getResponseText() {
        return responseTextArea.getText();
    }
    
    /**
     * 获取响应文本组件
     */
    public JTextArea getResponseTextArea() {
        return responseTextArea;
    }
    
    /**
     * 设置HTTP响应
     */
    public void setResponse(byte[] response) {
        if (response == null || response.length == 0) {
            BurpExtender.printError("[!] 设置响应失败：响应为空");
            return;
        }
        
        try {
            // 先清空已有内容
            clear();
            
            // 设置响应内容到文本区域
            setResponseData(response);
            
            // 使用 Montoya API 分析响应信息
            HttpResponse httpResponse = HttpResponse.httpResponse(ByteArray.byteArray(response));

            // 显示状态码
            statusCodeField.setText(String.valueOf(httpResponse.statusCode()));

            // 设置Content-Type
            String contentType = httpResponse.headerValue("Content-Type");
            contentTypeField.setText(contentType);
            
            // 设置响应长度
            responseLengthField.setText(String.valueOf(response.length));
            
            BurpExtender.printOutput("[+] 响应已加载: HTTP " + httpResponse.statusCode() + 
                             " (" + response.length + " 字节)");
        } catch (Exception e) {
            BurpExtender.printError("[!] 设置响应时出错: " + e.getMessage());
        }
    }
} 
