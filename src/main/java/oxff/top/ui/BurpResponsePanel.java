package oxff.top.ui;

import burp.BurpExtender;
import burp.IMessageEditor;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * 基于Burp原生编辑器的响应面板
 */
public class BurpResponsePanel extends JPanel {
    private static final long serialVersionUID = 1L;
    
    private final IMessageEditor responseEditor;
    private byte[] currentResponse;
    
    /**
     * 创建响应面板
     */
    public BurpResponsePanel() {
        super(new BorderLayout());
        
        // 创建Burp原生响应编辑器
        responseEditor = BurpExtender.callbacks.createMessageEditor(null, false);
        
        // 创建保存按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveButton = new JButton("保存响应");
        saveButton.addActionListener(e -> saveResponseToFile());
        buttonPanel.add(saveButton);
        
        // 添加到面板
        add(buttonPanel, BorderLayout.NORTH);
        add(responseEditor.getComponent(), BorderLayout.CENTER);
    }
    
    /**
     * 将响应内容保存到文件
     */
    private void saveResponseToFile() {
        if (currentResponse == null || currentResponse.length == 0) {
            JOptionPane.showMessageDialog(this, 
                "没有响应内容可保存", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("保存响应内容");
        
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            
            try (FileOutputStream fos = new FileOutputStream(selectedFile)) {
                fos.write(currentResponse);
                JOptionPane.showMessageDialog(this, 
                    "保存成功: " + selectedFile.getAbsolutePath(), 
                    "保存完成", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, 
                    "保存失败: " + ex.getMessage(), 
                    "错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    /**
     * 设置响应数据
     * 
     * @param response 响应字节数组
     */
    public void setResponse(byte[] response) {
        if (response != null) {
            responseEditor.setMessage(response, false);
            currentResponse = response.clone();
        }
    }
    
    /**
     * 获取响应数据
     * 
     * @return 响应字节数组
     */
    public byte[] getResponse() {
        return responseEditor.getMessage();
    }
    
    /**
     * 获取原生响应编辑器
     * 
     * @return Burp的IMessageEditor接口
     */
    public IMessageEditor getResponseEditor() {
        return responseEditor;
    }
    
    /**
     * 清空响应内容
     */
    public void clear() {
        responseEditor.setMessage(new byte[0], false);
        currentResponse = null;
    }
} 