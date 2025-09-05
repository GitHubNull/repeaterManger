package oxff.top.ui;

import oxff.top.ui.viewer.HttpViewerPanel;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * 增强型响应面板 - 支持美化、原始和十六进制视图模式
 */
public class EnhancedResponsePanel extends JPanel {
    private static final long serialVersionUID = 1L;
    
    private final HttpViewerPanel responseViewer;
    private byte[] currentResponse;
    
    /**
     * 创建增强型响应面板
     */
    public EnhancedResponsePanel() {
        super(new BorderLayout());
        
        // 创建响应查看器
        responseViewer = new HttpViewerPanel("响应", false);
        responseViewer.setupContextMenu();
        
        // 添加额外的右键菜单选项
        addCustomContextMenu();
        
        // 添加到面板
        add(responseViewer, BorderLayout.CENTER);
    }
    
    /**
     * 添加自定义上下文菜单
     */
    private void addCustomContextMenu() {
        JPopupMenu popupMenu = new JPopupMenu();
        
        JMenuItem saveItem = new JMenuItem("另存为文件");
        saveItem.addActionListener(e -> saveResponseToFile());
        
        // 使用一种更干净的方式获取和修改现有上下文菜单
        // 这只是一个简化版本，实际实现需要获取和扩展现有菜单
        popupMenu.add(saveItem);
    }
    
    /**
     * 将响应内容保存到文件
     */
    private void saveResponseToFile() {
        if (currentResponse == null) {
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
     * 设置响应文本
     * 
     * @param text 响应文本
     */
    public void setResponseText(String text) {
        responseViewer.setText(text);
        currentResponse = text.getBytes();
    }
    
    /**
     * 设置响应数据
     * 
     * @param data 响应字节数组
     */
    public void setResponseData(byte[] data) {
        if (data != null) {
            responseViewer.setData(data);
            currentResponse = data.clone();
        }
    }
    
    /**
     * 获取响应文本
     * 
     * @return 响应文本
     */
    public String getResponseText() {
        return responseViewer.getText();
    }
    
    /**
     * 获取响应查看器组件
     * 
     * @return HttpViewerPanel实例
     */
    public HttpViewerPanel getResponseViewer() {
        return responseViewer;
    }
    
    /**
     * 清空响应内容
     */
    public void clear() {
        responseViewer.clear();
        currentResponse = null;
    }
} 