package burp;

import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;

/**
 * Burp扩展入口点 - 负责注册插件并初始化所需组件
 */
public class BurpExtender implements IBurpExtender, IContextMenuFactory {
    
    // 公共变量，供插件其他部分使用
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    
    // 日志输出流
    private static PrintWriter stdout;
    private static PrintWriter stderr;
    
    // 主UI组件
    private static EnhancedRepeaterUI repeaterUI;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 保存回调对象
        BurpExtender.callbacks = callbacks;
        BurpExtender.helpers = callbacks.getHelpers();
        
        // 设置插件名称
        callbacks.setExtensionName("增强型Repeater");
        
        try {
            // 初始化带有正确编码的输出流
            initializeOutputStreams(callbacks);
            
            // 创建UI和功能组件
            repeaterUI = new EnhancedRepeaterUI();
            
            // 将UI组件添加到Burp的UI
            callbacks.addSuiteTab(repeaterUI);
            
            // 注册上下文菜单工厂
            callbacks.registerContextMenuFactory(this);
            
            // 使用编码后的输出流打印信息
            stdout.println("[+] 增强型Repeater 插件加载成功");
        } catch (Exception e) {
            // 使用编码后的错误流输出异常
            if (stderr != null) {
                stderr.println("[!] 插件加载失败: " + e.getMessage());
                e.printStackTrace(stderr);
            } else {
                callbacks.printError("[!] 插件加载失败: " + e.getMessage());
                e.printStackTrace(new PrintWriter(callbacks.getStderr()));
            }
        }
    }
    
    /**
     * 初始化带有正确字符编码的输出流
     */
    private void initializeOutputStreams(IBurpExtenderCallbacks callbacks) {
        try {
            // 创建可以自动刷新的PrintWriter，并指定UTF-8编码
            // Java 10+可以直接使用PrintWriter(OutputStream, boolean, Charset)构造函数
            // 对于较早版本，我们需要使用中间的OutputStreamWriter
            OutputStreamWriter outWriter = new OutputStreamWriter(callbacks.getStdout(), "UTF-8");
            OutputStreamWriter errWriter = new OutputStreamWriter(callbacks.getStderr(), "UTF-8");
            
            // 使用自动刷新模式创建PrintWriter
            stdout = new PrintWriter(outWriter, true);
            stderr = new PrintWriter(errWriter, true);
        } catch (UnsupportedEncodingException e) {
            // UTF-8总是受支持的，这个异常不应该发生
            callbacks.printError("初始化自定义输出流失败: " + e.getMessage());
            
            // 回退到默认输出流
            stdout = new PrintWriter(callbacks.getStdout(), true);
            stderr = new PrintWriter(callbacks.getStderr(), true);
        }
    }
    
    /**
     * 输出日志到标准输出
     * 
     * @param message 日志消息
     */
    public static void printOutput(String message) {
        if (stdout != null) {
            stdout.println(message);
        } else if (callbacks != null) {
            callbacks.printOutput(message);
        }
    }
    
    /**
     * 输出错误日志
     * 
     * @param message 错误消息
     */
    public static void printError(String message) {
        if (stderr != null) {
            stderr.println(message);
        } else if (callbacks != null) {
            callbacks.printError(message);
        }
    }
    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        
        // 检查是否有请求被选中
        IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
        if (selectedMessages != null && selectedMessages.length > 0) {
            final IHttpRequestResponse requestResponse = selectedMessages[0];
            
            if (requestResponse != null && requestResponse.getRequest() != null) {
                // 创建菜单项
                JMenuItem sendToEnhancedRepeater = new JMenuItem("发送到增强型Repeater");
                sendToEnhancedRepeater.addActionListener(e -> {
                    // 调用EnhancedRepeaterUI的方法处理所选请求
                    if (repeaterUI != null) {
                        repeaterUI.setRequest(requestResponse);
                        
                        // 在UI线程中执行，提示用户请求已发送
                        SwingUtilities.invokeLater(() -> {
                            // 使用自定义的日志输出方法
                            printOutput("[+] 已将请求发送到增强型Repeater，请切换到相应标签页查看");
                            
                            // 注意: Burp API不提供直接切换标签页的方法
                            // 需要用户手动切换到"增强型Repeater"标签页
                        });
                    }
                });
                
                menuItems.add(sendToEnhancedRepeater);
            }
        }
        
        return menuItems;
    }
}