package burp;

import oxff.top.EnhancedRepeaterUI;
import oxff.top.controller.PopMenu;

import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import javax.swing.SwingUtilities;

/**
 * Burp扩展入口点 - 负责注册插件并初始化所需组件
 */
public class BurpExtender implements IBurpExtender {
    
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
            
            // 测试数据库连接和持久化
            stdout.println("[*] 正在测试数据库连接和持久化...");
            oxff.top.db.DatabaseManager dbManager = oxff.top.db.DatabaseManager.getInstance();
            
            // 确保数据库初始化
            if (dbManager.initialize()) {
                stdout.println("[+] 数据库初始化成功");
                
                // 测试写入示例数据
                dbManager.testDatabaseWithSampleData();
                stdout.println("[+] 数据库测试完成");
                
                // 检查数据库状态
                dbManager.checkDatabaseStatus();
            } else {
                stdout.println("[!] 数据库初始化失败");
            }
            
            // 创建UI和功能组件
            repeaterUI = new EnhancedRepeaterUI();
            
            // 将UI组件添加到Burp的UI
            callbacks.addSuiteTab(repeaterUI);
            
            // 注册上下文菜单工厂
            callbacks.registerContextMenuFactory(new PopMenu());
            
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
        // 过滤掉已知的无害错误信息
        if (shouldFilterError(message)) {
            return;
        }
        
        if (stderr != null) {
            stderr.println(message);
        } else if (callbacks != null) {
            callbacks.printError(message);
        }
    }
    
    /**
     * 判断是否应该过滤掉特定的错误信息
     * 
     * @param message 错误消息
     * @return 是否应该过滤
     */
    private static boolean shouldFilterError(String message) {
        if (message == null) {
            return false;
        }
        
        // 过滤掉IntelliJ相关的ClassNotFoundException
        if (message.contains("ClassNotFoundException") && 
            (message.contains("com.intellij.") || 
             message.contains("EditorCopyPasteHelperImpl") ||
             message.contains("CopyPasteOptionsTransferableData"))) {
            return true;
        }
        
        // 过滤掉其他已知的无害异常
        if (message.contains("DataFlavor for: application/x-java-serialized-object") &&
            message.contains("com.intellij.openapi.editor.impl")) {
            return true;
        }
        
        return false;
    }

    public static void setRepeaterUIRequest(IHttpRequestResponse requestResponse) {
        if (repeaterUI != null) {


            SwingUtilities.invokeLater(() -> {
                repeaterUI.setRequest(requestResponse);
                // 使用自定义的日志输出方法
                printOutput("[+] 已将请求发送到增强型Repeater，请切换到相应标签页查看");

                // 注意: Burp API不提供直接切换标签页的方法
                // 需要用户手动切换到"增强型Repeater"标签页

            });
        }
    }
}