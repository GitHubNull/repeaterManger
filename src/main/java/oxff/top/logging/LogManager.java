package oxff.top.logging;

import burp.api.montoya.MontoyaApi;
import oxff.top.ui.LogPanel;

import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 日志管理器单例 - 所有日志输出的统一入口
 * <p>
 * 替代现有的 BurpExtender.printOutput/printError 静态方法，
 * 支持多种输出目标（Burp控制台、文件、UI面板）和日志级别过滤。
 */
public class LogManager {

    private static LogManager instance;

    private final CopyOnWriteArrayList<LogHandler> handlers = new CopyOnWriteArrayList<>();
    private volatile LogLevel currentLevel = LogLevel.INFO;

    // 各输出通道开关
    private volatile boolean fileLoggingEnabled = true;
    private volatile boolean uiLoggingEnabled = true;
    private volatile boolean burpConsoleEnabled = true;

    // 特定Handler引用，便于独立控制
    private BurpConsoleHandler burpConsoleHandler;
    private RollingFileHandler rollingFileHandler;
    private UIHandler uiHandler;

    private LogManager() {
    }

    public static synchronized LogManager getInstance() {
        if (instance == null) {
            instance = new LogManager();
        }
        return instance;
    }

    /**
     * 初始化日志管理器，注册Burp控制台Handler
     *
     * @param api MontoyaApi实例
     */
    public void initialize(MontoyaApi api) {
        burpConsoleHandler = new BurpConsoleHandler(api);
        burpConsoleHandler.setEnabled(burpConsoleEnabled);
        handlers.add(burpConsoleHandler);
    }

    /**
     * 初始化文件日志Handler
     * 若已存在 RollingFileHandler，先关闭旧的再创建新的（幂等）
     *
     * @param logDirectory 日志目录
     * @param maxFileSize  单文件最大字节数
     * @param maxBackups   最大备份数
     */
    public void initializeFileHandler(String logDirectory, long maxFileSize, int maxBackups) {
        try {
            // 幂等：若已存在旧的文件 Handler，先关闭并移除
            if (rollingFileHandler != null) {
                handlers.remove(rollingFileHandler);
                rollingFileHandler.close();
                rollingFileHandler = null;
            }

            rollingFileHandler = new RollingFileHandler(logDirectory, maxFileSize, maxBackups);
            rollingFileHandler.setEnabled(fileLoggingEnabled);
            handlers.add(rollingFileHandler);
        } catch (Exception e) {
            // 文件Handler初始化失败不应阻止插件加载
            if (burpConsoleHandler != null) {
                burpConsoleHandler.publish(new LogEntry(LogLevel.ERROR,
                    "文件日志处理器初始化失败: " + e.getMessage()));
            }
        }
    }

    /**
     * 重定位文件日志 Handler 到新的日志目录
     * 用于会话切换时将日志输出移动到新会话的 logs/ 目录
     *
     * @param newLogDirectory 新的日志目录路径
     */
    public void relocateFileHandler(String newLogDirectory) {
        if (!fileLoggingEnabled) {
            return;
        }

        long maxSize = 5 * 1024 * 1024; // 默认5MB
        int maxBackups = 5;

        // 保留旧 Handler 的配置
        if (rollingFileHandler != null) {
            // 读取旧配置（使用默认值，因为 RollingFileHandler 不暴露这些字段）
            // 关闭旧 Handler
            handlers.remove(rollingFileHandler);
            rollingFileHandler.close();
            rollingFileHandler = null;
        }

        initializeFileHandler(newLogDirectory, maxSize, maxBackups);
    }

    /**
     * 设置UI面板，创建并注册UIHandler
     */
    public void setLogPanel(LogPanel panel) {
        if (uiHandler != null) {
            handlers.remove(uiHandler);
            uiHandler.close();
        }
        uiHandler = new UIHandler(panel);
        uiHandler.setEnabled(uiLoggingEnabled);
        handlers.add(uiHandler);
    }

    /**
     * 核心日志方法 - 分发日志到所有Handler
     */
    public void log(LogLevel level, String message) {
        if (level.getLevel() < currentLevel.getLevel()) {
            return;
        }

        LogEntry entry = new LogEntry(level, message);

        for (LogHandler handler : handlers) {
            try {
                // 根据Handler类型检查对应的开关
                if (handler instanceof BurpConsoleHandler && !burpConsoleEnabled) {
                    continue;
                }
                if (handler instanceof RollingFileHandler && !fileLoggingEnabled) {
                    continue;
                }
                if (handler instanceof UIHandler && !uiLoggingEnabled) {
                    continue;
                }
                handler.publish(entry);
            } catch (Exception e) {
                // 单个Handler异常不应影响其他Handler
                System.err.println("LogHandler异常: " + e.getMessage());
            }
        }
    }

    // ========== 便捷方法 ==========

    public void debug(String message) {
        log(LogLevel.DEBUG, message);
    }

    public void info(String message) {
        log(LogLevel.INFO, message);
    }

    public void success(String message) {
        log(LogLevel.SUCCESS, message);
    }

    public void warn(String message) {
        log(LogLevel.WARN, message);
    }

    public void error(String message) {
        log(LogLevel.ERROR, message);
    }

    // ========== 兼容旧代码的静态方法 ==========

    /**
     * 兼容旧代码的输出方法 - 解析消息前缀映射级别后调用log()
     * 替代 BurpExtender.printOutput()
     */
    public void printOutput(String message) {
        LogLevel level = LogLevel.fromPrefix(message);
        // 从前缀无法区分 WARN 和 ERROR，[!] 在 printOutput 中默认为 WARN
        log(level, message);
    }

    /**
     * 兼容旧代码的错误输出方法
     * 替代 BurpExtender.printError()
     */
    public void printError(String message) {
        // printError 中的消息统一视为 ERROR 级别
        log(LogLevel.ERROR, message);
    }

    // ========== 级别和开关控制 ==========

    public void setLevel(LogLevel level) {
        this.currentLevel = level;
    }

    public LogLevel getLevel() {
        return currentLevel;
    }

    public void setFileLoggingEnabled(boolean enabled) {
        this.fileLoggingEnabled = enabled;
        if (rollingFileHandler != null) {
            rollingFileHandler.setEnabled(enabled);
        }
    }

    public boolean isFileLoggingEnabled() {
        return fileLoggingEnabled;
    }

    public void setUILoggingEnabled(boolean enabled) {
        this.uiLoggingEnabled = enabled;
        if (uiHandler != null) {
            uiHandler.setEnabled(enabled);
        }
    }

    public boolean isUILoggingEnabled() {
        return uiLoggingEnabled;
    }

    public void setBurpConsoleEnabled(boolean enabled) {
        this.burpConsoleEnabled = enabled;
        if (burpConsoleHandler != null) {
            burpConsoleHandler.setEnabled(enabled);
        }
    }

    public boolean isBurpConsoleEnabled() {
        return burpConsoleEnabled;
    }

    public RollingFileHandler getRollingFileHandler() {
        return rollingFileHandler;
    }

    /**
     * 关闭所有Handler，释放资源
     */
    public void shutdown() {
        for (LogHandler handler : handlers) {
            try {
                handler.close();
            } catch (Exception e) {
                System.err.println("关闭LogHandler异常: " + e.getMessage());
            }
        }
        handlers.clear();
        burpConsoleHandler = null;
        rollingFileHandler = null;
        uiHandler = null;
    }

    /**
     * 添加自定义Handler
     */
    public void addHandler(LogHandler handler) {
        handlers.add(handler);
    }

    /**
     * 移除Handler
     */
    public void removeHandler(LogHandler handler) {
        handlers.remove(handler);
    }
}
