package oxff.top.logging;

import java.awt.Color;

/**
 * 日志级别枚举 - 定义不同的日志级别及其显示属性
 */
public enum LogLevel {

    DEBUG(0, "[D]", new Color(150, 150, 150)),
    INFO(10, "[*]", new Color(200, 200, 200)),
    SUCCESS(20, "[+]", new Color(80, 200, 80)),
    WARN(30, "[!]", new Color(255, 180, 50)),
    ERROR(40, "[!]", new Color(255, 80, 80));

    private final int level;
    private final String prefix;
    private final Color displayColor;

    LogLevel(int level, String prefix, Color displayColor) {
        this.level = level;
        this.prefix = prefix;
        this.displayColor = displayColor;
    }

    public int getLevel() {
        return level;
    }

    public String getPrefix() {
        return prefix;
    }

    public Color getDisplayColor() {
        return displayColor;
    }

    /**
     * 从消息前缀反推日志级别（兼容旧代码中的 [*], [+], [!] 前缀）
     *
     * @param message 日志消息
     * @return 对应的日志级别，默认返回 INFO
     */
    public static LogLevel fromPrefix(String message) {
        if (message == null || message.isEmpty()) {
            return INFO;
        }
        if (message.startsWith("[+]")) {
            return SUCCESS;
        }
        if (message.startsWith("[D]")) {
            return DEBUG;
        }
        if (message.startsWith("[!]")) {
            return WARN; // [!] 默认映射为 WARN，具体是 WARN 还是 ERROR 由调用方显式指定
        }
        if (message.startsWith("[*]")) {
            return INFO;
        }
        return INFO;
    }

    /**
     * 从字符串名称解析日志级别
     *
     * @param name 级别名称（不区分大小写）
     * @return 对应的日志级别，默认返回 INFO
     */
    public static LogLevel fromName(String name) {
        if (name == null || name.isEmpty()) {
            return INFO;
        }
        switch (name.toUpperCase()) {
            case "DEBUG":
                return DEBUG;
            case "INFO":
                return INFO;
            case "SUCCESS":
                return SUCCESS;
            case "WARN":
            case "WARNING":
                return WARN;
            case "ERROR":
                return ERROR;
            default:
                return INFO;
        }
    }
}
