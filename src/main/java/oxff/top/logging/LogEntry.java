package oxff.top.logging;

import java.awt.Color;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * 日志条目数据模型 - 表示一条完整的日志记录
 */
public class LogEntry {

    private static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("HH:mm:ss.SSS");
    private static final SimpleDateFormat FULL_TIME_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");

    private final long timestamp;
    private final LogLevel level;
    private final String message;
    private final String formattedMessage;

    /**
     * 创建日志条目
     *
     * @param level   日志级别
     * @param message 日志消息
     */
    public LogEntry(LogLevel level, String message) {
        this.timestamp = System.currentTimeMillis();
        this.level = level;
        this.message = message;
        this.formattedMessage = formatMessage();
    }

    private String formatMessage() {
        String timeStr = TIME_FORMAT.format(new Date(timestamp));
        return timeStr + " " + level.getPrefix() + " " + message;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public LogLevel getLevel() {
        return level;
    }

    public String getMessage() {
        return message;
    }

    public String getFormattedMessage() {
        return formattedMessage;
    }

    /**
     * 获取用于文件输出的完整格式化消息（包含日期）
     */
    public String getFileFormattedMesssage() {
        String timeStr = FULL_TIME_FORMAT.format(new Date(timestamp));
        return timeStr + " " + level.getPrefix() + " " + message;
    }

    /**
     * 获取该级别对应的 UI 显示颜色
     */
    public Color getDisplayColor() {
        return level.getDisplayColor();
    }

    @Override
    public String toString() {
        return formattedMessage;
    }
}
