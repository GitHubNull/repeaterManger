package org.oxff.repeater.logging;

/**
 * 日志处理器接口 - 所有日志输出目标的抽象
 */
public interface LogHandler {

    /**
     * 发布一条日志
     *
     * @param entry 日志条目
     */
    void publish(LogEntry entry);

    /**
     * 刷新缓冲区
     */
    void flush();

    /**
     * 关闭处理器，释放资源
     */
    void close();
}
