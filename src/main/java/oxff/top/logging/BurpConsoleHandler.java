package oxff.top.logging;

import burp.api.montoya.MontoyaApi;

/**
 * Burp控制台日志处理器 - 将日志输出到Burp Suite的标准输出/错误流
 */
public class BurpConsoleHandler implements LogHandler {

    private MontoyaApi api;
    private boolean enabled = true;

    public BurpConsoleHandler(MontoyaApi api) {
        this.api = api;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void publish(LogEntry entry) {
        if (!enabled || api == null) {
            return;
        }

        String message = entry.getFormattedMessage();

        switch (entry.getLevel()) {
            case DEBUG:
            case INFO:
            case SUCCESS:
                api.logging().logToOutput(message);
                break;
            case WARN:
            case ERROR:
                api.logging().logToError(message);
                break;
        }
    }

    @Override
    public void flush() {
        // Burp日志API无需刷新
    }

    @Override
    public void close() {
        api = null;
    }
}
