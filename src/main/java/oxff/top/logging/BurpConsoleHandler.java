package oxff.top.logging;

import burp.IBurpExtenderCallbacks;

/**
 * Burp控制台日志处理器 - 将日志输出到Burp Suite的标准输出/错误流
 */
public class BurpConsoleHandler implements LogHandler {

    private IBurpExtenderCallbacks callbacks;
    private boolean enabled = true;

    public BurpConsoleHandler(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void publish(LogEntry entry) {
        if (!enabled || callbacks == null) {
            return;
        }

        String message = entry.getFormattedMessage();

        switch (entry.getLevel()) {
            case DEBUG:
            case INFO:
            case SUCCESS:
                callbacks.printOutput(message);
                break;
            case WARN:
            case ERROR:
                callbacks.printError(message);
                break;
        }
    }

    @Override
    public void flush() {
        // Burp回调无需刷新
    }

    @Override
    public void close() {
        callbacks = null;
    }
}
