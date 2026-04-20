package oxff.top.logging;

import oxff.top.ui.LogPanel;

import javax.swing.SwingUtilities;
import java.lang.ref.WeakReference;

/**
 * UI面板日志处理器 - 将日志推送到LogPanel UI组件
 */
public class UIHandler implements LogHandler {

    private final WeakReference<LogPanel> panelRef;
    private volatile boolean enabled = true;

    public UIHandler(LogPanel panel) {
        this.panelRef = new WeakReference<>(panel);
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void publish(LogEntry entry) {
        if (!enabled) {
            return;
        }

        final LogPanel panel = panelRef.get();
        if (panel == null) {
            return;
        }

        // 必须在EDT线程中更新UI
        SwingUtilities.invokeLater(() -> panel.appendLogEntry(entry));
    }

    @Override
    public void flush() {
        // UI面板无需刷新操作
    }

    @Override
    public void close() {
        // WeakReference无需显式清理
    }
}
