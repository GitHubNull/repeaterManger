package oxff.top.ui;

import javax.swing.*;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * 状态栏面板组件 - 显示在右侧面板底部，展示请求执行状态信息
 */
public class StatusPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private static final String PLACEHOLDER = "--";
    private static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");

    private final JLabel modeLabel;
    private final JLabel statusLabel;
    private final JLabel responseSizeLabel;
    private final JLabel requestTimeLabel;
    private final JLabel responseTimeLabel;
    private final JLabel durationLabel;

    public StatusPanel() {
        setLayout(new FlowLayout(FlowLayout.LEFT, 12, 2));
        setBorder(BorderFactory.createEtchedBorder());

        // 模式指示
        add(new JLabel("模式:"));
        modeLabel = new JLabel("普通模式");
        modeLabel.setForeground(new Color(0, 100, 200));
        add(modeLabel);

        // 状态
        add(createSeparator());
        add(new JLabel("状态:"));
        statusLabel = new JLabel(PLACEHOLDER);
        add(statusLabel);

        // 响应大小
        add(createSeparator());
        add(new JLabel("响应大小:"));
        responseSizeLabel = new JLabel(PLACEHOLDER);
        add(responseSizeLabel);

        // 请求时间
        add(createSeparator());
        add(new JLabel("请求时间:"));
        requestTimeLabel = new JLabel(PLACEHOLDER);
        add(requestTimeLabel);

        // 响应时间
        add(createSeparator());
        add(new JLabel("响应时间:"));
        responseTimeLabel = new JLabel(PLACEHOLDER);
        add(responseTimeLabel);

        // 耗时
        add(createSeparator());
        add(new JLabel("耗时:"));
        durationLabel = new JLabel(PLACEHOLDER);
        add(durationLabel);
        add(new JLabel("ms"));
    }

    /**
     * 更新状态栏信息
     *
     * @param success       请求是否成功
     * @param responseSize  响应报文大小（含响应头，单位bytes）
     * @param requestTimeMs 请求发送时刻（epoch毫秒）
     * @param responseTimeMs 响应接收时刻（epoch毫秒）
     * @param durationMs    请求响应耗时（毫秒）
     */
    public void updateStatus(boolean success, int responseSize, long requestTimeMs, long responseTimeMs, long durationMs) {
        if (success) {
            statusLabel.setText("\u2713 成功");
            statusLabel.setForeground(new Color(0, 128, 0));
        } else {
            statusLabel.setText("\u2717 失败");
            statusLabel.setForeground(Color.RED);
        }

        responseSizeLabel.setText(responseSize + " bytes");
        requestTimeLabel.setText(formatTime(requestTimeMs));
        responseTimeLabel.setText(formatTime(responseTimeMs));
        durationLabel.setText(String.valueOf(durationMs));
    }

    /**
     * 设置模式指示器
     *
     * @param privilegeTestMode true=权限测试模式, false=普通模式
     */
    public void setModeIndicator(boolean privilegeTestMode) {
        SwingUtilities.invokeLater(() -> {
            if (privilegeTestMode) {
                modeLabel.setText("权限测试");
                modeLabel.setForeground(new Color(200, 80, 0));
                modeLabel.setFont(modeLabel.getFont().deriveFont(Font.BOLD));
            } else {
                modeLabel.setText("普通模式");
                modeLabel.setForeground(new Color(0, 100, 200));
                modeLabel.setFont(modeLabel.getFont().deriveFont(Font.PLAIN));
            }
        });
    }

    /**
     * 清空状态栏，恢复初始状态
     */
    public void clear() {
        statusLabel.setText(PLACEHOLDER);
        statusLabel.setForeground(UIManager.getColor("Label.foreground"));
        responseSizeLabel.setText(PLACEHOLDER);
        requestTimeLabel.setText(PLACEHOLDER);
        responseTimeLabel.setText(PLACEHOLDER);
        durationLabel.setText(PLACEHOLDER);
        // 重置模式指示为普通模式
        setModeIndicator(false);
    }

    private JLabel createSeparator() {
        JLabel sep = new JLabel("|");
        sep.setForeground(Color.GRAY);
        return sep;
    }

    private String formatTime(long timeMs) {
        if (timeMs <= 0) {
            return PLACEHOLDER;
        }
        return TIME_FORMAT.format(new Date(timeMs));
    }
}
