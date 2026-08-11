package org.oxff.repeater.ui;

import org.oxff.repeater.i18n.I18nManager;

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
    private final JLabel batchProgressLabel;

    // 需要在语言切换时刷新的静态标签
    private final JLabel modeTitleLabel;
    private final JLabel statusTitleLabel;
    private final JLabel responseSizeTitleLabel;
    private final JLabel requestTimeTitleLabel;
    private final JLabel responseTimeTitleLabel;
    private final JLabel durationTitleLabel;
    private final JLabel msUnitLabel;

    // 当前模式状态（用于语言切换时恢复显示）
    private boolean currentPrivilegeMode = false;
    // 当前成功状态（用于语言切换时恢复显示）
    private Boolean lastSuccess = null;

    public StatusPanel() {
        setLayout(new FlowLayout(FlowLayout.LEFT, 12, 2));
        setBorder(BorderFactory.createEtchedBorder());

        // 模式指示
        modeTitleLabel = new JLabel(I18nManager.tr("status.mode"));
        add(modeTitleLabel);
        modeLabel = new JLabel(I18nManager.tr("status.mode.normal"));
        modeLabel.setForeground(new Color(0, 100, 200));
        add(modeLabel);

        // 状态
        add(createSeparator());
        statusTitleLabel = new JLabel(I18nManager.tr("status.state"));
        add(statusTitleLabel);
        statusLabel = new JLabel(PLACEHOLDER);
        add(statusLabel);

        // 响应大小
        add(createSeparator());
        responseSizeTitleLabel = new JLabel(I18nManager.tr("status.response.size"));
        add(responseSizeTitleLabel);
        responseSizeLabel = new JLabel(PLACEHOLDER);
        add(responseSizeLabel);

        // 请求时间
        add(createSeparator());
        requestTimeTitleLabel = new JLabel(I18nManager.tr("status.request.time"));
        add(requestTimeTitleLabel);
        requestTimeLabel = new JLabel(PLACEHOLDER);
        add(requestTimeLabel);

        // 响应时间
        add(createSeparator());
        responseTimeTitleLabel = new JLabel(I18nManager.tr("status.response.time"));
        add(responseTimeTitleLabel);
        responseTimeLabel = new JLabel(PLACEHOLDER);
        add(responseTimeLabel);

        // 耗时
        add(createSeparator());
        durationTitleLabel = new JLabel(I18nManager.tr("status.elapsed"));
        add(durationTitleLabel);
        durationLabel = new JLabel(PLACEHOLDER);
        add(durationLabel);
        msUnitLabel = new JLabel(I18nManager.tr("common.unit.ms"));
        add(msUnitLabel);

        // 批量操作进度
        add(createSeparator());
        batchProgressLabel = new JLabel("");
        batchProgressLabel.setForeground(new Color(0, 100, 200));
        add(batchProgressLabel);

        // 注册语言变更监听
        I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);
    }

    /**
     * 语言变更时刷新所有静态文本
     */
    private void refreshTexts() {
        modeTitleLabel.setText(I18nManager.tr("status.mode"));
        statusTitleLabel.setText(I18nManager.tr("status.state"));
        responseSizeTitleLabel.setText(I18nManager.tr("status.response.size"));
        requestTimeTitleLabel.setText(I18nManager.tr("status.request.time"));
        responseTimeTitleLabel.setText(I18nManager.tr("status.response.time"));
        durationTitleLabel.setText(I18nManager.tr("status.elapsed"));
        msUnitLabel.setText(I18nManager.tr("common.unit.ms"));

        // 恢复模式指示文本
        modeLabel.setText(I18nManager.tr(currentPrivilegeMode ? "status.mode.privilege" : "status.mode.normal"));

        // 恢复状态文本
        if (lastSuccess != null) {
            statusLabel.setText(I18nManager.tr(lastSuccess ? "status.success" : "status.failure"));
        }

        revalidate();
        repaint();
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
        lastSuccess = success;
        if (success) {
            statusLabel.setText(I18nManager.tr("status.success"));
            statusLabel.setForeground(new Color(0, 128, 0));
        } else {
            statusLabel.setText(I18nManager.tr("status.failure"));
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
        currentPrivilegeMode = privilegeTestMode;
        SwingUtilities.invokeLater(() -> {
            if (privilegeTestMode) {
                modeLabel.setText(I18nManager.tr("status.mode.privilege"));
                modeLabel.setForeground(new Color(200, 80, 0));
                modeLabel.setFont(modeLabel.getFont().deriveFont(Font.BOLD));
            } else {
                modeLabel.setText(I18nManager.tr("status.mode.normal"));
                modeLabel.setForeground(new Color(0, 100, 200));
                modeLabel.setFont(modeLabel.getFont().deriveFont(Font.PLAIN));
            }
        });
    }

    /**
     * 清空状态栏，恢复初始状态
     */
    public void clear() {
        lastSuccess = null;
        statusLabel.setText(PLACEHOLDER);
        statusLabel.setForeground(UIManager.getColor("Label.foreground"));
        responseSizeLabel.setText(PLACEHOLDER);
        requestTimeLabel.setText(PLACEHOLDER);
        responseTimeLabel.setText(PLACEHOLDER);
        durationLabel.setText(PLACEHOLDER);
        // 重置模式指示为普通模式
        setModeIndicator(false);
    }

    /**
     * 显示批量操作进度
     *
     * @param current     当前已完成数量
     * @param total       总数量
     * @param description 操作描述（如"权限测试"、"重放"）
     */
    public void showBatchProgress(int current, int total, String description) {
        SwingUtilities.invokeLater(() -> {
            batchProgressLabel.setText(I18nManager.tr("status.batch", current, total, description));
            batchProgressLabel.setFont(batchProgressLabel.getFont().deriveFont(Font.BOLD));
        });
    }

    /**
     * 清除批量操作进度显示
     */
    public void clearBatchProgress() {
        SwingUtilities.invokeLater(() -> {
            batchProgressLabel.setText("");
            batchProgressLabel.setFont(batchProgressLabel.getFont().deriveFont(Font.PLAIN));
        });
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
