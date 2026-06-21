package org.oxff.repeater.ui;

import javax.swing.*;
import java.awt.*;

/**
 * 类 HTML 风格的 Switch 开关组件。
 *
 * <p>外观：圆角长条轨道 + 白色圆形滑块。未选中时轨道为浅灰色，选中时为深色，
 * 视觉上与常见 Web Switch 组件一致。组件自身不显示文字，调用方可通过 JLabel 等
 * 附加标签说明当前状态。</p>
 */
public class SwitchButton extends JToggleButton {

    private static final int DEFAULT_WIDTH = 44;
    private static final int DEFAULT_HEIGHT = 24;

    private static final Color COLOR_OFF_TRACK = new Color(204, 204, 204);
    private static final Color COLOR_ON_TRACK = new Color(15, 23, 42); // 接近黑色的深蓝灰
    private static final Color COLOR_THUMB = new Color(255, 255, 255);

    public SwitchButton() {
        setOpaque(false);
        setContentAreaFilled(false);
        setBorderPainted(false);
        setFocusPainted(false);
        setText("");
        setPreferredSize(new Dimension(DEFAULT_WIDTH, DEFAULT_HEIGHT));
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
    }

    @Override
       protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            int w = getWidth();
            int h = getHeight();

            // 绘制轨道
            g2.setColor(isSelected() ? COLOR_ON_TRACK : COLOR_OFF_TRACK);
            g2.fillRoundRect(0, 0, w, h, h, h);

            // 绘制滑块
            int padding = 2;
            int thumbSize = h - padding * 2;
            int thumbX = isSelected() ? w - thumbSize - padding : padding;
            int thumbY = (h - thumbSize) / 2;

            g2.setColor(COLOR_THUMB);
            g2.fillOval(thumbX, thumbY, thumbSize, thumbSize);
        } finally {
            g2.dispose();
        }
    }

    @Override
    public void setText(String text) {
        // Switch 组件不显示文字，但允许保持为空
        super.setText("");
    }

    @Override
    public Dimension getPreferredSize() {
        return new Dimension(DEFAULT_WIDTH, DEFAULT_HEIGHT);
    }

    @Override
    public Dimension getMinimumSize() {
        return getPreferredSize();
    }

    @Override
    public Dimension getMaximumSize() {
        return getPreferredSize();
    }
}
