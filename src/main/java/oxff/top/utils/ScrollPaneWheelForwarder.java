package oxff.top.utils;

import javax.swing.*;

/**
 * 滚轮事件转发器，解决嵌套 JScrollPane 的滚轮滚动问题。
 * 当内层 JScrollPane 无法继续滚动时，直接操作外层滚动条值，
 * 避免 dispatchEvent 的构造开销，实现流畅的 Chrome 式滚动体验。
 */
public final class ScrollPaneWheelForwarder {

    /** 每次滚轮刻度滚动的像素数，模拟浏览器滚动体验 */
    private static final int SCROLL_PIXELS_PER_UNIT = 40;

    private ScrollPaneWheelForwarder() {
    }

    /**
     * 为内层 JScrollPane 安装滚轮事件转发器。
     * 当内层无法继续滚动时，直接操作外层滚动条实现滚动。
     *
     * @param inner 内层 JScrollPane
     * @param outer 外层 JScrollPane（转发目标）
     */
    public static void install(JScrollPane inner, JScrollPane outer) {
        // 设置外层滚动条的点击箭头步长
        outer.getVerticalScrollBar().setUnitIncrement(SCROLL_PIXELS_PER_UNIT);

        inner.addMouseWheelListener(e -> {
            JScrollBar innerBar = inner.getVerticalScrollBar();

            if (canScroll(innerBar, e.getWheelRotation())) {
                return; // 内层可滚动，让 JScrollPane 默认处理器处理
            }

            e.consume();

            // 直接操作外层滚动条值：wheelRotation>0 表示向下滚，滚动条值应增大
            JScrollBar outerBar = outer.getVerticalScrollBar();
            int scrollDelta = e.getWheelRotation() * SCROLL_PIXELS_PER_UNIT;
            int newValue = outerBar.getValue() + scrollDelta;
            newValue = Math.max(outerBar.getMinimum(),
                    Math.min(newValue, outerBar.getMaximum() - outerBar.getVisibleAmount()));
            outerBar.setValue(newValue);
        });
    }

    /**
     * 判断 JScrollPane 是否可以在指定方向上继续滚动
     *
     * @param bar           垂直滚动条
     * @param wheelRotation 滚轮旋转方向（正数=向下，负数=向上）
     * @return true 表示内层可继续滚动，false 表示应转发给外层
     */
    private static boolean canScroll(JScrollBar bar, int wheelRotation) {
        if (!bar.isVisible()) {
            return false;
        }

        if (wheelRotation > 0) {
            return bar.getValue() + bar.getVisibleAmount() < bar.getMaximum();
        } else {
            return bar.getValue() > bar.getMinimum();
        }
    }
}
