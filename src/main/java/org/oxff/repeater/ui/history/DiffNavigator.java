package org.oxff.repeater.ui.history;

import java.util.ArrayList;
import java.util.List;

/**
 * 差异区域导航器 — 管理左右两侧 DiffPane 的差异区域同步导航
 * 合并差异区域列表，支持上一个/下一个差异跳转
 */
public class DiffNavigator {

    private final DiffPane leftDiffPane;
    private final DiffPane rightDiffPane;

    /** 合并后的差异区域列表（按行号排序去重） */
    private final List<MergedDiffRegion> mergedRegions = new ArrayList<>();

    /** 当前导航索引 */
    private int currentDiffIndex = -1;

    /**
     * 合并差异区域 — 跨左右面板的唯一差异行
     */
    public static class MergedDiffRegion {
        private final int lineNumber;
        private final DiffEngine.DiffType diffType;
        private final int leftStartOffset;
        private final int leftEndOffset;
        private final int rightStartOffset;
        private final int rightEndOffset;

        public MergedDiffRegion(int lineNumber, DiffEngine.DiffType diffType,
                                int leftStartOffset, int leftEndOffset,
                                int rightStartOffset, int rightEndOffset) {
            this.lineNumber = lineNumber;
            this.diffType = diffType;
            this.leftStartOffset = leftStartOffset;
            this.leftEndOffset = leftEndOffset;
            this.rightStartOffset = rightStartOffset;
            this.rightEndOffset = rightEndOffset;
        }

        public int getLineNumber() { return lineNumber; }
        public DiffEngine.DiffType getDiffType() { return diffType; }
        public int getLeftStartOffset() { return leftStartOffset; }
        public int getLeftEndOffset() { return leftEndOffset; }
        public int getRightStartOffset() { return rightStartOffset; }
        public int getRightEndOffset() { return rightEndOffset; }
    }

    /**
     * 创建差异导航器
     *
     * @param leftDiffPane  左侧(原始)差异面板
     * @param rightDiffPane 右侧(会话)差异面板
     */
    public DiffNavigator(DiffPane leftDiffPane, DiffPane rightDiffPane) {
        this.leftDiffPane = leftDiffPane;
        this.rightDiffPane = rightDiffPane;
        buildMergedRegions();
    }

    /**
     * 从左右 DiffPane 的差异区域列表构建合并列表
     * 使用行号作为关联键，去重合并
     */
    private void buildMergedRegions() {
        mergedRegions.clear();
        currentDiffIndex = -1;

        List<DiffPane.DiffRegion> leftRegions = leftDiffPane.getDiffRegions();
        List<DiffPane.DiffRegion> rightRegions = rightDiffPane.getDiffRegions();

        // 使用归并方式按行号合并（两个列表本身是按行号顺序的）
        int li = 0, ri = 0;

        while (li < leftRegions.size() && ri < rightRegions.size()) {
            DiffPane.DiffRegion left = leftRegions.get(li);
            DiffPane.DiffRegion right = rightRegions.get(ri);

            if (left.getLineNumber() == right.getLineNumber()) {
                // 同一行号，合并为一个 MergedDiffRegion
                mergedRegions.add(new MergedDiffRegion(
                    left.getLineNumber(),
                    chooseDiffType(left.getDiffType(), right.getDiffType()),
                    left.getStartOffset(), left.getEndOffset(),
                    right.getStartOffset(), right.getEndOffset()
                ));
                li++;
                ri++;
            } else if (left.getLineNumber() < right.getLineNumber()) {
                // 左侧差异行号更小
                mergedRegions.add(new MergedDiffRegion(
                    left.getLineNumber(), left.getDiffType(),
                    left.getStartOffset(), left.getEndOffset(),
                    -1, -1
                ));
                li++;
            } else {
                // 右侧差异行号更小
                mergedRegions.add(new MergedDiffRegion(
                    right.getLineNumber(), right.getDiffType(),
                    -1, -1,
                    right.getStartOffset(), right.getEndOffset()
                ));
                ri++;
            }
        }

        // 处理剩余
        while (li < leftRegions.size()) {
            DiffPane.DiffRegion left = leftRegions.get(li);
            mergedRegions.add(new MergedDiffRegion(
                left.getLineNumber(), left.getDiffType(),
                left.getStartOffset(), left.getEndOffset(),
                -1, -1
            ));
            li++;
        }
        while (ri < rightRegions.size()) {
            DiffPane.DiffRegion right = rightRegions.get(ri);
            mergedRegions.add(new MergedDiffRegion(
                right.getLineNumber(), right.getDiffType(),
                -1, -1,
                right.getStartOffset(), right.getEndOffset()
            ));
            ri++;
        }
    }

    /**
     * 选择合并后的差异类型（优先级: CHANGED > REMOVED > ADDED）
     */
    private DiffEngine.DiffType chooseDiffType(DiffEngine.DiffType left, DiffEngine.DiffType right) {
        if (left == DiffEngine.DiffType.CHANGED || right == DiffEngine.DiffType.CHANGED) {
            return DiffEngine.DiffType.CHANGED;
        }
        if (left == DiffEngine.DiffType.REMOVED || right == DiffEngine.DiffType.REMOVED) {
            return DiffEngine.DiffType.REMOVED;
        }
        return DiffEngine.DiffType.ADDED;
    }

    // ==================== 导航方法 ====================

    /**
     * 跳转到下一个差异区域
     *
     * @return true=成功跳转, false=没有差异区域
     */
    public boolean nextDiff() {
        if (mergedRegions.isEmpty()) return false;

        currentDiffIndex++;
        if (currentDiffIndex >= mergedRegions.size()) {
            currentDiffIndex = 0; // 循环
        }

        scrollToCurrentDiff();
        return true;
    }

    /**
     * 跳转到上一个差异区域
     *
     * @return true=成功跳转, false=没有差异区域
     */
    public boolean prevDiff() {
        if (mergedRegions.isEmpty()) return false;

        currentDiffIndex--;
        if (currentDiffIndex < 0) {
            currentDiffIndex = mergedRegions.size() - 1; // 循环
        }

        scrollToCurrentDiff();
        return true;
    }

    /**
     * 滚动到当前差异区域
     */
    private void scrollToCurrentDiff() {
        if (currentDiffIndex < 0 || currentDiffIndex >= mergedRegions.size()) return;

        MergedDiffRegion region = mergedRegions.get(currentDiffIndex);

        // 滚动左侧
        if (region.getLeftStartOffset() >= 0) {
            leftDiffPane.getTextPane().setCaretPosition(region.getLeftStartOffset());
        }

        // 滚动右侧
        if (region.getRightStartOffset() >= 0) {
            rightDiffPane.getTextPane().setCaretPosition(region.getRightStartOffset());
        }
    }

    // ==================== 状态查询 ====================

    /**
     * 获取差异总数
     */
    public int getDiffCount() {
        return mergedRegions.size();
    }

    /**
     * 获取当前差异索引 (0-based)，-1 表示未导航
     */
    public int getCurrentDiffIndex() {
        return currentDiffIndex;
    }

    /**
     * 获取导航状态文本，如 "差异 3/15"
     */
    public String getStatusText() {
        if (mergedRegions.isEmpty()) {
            return "差异 0/0";
        }
        int displayIndex = (currentDiffIndex >= 0) ? currentDiffIndex + 1 : 0;
        return "差异 " + displayIndex + "/" + mergedRegions.size();
    }
}
