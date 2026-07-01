package org.oxff.repeater.ui.history;

/**
 * 差异类型枚举
 */
public enum DiffType {
    UNCHANGED,   // 未变化
    ADDED,       // 新增行
    REMOVED,     // 删除行
    CHANGED      // 修改行（内容有变化但行号对齐，配对产生）
}
