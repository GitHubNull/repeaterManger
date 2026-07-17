package org.oxff.repeater.privilege.model;

import java.util.ArrayList;
import java.util.List;

/**
 * 测试信息配置模型
 * 存储越权测试目标的可选元信息，用于报告头部展示
 */
public class TestInfoConfig {

    private int id;
    /** 目标名称 */
    private String targetName;
    /** 目标入口（URL地址、APP下载链接等） */
    private String targetEntry;
    /** 测试目标截图文件路径列表 */
    private List<String> targetScreenshots;
    /** 测试时间段 */
    private String testTimeRange;
    /** 测试人员 */
    private String testPersonnel;
    private long createdAt;
    private long updatedAt;

    public TestInfoConfig() {
        this.targetName = "";
        this.targetEntry = "";
        this.targetScreenshots = new ArrayList<>();
        this.testTimeRange = "";
        this.testPersonnel = "";
        this.createdAt = System.currentTimeMillis();
        this.updatedAt = System.currentTimeMillis();
    }

    public TestInfoConfig(String targetName, String targetEntry, List<String> targetScreenshots,
                          String testTimeRange, String testPersonnel) {
        this.targetName = targetName != null ? targetName : "";
        this.targetEntry = targetEntry != null ? targetEntry : "";
        this.targetScreenshots = targetScreenshots != null ? targetScreenshots : new ArrayList<>();
        this.testTimeRange = testTimeRange != null ? testTimeRange : "";
        this.testPersonnel = testPersonnel != null ? testPersonnel : "";
        this.createdAt = System.currentTimeMillis();
        this.updatedAt = System.currentTimeMillis();
    }

    /**
     * 检查是否有任何字段已填写
     */
    public boolean hasAnyData() {
        return !targetName.isEmpty() || !targetEntry.isEmpty()
                || (targetScreenshots != null && !targetScreenshots.isEmpty())
                || !testTimeRange.isEmpty() || !testPersonnel.isEmpty();
    }

    // Getters and Setters

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getTargetName() { return targetName; }
    public void setTargetName(String targetName) { this.targetName = targetName != null ? targetName : ""; }

    public String getTargetEntry() { return targetEntry; }
    public void setTargetEntry(String targetEntry) { this.targetEntry = targetEntry != null ? targetEntry : ""; }

    public List<String> getTargetScreenshots() { return targetScreenshots; }
    public void setTargetScreenshots(List<String> targetScreenshots) {
        this.targetScreenshots = targetScreenshots != null ? targetScreenshots : new ArrayList<>();
    }

    public String getTestTimeRange() { return testTimeRange; }
    public void setTestTimeRange(String testTimeRange) { this.testTimeRange = testTimeRange != null ? testTimeRange : ""; }

    public String getTestPersonnel() { return testPersonnel; }
    public void setTestPersonnel(String testPersonnel) { this.testPersonnel = testPersonnel != null ? testPersonnel : ""; }

    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }

    public long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(long updatedAt) { this.updatedAt = updatedAt; }

    @Override
    public String toString() {
        return "TestInfoConfig{id=" + id + ", targetName='" + targetName + "', targetEntry='" + targetEntry
                + "', screenshots=" + (targetScreenshots != null ? targetScreenshots.size() : 0)
                + ", testTimeRange='" + testTimeRange + "', testPersonnel='" + testPersonnel + "'}";
    }
}
