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
    /** 报告标题（用户自定义，仅当 useDefaultTitle=false 时生效） */
    private String reportTitle;
    /** 是否使用默认标题（true=使用默认值"越权测试报告"） */
    private boolean useDefaultTitle;
    /** 报告副标题（可选，为空时不显示） */
    private String reportSubtitle;
    private long createdAt;
    private long updatedAt;

    public TestInfoConfig() {
        this.targetName = "";
        this.targetEntry = "";
        this.targetScreenshots = new ArrayList<>();
        this.testTimeRange = "";
        this.testPersonnel = "";
        this.reportTitle = "";
        this.useDefaultTitle = true;
        this.reportSubtitle = "";
        this.createdAt = System.currentTimeMillis();
        this.updatedAt = System.currentTimeMillis();
    }

    public TestInfoConfig(String targetName, String targetEntry, List<String> targetScreenshots,
                          String testTimeRange, String testPersonnel,
                          String reportTitle, boolean useDefaultTitle, String reportSubtitle) {
        this.targetName = targetName != null ? targetName : "";
        this.targetEntry = targetEntry != null ? targetEntry : "";
        this.targetScreenshots = targetScreenshots != null ? targetScreenshots : new ArrayList<>();
        this.testTimeRange = testTimeRange != null ? testTimeRange : "";
        this.testPersonnel = testPersonnel != null ? testPersonnel : "";
        this.reportTitle = reportTitle != null ? reportTitle : "";
        this.useDefaultTitle = useDefaultTitle;
        this.reportSubtitle = reportSubtitle != null ? reportSubtitle : "";
        this.createdAt = System.currentTimeMillis();
        this.updatedAt = System.currentTimeMillis();
    }

    /**
     * 检查是否有任何字段已填写
     */
    public boolean hasAnyData() {
        return !targetName.isEmpty() || !targetEntry.isEmpty()
                || (targetScreenshots != null && !targetScreenshots.isEmpty())
                || !testTimeRange.isEmpty() || !testPersonnel.isEmpty()
                || !reportSubtitle.isEmpty();
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

    public String getReportTitle() { return reportTitle; }
    public void setReportTitle(String reportTitle) { this.reportTitle = reportTitle != null ? reportTitle : ""; }

    public boolean isUseDefaultTitle() { return useDefaultTitle; }
    public void setUseDefaultTitle(boolean useDefaultTitle) { this.useDefaultTitle = useDefaultTitle; }

    public String getReportSubtitle() { return reportSubtitle; }
    public void setReportSubtitle(String reportSubtitle) { this.reportSubtitle = reportSubtitle != null ? reportSubtitle : ""; }

    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }

    public long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(long updatedAt) { this.updatedAt = updatedAt; }

    @Override
    public String toString() {
        return "TestInfoConfig{id=" + id + ", targetName='" + targetName + "', targetEntry='" + targetEntry
                + "', screenshots=" + (targetScreenshots != null ? targetScreenshots.size() : 0)
                + ", testTimeRange='" + testTimeRange + "', testPersonnel='" + testPersonnel
                + "', reportTitle='" + reportTitle + "', useDefaultTitle=" + useDefaultTitle
                + ", reportSubtitle='" + reportSubtitle + "'}";
    }
}
