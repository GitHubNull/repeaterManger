package org.oxff.repeater.privilege.model;

import java.awt.Color;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 用户会话模型
 * 代表权限测试中的一个用户身份
 * 每个用户为所有字段提供不同的值
 */
public class UserSession {
    private int id;
    private String name;
    private Color color;
    private boolean enabled;
    /** 关联的方案ID（一对一） */
    private Integer schemeId;

    /** 请求超时时间（秒） */
    private int requestTimeout;

    /** 并发线程数 */
    private int maxConcurrent;

    /** 失败重试次数 */
    private int retryCount;

    /** 重试间隔（毫秒） */
    private int retryDelay;

    /** 重放间隔延迟（毫秒） */
    private int replayDelay;

    /** 字段值映射：fieldId -> value */
    private Map<Integer, String> fieldValues;
    private long createdAt;

    public UserSession() {
        this.name = "";
        this.enabled = true;
        this.schemeId = null;
        this.requestTimeout = 30;
        this.maxConcurrent = 1;
        this.retryCount = 0;
        this.retryDelay = 1000;
        this.replayDelay = 0;
        this.fieldValues = new LinkedHashMap<>();
        this.createdAt = System.currentTimeMillis();
    }

    public UserSession(String name, Color color, boolean enabled) {
        this.name = name;
        this.color = color;
        this.enabled = enabled;
        this.schemeId = null;
        this.requestTimeout = 30;
        this.maxConcurrent = 1;
        this.retryCount = 0;
        this.retryDelay = 1000;
        this.replayDelay = 0;
        this.fieldValues = new LinkedHashMap<>();
        this.createdAt = System.currentTimeMillis();
    }

    public UserSession(int id, String name, Color color, boolean enabled) {
        this.id = id;
        this.name = name;
        this.color = color;
        this.enabled = enabled;
        this.schemeId = null;
        this.requestTimeout = 30;
        this.maxConcurrent = 1;
        this.retryCount = 0;
        this.retryDelay = 1000;
        this.replayDelay = 0;
        this.fieldValues = new LinkedHashMap<>();
        this.createdAt = System.currentTimeMillis();
    }

    // Getters and Setters

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Color getColor() {
        return color;
    }

    public void setColor(Color color) {
        this.color = color;
    }

    /**
     * 获取颜色的十六进制表示
     */
    public String getColorHex() {
        if (color == null) {
            return null;
        }
        return String.format("#%02x%02x%02x", color.getRed(), color.getGreen(), color.getBlue());
    }

    /**
     * 从十六进制字符串设置颜色
     */
    public void setColorHex(String hex) {
        if (hex != null && !hex.isEmpty()) {
            try {
                this.color = Color.decode(hex);
            } catch (NumberFormatException e) {
                this.color = null;
            }
        } else {
            this.color = null;
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Map<Integer, String> getFieldValues() {
        return fieldValues;
    }

    public void setFieldValues(Map<Integer, String> fieldValues) {
        this.fieldValues = fieldValues != null ? fieldValues : new LinkedHashMap<>();
    }

    /**
     * 设置指定字段的值
     */
    public void setFieldValue(int fieldId, String value) {
        fieldValues.put(fieldId, value);
    }

    /**
     * 获取指定字段的值
     */
    public String getFieldValue(int fieldId) {
        return fieldValues.get(fieldId);
    }

    public Integer getSchemeId() {
        return schemeId;
    }

    public void setSchemeId(Integer schemeId) {
        this.schemeId = schemeId;
    }

    public int getRequestTimeout() {
        return requestTimeout;
    }

    public void setRequestTimeout(int requestTimeout) {
        this.requestTimeout = requestTimeout;
    }

    public int getMaxConcurrent() {
        return maxConcurrent;
    }

    public void setMaxConcurrent(int maxConcurrent) {
        this.maxConcurrent = maxConcurrent;
    }

    public int getRetryCount() {
        return retryCount;
    }

    public void setRetryCount(int retryCount) {
        this.retryCount = retryCount;
    }

    public int getRetryDelay() {
        return retryDelay;
    }

    public void setRetryDelay(int retryDelay) {
        this.retryDelay = retryDelay;
    }

    public int getReplayDelay() {
        return replayDelay;
    }

    public void setReplayDelay(int replayDelay) {
        this.replayDelay = replayDelay;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * 获取字段值的摘要文本，用于表格展示
     * 两层截断：单值超过30字符截断，整体超过80字符截断
     */
    public String getFieldValuesSummary() {
        if (fieldValues.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Map.Entry<Integer, String> entry : fieldValues.entrySet()) {
            if (!first) {
                sb.append(" | ");
            }
            String value = entry.getValue();
            if (value != null) {
                // 换行符替换为可见符号，防止破坏表格渲染
                value = value.replace("\r\n", "\u21B5").replace("\n", "\u21B5").replace("\r", "\u21B5");
                if (value.length() > 30) {
                    value = value.substring(0, 27) + "...";
                }
            } else {
                value = "";
            }
            sb.append(value);
            first = false;
        }
        String result = sb.toString();
        if (result.length() > 80) {
            result = result.substring(0, 77) + "...";
        }
        return result;
    }

    @Override
    public String toString() {
        return String.format("UserSession{id=%d, name='%s', enabled=%s, fieldCount=%d}",
                id, name, enabled, fieldValues.size());
    }
}
