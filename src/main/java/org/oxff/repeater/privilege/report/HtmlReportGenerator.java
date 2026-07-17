package org.oxff.repeater.privilege.report;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * HTML 格式报告生成器
 * 支持两种输出模式：
 * 1. 单文件 generate() — 兼容旧代码（MD 模板体系）
 * 2. 多文件 generateToDirectory() — 分离式架构（index.html + style.css + controller.js + data.js + screenshots/）
 */
public class HtmlReportGenerator extends ReportGenerator {

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static final Gson GSON = new GsonBuilder().create();

    @Override
    public String getFileExtension() {
        return "html";
    }

    /**
     * 单文件模式生成（兼容旧代码）：内联 CSS/JS 资源，生成完整独立 HTML
     */
    @Override
    public String generate(ReportData data) {
        try {
            Map<String, Object> model = buildModel(data);
            // 添加 userInfoEntries 用于模板直接渲染
            model.put("userInfoEntries", data.getUserInfoEntries());
            // 标记为单文件模式，模板将内联 CSS 而非外部引用
            model.put("inlineMode", true);
            StringWriter writer = new StringWriter();
            FreeMarkerConfig.getInstance().getHtmlTemplate("html_report.ftl").process(model, writer);
            return writer.toString();
        } catch (Exception e) {
            throw new RuntimeException("HTML 报告生成失败: " + e.getMessage(), e);
        }
    }

    /**
     * 多文件模式：将报告写入目录
     */
    public void generateToDirectory(ReportData data, File reportDir) throws Exception {
        if (!reportDir.exists()) {
            reportDir.mkdirs();
        }

        // 1. 写入 style.css（读取 FreeMarker 模板内容，去掉 <style> 标签）
        writeStyleCss(reportDir);

        // 2. 写入 controller.js（从 classpath 复制）
        writeControllerJs(reportDir);

        // 3. 写入 data.js（JSON 数据，不含 base64 图片）
        writeDataJs(data, reportDir);

        // 4. 写入截图文件到 screenshots/ 子目录
        writeScreenshots(data, reportDir);

        // 5. 写入 index.html（FreeMarker 渲染）
        writeIndexHtml(data, reportDir);
    }

    /**
     * 将 html_css.ftl 模板内容写入 style.css（去掉 <#--...--> 注释和 <style> 标签）
     */
    private void writeStyleCss(File reportDir) throws Exception {
        // 读取 FreeMarker 模板的纯内容
        StringWriter sw = new StringWriter();
        FreeMarkerConfig.getInstance().getHtmlTemplate("html_css.ftl").process(new HashMap<>(), sw);
        String content = sw.toString();

        // 去掉 FreeMarker 注释和 <style>/</style> 标签（(?s) 启用 DOTALL 模式以匹配多行注释）
        content = content.replaceAll("(?s)<#--.*?-->", "");
        content = content.replace("<style>", "").replace("</style>", "");
        content = content.trim();

        File cssFile = new File(reportDir, "style.css");
        try (FileOutputStream fos = new FileOutputStream(cssFile)) {
            fos.write(content.getBytes(StandardCharsets.UTF_8));
        }
    }

    /**
     * 从 classpath 复制 controller.js 到报告目录
     */
    private void writeControllerJs(File reportDir) throws Exception {
        InputStream is = getClass().getResourceAsStream("/templates/report/controller.js");
        if (is == null) {
            throw new IOException("controller.js 模板资源未找到");
        }
        File jsFile = new File(reportDir, "controller.js");
        try (InputStream in = is;
             FileOutputStream out = new FileOutputStream(jsFile)) {
            byte[] buf = new byte[8192];
            int len;
            while ((len = in.read(buf)) > 0) {
                out.write(buf, 0, len);
            }
        }
    }

    /**
     * 将 ReportData 序列化为 data.js（不包含 base64 图片数据）
     */
    private void writeDataJs(ReportData data, File reportDir) throws Exception {
        // 构建用于 JS 的数据对象（包含 userInfoEntries 但 base64 置空）
        Map<String, Object> jsData = new LinkedHashMap<>();
        jsData.put("title", data.getTitle());
        jsData.put("generatedAt", DATE_FORMAT.format(data.getGeneratedAt()));
        jsData.put("pluginVersion", data.getPluginVersion());

        // 摘要
        Map<String, Object> summary = new LinkedHashMap<>();
        if (data.getSummary() != null) {
            summary.put("totalTests", data.getSummary().getTotalTests());
            summary.put("escalatedCount", data.getSummary().getEscalatedCount());
            summary.put("safeCount", data.getSummary().getSafeCount());
            summary.put("errorCount", data.getSummary().getErrorCount());
        }
        jsData.put("summary", summary);

        // 用户信息条目（不含 base64，但有 screenshotFilenames）
        List<Map<String, Object>> userInfoJs = new ArrayList<>();
        for (ReportData.UserInfoEntry entry : data.getUserInfoEntries()) {
            Map<String, Object> entryMap = new LinkedHashMap<>();
            entryMap.put("sessionName", entry.getSessionName());
            entryMap.put("role", entry.getRole());
            entryMap.put("username", entry.getUsername());
            entryMap.put("isAnonymous", entry.isAnonymous());
            entryMap.put("screenshotFilenames", entry.getScreenshotFilenames());
            userInfoJs.add(entryMap);
        }
        jsData.put("userInfoEntries", userInfoJs);

        // 测试信息配置（不含 base64，但有 screenshotFilenames）
        if (data.getTestInfoConfig() != null && data.getTestInfoConfig().hasAnyData()) {
            Map<String, Object> configJs = new LinkedHashMap<>();
            configJs.put("targetName", data.getTestInfoConfig().getTargetName());
            configJs.put("targetEntry", data.getTestInfoConfig().getTargetEntry());
            configJs.put("testTimeRange", data.getTestInfoConfig().getTestTimeRange());
            configJs.put("testPersonnel", data.getTestInfoConfig().getTestPersonnel());
            configJs.put("screenshotFilenames", data.getTestInfoConfigScreenshotFilenames() != null
                    ? data.getTestInfoConfigScreenshotFilenames() : new ArrayList<>());
            jsData.put("testInfoConfig", configJs);
        }

        String json = GSON.toJson(jsData);
        String jsContent = "var REPORT_DATA = " + json + ";";

        File dataJsFile = new File(reportDir, "data.js");
        try (FileOutputStream fos = new FileOutputStream(dataJsFile)) {
            fos.write(jsContent.getBytes(StandardCharsets.UTF_8));
        }
    }

    /**
     * 将 base64 截图解码写入 screenshots/ 子目录
     */
    private void writeScreenshots(ReportData data, File reportDir) throws Exception {
        File screenshotsDir = new File(reportDir, "screenshots");
        boolean hasScreenshots = false;
        for (ReportData.UserInfoEntry entry : data.getUserInfoEntries()) {
            if (entry.getScreenshotsBase64() != null && !entry.getScreenshotsBase64().isEmpty()) {
                hasScreenshots = true;
                break;
            }
        }
        // 也检查测试信息配置截图
        if (!hasScreenshots && data.getTestInfoConfigBase64Screenshots() != null
                && !data.getTestInfoConfigBase64Screenshots().isEmpty()) {
            hasScreenshots = true;
        }
        if (!hasScreenshots) return;

        screenshotsDir.mkdirs();

        // 写入用户信息截图
        for (ReportData.UserInfoEntry entry : data.getUserInfoEntries()) {
            List<String> base64List = entry.getScreenshotsBase64();
            List<String> filenameList = entry.getScreenshotFilenames();
            if (base64List == null || filenameList == null) continue;

            for (int i = 0; i < base64List.size() && i < filenameList.size(); i++) {
                String base64 = base64List.get(i);
                String filename = filenameList.get(i);
                if (base64 == null || !base64.startsWith("data:image/")) continue;

                int commaIdx = base64.indexOf(",");
                if (commaIdx < 0) continue;
                byte[] imageBytes = Base64.getDecoder().decode(base64.substring(commaIdx + 1));

                File outFile = new File(screenshotsDir, filename);
                try (FileOutputStream fos = new FileOutputStream(outFile)) {
                    fos.write(imageBytes);
                }
            }
        }

        // 写入测试信息配置截图
        List<String> configBase64List = data.getTestInfoConfigBase64Screenshots();
        List<String> configFilenameList = data.getTestInfoConfigScreenshotFilenames();
        if (configBase64List != null && configFilenameList != null) {
            for (int i = 0; i < configBase64List.size() && i < configFilenameList.size(); i++) {
                String base64 = configBase64List.get(i);
                String filename = configFilenameList.get(i);
                if (base64 == null || !base64.startsWith("data:image/")) continue;

                int commaIdx = base64.indexOf(",");
                if (commaIdx < 0) continue;
                byte[] imageBytes = Base64.getDecoder().decode(base64.substring(commaIdx + 1));

                File outFile = new File(screenshotsDir, filename);
                try (FileOutputStream fos = new FileOutputStream(outFile)) {
                    fos.write(imageBytes);
                }
            }
        }
    }

    /**
     * 使用 FreeMarker 渲染 index.html
     */
    private void writeIndexHtml(ReportData data, File reportDir) throws Exception {
        Map<String, Object> model = buildModel(data);
        // 添加 userInfoEntries 供模板使用
        model.put("userInfoEntries", data.getUserInfoEntries());
        File indexFile = new File(reportDir, "index.html");
        try (OutputStreamWriter osw = new OutputStreamWriter(
                new FileOutputStream(indexFile), StandardCharsets.UTF_8)) {
            FreeMarkerConfig.getInstance().getHtmlTemplate("html_report.ftl").process(model, osw);
        }
    }

    /**
     * 构建 FreeMarker 模型
     */
    private Map<String, Object> buildModel(ReportData data) {
        Map<String, Object> model = new HashMap<>();
        model.put("title", data.getTitle());
        model.put("generatedAt", DATE_FORMAT.format(data.getGeneratedAt()));
        model.put("pluginVersion", data.getPluginVersion());
        model.put("summary", data.getSummary());
        model.put("sessionBreakdown", data.getSessionBreakdown());
        model.put("escalatedEndpoints", data.getEscalatedEndpoints());
        model.put("errorEndpoints", data.getErrorEndpoints());
        model.put("safeEndpoints", data.getSafeEndpoints());
        model.put("endpoints", data.getEndpoints());
        // 测试信息配置（供单文件内联模式使用）
        if (data.getTestInfoConfig() != null) {
            model.put("testInfoConfig", data.getTestInfoConfig());
            model.put("testInfoConfigScreenshots", data.getTestInfoConfigBase64Screenshots());
        }
        return model;
    }
}
