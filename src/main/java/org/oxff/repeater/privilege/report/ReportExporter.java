package org.oxff.repeater.privilege.report;

import burp.BurpExtender;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * 报告导出 UI 入口
 * 处理格式选择、加密模式、文件保存对话框、异步生成和进度显示
 */
public class ReportExporter {

    private final Component parent;

    public ReportExporter(Component parent) {
        this.parent = parent;
    }

    /**
     * 导出报告
     *
     * @param format         "html" | "md" | "pdf"
     * @param encryptionMode 加密压缩模式
     */
    public void export(String format, ReportContainerWriter.EncryptionMode encryptionMode) {
        ReportGenerator generator;
        String ext;
        switch (format) {
            case "html":
                generator = new HtmlReportGenerator();
                ext = "html";
                break;
            case "md":
                generator = new MarkdownReportGenerator();
                ext = "md";
                break;
            case "pdf":
                generator = new PdfReportGenerator();
                ext = "pdf";
                break;
            default:
                JOptionPane.showMessageDialog(parent,
                        "不支持的格式: " + format, "错误", JOptionPane.ERROR_MESSAGE);
                return;
        }

        // 文件保存对话框
        boolean useContainer = encryptionMode != ReportContainerWriter.EncryptionMode.PLAIN;
        String outputExt = useContainer ? "ermr" : ext;
        String defaultFilename = "privilege_test_report." + outputExt;

        javax.swing.filechooser.FileNameExtensionFilter saveFilter;
        if (useContainer) {
            saveFilter = new javax.swing.filechooser.FileNameExtensionFilter(
                    "ERM Report (*.ermr)", "ermr");
        } else {
            saveFilter = new javax.swing.filechooser.FileNameExtensionFilter(
                    format.toUpperCase() + " Report (*." + ext + ")", ext);
        }

        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showSaveDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_REPORT_EXPORT, "导出越权测试报告", parent,
                new File(defaultFilename), saveFilter);

        if (selectedFile == null) {
            return;
        }

        File outputFile = selectedFile;
        if (!outputFile.getName().contains(".")) {
            outputFile = new File(outputFile.getAbsolutePath() + "." + outputExt);
        }

        // 覆盖确认
        if (outputFile.exists()) {
            int overwrite = JOptionPane.showConfirmDialog(parent,
                    "文件已存在，是否覆盖？\n" + outputFile.getAbsolutePath(),
                    "确认覆盖", JOptionPane.YES_NO_OPTION);
            if (overwrite != JOptionPane.YES_OPTION) {
                return;
            }
        }

        // 敏感数据警告
        int confirm = JOptionPane.showConfirmDialog(parent,
                "报告将包含完整的请求/响应数据，可能包含\n"
                        + "Bearer Token、Session Cookie 等敏感信息。\n"
                        + "请确保报告文件的安全存储。\n\n是否继续？",
                "敏感数据警告", JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) {
            return;
        }

        // 异步生成
        final File finalFile = outputFile;
        final ReportGenerator finalGenerator = generator;

        // 进度对话框
        JDialog progressDialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(parent),
                "生成报告...", true);
        progressDialog.setLayout(new BorderLayout());
        progressDialog.add(new JLabel("正在生成报告，请稍候...", SwingConstants.CENTER), BorderLayout.CENTER);
        JProgressBar progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        progressDialog.add(progressBar, BorderLayout.SOUTH);
        progressDialog.setSize(300, 100);
        progressDialog.setLocationRelativeTo(parent);

        new Thread(() -> {
            try {
                SwingUtilities.invokeLater(() -> progressDialog.setVisible(true));

                BurpExtender.printOutput("[*] 开始生成越权测试报告...");
                ReportData data = finalGenerator.collectData();

                // 生成报告内容为 byte[]
                byte[] reportBytes;
                if ("pdf".equals(format)) {
                    reportBytes = ((PdfReportGenerator) finalGenerator).generateToBytes(data);
                } else {
                    String content = finalGenerator.generate(data);
                    reportBytes = content.getBytes(StandardCharsets.UTF_8);
                }

                // 根据加密模式输出
                if (useContainer) {
                    String originalFilename = "privilege_test_report." + ext;
                    ReportContainerWriter containerWriter = new ReportContainerWriter();
                    boolean success = containerWriter.write(finalFile, reportBytes, originalFilename,
                            encryptionMode, parent);
                    if (!success) {
                        // 用户取消密码输入
                        SwingUtilities.invokeLater(() -> {
                            progressDialog.dispose();
                        });
                        return;
                    }
                } else {
                    // 明文模式: 直接写文件
                    try (FileOutputStream fos = new FileOutputStream(finalFile)) {
                        fos.write(reportBytes);
                    }
                }

                SwingUtilities.invokeLater(() -> {
                    progressDialog.dispose();
                    String modeDesc = useContainer ? " (" + encryptionMode + ")" : " (明文)";
                    JOptionPane.showMessageDialog(parent,
                            "报告导出成功！\n" + finalFile.getAbsolutePath() + modeDesc,
                            "导出成功", JOptionPane.INFORMATION_MESSAGE);
                });
                BurpExtender.printOutput("[+] 越权测试报告导出成功: " + finalFile.getAbsolutePath());
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    progressDialog.dispose();
                    JOptionPane.showMessageDialog(parent,
                            "导出失败: " + e.getMessage(),
                            "导出错误", JOptionPane.ERROR_MESSAGE);
                });
                BurpExtender.printError("[!] 越权测试报告导出失败: " + e.getMessage());
            }
        }).start();
    }

    /**
     * 解密报告文件 (UI 入口)
     */
    public static void decryptReportFile(Component parent) {
        ReportContainerReader reader = new ReportContainerReader();
        reader.extractAndSave(parent);
    }
}
