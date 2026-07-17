package org.oxff.repeater.privilege.report;

import org.oxff.repeater.config.SessionDirectory;
import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.utils.FileChooserHelper;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;

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

        // 预生成统一时间戳，确保外部文件名和容器内部文件名一致
        final String exportTimestamp = SessionDirectory.generateTimestamp();

        final boolean isHtml = "html".equals(format);
        final boolean useContainer = encryptionMode != ReportContainerWriter.EncryptionMode.PLAIN;

        File selectedFile;
        String outputExt = useContainer ? "ermr" : ext;

        if (isHtml && !useContainer) {
            // HTML 明文模式：选择目录
            String dirName = "privilege_test_report_" + exportTimestamp;
            javax.swing.filechooser.FileNameExtensionFilter dummyFilter =
                    new javax.swing.filechooser.FileNameExtensionFilter("文件夹", "___dummy___");
            selectedFile = FileChooserHelper.showSaveDialog(
                    FileChooserHelper.OP_REPORT_EXPORT, "选择导出目录", parent,
                    new File(dirName), dummyFilter);
        } else {
            // 单文件模式（PDF/MD/加密HTML）
            String defaultFilename = "privilege_test_report_" + exportTimestamp + "." + outputExt;
            javax.swing.filechooser.FileNameExtensionFilter saveFilter;
            if (useContainer) {
                saveFilter = new javax.swing.filechooser.FileNameExtensionFilter(
                        "ERM Report (*.ermr)", "ermr");
            } else {
                saveFilter = new javax.swing.filechooser.FileNameExtensionFilter(
                        format.toUpperCase() + " Report (*." + ext + ")", ext);
            }
            selectedFile = FileChooserHelper.showSaveDialog(
                    FileChooserHelper.OP_REPORT_EXPORT, "导出越权测试报告", parent,
                    new File(defaultFilename), saveFilter);
        }

        if (selectedFile == null) {
            return;
        }

        File outputFile = selectedFile;

        // 覆盖确认
        if (isHtml && !useContainer) {
            // HTML 多文件模式：检查目标目录是否非空
            if (outputFile.exists() && outputFile.isDirectory()) {
                File[] existingFiles = outputFile.listFiles(f -> !f.isHidden());
                if (existingFiles != null && existingFiles.length > 0) {
                    int overwrite = JOptionPane.showConfirmDialog(parent,
                            "目标目录已存在且非空，继续导出将覆盖其中的同名文件。\n"
                                    + outputFile.getAbsolutePath() + "\n\n是否继续？",
                            "确认覆盖", JOptionPane.YES_NO_OPTION,
                            JOptionPane.WARNING_MESSAGE);
                    if (overwrite != JOptionPane.YES_OPTION) {
                        return;
                    }
                }
            }
        } else {
            // 单文件模式：检查文件是否已存在
            if (outputFile.exists()) {
                int overwrite = JOptionPane.showConfirmDialog(parent,
                        "文件已存在，是否覆盖？\n" + outputFile.getAbsolutePath(),
                        "确认覆盖", JOptionPane.YES_NO_OPTION);
                if (overwrite != JOptionPane.YES_OPTION) {
                    return;
                }
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

        final String fExt = ext;
        final String fTimestamp = exportTimestamp;
        new Thread(() -> {
            try {
                SwingUtilities.invokeLater(() -> progressDialog.setVisible(true));

                LogManager.getInstance().printOutput("[*] 开始生成越权测试报告...");
                ReportData data = finalGenerator.collectData();

                if (isHtml && !useContainer) {
                    // HTML 多文件明文模式：写入目录
                    File reportDir = finalFile;
                    if (!reportDir.exists()) {
                        reportDir.mkdirs();
                    }
                    ((HtmlReportGenerator) finalGenerator).generateToDirectory(data, reportDir);

                    SwingUtilities.invokeLater(() -> {
                        progressDialog.dispose();
                        JOptionPane.showMessageDialog(parent,
                                "报告导出成功！\n" + reportDir.getAbsolutePath(),
                                "导出成功", JOptionPane.INFORMATION_MESSAGE);
                    });
                    LogManager.getInstance().printOutput("[+] HTML 多文件报告导出成功: " + reportDir.getAbsolutePath());
                } else if (isHtml && useContainer) {
                    // HTML 多文件加密模式：先生成到临时目录，再 ZIP 打包加密
                    File tempDir = new File(System.getProperty("java.io.tmpdir"),
                            "erm_report_" + fTimestamp);
                    if (tempDir.exists()) {
                        deleteRecursively(tempDir.toPath());
                    }
                    tempDir.mkdirs();
                    try {
                        ((HtmlReportGenerator) finalGenerator).generateToDirectory(data, tempDir);

                        ReportContainerWriter containerWriter = new ReportContainerWriter();
                        boolean success = containerWriter.write(finalFile, tempDir,
                                encryptionMode, parent);
                        if (!success) {
                            SwingUtilities.invokeLater(() -> progressDialog.dispose());
                            return;
                        }

                        SwingUtilities.invokeLater(() -> {
                            progressDialog.dispose();
                            JOptionPane.showMessageDialog(parent,
                                    "报告导出成功！\n" + finalFile.getAbsolutePath() + " (" + encryptionMode + ")",
                                    "导出成功", JOptionPane.INFORMATION_MESSAGE);
                        });
                        LogManager.getInstance().printOutput("[+] 加密 HTML 多文件报告导出成功: " + finalFile.getAbsolutePath());
                    } finally {
                        deleteRecursively(tempDir.toPath());
                    }
                } else {
                    // 单文件模式（PDF/MD）
                    byte[] reportBytes;
                    if ("pdf".equals(fExt)) {
                        reportBytes = ((PdfReportGenerator) finalGenerator).generateToBytes(data);
                    } else {
                        String content = finalGenerator.generate(data);
                        reportBytes = content.getBytes(StandardCharsets.UTF_8);
                    }

                    if (useContainer) {
                        String originalFilename = "privilege_test_report_" + fTimestamp + "." + fExt;
                        ReportContainerWriter containerWriter = new ReportContainerWriter();
                        boolean success = containerWriter.write(finalFile, reportBytes, originalFilename,
                                encryptionMode, parent);
                        if (!success) {
                            SwingUtilities.invokeLater(() -> progressDialog.dispose());
                            return;
                        }
                    } else {
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
                    LogManager.getInstance().printOutput("[+] 越权测试报告导出成功: " + finalFile.getAbsolutePath());
                }
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    progressDialog.dispose();
                    JOptionPane.showMessageDialog(parent,
                            "导出失败: " + e.getMessage(),
                            "导出错误", JOptionPane.ERROR_MESSAGE);
                });
                LogManager.getInstance().printError("[!] 越权测试报告导出失败: " + e.getMessage());
            }
        }).start();
    }

    private void deleteRecursively(Path path) {
        try {
            if (Files.exists(path)) {
                Files.walk(path)
                        .sorted(Comparator.reverseOrder())
                        .forEach(p -> {
                            try { Files.delete(p); } catch (IOException e) {
                                LogManager.getInstance().debug("[*] 临时文件删除失败: " + p + " - " + e.getMessage());
                            }
                        });
            }
        } catch (IOException e) {
            LogManager.getInstance().debug("[*] 临时目录清理失败: " + path + " - " + e.getMessage());
        }
    }

    /**
     * 解密报告文件 (UI 入口)
     */
    public static void decryptReportFile(Component parent) {
        ReportContainerReader reader = new ReportContainerReader();
        reader.extractAndSave(parent);
    }
}
