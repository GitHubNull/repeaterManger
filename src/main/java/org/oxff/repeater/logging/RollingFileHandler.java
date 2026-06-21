package org.oxff.repeater.logging;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

/**
 * 文件滚动日志处理器 - 将日志写入本地文件，支持大小滚动
 * <p>
 * 滚动策略：
 * - 当前日志文件: repeater_manager.log
 * - 滚动备份文件: repeater_manager.log.1 ~ repeater_manager.log.N
 * - 当文件大小超过 maxFileSize 时触发滚动
 */
public class RollingFileHandler implements LogHandler {

    private static final String BASE_FILENAME = "repeater_manager.log";

    private volatile boolean enabled = true;
    private final String logDirectory;
    private final long maxFileSize;
    private final int maxBackups;
    private final File currentLogFile;

    private BufferedWriter writer;
    private final Object writeLock = new Object();

    /**
     * 创建文件滚动日志处理器
     *
     * @param logDirectory 日志目录路径
     * @param maxFileSize  单文件最大字节数（默认5MB）
     * @param maxBackups   最大备份数（默认5）
     */
    public RollingFileHandler(String logDirectory, long maxFileSize, int maxBackups) throws IOException {
        this.logDirectory = logDirectory;
        this.maxFileSize = maxFileSize > 0 ? maxFileSize : 5 * 1024 * 1024; // 默认5MB
        this.maxBackups = maxBackups > 0 ? maxBackups : 5;

        // 确保日志目录存在
        File dir = new File(logDirectory);
        if (!dir.exists()) {
            dir.mkdirs();
        }

        this.currentLogFile = new File(dir, BASE_FILENAME);
        openWriter();
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    private void openWriter() throws IOException {
        writer = new BufferedWriter(
            new OutputStreamWriter(new FileOutputStream(currentLogFile, true), StandardCharsets.UTF_8));
    }

    @Override
    public void publish(LogEntry entry) {
        if (!enabled || writer == null) {
            return;
        }

        String line = entry.getFileFormattedMesssage();

        synchronized (writeLock) {
            try {
                writer.write(line);
                writer.newLine();
                writer.flush();

                // 检查是否需要滚动
                if (currentLogFile.length() > maxFileSize) {
                    rollOver();
                }
            } catch (IOException e) {
                System.err.println("写入日志文件失败: " + e.getMessage());
            }
        }
    }

    /**
     * 执行日志文件滚动
     * 删除最老的备份，依次重命名，当前文件变为 .1
     */
    private void rollOver() {
        synchronized (writeLock) {
            try {
                // 关闭当前写入流
                if (writer != null) {
                    writer.close();
                }

                // 删除最老的备份文件
                File oldestBackup = new File(logDirectory, BASE_FILENAME + "." + maxBackups);
                if (oldestBackup.exists()) {
                    oldestBackup.delete();
                }

                // 依次重命名备份文件：.N-1 -> .N, ..., .1 -> .2
                for (int i = maxBackups - 1; i >= 1; i--) {
                    File backup = new File(logDirectory, BASE_FILENAME + "." + i);
                    if (backup.exists()) {
                        File newBackup = new File(logDirectory, BASE_FILENAME + "." + (i + 1));
                        backup.renameTo(newBackup);
                    }
                }

                // 当前日志文件重命名为 .1
                File firstBackup = new File(logDirectory, BASE_FILENAME + ".1");
                currentLogFile.renameTo(firstBackup);

                // 创建新的空日志文件
                openWriter();
            } catch (IOException e) {
                System.err.println("日志文件滚动失败: " + e.getMessage());
                try {
                    openWriter();
                } catch (IOException ex) {
                    System.err.println("重新打开日志文件失败: " + ex.getMessage());
                }
            }
        }
    }

    @Override
    public void flush() {
        synchronized (writeLock) {
            if (writer != null) {
                try {
                    writer.flush();
                } catch (IOException e) {
                    System.err.println("刷新日志文件失败: " + e.getMessage());
                }
            }
        }
    }

    @Override
    public void close() {
        synchronized (writeLock) {
            if (writer != null) {
                try {
                    writer.flush();
                    writer.close();
                } catch (IOException e) {
                    System.err.println("关闭日志文件失败: " + e.getMessage());
                }
                writer = null;
            }
        }
    }
}
