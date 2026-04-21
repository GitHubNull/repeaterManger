package oxff.top.io;

import burp.BurpExtender;
import oxff.top.db.DatabaseManager;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.nio.file.FileVisitOption;
import java.nio.file.FileVisitResult;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.EnumSet;

/**
 * SQLite数据库导出器
 */
public class SQLiteExporter {
    private final DatabaseManager dbManager;

    public SQLiteExporter() {
        this.dbManager = DatabaseManager.getInstance();
    }

    /**
     * 导出当前数据库到SQLite文件
     */
    public boolean export(Component parent) {
        try {
            BurpExtender.printOutput("[+] 开始SQLite数据库导出过程");

            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("导出SQLite数据库");
            FileNameExtensionFilter filter = new FileNameExtensionFilter(
                "SQLite Files (*.sqlite3, *.db)", "sqlite3", "db");
            fileChooser.setFileFilter(filter);
            fileChooser.setSelectedFile(new File("replayer_export.sqlite3"));

            int result = fileChooser.showSaveDialog(parent);
            if (result != JFileChooser.APPROVE_OPTION) {
                return false;
            }

            File outputFile = fileChooser.getSelectedFile();

            // 确保有正确的扩展名
            String name = outputFile.getName().toLowerCase();
            if (!name.endsWith(".sqlite3") && !name.endsWith(".db") && !name.endsWith(".sqlite")) {
                outputFile = new File(outputFile.getAbsolutePath() + ".sqlite3");
            }

            // 确认覆盖
            if (outputFile.exists()) {
                int overwrite = JOptionPane.showConfirmDialog(
                    parent, "文件已存在，是否覆盖？", "确认覆盖", JOptionPane.YES_NO_OPTION);
                if (overwrite != JOptionPane.YES_OPTION) {
                    return false;
                }
            }

            // 获取源数据库路径
            String currentDbPath = dbManager.getCurrentDatabasePath();
            if (currentDbPath == null) {
                currentDbPath = dbManager.getConfig().getDatabasePath();
            }
            File sourceDb = new File(currentDbPath);

            // 如果源文件不存在，尝试初始化
            if (!sourceDb.exists()) {
                if (!dbManager.initialize()) {
                    throw new IOException("无法初始化数据库");
                }
                try (Connection conn = dbManager.getConnection();
                     Statement stmt = conn.createStatement()) {
                    stmt.executeQuery("SELECT 1");
                } catch (SQLException e) {
                    throw new IOException("创建数据库文件失败: " + e.getMessage());
                }
            }

            if (!sourceDb.exists()) {
                throw new IOException("源数据库文件不存在");
            }

            // 复制数据库文件
            copyFile(sourceDb, outputFile);

            // 复制 blobs/ 目录（v2 Schema 的文件型 Body 存储）
            File sourceDir = sourceDb.getParentFile();
            File sourceBlobs = new File(sourceDir, "blobs");
            if (sourceBlobs.exists() && sourceBlobs.isDirectory()) {
                File outputDir = outputFile.getParentFile();
                File targetBlobs = new File(outputDir, "blobs");
                copyDirectory(sourceBlobs, targetBlobs);
                BurpExtender.printOutput("[+] blobs/ 目录已复制");
            }

            BurpExtender.printOutput("[+] 数据导出成功: " + outputFile.getAbsolutePath());
            JOptionPane.showMessageDialog(parent,
                "SQLite数据库导出成功！\n文件: " + outputFile.getAbsolutePath(),
                "导出成功", JOptionPane.INFORMATION_MESSAGE);
            return true;

        } catch (Exception e) {
            BurpExtender.printError("[!] 导出SQLite失败: " + e.getMessage());
            JOptionPane.showMessageDialog(parent,
                "导出失败: " + e.getMessage(), "导出错误", JOptionPane.ERROR_MESSAGE);
            return false;
        }
    }

    private void copyFile(File source, File dest) throws IOException {
        File parentDir = dest.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs();
        }

        try {
            Files.copy(source.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
            return;
        } catch (IOException e) {
            BurpExtender.printOutput("[*] NIO复制失败，尝试文件流方式...");
        }

        try (FileInputStream fis = new FileInputStream(source);
             FileOutputStream fos = new FileOutputStream(dest)) {
            byte[] buffer = new byte[8192];
            int length;
            while ((length = fis.read(buffer)) > 0) {
                fos.write(buffer, 0, length);
            }
            return;
        } catch (IOException e) {
            BurpExtender.printOutput("[*] 文件流复制失败，尝试FileChannel...");
        }

        try (FileInputStream fis = new FileInputStream(source);
             FileOutputStream fos = new FileOutputStream(dest);
             FileChannel inChannel = fis.getChannel();
             FileChannel outChannel = fos.getChannel()) {
            long size = inChannel.size();
            long position = 0;
            while (position < size) {
                position += inChannel.transferTo(position, 1024 * 1024, outChannel);
            }
        }
    }

    /**
     * 递归复制目录
     */
    private void copyDirectory(File source, File target) throws IOException {
        if (!source.exists()) return;

        Path sourcePath = source.toPath();
        Path targetPath = target.toPath();

        java.nio.file.Files.walkFileTree(sourcePath, EnumSet.noneOf(FileVisitOption.class), Integer.MAX_VALUE,
            new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                    Path relative = sourcePath.relativize(dir);
                    Path targetDir = targetPath.resolve(relative);
                    java.nio.file.Files.createDirectories(targetDir);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Path relative = sourcePath.relativize(file);
                    java.nio.file.Files.copy(file, targetPath.resolve(relative), StandardCopyOption.REPLACE_EXISTING);
                    return FileVisitResult.CONTINUE;
                }
            });
    }
}
