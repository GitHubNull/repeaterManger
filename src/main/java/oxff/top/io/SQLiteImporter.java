package oxff.top.io;

import burp.BurpExtender;
import oxff.top.db.DatabaseManager;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.nio.file.FileVisitOption;
import java.nio.file.FileVisitResult;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.sql.SQLException;
import java.util.EnumSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * SQLite数据库导入器
 */
public class SQLiteImporter {
    private final DatabaseManager dbManager;
    private final AtomicBoolean isImporting = new AtomicBoolean(false);

    public SQLiteImporter() {
        this.dbManager = DatabaseManager.getInstance();
    }

    /**
     * 从SQLite文件导入（UI入口）
     */
    public boolean importFromFile(Component parent) {
        if (isImporting.get()) {
            JOptionPane.showMessageDialog(parent,
                "另一个导入操作正在进行中，请稍后再试。", "导入繁忙", JOptionPane.WARNING_MESSAGE);
            return false;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导入SQLite数据库");
        fileChooser.setFileFilter(new FileNameExtensionFilter(
            "SQLite数据库文件 (*.sqlite3, *.db)", "sqlite3", "db", "sqlite"));
        fileChooser.setAcceptAllFileFilterUsed(false);

        int result = fileChooser.showOpenDialog(parent);
        if (result != JFileChooser.APPROVE_OPTION) {
            return false;
        }

        File selectedFile = fileChooser.getSelectedFile();
        if (!selectedFile.exists() || !selectedFile.isFile()) {
            JOptionPane.showMessageDialog(parent, "所选文件不存在", "导入错误", JOptionPane.ERROR_MESSAGE);
            return false;
        }

        int confirm = JOptionPane.showConfirmDialog(parent,
            "导入操作将使用新的数据库文件，当前会话数据将不可用。\n是否继续？",
            "确认导入", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);

        if (confirm != JOptionPane.YES_OPTION) {
            return false;
        }

        isImporting.set(true);
        CompletableFuture.runAsync(() -> {
            try {
                doImport(selectedFile, parent);
                JOptionPane.showMessageDialog(parent, "数据导入成功", "导入成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                BurpExtender.printError("[!] 导入数据失败: " + e.getMessage());
                JOptionPane.showMessageDialog(parent,
                    "导入数据失败: " + e.getMessage(), "导入错误", JOptionPane.ERROR_MESSAGE);
            } finally {
                isImporting.set(false);
            }
        });

        return true;
    }

    /**
     * 执行导入：将源SQLite复制到新的会话数据库文件
     */
    private void doImport(File sourceFile, Component parent) throws IOException, SQLException {
        BurpExtender.printOutput("[*] 开始SQLite数据库导入...");

        // 新策略：将源文件复制到当前基础目录下的新自动生成的文件名
        String newDbPath = dbManager.getConfig().getEffectiveDatabasePath();
        File targetFile = new File(newDbPath);
        File targetDir = targetFile.getParentFile();

        if (targetDir != null && !targetDir.exists()) {
            targetDir.mkdirs();
        }

        // 复制文件
        Files.copy(sourceFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        BurpExtender.printOutput("[+] 已复制数据库文件到: " + targetFile.getAbsolutePath());

        // 复制 blobs/ 目录（v2 Schema 的文件型 Body 存储）
        File sourceDir = sourceFile.getParentFile();
        File sourceBlobs = new File(sourceDir, "blobs");
        if (sourceBlobs.exists() && sourceBlobs.isDirectory()) {
            File targetBlobs = new File(targetDir, "blobs");
            copyDirectory(sourceBlobs, targetBlobs);
            BurpExtender.printOutput("[+] blobs/ 目录已复制");
        }

        // 设置为当前会话文件并重新初始化
        dbManager.getConfig().setSessionFile(newDbPath);
        dbManager.resetForNewSession();

        boolean success = dbManager.initialize();
        if (!success) {
            throw new SQLException("导入数据库后初始化失败");
        }

        BurpExtender.printOutput("[+] 数据导入成功，新数据库: " + newDbPath);

        // 刷新UI
        refreshUIAfterImport();
    }

    /**
     * 递归复制目录
     */
    private void copyDirectory(File source, File target) throws IOException {
        if (!source.exists()) return;

        Path sourcePath = source.toPath();
        Path targetPath = target.toPath();

        Files.walkFileTree(sourcePath, EnumSet.noneOf(FileVisitOption.class), Integer.MAX_VALUE,
            new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                    Path relative = sourcePath.relativize(dir);
                    Path targetDir = targetPath.resolve(relative);
                    Files.createDirectories(targetDir);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Path relative = sourcePath.relativize(file);
                    Files.copy(file, targetPath.resolve(relative), StandardCopyOption.REPLACE_EXISTING);
                    return FileVisitResult.CONTINUE;
                }
            });
    }

    private void refreshUIAfterImport() {
        try {
            java.lang.reflect.Field repeaterUIField = burp.BurpExtender.class.getDeclaredField("repeaterUI");
            repeaterUIField.setAccessible(true);
            Object repeaterUIObj = repeaterUIField.get(null);
            if (repeaterUIObj != null && repeaterUIObj instanceof oxff.top.EnhancedRepeaterUI) {
                ((oxff.top.EnhancedRepeaterUI) repeaterUIObj).refreshAllData();
                BurpExtender.printOutput("[+] 界面数据刷新成功");
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 刷新界面数据时出错: " + e.getMessage());
        }
    }
}
