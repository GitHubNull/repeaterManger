package oxff.top.io;

import burp.BurpExtender;
import oxff.top.db.DatabaseManager;
import oxff.top.db.HistoryDAO;
import oxff.top.db.RequestDAO;
import oxff.top.http.RequestResponseRecord;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Color;
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
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
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
     * 从SQLite数据库直接导入数据到当前数据库（合并模式）
     * 使用 DAO 层写入，自动适配 v2 Schema（去重存储）
     */
    public void importDataFromSQLite(String sourceDbPath) {
        try {
            File sourceFile = new File(sourceDbPath);
            if (!sourceFile.exists()) {
                BurpExtender.printError("[!] 源数据库文件不存在: " + sourceDbPath);
                return;
            }

            RequestDAO requestDAO = new RequestDAO();
            HistoryDAO historyDAO = new HistoryDAO();

            Connection sourceConn = java.sql.DriverManager.getConnection("jdbc:sqlite:" + sourceDbPath);

            try {
                // 导入请求数据
                Statement stmt = sourceConn.createStatement();
                ResultSet rs = stmt.executeQuery("SELECT * FROM requests");

                while (rs.next()) {
                    String protocol = rs.getString("protocol");
                    String domain = rs.getString("domain");
                    String path = rs.getString("path");
                    String query = rs.getString("query");
                    String method = rs.getString("method");
                    String comment = rs.getString("comment");
                    String colorStr = rs.getString("color");
                    byte[] requestData = rs.getBytes("request_data");

                    int newId = requestDAO.saveRequest(protocol, domain, path, query, method, requestData);

                    if (newId > 0) {
                        if (comment != null && !comment.isEmpty()) {
                            requestDAO.updateRequestComment(newId, comment);
                        }
                        if (colorStr != null && !colorStr.isEmpty()) {
                            try {
                                requestDAO.updateRequestColor(newId, Color.decode(colorStr));
                            } catch (Exception e) {
                                // 忽略颜色解析错误
                            }
                        }
                    }
                }

                // 导入历史数据
                rs = stmt.executeQuery("SELECT * FROM history");
                while (rs.next()) {
                    RequestResponseRecord record = new RequestResponseRecord();

                    int requestId = rs.getInt("request_id");
                    if (rs.wasNull()) {
                        requestId = -1;
                    }
                    record.setRequestId(requestId);
                    record.setMethod(rs.getString("method"));
                    record.setProtocol(rs.getString("protocol"));
                    record.setDomain(rs.getString("domain"));
                    record.setPath(rs.getString("path"));
                    record.setQueryParameters(rs.getString("query"));
                    record.setStatusCode(rs.getInt("status_code"));
                    record.setResponseLength(rs.getInt("response_length"));
                    record.setResponseTime(rs.getInt("response_time"));
                    record.setComment(rs.getString("comment"));

                    String colorStr = rs.getString("color");
                    if (colorStr != null && !colorStr.isEmpty()) {
                        try {
                            record.setColor(Color.decode(colorStr));
                        } catch (Exception e) {
                            // 忽略颜色解析错误
                        }
                    }

                    record.setRequestData(rs.getBytes("request_data"));
                    record.setResponseData(rs.getBytes("response_data"));

                    historyDAO.saveHistory(record);
                }

                BurpExtender.printOutput("[+] SQLite数据合并导入完成");

            } catch (Exception e) {
                BurpExtender.printError("[!] 导入数据时出错: " + e.getMessage());
            } finally {
                sourceConn.close();
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 导入数据库时出错: " + e.getMessage());
        }
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
