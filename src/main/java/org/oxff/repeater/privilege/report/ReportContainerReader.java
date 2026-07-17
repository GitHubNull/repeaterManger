package org.oxff.repeater.privilege.report;

import org.oxff.repeater.io.ErmCryptoHelper;
import org.oxff.repeater.io.ErmFormatConstants;

import javax.swing.*;
import java.awt.Component;
import java.awt.Frame;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.zip.CRC32;
import java.util.zip.Inflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * .ermr 容器读取/解密器
 * 读取加密压缩的报告容器文件，还原为原始报告
 */
public class ReportContainerReader {

    /** 容器头魔法数字 */
    private static final byte[] MAGIC_HEADER = {(byte) 0x89, 0x45, 0x52, 0x52};
    /** 容器尾魔法数字 */
    private static final byte[] MAGIC_FOOTER = {0x45, 0x52, 0x52, 0x45};
    /** 标志位: 加密 */
    private static final int FLAG_ENCRYPTED = 0x00000001;
    /** 标志位: 压缩 */
    private static final int FLAG_COMPRESSED = 0x00000002;
    /** 缓冲区大小 */
    private static final int BUFFER_SIZE = 8192;

    // ========== 数据结构 ==========

    /** 容器头解析结果 */
    static class ContainerHeader {
        final int formatVersion;
        final int flags;
        final String originalFilename;
        final long originalSize;
        final boolean isEncrypted;
        final boolean isCompressed;

        ContainerHeader(int formatVersion, int flags, String originalFilename,
                        long originalSize, boolean isEncrypted, boolean isCompressed) {
            this.formatVersion = formatVersion;
            this.flags = flags;
            this.originalFilename = originalFilename;
            this.originalSize = originalSize;
            this.isEncrypted = isEncrypted;
            this.isCompressed = isCompressed;
        }
    }

    /** 提取结果 */
    static class ExtractionResult {
        final String originalFilename;
        final byte[] content;
        final long originalSize;

        ExtractionResult(String originalFilename, byte[] content, long originalSize) {
            this.originalFilename = originalFilename;
            this.content = content;
            this.originalSize = originalSize;
        }
    }

    // ========== 核心读取方法 ==========

    /**
     * 仅读取容器头信息（不解密不解压），用于在 UI 流程中提前判断文件是否加密
     *
     * @param inputFile 输入文件
     * @return 容器头信息
     * @throws IOException 读取/格式错误
     */
    public ContainerHeader readHeaderOnly(File inputFile) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(inputFile, "r")) {
            return readHeader(raf);
        }
    }

    /**
     * 读取 .ermr 容器，解密解压后返回原始报告
     *
     * @param inputFile 输入文件
     * @param parent    父组件 (用于密码对话框，已废弃，传 null 即可)
     * @return 提取结果
     * @throws Exception 读取/解密/解压失败
     * @deprecated 使用 {@link #read(File, char[])} 代替，密码应由调用方在 EDT 上提前获取
     */
    @Deprecated
    public ExtractionResult read(File inputFile, Component parent) throws Exception {
        return read(inputFile, (char[]) null);
    }

    /**
     * 读取 .ermr 容器，解密解压后返回原始报告
     * 密码由调用方提前获取，不在内部弹出密码对话框
     *
     * @param inputFile 输入文件
     * @param password  加密密码，文件未加密时传 null；加密时传 null 则抛出异常
     * @return 提取结果
     * @throws Exception 读取/解密/解压失败
     */
    public ExtractionResult read(File inputFile, char[] password) throws Exception {
        try (RandomAccessFile raf = new RandomAccessFile(inputFile, "r")) {
            // 1. 读取并验证 Header
            ContainerHeader header = readHeader(raf);
            long headerEnd = raf.getFilePointer();

            // 2. 读取 Footer 并验证，获取 Data CRC
            long fileLength = raf.length();
            if (fileLength < headerEnd + 12) {
                throw new IOException("Invalid .ermr file: too short for footer");
            }
            long dataEnd = fileLength - 12;
            int expectedDataCrc = verifyFooter(raf, dataEnd);

            // 3. 读取 Data 段
            long dataStart = headerEnd;
            // 如果加密，data段前有64字节crypto header
            if (header.isEncrypted) {
                dataStart = headerEnd + ErmFormatConstants.CRYPTO_HEADER_SIZE;
            }

            int dataLength = (int) (dataEnd - dataStart);
            if (dataLength < 0) {
                throw new IOException("Invalid .ermr file: negative data length");
            }

            byte[] dataBytes = new byte[dataLength];
            raf.seek(dataStart);
            raf.readFully(dataBytes);

            // 4. 验证 Data CRC（对存储态数据校验，即加密/压缩后的数据）
            CRC32 dataCrc = new CRC32();
            dataCrc.update(dataBytes);
            int computedDataCrc = (int) dataCrc.getValue();
            if (computedDataCrc != expectedDataCrc) {
                throw new IOException("Invalid .ermr file: data CRC mismatch (file may be corrupted)");
            }

            // 5. 解密 (如果加密)
            if (header.isEncrypted) {
                if (password == null) {
                    throw new SecurityException("加密文件需要密码，但未提供密码");
                }
                dataBytes = decryptData(raf, headerEnd, header, password);
            }

            // 6. 解压 (如果压缩)
            if (header.isCompressed) {
                dataBytes = decompressData(dataBytes, (int) header.originalSize);
            }

            return new ExtractionResult(header.originalFilename, dataBytes, header.originalSize);
        }
    }

    /**
     * 读取并验证容器头
     */
    private ContainerHeader readHeader(RandomAccessFile raf) throws IOException {
        // Magic (4B)
        byte[] magic = new byte[4];
        raf.readFully(magic);
        if (!arrayEquals(magic, MAGIC_HEADER)) {
            throw new IOException("Invalid .ermr file: bad magic header");
        }

        // Format Version (2B)
        int formatVersion = raf.readShort() & 0xFFFF;
        if (formatVersion > 1) {
            throw new IOException("Unsupported .ermr format version: " + formatVersion);
        }

        // Flags (4B)
        int flags = raf.readInt();

        // Original Filename: 2B length + UTF-8 bytes
        int filenameLen = raf.readShort() & 0xFFFF;
        if (filenameLen > 1024) {
            throw new IOException("Invalid .ermr file: filename too long (" + filenameLen + ")");
        }
        byte[] filenameBytes = new byte[filenameLen];
        raf.readFully(filenameBytes);
        String originalFilename = new String(filenameBytes, StandardCharsets.UTF_8);

        // Original Size (8B)
        long originalSize = raf.readLong();

        // Header CRC (4B) - 验证
        long headerEndBeforeCrc = raf.getFilePointer();
        int expectedHeaderCrc = raf.readInt();

        // 回读 header bytes 计算 CRC
        long savedPos = raf.getFilePointer();
        raf.seek(0);
        byte[] headerBytes = new byte[(int) headerEndBeforeCrc];
        raf.readFully(headerBytes);
        raf.seek(savedPos);

        CRC32 headerCrc = new CRC32();
        headerCrc.update(headerBytes);
        int computedHeaderCrc = (int) headerCrc.getValue();

        if (computedHeaderCrc != expectedHeaderCrc) {
            throw new IOException("Invalid .ermr file: header CRC mismatch (file may be corrupted)");
        }

        boolean isEncrypted = (flags & FLAG_ENCRYPTED) != 0;
        boolean isCompressed = (flags & FLAG_COMPRESSED) != 0;

        return new ContainerHeader(formatVersion, flags, originalFilename, originalSize,
                isEncrypted, isCompressed);
    }

    /**
     * 验证 Footer 并返回 Data CRC
     *
     * @param raf         随机访问文件
     * @param footerStart Footer 起始位置
     * @return Footer 中记录的 Data CRC 值
     */
    private int verifyFooter(RandomAccessFile raf, long footerStart) throws IOException {
        raf.seek(footerStart);

        // Magic (4B)
        byte[] magic = new byte[4];
        raf.readFully(magic);
        if (!arrayEquals(magic, MAGIC_FOOTER)) {
            throw new IOException("Invalid .ermr file: bad footer magic (file may be truncated)");
        }

        // Data CRC (4B)
        int expectedDataCrc = raf.readInt();

        // Footer CRC (4B)
        int expectedFooterCrc = raf.readInt();

        // 验证 Footer CRC
        raf.seek(footerStart);
        byte[] footerPrefix = new byte[8];
        raf.readFully(footerPrefix);
        CRC32 footerCrc = new CRC32();
        footerCrc.update(footerPrefix);
        int computedFooterCrc = (int) footerCrc.getValue();

        if (computedFooterCrc != expectedFooterCrc) {
            throw new IOException("Invalid .ermr file: footer CRC mismatch (file may be corrupted)");
        }

        return expectedDataCrc;
    }

    /**
     * 解密数据
     *
     * @param raf               随机访问文件
     * @param cryptoHeaderStart Crypto Header 起始位置
     * @param header            容器头
     * @param password          用户提供的密码
     */
    private byte[] decryptData(RandomAccessFile raf, long cryptoHeaderStart,
                               ContainerHeader header, char[] password) throws Exception {
        // 读取 Crypto Header
        raf.seek(cryptoHeaderStart);
        byte[] salt = new byte[ErmFormatConstants.SALT_SIZE];
        raf.readFully(salt);
        byte[] iv = new byte[ErmFormatConstants.IV_SIZE];
        raf.readFully(iv);
        byte[] hmac = new byte[ErmFormatConstants.HMAC_SIZE];
        raf.readFully(hmac);

        try {
            // 派生密钥
            ErmCryptoHelper.KeyPair keyPair = ErmCryptoHelper.deriveKeys(password, salt);

            // 读取密文
            long fileLength = raf.length();
            long dataStart = cryptoHeaderStart + ErmFormatConstants.CRYPTO_HEADER_SIZE;
            long dataEnd = fileLength - 12; // 减去footer
            int ciphertextLength = (int) (dataEnd - dataStart);
            if (ciphertextLength < 0) {
                throw new IOException("Invalid .ermr file: invalid data range for decryption");
            }

            byte[] ciphertext = new byte[ciphertextLength];
            raf.seek(dataStart);
            raf.readFully(ciphertext);

            // 验证 HMAC 并解密
            return ErmCryptoHelper.decrypt(ciphertext, iv, hmac, keyPair.aesKey, keyPair.hmacKey);
        } finally {
            ErmCryptoHelper.clearPassword(password);
        }
    }

    /**
     * 解压数据 (INFLATE)
     */
    private byte[] decompressData(byte[] compressed, int uncompressedSize) throws IOException {
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(compressed);

            // 如果知道原始大小，直接分配；否则逐步扩展
            if (uncompressedSize > 0 && uncompressedSize < 100 * 1024 * 1024) { // <100MB
                byte[] uncompressed = new byte[uncompressedSize];
                int total = 0;
                while (total < uncompressedSize) {
                    int read = inflater.inflate(uncompressed, total, uncompressedSize - total);
                    if (read == 0) break;
                    total += read;
                }
                if (total != uncompressedSize) {
                    throw new IOException("Decompressed size mismatch: expected " + uncompressedSize
                            + ", got " + total);
                }
                return uncompressed;
            } else {
                // 原始大小未知或过大，逐步解压
                ByteArrayOutputStream baos = new ByteArrayOutputStream(compressed.length * 2);
                byte[] buffer = new byte[BUFFER_SIZE];
                while (!inflater.finished()) {
                    int read = inflater.inflate(buffer);
                    if (read > 0) {
                        baos.write(buffer, 0, read);
                    } else {
                        break;
                    }
                }
                return baos.toByteArray();
            }
        } catch (Exception e) {
            throw new IOException("Decompression failed: " + e.getMessage(), e);
        } finally {
            inflater.end();
        }
    }

    // ========== UI 入口方法 ==========

    /**
     * 完整的 UI 解密还原流程:
     * 1. 文件选择器 (.ermr)
     * 2. 读取容器头，判断是否加密
     * 3. 若加密，先在 EDT 上弹出密码输入框
     * 4. 异步解密解压（此时才显示进度对话框）
     * 5. 保存对话框
     * 6. 写入文件
     *
     * @param parent 父组件
     * @return true=成功, false=用户取消或失败
     */
    public boolean extractAndSave(Component parent) {
        // 1. 文件选择器
        File inputFile = org.oxff.repeater.utils.FileChooserHelper.showOpenDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_REPORT_IMPORT, "选择加密报告文件", parent,
                new javax.swing.filechooser.FileNameExtensionFilter("ERM Report (*.ermr)", "ermr"));

        if (inputFile == null) {
            return false;
        }

        // 2. 读取容器头，判断是否加密（在 EDT 上同步执行，读取头很快）
        ContainerHeader header;
        try {
            header = readHeaderOnly(inputFile);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(parent,
                    "无法读取文件头: " + e.getMessage(),
                    "错误", JOptionPane.ERROR_MESSAGE);
            return false;
        }

        // 3. 若加密，先在 EDT 上弹出密码输入框
        char[] password = null;
        if (header.isEncrypted) {
            password = ErmCryptoHelper.promptPasswordForImport(parent);
            if (password == null) {
                // 用户取消输入密码
                return false;
            }
        }

        // 4. 异步解密解压（密码已获取，此时才显示进度对话框）
        JDialog progressDialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(parent),
                "解密报告...", true);
        progressDialog.setLayout(new java.awt.BorderLayout());
        progressDialog.add(new JLabel("正在解密报告，请稍候...", SwingConstants.CENTER),
                java.awt.BorderLayout.CENTER);
        JProgressBar progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        progressDialog.add(progressBar, java.awt.BorderLayout.SOUTH);
        progressDialog.setSize(300, 100);
        progressDialog.setLocationRelativeTo(parent);

        final boolean[] success = {false};
        final char[] finalPassword = password;

        new Thread(() -> {
            try {
                SwingUtilities.invokeLater(() -> progressDialog.setVisible(true));

                ExtractionResult result = read(inputFile, finalPassword);

                SwingUtilities.invokeLater(() -> {
                    progressDialog.dispose();

                    // 检测是否为 ZIP 打包的多文件报告
                    boolean isZip = result.originalFilename != null &&
                            result.originalFilename.toLowerCase().endsWith(".zip");

                    if (isZip) {
                        // 目录选择器（用于 ZIP 解压）
                        JFileChooser dirChooser = new JFileChooser();
                        dirChooser.setDialogTitle("选择解压目录");
                        dirChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                        dirChooser.setAcceptAllFileFilterUsed(false);
                        if (dirChooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) {
                            return;
                        }
                        File extractDir = dirChooser.getSelectedFile();

                        try {
                            // 解压 ZIP 到选中目录
                            try (ZipInputStream zis = new ZipInputStream(
                                    new ByteArrayInputStream(result.content))) {
                                ZipEntry entry;
                                while ((entry = zis.getNextEntry()) != null) {
                                    File outFile = new File(extractDir, entry.getName());
                                    if (entry.isDirectory()) {
                                        outFile.mkdirs();
                                    } else {
                                        outFile.getParentFile().mkdirs();
                                        Files.copy(zis, outFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                                    }
                                    zis.closeEntry();
                                }
                            }
                            JOptionPane.showMessageDialog(parent,
                                    "报告解密成功！\n" + extractDir.getAbsolutePath(),
                                    "解密成功", JOptionPane.INFORMATION_MESSAGE);
                            success[0] = true;
                        } catch (IOException ex) {
                            JOptionPane.showMessageDialog(parent,
                                    "解压失败: " + ex.getMessage(),
                                    "错误", JOptionPane.ERROR_MESSAGE);
                        }
                        return;
                    }

                    // 5. 普通单文件：保存对话框
                    File outputFile = org.oxff.repeater.utils.FileChooserHelper.showSaveDialog(
                            org.oxff.repeater.utils.FileChooserHelper.OP_REPORT_SAVE, "保存解密报告", parent,
                            new File(result.originalFilename));

                    if (outputFile == null) {
                        return;
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

                    // 6. 写入文件
                    try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                        fos.write(result.content);
                    } catch (IOException ex) {
                        JOptionPane.showMessageDialog(parent,
                                "保存文件失败: " + ex.getMessage(),
                                "错误", JOptionPane.ERROR_MESSAGE);
                        return;
                    }

                    JOptionPane.showMessageDialog(parent,
                            "报告解密成功！\n" + outputFile.getAbsolutePath(),
                            "解密成功", JOptionPane.INFORMATION_MESSAGE);
                    success[0] = true;
                });
            } catch (SecurityException e) {
                SwingUtilities.invokeLater(() -> {
                    progressDialog.dispose();
                    JOptionPane.showMessageDialog(parent,
                            "解密失败：密码错误或文件已被篡改",
                            "解密失败", JOptionPane.ERROR_MESSAGE);
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    progressDialog.dispose();
                    JOptionPane.showMessageDialog(parent,
                            "解密失败: " + e.getMessage(),
                            "错误", JOptionPane.ERROR_MESSAGE);
                });
            } finally {
                // 清理密码
                if (finalPassword != null) {
                    ErmCryptoHelper.clearPassword(finalPassword);
                }
            }
        }).start();

        return success[0];
    }

    // ========== 工具方法 ==========

    private static boolean arrayEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }
}
