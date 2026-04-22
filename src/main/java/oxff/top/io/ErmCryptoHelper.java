package oxff.top.io;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * ERM 存档加解密辅助类
 * 封装 AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC) 加密方案
 * 密钥派生使用 PBKDF2WithHmacSHA256
 */
public class ErmCryptoHelper {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private ErmCryptoHelper() {}

    // ========== 数据类 ==========

    /**
     * 密钥对：AES 密钥 + HMAC 密钥
     */
    public static class KeyPair {
        public final SecretKey aesKey;
        public final SecretKey hmacKey;

        public KeyPair(SecretKey aesKey, SecretKey hmacKey) {
            this.aesKey = aesKey;
            this.hmacKey = hmacKey;
        }
    }

    /**
     * 加密结果：IV + 密文 + HMAC
     */
    public static class EncryptionResult {
        public final byte[] iv;
        public final byte[] ciphertext;
        public final byte[] hmac;

        public EncryptionResult(byte[] iv, byte[] ciphertext, byte[] hmac) {
            this.iv = iv;
            this.ciphertext = ciphertext;
            this.hmac = hmac;
        }
    }

    // ========== 密钥派生 ==========

    /**
     * 从密码和盐值派生 AES 密钥和 HMAC 密钥
     * PBKDF2 输出 64 字节密钥材料，前 32 字节为 AES 密钥，后 32 字节为 HMAC 密钥
     *
     * @param password 用户密码
     * @param salt     盐值（16 字节）
     * @return KeyPair 包含 AES 密钥和 HMAC 密钥
     */
    public static KeyPair deriveKeys(char[] password, byte[] salt) throws Exception {
        PBEKeySpec keySpec = new PBEKeySpec(password, salt,
                ErmFormatConstants.PBKDF2_ITERATIONS,
                ErmFormatConstants.PBKDF2_KEY_MATERIAL_LENGTH * 8);

        SecretKeyFactory factory = SecretKeyFactory.getInstance(ErmFormatConstants.PBKDF2_ALGORITHM);
        byte[] keyMaterial = factory.generateSecret(keySpec).getEncoded();
        keySpec.clearPassword();

        try {
            byte[] aesKeyBytes = new byte[ErmFormatConstants.AES_KEY_SIZE];
            byte[] hmacKeyBytes = new byte[ErmFormatConstants.HMAC_KEY_SIZE];
            System.arraycopy(keyMaterial, 0, aesKeyBytes, 0, ErmFormatConstants.AES_KEY_SIZE);
            System.arraycopy(keyMaterial, ErmFormatConstants.AES_KEY_SIZE, hmacKeyBytes, 0, ErmFormatConstants.HMAC_KEY_SIZE);

            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            SecretKey hmacKey = new SecretKeySpec(hmacKeyBytes, ErmFormatConstants.HMAC_ALGORITHM);

            return new KeyPair(aesKey, hmacKey);
        } finally {
            // 清理临时密钥材料
            Arrays.fill(keyMaterial, (byte) 0);
        }
    }

    // ========== 加密 ==========

    /**
     * Encrypt-then-MAC 加密
     * 1. AES-256-CBC 加密明文
     * 2. HMAC-SHA256 对密文计算认证标签
     *
     * @param plaintext 明文数据
     * @param aesKey    AES 密钥
     * @param hmacKey   HMAC 密钥
     * @return EncryptionResult 包含 iv、密文、hmac
     */
    public static EncryptionResult encrypt(byte[] plaintext, SecretKey aesKey, SecretKey hmacKey) throws Exception {
        // 生成随机 IV
        byte[] iv = new byte[ErmFormatConstants.IV_SIZE];
        SECURE_RANDOM.nextBytes(iv);

        // AES-256-CBC 加密
        Cipher cipher = Cipher.getInstance(ErmFormatConstants.AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        // HMAC-SHA256 对密文计算认证标签 (Encrypt-then-MAC)
        Mac mac = Mac.getInstance(ErmFormatConstants.HMAC_ALGORITHM);
        mac.init(hmacKey);
        byte[] hmac = mac.doFinal(ciphertext);

        return new EncryptionResult(iv, ciphertext, hmac);
    }

    // ========== 解密 ==========

    /**
     * Verify-then-Decrypt 解密
     * 1. 先验证 HMAC（密文完整性 + 认证）
     * 2. HMAC 验证通过后 AES-256-CBC 解密
     *
     * @param ciphertext  密文数据
     * @param iv          初始化向量
     * @param expectedHmac 期望的 HMAC 值
     * @param aesKey      AES 密钥
     * @param hmacKey     HMAC 密钥
     * @return 解密后的明文
     * @throws Exception HMAC 验证失败或解密失败
     */
    public static byte[] decrypt(byte[] ciphertext, byte[] iv, byte[] expectedHmac,
                                  SecretKey aesKey, SecretKey hmacKey) throws Exception {
        // 先验证 HMAC (Verify-then-Decrypt)
        Mac mac = Mac.getInstance(ErmFormatConstants.HMAC_ALGORITHM);
        mac.init(hmacKey);
        byte[] computedHmac = mac.doFinal(ciphertext);

        if (!MessageDigest.isEqual(computedHmac, expectedHmac)) {
            throw new SecurityException("HMAC 验证失败：密码错误或存档数据已被篡改");
        }

        // HMAC 验证通过，执行解密
        Cipher cipher = Cipher.getInstance(ErmFormatConstants.AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }

    // ========== 盐值生成 ==========

    /**
     * 生成随机盐值
     *
     * @return 指定大小的随机盐值
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[ErmFormatConstants.SALT_SIZE];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    // ========== 密码输入 UI ==========

    /**
     * 导出时弹出密码输入对话框（两次确认）
     *
     * @param parent 父组件
     * @return 密码字符数组，用户取消返回 null
     */
    public static char[] promptPasswordForExport(Component parent) {
        javax.swing.JPasswordField passwordField = new javax.swing.JPasswordField(20);
        javax.swing.JPasswordField confirmField = new javax.swing.JPasswordField(20);

        javax.swing.JPanel panel = new javax.swing.JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new javax.swing.JLabel("输入密码:"), gbc);
        gbc.gridx = 1;
        panel.add(passwordField, gbc);

        gbc.gridx = 0; gbc.gridy = 1;
        panel.add(new javax.swing.JLabel("确认密码:"), gbc);
        gbc.gridx = 1;
        panel.add(confirmField, gbc);

        int result = javax.swing.JOptionPane.showConfirmDialog(
                parent, panel, "设置加密密码",
                javax.swing.JOptionPane.OK_CANCEL_OPTION,
                javax.swing.JOptionPane.PLAIN_MESSAGE);

        if (result != javax.swing.JOptionPane.OK_OPTION) {
            return null;
        }

        char[] password = passwordField.getPassword();
        char[] confirm = confirmField.getPassword();

        try {
            if (password.length == 0) {
                javax.swing.JOptionPane.showMessageDialog(parent,
                        "密码不能为空", "输入错误", javax.swing.JOptionPane.WARNING_MESSAGE);
                return null;
            }

            if (!Arrays.equals(password, confirm)) {
                javax.swing.JOptionPane.showMessageDialog(parent,
                        "两次输入的密码不一致", "输入错误", javax.swing.JOptionPane.WARNING_MESSAGE);
                return null;
            }

            char[] copy = password.clone();
            return copy;
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(confirm, '\0');
        }
    }

    /**
     * 导入时弹出密码输入对话框（一次输入）
     *
     * @param parent 父组件
     * @return 密码字符数组，用户取消返回 null
     */
    public static char[] promptPasswordForImport(Component parent) {
        javax.swing.JPasswordField passwordField = new javax.swing.JPasswordField(20);

        javax.swing.JPanel panel = new javax.swing.JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new javax.swing.JLabel("输入密码:"), gbc);
        gbc.gridx = 1;
        panel.add(passwordField, gbc);

        int result = javax.swing.JOptionPane.showConfirmDialog(
                parent, panel, "输入解密密码",
                javax.swing.JOptionPane.OK_CANCEL_OPTION,
                javax.swing.JOptionPane.PLAIN_MESSAGE);

        if (result != javax.swing.JOptionPane.OK_OPTION) {
            return null;
        }

        char[] password = passwordField.getPassword();
        if (password.length == 0) {
            javax.swing.JOptionPane.showMessageDialog(parent,
                    "密码不能为空", "输入错误", javax.swing.JOptionPane.WARNING_MESSAGE);
            return null;
        }

        return password;
    }

    /**
     * 安全清零密码字符数组
     *
     * @param password 密码数组
     */
    public static void clearPassword(char[] password) {
        if (password != null) {
            Arrays.fill(password, '\0');
        }
    }
}
