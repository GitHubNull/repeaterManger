package org.oxff.repeater.privilege;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.Base64;

/**
 * 截图编码工具类。
 * 将截图文件读取、缩放、编码为 PNG base64 data URI，
 * 从 ReportGenerator 中抽取以解耦 I/O 与报告生成职责。
 *
 * <p>对外暴露三步可组合方法（read / scale / encode）和一步便捷方法。</p>
 */
public final class ScreenshotEncoder {

    /** 默认最大宽度（像素），Integer.MAX_VALUE 表示不缩放，保留原始分辨率 */
    public static final int DEFAULT_MAX_WIDTH = Integer.MAX_VALUE;

    private ScreenshotEncoder() {
        // 工具类，禁止实例化
    }

    /**
     * 便捷方法：读入截图文件 → 缩放至 maxWidth → 输出 base64 data URI。
     *
     * @param path     截图文件路径
     * @param maxWidth 最大宽度，超出时等比缩放
     * @return PNG base64 data URI（含 "data:image/png;base64," 前缀）
     * @throws IOException 文件不存在、格式不支持或编码失败时抛出
     */
    public static String encode(String path, int maxWidth) throws IOException {
        File file = new File(path);
        if (!file.exists()) {
            throw new IOException("截图文件不存在: " + path);
        }

        BufferedImage original = ImageIO.read(file);
        if (original == null) {
            throw new IOException("无法解码截图文件（格式不支持或损坏）: " + path);
        }

        BufferedImage scaled = scaleMaxWidth(original, maxWidth);
        return toBase64DataUri(scaled);
    }

    /**
     * 使用默认最大宽度 {@value DEFAULT_MAX_WIDTH} 编码截图。
     */
    public static String encode(String path) throws IOException {
        return encode(path, DEFAULT_MAX_WIDTH);
    }

    /**
     * 将 BufferedImage 缩放至指定最大宽度，保持宽高比。
     * 若原图宽度 ≤ maxWidth 则直接返回原图。
     */
    public static BufferedImage scaleMaxWidth(BufferedImage original, int maxWidth) {
        int width = original.getWidth();
        int height = original.getHeight();
        if (width <= maxWidth) {
            return original;
        }
        double ratio = (double) maxWidth / width;
        int newHeight = (int) (height * ratio);
        Image scaled = original.getScaledInstance(maxWidth, newHeight, Image.SCALE_SMOOTH);
        BufferedImage result = new BufferedImage(maxWidth, newHeight, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2d = result.createGraphics();
        g2d.drawImage(scaled, 0, 0, null);
        g2d.dispose();
        return result;
    }

    /**
     * 将 BufferedImage 编码为 PNG base64 data URI。
     *
     * @return 格式为 "data:image/png;base64,..." 的字符串
     */
    public static String toBase64DataUri(BufferedImage image) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "png", baos);
        String base64 = Base64.getEncoder().encodeToString(baos.toByteArray());
        return "data:image/png;base64," + base64;
    }
}
