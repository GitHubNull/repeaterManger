package org.oxff.repeater.ui.privilege;

import org.oxff.repeater.privilege.model.UserInfo;
import org.oxff.repeater.privilege.model.UserSession;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;

/**
 * 用户信息详情查看对话框
 * 展示会话名称、角色、用户名、匿名状态及截图缩略图（点击可全屏查看）
 */
public class UserInfoDetailDialog extends JDialog {

    public UserInfoDetailDialog(Frame owner, UserSession session, UserInfo userInfo) {
        super(owner, "用户信息 - " + session.getName(), true);
        setSize(550, 500);
        setLocationRelativeTo(owner);
        setResizable(true);

        JPanel mainPanel = new JPanel(new GridBagLayout());
        mainPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.NORTHWEST;

        int row = 0;

        // 会话名称
        addInfoRow(mainPanel, gbc, row++, "会话名称:", session.getName());

        // 角色 / 用户名 / 匿名
        if (userInfo != null) {
            addInfoRow(mainPanel, gbc, row++, "角色:", 
                    userInfo.getRole() != null && !userInfo.getRole().isEmpty() ? userInfo.getRole() : "（未设置）");
            addInfoRow(mainPanel, gbc, row++, "用户名:",
                    userInfo.getUsername() != null && !userInfo.getUsername().isEmpty() ? userInfo.getUsername() : "（未设置）");
            addInfoRow(mainPanel, gbc, row++, "匿名:",
                    userInfo.isAnonymous() ? "是（匿名用户）" : "否");

            // 截图缩略图
            if (userInfo.getScreenshotPaths() != null && !userInfo.getScreenshotPaths().isEmpty()) {
                gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1; gbc.weightx = 0;
                mainPanel.add(new JLabel("截图:"), gbc);

                JPanel thumbnailPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
                for (String path : userInfo.getScreenshotPaths()) {
                    thumbnailPanel.add(createThumbnail(path));
                }
                JScrollPane thumbScroll = new JScrollPane(thumbnailPanel);
                thumbScroll.setPreferredSize(new Dimension(400, 120));
                thumbScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER);
                gbc.gridx = 1; gbc.weightx = 1.0;
                gbc.fill = GridBagConstraints.HORIZONTAL;
                mainPanel.add(thumbScroll, gbc);
                row++;
            }
        } else {
            JLabel noInfoLabel = new JLabel("（暂无用户信息）");
            noInfoLabel.setForeground(Color.GRAY);
            gbc.gridx = 0; gbc.gridy = row++; gbc.gridwidth = 2;
            mainPanel.add(noInfoLabel, gbc);
        }

        gbc.gridwidth = 1;

        // 关闭按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton closeBtn = new JButton("关闭");
        closeBtn.addActionListener(e -> dispose());
        buttonPanel.add(closeBtn);

        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(mainPanel, BorderLayout.CENTER);
        getContentPane().add(buttonPanel, BorderLayout.SOUTH);
    }

    /**
     * 添加一行标签-值信息
     */
    private void addInfoRow(JPanel panel, GridBagConstraints gbc, int row, String label, String value) {
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        panel.add(new JLabel(label), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        panel.add(new JLabel(value), gbc);
    }

    /**
     * 创建截图缩略图（100x75），点击可全屏查看
     */
    private JLabel createThumbnail(String imagePath) {
        try {
            File file = new File(imagePath);
            if (!file.exists()) {
                JLabel label = new JLabel("（文件不存在）");
                label.setPreferredSize(new Dimension(100, 75));
                label.setBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY));
                return label;
            }

            ImageIcon originalIcon = new ImageIcon(imagePath);
            Image scaled = originalIcon.getImage().getScaledInstance(100, 75, Image.SCALE_SMOOTH);
            ImageIcon thumbIcon = new ImageIcon(scaled);
            JLabel thumbLabel = new JLabel(thumbIcon);
            thumbLabel.setPreferredSize(new Dimension(100, 75));
            thumbLabel.setBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY));
            thumbLabel.setToolTipText(file.getName());
            thumbLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

            // 点击全屏查看
            thumbLabel.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    showFullscreenImage(imagePath, file.getName());
                }
            });

            return thumbLabel;
        } catch (Exception e) {
            JLabel label = new JLabel("（加载失败）");
            label.setPreferredSize(new Dimension(100, 75));
            label.setBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY));
            return label;
        }
    }

    /**
     * 全屏查看截图
     */
    private void showFullscreenImage(String imagePath, String title) {
        try {
            ImageIcon icon = new ImageIcon(imagePath);
            JDialog fullscreenDialog = new JDialog(this, title, true);
            fullscreenDialog.setUndecorated(false);

            JLabel imageLabel = new JLabel(icon);
            JScrollPane scrollPane = new JScrollPane(imageLabel);

            // 限制最大尺寸为屏幕的90%
            Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
            int maxWidth = (int) (screenSize.width * 0.9);
            int maxHeight = (int) (screenSize.height * 0.9);

            int imgWidth = icon.getIconWidth();
            int imgHeight = icon.getIconHeight();
            if (imgWidth > maxWidth || imgHeight > maxHeight) {
                double scale = Math.min((double) maxWidth / imgWidth, (double) maxHeight / imgHeight);
                Image scaled = icon.getImage().getScaledInstance(
                        (int) (imgWidth * scale), (int) (imgHeight * scale), Image.SCALE_SMOOTH);
                imageLabel.setIcon(new ImageIcon(scaled));
            }

            fullscreenDialog.add(scrollPane);
            fullscreenDialog.setSize(Math.min(imgWidth + 20, maxWidth), Math.min(imgHeight + 40, maxHeight));
            fullscreenDialog.setLocationRelativeTo(this);

            // ESC 关闭
            KeyStroke escapeKey = KeyStroke.getKeyStroke("ESCAPE");
            fullscreenDialog.getRootPane().registerKeyboardAction(
                    e -> fullscreenDialog.dispose(), escapeKey, JComponent.WHEN_IN_FOCUSED_WINDOW);

            fullscreenDialog.setVisible(true);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "无法加载图片: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }
}
