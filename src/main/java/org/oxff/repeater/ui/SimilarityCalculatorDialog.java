package org.oxff.repeater.ui;

import org.oxff.repeater.privilege.SimilarityEngine;

import javax.swing.*;
import java.awt.*;

/**
 * 相似度计算工具对话框
 * 提供两个多行文本输入框，用户可输入两个HTTP报文，
 * 使用项目内置的混合相似度引擎计算并展示相似度结果
 */
public class SimilarityCalculatorDialog extends JDialog {

    private JTextArea messageArea1;
    private JTextArea messageArea2;
    private JLabel resultLabel;

    public SimilarityCalculatorDialog(Frame owner) {
        super(owner, "相似度计算", true);
        initUI();
        setSize(700, 500);
        setMinimumSize(new Dimension(500, 350));
        setLocationRelativeTo(owner);
    }

    private void initUI() {
        setLayout(new BorderLayout());

        // 顶部说明面板
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel titleLabel = new JLabel("请输入两个HTTP报文进行相似度计算");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 13f));
        topPanel.add(titleLabel);
        add(topPanel, BorderLayout.NORTH);

        // 中间输入区域
        JPanel centerPanel = new JPanel(new GridLayout(2, 1, 0, 5));

        messageArea1 = new JTextArea();
        messageArea1.setLineWrap(true);
        messageArea1.setWrapStyleWord(true);
        JScrollPane scroll1 = new JScrollPane(messageArea1);
        scroll1.setBorder(BorderFactory.createTitledBorder("报文 1"));

        messageArea2 = new JTextArea();
        messageArea2.setLineWrap(true);
        messageArea2.setWrapStyleWord(true);
        JScrollPane scroll2 = new JScrollPane(messageArea2);
        scroll2.setBorder(BorderFactory.createTitledBorder("报文 2"));

        centerPanel.add(scroll1);
        centerPanel.add(scroll2);
        add(centerPanel, BorderLayout.CENTER);

        // 底部按钮面板
        JPanel bottomPanel = new JPanel(new BorderLayout(10, 5));
        bottomPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10));

        // 结果区域
        JPanel resultPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 5));
        JButton calcButton = new JButton("计算相似度");
        calcButton.setToolTipText("使用项目内置混合相似度引擎计算两个报文的相似度");
        calcButton.addActionListener(e -> calculateSimilarity());

        resultLabel = new JLabel("请输入两个报文后点击计算");
        resultLabel.setFont(resultLabel.getFont().deriveFont(Font.BOLD, 14f));

        resultPanel.add(calcButton);
        resultPanel.add(resultLabel);
        bottomPanel.add(resultPanel, BorderLayout.CENTER);

        // 确定/取消按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        JButton okButton = new JButton("确定");
        okButton.addActionListener(e -> dispose());
        JButton cancelButton = new JButton("取消");
        cancelButton.addActionListener(e -> dispose());
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        bottomPanel.add(buttonPanel, BorderLayout.SOUTH);

        add(bottomPanel, BorderLayout.SOUTH);
    }

    /**
     * 获取两个文本框内容，调用 SimilarityEngine 计算相似度，更新结果显示
     */
    private void calculateSimilarity() {
        String text1 = messageArea1.getText();
        String text2 = messageArea2.getText();

        if (text1.isEmpty() && text2.isEmpty()) {
            resultLabel.setText("两个报文均为空，相似度: 1.0000 (100.00%)");
            return;
        }

        double similarity = SimilarityEngine.similarity(text1, text2);
        resultLabel.setText(String.format("相似度: %.4f (%.2f%%)", similarity, similarity * 100));
    }
}
