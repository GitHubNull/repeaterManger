package oxff.top.utils;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import javax.swing.text.*;
import java.awt.*;
import java.beans.*;
import java.util.HashMap;

/**
 * 文本行号组件 - 为JTextComponent提供行号显示功能
 */
public class TextLineNumber extends JPanel implements CaretListener, DocumentListener, PropertyChangeListener {
    private static final long serialVersionUID = 1L;
    private static final int HEIGHT = Integer.MAX_VALUE - 1000000;
    
    // 文本组件的属性
    private final JTextComponent component;
    private boolean updateFont;
    private Color currentLineForeground;
    private Color foreground;
    
    // 缓存以提升性能
    private int lastDigits;
    private int lastHeight;
    private int lastLine;
    private HashMap<String, FontMetrics> fonts;
    
    /**
     * 创建一个带默认样式的行号组件
     * @param component 关联的文本组件
     */
    public TextLineNumber(JTextComponent component) {
        this(component, 3);
    }
    
    /**
     * 创建一个带自定义边距的行号组件
     * @param component 关联的文本组件
     * @param borderGap 边框与行号之间的间距
     */
    public TextLineNumber(JTextComponent component, int borderGap) {
        this.component = component;
        this.updateFont = true;
        
        // 默认颜色和字体
        this.foreground = Color.GRAY;
        this.currentLineForeground = Color.BLACK;
        this.setBackground(Color.WHITE);
        
        // 设置边框
        this.setBorder(new EmptyBorder(0, borderGap, 0, borderGap));
        
        // 添加监听器以更新行号视图
        component.getDocument().addDocumentListener(this);
        component.addCaretListener(this);
        component.addPropertyChangeListener("font", this);
    }
    
    /**
     * 设置当前行的前景色
     * @param currentLineForeground 颜色
     */
    public void setCurrentLineForeground(Color currentLineForeground) {
        this.currentLineForeground = currentLineForeground;
    }
    
    /**
     * 设置是否更新行号组件的字体以匹配文本组件
     * @param updateFont 布尔值
     */
    public void setUpdateFont(boolean updateFont) {
        this.updateFont = updateFont;
    }
    
    /**
     * 设置边框间距
     * @param borderGap 间距值（像素）
     */
    public void setBorderGap(int borderGap) {
        Border inner = new EmptyBorder(0, borderGap, 0, borderGap);
        this.setBorder(inner);
        
        this.lastDigits = 0;
        this.setPreferredWidth();
    }
    
    /**
     * 设置行号的前景色
     * @param foreground 颜色
     */
    @Override
    public void setForeground(Color foreground) {
        this.foreground = foreground;
        super.setForeground(foreground);
    }
    
    /**
     * 设置行号的背景色
     * @param background 颜色
     */
    @Override
    public void setBackground(Color background) {
        super.setBackground(background);
    }
    
    /**
     * 设置行号的字体
     * @param font 字体
     */
    @Override
    public void setFont(Font font) {
        super.setFont(font);
    }
    
    /**
     * 根据文本组件的行数设置组件宽度
     */
    private void setPreferredWidth() {
        Element root = component.getDocument().getDefaultRootElement();
        int lines = root.getElementCount();
        int digits = Math.max(String.valueOf(lines).length(), 3);
        
        if (lastDigits != digits) {
            lastDigits = digits;
            FontMetrics fontMetrics = getFontMetrics(getFont());
            int width = fontMetrics.charWidth('0') * digits;
            Insets insets = getInsets();
            
            int preferredWidth = insets.left + insets.right + width;
            
            Dimension d = getPreferredSize();
            d.setSize(preferredWidth, HEIGHT);
            setPreferredSize(d);
            setSize(d);
        }
    }
    
    /**
     * 处理文档变化事件
     */
    @Override
    public void changedUpdate(DocumentEvent e) {
        documentChanged();
    }
    
    /**
     * 处理插入事件
     */
    @Override
    public void insertUpdate(DocumentEvent e) {
        documentChanged();
    }
    
    /**
     * 处理删除事件
     */
    @Override
    public void removeUpdate(DocumentEvent e) {
        documentChanged();
    }
    
    /**
     * 文档改变时更新行号视图
     */
    private void documentChanged() {
        SwingUtilities.invokeLater(() -> {
            try {
                int endPos = component.getDocument().getLength();
                Rectangle rect = component.modelToView(endPos);
                
                if (rect != null && rect.y != lastHeight) {
                    setPreferredWidth();
                    repaint();
                    lastHeight = rect.y;
                }
            } catch (BadLocationException e) {
                // 忽略异常
            }
        });
    }
    
    /**
     * 处理光标位置变化事件
     */
    @Override
    public void caretUpdate(CaretEvent e) {
        // 获取当前行以高亮显示
        int caretPosition = component.getCaretPosition();
        Element root = component.getDocument().getDefaultRootElement();
        int currentLine = root.getElementIndex(caretPosition);
        
        if (lastLine != currentLine) {
            repaint();
            lastLine = currentLine;
        }
    }
    
    /**
     * 处理属性变化事件
     */
    @Override
    public void propertyChange(PropertyChangeEvent evt) {
        if (evt.getNewValue() instanceof Font) {
            if (updateFont) {
                Font newFont = (Font) evt.getNewValue();
                setFont(newFont);
                lastDigits = 0;
                setPreferredWidth();
            } else {
                repaint();
            }
        }
    }
    
    /**
     * 绘制行号
     */
    @Override
    public void paintComponent(Graphics g) {
        super.paintComponent(g);
        
        // 确定行号的位置
        FontMetrics fontMetrics = component.getFontMetrics(component.getFont());
        Insets insets = getInsets();
        int availableWidth = getSize().width - insets.left - insets.right;
        
        // 获取当前视图中第一行的位置
        Rectangle clip = g.getClipBounds();
        int rowStartOffset = component.viewToModel(new Point(0, clip.y));
        int endOffset = component.viewToModel(new Point(0, clip.y + clip.height));
        
        while (rowStartOffset <= endOffset) {
            try {
                if (isCurrentLine(rowStartOffset)) {
                    g.setColor(currentLineForeground);
                } else {
                    g.setColor(foreground);
                }
                
                // 获取行号
                String lineNumber = getTextLineNumber(rowStartOffset);
                int stringWidth = fontMetrics.stringWidth(lineNumber);
                int x = availableWidth - stringWidth + insets.left;
                int y = getOffsetY(rowStartOffset, fontMetrics);
                g.drawString(lineNumber, x, y);
                
                // 移到下一行
                rowStartOffset = Utilities.getRowEnd(component, rowStartOffset) + 1;
            } catch (Exception e) {
                break;
            }
        }
    }
    
    /**
     * 判断指定位置是否为当前行
     */
    private boolean isCurrentLine(int rowStartOffset) {
        int caretPosition = component.getCaretPosition();
        Element root = component.getDocument().getDefaultRootElement();
        
        return root.getElementIndex(rowStartOffset) == root.getElementIndex(caretPosition);
    }
    
    /**
     * 获取指定位置的行号文本
     */
    protected String getTextLineNumber(int rowStartOffset) {
        Element root = component.getDocument().getDefaultRootElement();
        int index = root.getElementIndex(rowStartOffset);
        return String.valueOf(index + 1);
    }
    
    /**
     * 计算绘制行号的垂直位置
     */
    private int getOffsetY(int rowStartOffset, FontMetrics fontMetrics) throws BadLocationException {
        Rectangle r = component.modelToView(rowStartOffset);
        int lineHeight = fontMetrics.getHeight();
        int y = r.y + r.height;
        int descent = 0;
        
        if (r.height == lineHeight) {
            descent = fontMetrics.getDescent();
        } else {
            if (fonts == null) {
                fonts = new HashMap<>();
            }
            
            Element root = component.getDocument().getDefaultRootElement();
            int index = root.getElementIndex(rowStartOffset);
            Element line = root.getElement(index);
            
            for (int i = 0; i < line.getElementCount(); i++) {
                Element child = line.getElement(i);
                AttributeSet as = child.getAttributes();
                String fontFamily = (String) as.getAttribute(StyleConstants.FontFamily);
                Integer fontSize = (Integer) as.getAttribute(StyleConstants.FontSize);
                String key = fontFamily + fontSize;
                
                FontMetrics fm = fonts.get(key);
                if (fm == null) {
                    Font font = new Font(fontFamily, Font.PLAIN, fontSize);
                    fm = component.getFontMetrics(font);
                    fonts.put(key, fm);
                }
                
                descent = Math.max(descent, fm.getDescent());
            }
        }
        
        return y - descent;
    }
} 