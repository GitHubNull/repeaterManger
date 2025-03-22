#!/bin/bash

echo "开始构建增强型Repeater插件..."

# 检查Maven是否安装
if ! command -v mvn &> /dev/null; then
    echo "错误：未安装Maven或未添加到PATH中"
    echo "请安装Maven并确保其已添加到PATH环境变量中"
    exit 1
fi

# 清理和构建项目
echo "正在执行Maven构建..."
mvn clean package

if [ $? -ne 0 ]; then
    echo "构建失败，请检查错误信息"
    exit 1
fi

echo "构建成功！"
echo "插件文件位于: $(pwd)/target/repeaterManger-1.0-SNAPSHOT-jar-with-dependencies.jar"

# 显示安装指南
echo ""
echo "安装指南:"
echo "1. 打开Burp Suite"
echo "2. 进入Extender选项卡"
echo "3. 点击Add按钮"
echo "4. 选择Java作为扩展类型"
echo "5. 选择以上路径的JAR文件"
echo "6. 点击Next完成安装"
echo ""

# 询问是否要打开目标文件夹
read -p "是否打开包含插件的文件夹? (y/n): " open_folder
if [[ "$open_folder" =~ ^[Yy]$ ]]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        open "$(pwd)/target"
    else
        # Linux
        xdg-open "$(pwd)/target" &> /dev/null || echo "无法打开文件夹，请手动导航到$(pwd)/target"
    fi
fi

echo "完成。" 