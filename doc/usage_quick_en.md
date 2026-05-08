# Quick Start Guide

> Get started with Repeater Manager in 5 minutes

## 1. Install the Plugin

1. Download the latest JAR file from [Releases](../../releases)
2. Open Burp Suite Professional
3. Navigate to `Extender` → `Extensions` → Click `Add`
4. Select the downloaded JAR file → Click `Next`
5. You'll see **"Repeater Manager 插件加载成功"** confirming successful installation

## 2. Send a Request

Right-click on any HTTP request in Burp Suite:

- Select **"Send to Repeater Manager"** (发送到 Repeater Manager)
- Switch to the **"Repeater Manager"** tab at the top

## 3. Edit and Replay

- Top-right area: Edit request content (with syntax highlighting)
- Click the **"Send"** button to replay the request
- Right panel displays the response content
- Bottom status bar shows response time and size

## 4. View History

- Bottom-left panel: View all historical replay records for the request
- Double-click a history entry: Load that replay's request and response
- Compare response changes across different points in time

## 5. Manage Requests

- **Color marking**: Right-click a request in the list to choose a color
- **Comments**: Add annotation notes to requests
- **Search**: Enter keywords in the search box to quickly locate requests
- **New request**: Click the **"New Request"** (新建请求) button at the top

## 6. Export Data

Navigate to **"Configuration"** (配置) → **"Data Import/Export"** (数据导入导出):

- **ERM Archive**: Export/import in plugin-specific format, with optional encryption
- **Postman**: Export as Postman Collection v2.1 format
- **Smart Import**: Automatically detect file format

---

> For detailed feature descriptions, please refer to the [Detailed Usage Tutorial](usage_detailed_en.md)
