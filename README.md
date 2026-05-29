# SVG XSS Upload Scanner — Burp Suite Extension

一个 Burp Suite 被动扫描扩展，用于自动化检测文件上传接口的 SVG XSS 漏洞。

## 功能特性

- **Payload 库** — 内置 5 种 SVG XSS payload：基础事件、CDATA 混淆、编码绕过、动画事件、foreignObject 绕过，支持一键切换
- **安全注入** — 通过 `makeHttpRequest` 发送独立请求测试，**绝不修改代理/Repeater 中的原始流量**
- **被动扫描** — 自动识别 multipart 上传请求，检测已上传的 SVG 文件
- **Site Map 查找** — 一键搜索 Burp Site Map 中所有 `.svg` 文件
- **多编码支持** — 使用 `java.lang.String(bytes, charset)` 可靠解码 GBK/GB2312/UTF-8/Big5/Latin1 等编码
- **Burp Issue 自动创建** — 检测到 XSS 特征时自动向 Scanner 报告
- **深色主题 HTML 响应展示** — JSON 语法高亮、响应头格式化、错误页面提取
- **扫描记录自动保存** — 完整请求/响应保存到 `~/BurpSVGXSSLogs/`，文件名带 XSS/OK 前缀

## 安装

### 前提条件

- Burp Suite Professional 或 Community Edition (v2022+)
- Jython 2.7+ (在 **Extender → Options → Python Environment** 中配置 `jython-standalone.jar`)

### 步骤

1. 下载 `svg-xss.py`
2. 打开 Burp → **Extender** → **Add**
3. Extension Type: `Python`
4. 选择 `svg-xss.py` → **Next**
5. 加载成功后输出 `[SVG XSS Scanner] Loaded successfully`

## 使用方法

### 手动扫描

1. 在 Proxy / Repeater 中找到文件上传请求
2. 右键 → **"Send to SVG XSS Scanner"**
3. 切换到 **SVG XSS Scanner** 标签页查看结果

### 自动扫描

在插件界面勾选：
- **Passive scan**: 仅检测上传文件名/SVG 特征，**零流量修改**
- **Auto-inject**: 自动构造 SVG payload 请求单独发送，**不影响原始流量**

### Payload 切换

点击 `< Prev` / `Next >` 按钮在 5 种 payload 之间切换，或直接在文本框编辑自定义 payload。

### 目标过滤

在 "Target Host" 输入框填写域名，仅对该域名的请求生效（留空则处理所有）。

## 界面说明

| 区域 | 内容 |
|------|------|
| 控制面板 | Payload 编辑器、切换按钮、域名过滤、扫描模式开关、统计信息 |
| 结果日志 | 实时扫描日志，显示 Target/Status/XSS 结果 |
| Request 标签 | 显示注入 SVG payload 后的完整请求 |
| Response 标签 | 显示原始服务器响应 |
| Formatted 标签 | 深色主题 HTML 展示：响应头、JSON 语法高亮、错误信息提取 |

## 检测特征

插件自动检测以下 XSS 特征（可在代码 `XSS_INDICATORS` 中扩展）：

- `<svg>` 标签、`onload`/`onerror`/`onbegin` 事件
- `<script>` 标签、`javascript:` 协议
- `<foreignObject>` 嵌入
- `alert()`、`eval()` 调用
- `document.cookie` / `document.domain` 访问
- `image/svg+xml` 内容类型

## 内置 Payload 库

| # | 类型 | 说明 |
|---|------|------|
| 1 | 基础事件 | `onload="alert(1)"` — 最直接的 XSS 触发 |
| 2 | CDATA 混淆 | `<script>alert(document.domain)</script>` 嵌入 SVG |
| 3 | 编码绕过 | `use href="data:image/svg+xml,..."` HTML 实体编码 |
| 4 | 动画事件 | `onbegin="alert(1)"` 通过 `<set>` / `<animate>` 触发 |
| 5 | foreignObject | `<foreignObject>` 嵌入 `<iframe src="javascript:...">` |

## 扫描记录

记录保存到 `~/BurpSVGXSSLogs/`：

```
scan_XSS_20260103_143025.txt   ← 检测到 XSS
scan_OK_20260103_143102.txt    ← 未检测到
```

## 免责声明

本工具仅用于**授权安全测试**。使用者需自行承担法律责任。
