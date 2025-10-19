# Burp SVG XSS Upload Scanner

一个Burp Suite插件，用于自动化检测图片上传功能中的XSS漏洞。通过将上传的文件修改为SVG格式并插入XSS Payload来测试漏洞。

## 功能特性

- 🎯 **智能上传检测** - 自动识别multipart/form-data上传请求
- 🔄 **自动格式转换** - 将上传文件转换为SVG格式
- 🎨 **美化响应显示** - 彩色高亮的响应格式化输出
- 📊 **XSS检测标记** - 自动检测响应中的XSS特征
- 💾 **扫描记录保存** - 自动保存完整的请求和响应记录
- 🚀 **右键快速扫描** - 通过右键菜单快速发送请求到扫描器

## 安装说明

### 前提条件
- Burp Suite Professional 或 Community Edition
- Jython 2.7+ (在Burp的Extender → Options中配置)

### 安装步骤
1. 下载 `svg-xss-scanner.py`
2. 打开Burp Suite，进入 **Extender** 标签
3. 点击 **Add** 按钮
4. 选择 **Extension type: Python**
5. 选择下载的 `svg-xss-scanner.py` 文件
6. 点击 **Next** 完成加载

## 使用方法

### 基本使用
1. 在Proxy或其他工具中找到图片上传请求
2. 右键点击请求，选择 **"Send to SVG XSS Scanner"**
3. 切换到 **"SVG XSS Scanner"** 标签页查看结果

### 高级功能
- **自定义Payload**: 在插件界面修改SVG XSS Payload
- **目标域名过滤**: 设置特定域名进行自动扫描
- **自动扫描模式**: 开启后自动检测和修改所有上传请求
- **美化输出**: 彩色高亮的响应格式化显示

## 界面说明

插件界面包含三个主要区域：

### 控制面板
- SVG Payload配置
- 目标域名设置
- 功能开关控制

### 结果显示
- 扫描状态和结果摘要
- XSS检测标记

### 请求/响应查看
- **Request标签**: 显示修改后的请求
- **Response标签**: 显示原始服务器响应
- **Formatted Response标签**: 美化的彩色响应显示

## 检测的XSS特征

插件会自动检测以下XSS相关特征：
- SVG文件引用 (.svg)
- SVG标签 (<svg)
- JavaScript事件处理器 (onload, onerror)
- JavaScript协议 (javascript:)
- Script标签 (<script)
- 相关内容类型 (image/svg+xml, application/xml)

## 扫描记录

所有扫描记录自动保存到：
