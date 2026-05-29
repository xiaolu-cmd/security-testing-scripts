# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, ITab, IHttpListener
from javax.swing import JPanel, JTabbedPane, JTextArea, JScrollPane, JSplitPane
from javax.swing import JButton, JLabel, JTextField, JCheckBox, JEditorPane
from javax.swing import BoxLayout, BorderFactory, SwingUtilities
from java.awt import BorderLayout, Dimension, Font
from java.awt.event import ActionListener
from javax import swing
import re
import threading
import os
import time
from datetime import datetime
import sys
import json

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # 设置扩展名称
        callbacks.setExtensionName("SVG XSS Upload Scanner")
        
        # 注册上下文菜单
        callbacks.registerContextMenuFactory(self)
        
        # 注册HTTP监听器
        callbacks.registerHttpListener(self)
        
        # 初始化UI
        self._mainPanel = JPanel(BorderLayout())
        self.initUI()
        
        # 添加标签页到Burp
        callbacks.addSuiteTab(self)
        
        # 创建日志目录
        self.log_dir = os.path.join(os.path.expanduser("~"), "BurpSVGXSSLogs")
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        
        # 输出启动信息
        self._callbacks.printOutput("SVG XSS Upload Scanner Loaded!")
        self.logResult("Plugin started at: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
    def initUI(self):
        # 创建控制面板
        controlPanel = JPanel()
        controlPanel.setLayout(BoxLayout(controlPanel, BoxLayout.Y_AXIS))
        controlPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # 标题
        titleLabel = JLabel("SVG XSS Upload Scanner")
        titleLabel.setFont(Font("Arial", Font.BOLD, 16))
        controlPanel.add(titleLabel)
        
        controlPanel.add(JLabel(" "))
        
        # 配置选项
        configPanel = JPanel()
        configPanel.setLayout(BoxLayout(configPanel, BoxLayout.Y_AXIS))
        
        # SVG Payload 输入
        payloadLabel = JLabel("SVG XSS Payload:")
        configPanel.add(payloadLabel)
        
        self.payloadText = JTextArea(
            '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>', 
            3, 40
        )
        self.payloadText.setLineWrap(True)
        payloadScroll = JScrollPane(self.payloadText)
        payloadScroll.setPreferredSize(Dimension(400, 80))
        configPanel.add(payloadScroll)
        
        configPanel.add(JLabel(" "))
        
        # 目标域名过滤
        domainLabel = JLabel("Target Domain (optional):")
        configPanel.add(domainLabel)
        
        self.domainText = JTextField(30)
        configPanel.add(self.domainText)
        
        configPanel.add(JLabel(" "))
        
        # 自动扫描选项
        self.autoScanCheckbox = JCheckBox("Auto scan all image upload requests", False)
        configPanel.add(self.autoScanCheckbox)
        
        # 保存日志选项
        self.saveLogCheckbox = JCheckBox("Auto save scan records", True)
        configPanel.add(self.saveLogCheckbox)
        
        # 美化输出选项
        self.prettyPrintCheckbox = JCheckBox("Pretty print responses", True)
        configPanel.add(self.prettyPrintCheckbox)
        
        controlPanel.add(configPanel)
        
        # 按钮面板
        buttonPanel = JPanel()
        
        # 测试按钮
        self.testButton = JButton("Test Current Payload")
        self.testButton.addActionListener(TestButtonListener(self))
        buttonPanel.add(self.testButton)
        
        # 清除按钮
        self.clearButton = JButton("Clear Results")
        self.clearButton.addActionListener(ClearButtonListener(self))
        buttonPanel.add(self.clearButton)
        
        # 查看日志按钮
        self.viewLogButton = JButton("View Scan Records")
        self.viewLogButton.addActionListener(ViewLogButtonListener(self))
        buttonPanel.add(self.viewLogButton)
        
        controlPanel.add(buttonPanel)
        
        # 结果区域
        self.resultText = JTextArea(15, 60)
        self.resultText.setEditable(False)
        self.resultText.setFont(Font("Monospaced", Font.PLAIN, 12))
        resultScroll = JScrollPane(self.resultText)
        resultScroll.setPreferredSize(Dimension(600, 200))
        
        # 请求/响应显示区域
        self.requestText = JTextArea(10, 60)
        self.requestText.setEditable(False)
        self.requestText.setFont(Font("Monospaced", Font.PLAIN, 12))
        requestScroll = JScrollPane(self.requestText)
        
        self.responseText = JTextArea(10, 60)
        self.responseText.setEditable(False)
        self.responseText.setFont(Font("Monospaced", Font.PLAIN, 12))
        responseScroll = JScrollPane(self.responseText)
        
        # 创建HTML格式的响应显示区域
        self.htmlResponsePane = JEditorPane()
        self.htmlResponsePane.setContentType("text/html")
        self.htmlResponsePane.setEditable(False)
        htmlResponseScroll = JScrollPane(self.htmlResponsePane)
        
        # 创建标签页面板
        self.tabbedPane = JTabbedPane()
        self.tabbedPane.addTab("Request", requestScroll)
        self.tabbedPane.addTab("Response", responseScroll)
        self.tabbedPane.addTab("Formatted Response", htmlResponseScroll)
        
        # 创建分割面板
        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        splitPane.setTopComponent(resultScroll)
        splitPane.setBottomComponent(self.tabbedPane)
        splitPane.setDividerLocation(0.5)
        
        # 添加到主面板
        self._mainPanel.add(controlPanel, BorderLayout.NORTH)
        self._mainPanel.add(splitPane, BorderLayout.CENTER)
        
    def createMenuItems(self, invocation):
        menu = []
        
        # 只在有选中消息时显示菜单项
        if invocation.getInvocationContext() in [invocation.CONTEXT_MESSAGE_EDITOR_REQUEST, 
                                               invocation.CONTEXT_MESSAGE_VIEWER_REQUEST]:
            
            menuItem = swing.JMenuItem("Send to SVG XSS Scanner")
            menuItem.addActionListener(MenuItemListener(self, invocation))
            menu.append(menuItem)
            
        return menu
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # 只在代理或扫描器工具中处理请求
        if toolFlag not in [self._callbacks.TOOL_PROXY, self._callbacks.TOOL_SCANNER]:
            return
            
        if messageIsRequest and self.autoScanCheckbox.isSelected():
            self.analyzeAndModifyRequest(messageInfo)
    
    def analyzeAndModifyRequest(self, messageInfo):
        try:
            request = messageInfo.getRequest()
            analyzedRequest = self._helpers.analyzeRequest(messageInfo.getHttpService(), request)
            
            # 检查是否为上传请求
            if not self.isUploadRequest(analyzedRequest):
                return
                
            # 检查目标域名
            targetDomain = self.domainText.getText().strip()
            if targetDomain and targetDomain not in analyzedRequest.getUrl().getHost():
                return
            
            # 修改请求
            modifiedRequest = self.modifyUploadRequest(analyzedRequest, request)
            if modifiedRequest:
                messageInfo.setRequest(modifiedRequest)
                self.logResult("Auto modified upload request: " + str(analyzedRequest.getUrl()))
                
        except Exception as e:
            self.logResult("Auto scan error: " + str(e))
    
    def isUploadRequest(self, analyzedRequest):
        # 检查Content-Type是否包含multipart
        headers = analyzedRequest.getHeaders()
        for header in headers:
            if header.lower().startswith("content-type:") and "multipart/form-data" in header.lower():
                return True
        return False
    
    def modifyUploadRequest(self, analyzedRequest, originalRequest):
        try:
            body = originalRequest[analyzedRequest.getBodyOffset():]
            bodyStr = self._helpers.bytesToString(body)
            
            # 查找文件上传部分
            boundary = self.getBoundary(analyzedRequest.getHeaders())
            if not boundary:
                return None
            
            # 修改文件内容为SVG payload
            svgPayload = self.payloadText.getText()
            modifiedBody = self.replaceFileContent(bodyStr, boundary, svgPayload)
            
            if modifiedBody != bodyStr:
                # 重建请求
                headers = analyzedRequest.getHeaders()
                modifiedHeaders = self.updateContentLength(headers, len(modifiedBody))
                
                return self._helpers.buildHttpMessage(modifiedHeaders, modifiedBody)
            
        except Exception as e:
            self.logResult("Modify request error: " + str(e))
            
        return None
    
    def getBoundary(self, headers):
        for header in headers:
            if header.lower().startswith("content-type:"):
                match = re.search(r'boundary=([^\s;]+)', header)
                if match:
                    return match.group(1)
        return None
    
    def replaceFileContent(self, body, boundary, newContent):
        parts = body.split("--" + boundary)
        
        for i in range(1, len(parts) - 1):
            part = parts[i]
            
            # 检查是否是文件部分
            if "filename=" in part and "Content-Type:" in part:
                lines = part.strip().split('\r\n')
                newPartLines = []
                inHeaders = True
                
                for line in lines:
                    if inHeaders:
                        newPartLines.append(line)
                        if line.strip() == "":
                            inHeaders = False
                        # 修改文件名和Content-Type
                        elif "filename=" in line:
                            newPartLines[-1] = re.sub(r'filename="[^"]*"', 'filename="test.svg"', line)
                        elif "Content-Type:" in line:
                            newPartLines[-1] = "Content-Type: image/svg+xml"
                    else:
                        # 替换文件内容
                        newPartLines.append(newContent)
                        break
                
                parts[i] = '\r\n'.join(newPartLines) + '\r\n'
                break
        
        return "--" + boundary + "--" + boundary.join(parts[1:])
    
    def updateContentLength(self, headers, bodyLength):
        newHeaders = []
        for header in headers:
            if header.lower().startswith("content-length:"):
                newHeaders.append("Content-Length: " + str(bodyLength))
            else:
                newHeaders.append(header)
        return newHeaders
    
    def sendToScanner(self, invocation):
        # 在新线程中执行HTTP请求
        thread = threading.Thread(target=self._sendToScannerThread, args=(invocation,))
        thread.daemon = True
        thread.start()
    
    def _sendToScannerThread(self, invocation):
        try:
            messageInfo = invocation.getSelectedMessages()[0]
            httpService = messageInfo.getHttpService()
            request = messageInfo.getRequest()
            
            # 使用正确的analyzeRequest方法获取URL
            analyzedRequest = self._helpers.analyzeRequest(httpService, request)
            
            # 修改请求
            modifiedRequest = self.modifyUploadRequest(analyzedRequest, request)
            
            if modifiedRequest:
                # 在Swing线程中显示修改后的请求
                SwingUtilities.invokeLater(lambda: self.requestText.setText(self._helpers.bytesToString(modifiedRequest)))
                
                # 发送修改后的请求
                response_info = self._callbacks.makeHttpRequest(httpService, modifiedRequest)
                
                # 获取响应内容
                response_bytes = response_info.getResponse()
                analyzedResponse = self._helpers.analyzeResponse(response_bytes)
                
                # 正确解码响应体 - 修复中文乱码的关键
                response_str = self.decodeResponse(response_bytes, analyzedResponse)
                
                # 检测XSS可能性
                xss_detected = self.detectXSS(response_str)
                
                # 在Swing线程中更新UI
                def updateUI():
                    # 显示原始响应
                    self.responseText.setText(response_str)
                    
                    # 显示美化后的响应
                    if self.prettyPrintCheckbox.isSelected():
                        html_content = self.createPrettyHTMLResponse(response_str, analyzedResponse, xss_detected)
                        self.htmlResponsePane.setText(html_content)
                    
                    # 记录结果 - 安全地获取URL
                    result = "Scan completed:\n"
                    try:
                        url = analyzedRequest.getUrl()
                        result += "Target URL: " + str(url) + "\n"
                    except:
                        result += "Target URL: [Unable to get URL] " + str(httpService.getHost()) + "\n"
                    
                    result += "Status Code: " + str(analyzedResponse.getStatusCode()) + "\n"
                    result += "Response Length: " + str(len(response_bytes) - analyzedResponse.getBodyOffset()) + "\n"
                    
                    if xss_detected:
                        result += "🚨 [XSS SUSPECTED] Response contains SVG content or script features\n"
                    else:
                        result += "✅ No obvious XSS features found\n"
                    
                    result += "Modified request sent and recorded\n"
                    
                    self.logResult(result)
                    
                    # 保存记录
                    if self.saveLogCheckbox.isSelected():
                        try:
                            url_str = str(analyzedRequest.getUrl())
                        except:
                            url_str = "http://" + httpService.getHost() + ":" + str(httpService.getPort())
                        
                        self.saveScanRecord(url_str, 
                                          analyzedResponse.getStatusCode(), 
                                          xss_detected, 
                                          self._helpers.bytesToString(modifiedRequest), 
                                          response_str)
                    
                    # 自动切换到格式化响应标签
                    if self.prettyPrintCheckbox.isSelected():
                        self.tabbedPane.setSelectedIndex(2)
                    else:
                        self.tabbedPane.setSelectedIndex(1)
                
                SwingUtilities.invokeLater(updateUI)
                
            else:
                self.logResult("Error: Cannot modify request or not a valid upload request")
                
        except Exception as e:
            self.logResult("Scan error: " + str(e))
            import traceback
            self.logResult("Detailed error: " + traceback.format_exc())
    
    def decodeResponse(self, response_bytes, analyzedResponse):
        """正确解码响应，解决中文乱码问题"""
        try:
            # 获取响应头以检测编码
            headers = analyzedResponse.getHeaders()
            charset = 'utf-8'  # 默认编码
            
            # 从Content-Type头中提取编码
            for header in headers:
                if header.lower().startswith('content-type:'):
                    charset_match = re.search(r'charset=([^\s;]+)', header, re.IGNORECASE)
                    if charset_match:
                        charset = charset_match.group(1).lower()
                        # 处理常见的编码别名
                        if charset == 'gb2312':
                            charset = 'gbk'
                        break
            
            # 获取响应体
            body_offset = analyzedResponse.getBodyOffset()
            body_bytes = response_bytes[body_offset:]
            
            # 尝试使用检测到的编码解码
            try:
                body_str = body_bytes.tostring().decode(charset)
            except:
                # 如果指定编码失败，尝试常见编码
                for test_charset in ['utf-8', 'gbk', 'gb2312', 'latin1', 'iso-8859-1']:
                    try:
                        body_str = body_bytes.tostring().decode(test_charset)
                        charset = test_charset
                        break
                    except:
                        continue
                else:
                    # 所有编码都失败，使用默认编码并忽略错误
                    body_str = body_bytes.tostring().decode('utf-8', 'ignore')
            
            # 重建完整的响应（头部 + 解码后的body）
            header_str = self._helpers.bytesToString(response_bytes[:body_offset])
            return header_str + body_str
            
        except Exception as e:
            # 如果解码失败，返回原始字符串表示
            return self._helpers.bytesToString(response_bytes)
    
    def createPrettyHTMLResponse(self, response_str, analyzedResponse, xss_detected):
        """创建美化的HTML响应显示"""
        try:
            # 获取响应头
            headers = analyzedResponse.getHeaders()
            status_code = analyzedResponse.getStatusCode()
            
            # 获取响应体
            body_offset = analyzedResponse.getBodyOffset()
            body = response_str[body_offset:] if body_offset < len(response_str) else response_str
            
            # 检测内容类型
            content_type = ""
            for header in headers:
                if header.lower().startswith("content-type:"):
                    content_type = header.split(":", 1)[1].strip()
                    break
            
            # 状态码颜色和图标
            if status_code < 300:
                status_class = "status-success"
                status_icon = "✅"
            elif status_code < 400:
                status_class = "status-info"
                status_icon = "ℹ️"
            else:
                status_class = "status-error"
                status_icon = "❌"
            
            # 构建HTML内容
            html_content = """
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body { font-family: 'Consolas', 'Monaco', monospace; font-size: 12px; background: #f5f5f5; }
                    .container { background: white; padding: 15px; margin: 10px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                    .status-success { color: #28a745; font-weight: bold; }
                    .status-error { color: #dc3545; font-weight: bold; }
                    .status-info { color: #17a2b8; font-weight: bold; }
                    .header { color: #6c757d; font-weight: bold; margin-top: 10px; }
                    .key { color: #007bff; font-weight: bold; }
                    .value { color: #28a745; }
                    .string { color: #d63384; }
                    .number { color: #fd7e14; }
                    .boolean { color: #0dcaf0; }
                    .null { color: #6c757d; }
                    .xss-warning { background: #fff3cd; color: #856404; padding: 10px; border: 1px solid #ffeaa7; border-radius: 4px; margin: 10px 0; }
                    .error-box { background: #f8d7da; color: #721c24; padding: 10px; border: 1px solid #f5c6cb; border-radius: 4px; margin: 10px 0; }
                    pre { background: #f8f9fa; padding: 10px; border-radius: 4px; border: 1px solid #e9ecef; overflow-x: auto; white-space: pre-wrap; }
                </style>
            </head>
            <body>
            <div class="container">
            """
            
            # 状态码显示
            html_content += '<div class="' + status_class + '">' + status_icon + ' HTTP Status: ' + str(status_code) + '</div>'
            
            # XSS警告
            if xss_detected:
                html_content += '''
                <div class="xss-warning">
                🚨 <b>XSS Suspicion:</b> Response contains SVG content or script features that may indicate XSS vulnerability
                </div>
                '''
            
            # 响应头
            html_content += '<div class="header">📋 Response Headers:</div><pre>'
            for header in headers:
                escaped_header = self.escape_html(header)
                html_content += escaped_header + '\n'
            html_content += '</pre>'
            
            # 响应体
            html_content += '<div class="header">📄 Response Body:</div>'
            
            # JSON响应处理
            if "application/json" in content_type.lower():
                try:
                    parsed_json = json.loads(body)
                    formatted_json = json.dumps(parsed_json, indent=2, ensure_ascii=False)
                    # 添加语法高亮
                    formatted_json = self.highlightJSON(formatted_json)
                    html_content += '<pre>' + formatted_json + '</pre>'
                except Exception as json_error:
                    escaped_body = self.escape_html(body)
                    html_content += '<pre>JSON Parse Error: ' + str(json_error) + '\n\n' + escaped_body + '</pre>'
            
            # HTML错误页面处理
            elif status_code >= 400 and "text/html" in content_type.lower():
                html_content += self.formatErrorPage(body, status_code)
            
            # 其他文本内容
            elif "text/" in content_type.lower():
                escaped_body = self.escape_html(body)
                html_content += '<pre>' + escaped_body + '</pre>'
            
            # 二进制或其他内容
            else:
                html_content += '<pre>[Binary or unsupported content type: ' + content_type + ']</pre>'
                escaped_body = self.escape_html(body[:1000])
                html_content += '<pre>' + escaped_body + '</pre>'  # 显示前1000字符
            
            html_content += """
            </div>
            </body>
            </html>
            """
            
            return html_content
            
        except Exception as e:
            return "<html><body>Error formatting response: " + self.escape_html(str(e)) + "</body></html>"
    
    def formatErrorPage(self, html_body, status_code):
        """格式化错误页面"""
        try:
            # 提取错误信息
            result = ""
            
            # 提取标题
            title_match = re.search(r'<title>(.*?)</title>', html_body, re.IGNORECASE | re.DOTALL)
            if title_match:
                title_text = title_match.group(1)
                result += '<div class="error-box"><b>Error Title:</b> ' + self.escape_html(title_text) + '</div>'
            
            # 提取错误类型
            type_match = re.search(r'<p><b>([^<]*)</b>\s*([^<]+)</p>', html_body)
            if type_match and "类型" in type_match.group(1) or "Type" in type_match.group(1):
                result += '<div class="error-box"><b>Error Type:</b> ' + self.escape_html(type_match.group(2).strip()) + '</div>'
            
            # 提取错误描述
            desc_match = re.search(r'<p><b>([^<]*)</b>\s*([^<]+)</p>', html_body)
            if desc_match and ("描述" in desc_match.group(1) or "Description" in desc_match.group(1)):
                result += '<div class="error-box"><b>Description:</b> ' + self.escape_html(desc_match.group(2).strip()) + '</div>'
            
            # 提取异常信息
            exception_match = re.search(r'<pre>([^<]*)</pre>', html_body, re.DOTALL)
            if exception_match:
                result += '<div class="error-box"><b>Exception:</b><pre>' + self.escape_html(exception_match.group(1).strip()) + '</pre></div>'
            
            # 如果没有提取到特定信息，显示原始HTML
            if not result:
                result = '<pre>' + self.escape_html(html_body) + '</pre>'
            else:
                result += '<div class="header">Raw HTML:</div><pre>' + self.escape_html(html_body) + '</pre>'
            
            return result
            
        except Exception as e:
            return '<pre>Error parsing error page: ' + self.escape_html(str(e)) + '\n\n' + self.escape_html(html_body) + '</pre>'
    
    def escape_html(self, text):
        """HTML转义函数"""
        if text is None:
            return ""
        text = str(text)
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('"', '&quot;')
        text = text.replace("'", '&#x27;')
        return text
    
    def highlightJSON(self, json_str):
        """为JSON添加语法高亮"""
        # 转义HTML特殊字符
        json_str = self.escape_html(json_str)
        
        # JSON语法高亮
        json_str = re.sub(r'("(\\"|[^"])*"):', r'<span class="key">\1</span>:', json_str)
        json_str = re.sub(r':\s*("(\\"|[^"])*")', r': <span class="string">\1</span>', json_str)
        json_str = re.sub(r':\s*(\btrue\b|\bfalse\b)', r': <span class="boolean">\1</span>', json_str)
        json_str = re.sub(r':\s*(\bnull\b)', r': <span class="null">\1</span>', json_str)
        json_str = re.sub(r':\s*(\d+)', r': <span class="number">\1</span>', json_str)
        
        return json_str
    
    def detectXSS(self, response_str):
        """检测响应中是否包含XSS相关特征"""
        xss_indicators = [
            r'\.svg',  # SVG文件引用
            r'<svg',   # SVG标签
            r'onload=', # onload事件
            r'onerror=', # onerror事件
            r'javascript:', # JavaScript协议
            r'alert\(', # alert函数
            r'<script', # script标签
            r'application/xml', # XML内容类型
            r'image/svg+xml' # SVG内容类型
        ]
        
        for indicator in xss_indicators:
            if re.search(indicator, response_str, re.IGNORECASE):
                return True
        return False
    
    def saveScanRecord(self, url, status_code, xss_detected, request, response):
        """保存扫描记录到文件"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = "xss_scan_{}.txt".format(timestamp)
            filepath = os.path.join(self.log_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("SVG XSS Scan Record - {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                f.write("=" * 80 + "\n\n")
                
                f.write("Target URL: {}\n".format(url))
                f.write("Status Code: {}\n".format(status_code))
                f.write("XSS Detection: {}\n".format("SUSPECTED" if xss_detected else "Not Found"))
                f.write("\n")
                
                f.write("Request:\n")
                f.write("-" * 40 + "\n")
                f.write(request)
                f.write("\n\n")
                
                f.write("Response:\n")
                f.write("-" * 40 + "\n")
                f.write(response)
                f.write("\n\n")
                
                if xss_detected:
                    f.write("WARNING: This response may contain XSS vulnerability features!\n")
                
                f.write("=" * 80 + "\n")
            
            self.logResult("Scan record saved: " + filepath)
            
        except Exception as e:
            self.logResult("Save record error: " + str(e))
    
    def showScanRecords(self):
        """显示扫描记录目录"""
        try:
            if os.path.exists(self.log_dir):
                import subprocess
                if os.name == 'nt':  # Windows
                    os.startfile(self.log_dir)
                elif sys.platform == 'darwin':  # Mac
                    subprocess.call(['open', self.log_dir])
                else:  # Linux
                    subprocess.call(['xdg-open', self.log_dir])
                self.logResult("Scan records directory opened: " + self.log_dir)
            else:
                self.logResult("Scan records directory not exists: " + self.log_dir)
        except Exception as e:
            self.logResult("Open records directory error: " + str(e))
    
    def logResult(self, message):
        SwingUtilities.invokeLater(lambda: self.resultText.append(message + "\n" + "-" * 50 + "\n"))
    
    def getTabCaption(self):
        return "SVG XSS Scanner"
    
    def getUiComponent(self):
        return self._mainPanel

# 菜单项监听器
class MenuItemListener(ActionListener):
    def __init__(self, extender, invocation):
        self._extender = extender
        self._invocation = invocation
        
    def actionPerformed(self, event):
        self._extender.sendToScanner(self._invocation)

# 测试按钮监听器
class TestButtonListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
        
    def actionPerformed(self, event):
        self._extender.logResult("Test Payload: " + self._extender.payloadText.getText())

# 清除按钮监听器
class ClearButtonListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
        
    def actionPerformed(self, event):
        self._extender.resultText.setText("")
        self._extender.requestText.setText("")
        self._extender.responseText.setText("")

# 查看日志按钮监听器
class ViewLogButtonListener(ActionListener):
    def __init__(self, extender):
        self._extender = extender
        
    def actionPerformed(self, event):
        self._extender.showScanRecords()