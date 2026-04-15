# HiCyberMCP

HiCyberMCP 是一个用 Go 语言编写的 MCP (Model Context Protocol) 客户端，作为 AI 代理与 HiCyberServer 服务器之间的通信接口。它提供了对 150+ 安全工具的访问能力，支持与 Claude、GPT、VS Code Copilot 等 AI 客户端集成。

## 功能特性

- **通信桥梁**：建立与 HiCyberServer 服务器的连接，处理请求和响应
- **工具注册**：提供对 150+ 安全工具的访问，包括：
  - 网络扫描工具（nmap、rustscan、masscan 等）
  - Web 应用安全工具（gobuster、nuclei、sqlmap 等）
  - 云安全工具（prowler、trivy、scout-suite 等）
  - 二进制分析工具
  - 密码破解工具
  - 文件操作和载荷生成
  - Python 环境管理
- **错误处理**：实现了增强的错误处理和恢复机制
- **日志系统**：提供详细的日志输出，增强用户体验
- **AI 客户端集成**：支持与 Claude、GPT、VS Code Copilot 等 AI 客户端集成

## 快速开始

### 环境要求

- Go 1.20 或更高版本
- 运行中的 HiCyberServer 服务器

### 安装和运行

1. **克隆项目**

2. **安装依赖**
   ```bash
   cd HiCyberMCP
   go mod tidy
   ```

3. **运行客户端**
   ```bash
   go run main.go --server http://localhost:8888
   ```

   默认情况下，客户端会连接到 `http://127.0.0.1:8888`。

4. **命令行选项**
   - `--server`：HiCyberServer 服务器 URL（默认 http://127.0.0.1:8888）
   - `--timeout`：请求超时时间（默认 300 秒）
   - `--debug`：启用调试模式

### 验证安装

```bash
# 运行客户端并检查连接状态
go run main.go --server http://localhost:8888
```

## 与 AI 客户端集成

### Claude Desktop 或 Cursor 集成

编辑 `~/.config/Claude/claude_desktop_config.json`：

```json
{
  "mcpServers": {
    "cyberai": {
      "command": "go",
      "args": [
        "run",
        "/path/to/HiCyberMCP/main.go",
        "--server",
        "http://localhost:8888"
      ],
      "description": "HiCyberMCP - Advanced Cybersecurity MCP Client",
      "timeout": 300,
      "disabled": false
    }
  }
}
```

### VS Code Copilot 集成

配置 VS Code 设置：

```json
{
  "servers": {
    "cyberai": {
      "type": "stdio",
      "command": "go",
      "args": [
        "run",
        "/path/to/HiCyberMCP/main.go",
        "--server",
        "http://localhost:8888"
      ]
    }
  },
  "inputs": []
}
```

## 可用工具

### 网络扫描工具
- `nmap_scan`：执行 Nmap 扫描
- `dirb_scan`：执行 Dirb 目录扫描
- `ffuf_scan`：执行 FFuf 模糊测试
- `amass_scan`：执行 Amass 子域名枚举
- `subfinder_scan`：执行 Subfinder 被动子域名发现

### Web 应用安全工具
- `gobuster_scan`：执行 Gobuster 目录扫描
- `nuclei_scan`：执行 Nuclei 漏洞扫描
- `nikto_scan`：执行 Nikto Web 服务器扫描
- `sqlmap_scan`：执行 SQLMap SQL 注入测试
- `wpscan_analyze`：执行 WPScan WordPress 安全扫描

### 云安全工具
- `prowler_scan`：执行 Prowler 云安全评估
- `trivy_scan`：执行 Trivy 容器漏洞扫描

### 密码破解工具
- `hydra_attack`：执行 Hydra 密码破解
- `john_crack`：执行 John the Ripper 密码破解
- `hashcat_crack`：执行 Hashcat 密码破解

### 文件操作和载荷生成
- `create_file`：创建文件
- `modify_file`：修改文件
- `delete_file`：删除文件
- `list_files`：列出文件
- `generate_payload`：生成测试载荷

### Python 环境管理
- `install_python_package`：安装 Python 包
- `execute_python_script`：执行 Python 脚本

## 安全考虑

- 该工具为 AI 代理提供强大的系统访问权限
- 应在隔离环境或专用安全测试 VM 中运行
- AI 代理可以执行任意安全工具，确保适当的监督
- 通过实时仪表盘监控 AI 代理活动

## 合法和道德使用

**允许的使用场景**：
- 授权的渗透测试（需获得书面授权）
- Bug Bounty 计划（在计划范围和规则内）
- CTF 竞赛（教育和竞争环境）
- 安全研究（在拥有或授权的系统上）
- Red Team 演习（获得组织批准）

**禁止的使用场景**：
- 未授权测试（未经许可切勿测试系统）
- 恶意活动（无非法或有害活动）
- 数据盗窃（无未经授权的数据访问或窃取）

## 故障排除

### 常见问题

1. **连接失败**：
   - 检查 HiCyberServer 服务器是否正在运行
   - 验证服务器 URL 和端口配置
   - 检查网络连接和防火墙设置

2. **工具执行失败**：
   - 确保服务器上已安装相关安全工具
   - 检查工具路径是否正确
   - 查看服务器日志获取详细错误信息

3. **AI 代理无法连接**：
   - 验证 MCP 配置路径
   - 检查服务器日志中的连接尝试
   - 启用调试模式查看详细信息

### 调试模式

启用调试模式以获取详细日志：
```bash
go run main.go --server http://localhost:8888 --debug
```

## 贡献

我们欢迎来自网络安全和 Go 社区的贡献，包括：
- AI 代理集成
- 安全工具添加
- 性能优化
- 文档改进

## 许可证

MIT License
