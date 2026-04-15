# CyberAiServer

CyberAiServer 是一个用 Go 语言编写的网络安全自动化平台。它提供了智能决策引擎、安全工具集成和实时进程管理等功能，用于渗透测试、漏洞评估和安全研究。

## 功能特性

- **智能决策引擎**：根据目标类型和技术栈自动选择最佳安全工具和参数
- **150+ 安全工具集成**：包括网络扫描、Web 应用安全、云安全等多个类别
- **实时进程管理**：监控和管理工具执行进程
- **RESTful API**：提供完整的 API 接口，支持与 AI 客户端集成
- **错误处理和恢复**：增强的错误处理和自动恢复机制
- **现代视觉输出**：彩色日志和实时进度显示

## 快速开始

### 环境要求

- Go 1.20 或更高版本
- 安装了相关的安全工具（如 nmap、gobuster、nuclei 等）

### 安装和运行

1. **克隆项目**

2. **安装依赖**
   ```bash
   cd CyberAiServer
   go mod tidy
   ```

3. **运行服务器**
   ```bash
   go run main.go
   ```

   默认情况下，服务器会在 `127.0.0.1:8888` 上运行。

4. **环境变量配置**
   可以通过 `.env` 文件或系统环境变量配置以下选项：
   - `PORT`：服务器端口（默认 8888）
   - `GIN_MODE`：Gin 模式（默认 debug，生产环境设置为 release）

### 验证安装

```bash
# 测试服务器健康状态
curl http://localhost:8888/health

# 测试目标分析功能
curl -X POST http://localhost:8888/api/intelligence/analyze-target \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "analysis_type": "comprehensive"}'
```

## API 接口

### 核心系统端点

| 端点 | 方法 | 描述 |
|------|------|------|
| `/health` | GET | 服务器健康检查，包括工具可用性 |
| `/api/command` | POST | 执行任意命令，支持缓存 |
| `/api/intelligence/analyze-target` | POST | AI 驱动的目标分析 |
| `/api/intelligence/select-tools` | POST | 智能工具选择 |

### 工具执行端点

| 工具类别 | 端点 | 描述 |
|---------|------|------|
| 网络扫描 | `/api/tools/nmap` | 执行 Nmap 扫描 |
| Web 应用 | `/api/tools/gobuster` | 执行 Gobuster 目录扫描 |
| 漏洞扫描 | `/api/tools/nuclei` | 执行 Nuclei 漏洞扫描 |

### 进程管理端点

| 操作 | 端点 | 描述 |
|------|------|------|
| 列出进程 | `GET /api/processes/list` | 列出所有活动进程 |
| 进程状态 | `GET /api/processes/status/<id>` | 获取详细进程信息 |
| 终止进程 | `POST /api/processes/terminate/<id>` | 停止特定进程 |

## 与 AI 客户端集成

### Claude Desktop 或 Cursor 集成

编辑 `~/.config/Claude/claude_desktop_config.json`：

```json
{
  "mcpServers": {
    "cyberai": {
      "command": "python3",
      "args": [
        "/path/to/cyberai-mcp.py",
        "--server",
        "http://localhost:8888"
      ],
      "description": "CyberAiServer - Advanced Cybersecurity Automation Platform",
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
      "command": "python3",
      "args": [
        "/path/to/cyberai-mcp.py",
        "--server",
        "http://localhost:8888"
      ]
    }
  },
  "inputs": []
}
```

## 安全考虑

- 该工具为 AI 代理提供强大的系统访问权限
- 应在隔离环境或专用安全测试 VM 中运行
- AI 代理可以执行任意安全工具，确保适当的监督
- 通过实时仪表盘监控 AI 代理活动
- 考虑为生产部署实现认证

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

1. **服务器启动失败**：
   - 检查端口是否被占用
   - 确保 Go 环境配置正确
   - 查看日志输出了解具体错误

2. **工具执行失败**：
   - 确保相关安全工具已安装
   - 检查工具路径是否正确
   - 查看进程状态获取详细错误信息

3. **API 连接失败**：
   - 检查服务器是否正在运行
   - 验证 URL 和端口配置
   - 检查网络连接和防火墙设置

### 调试模式

默认情况下，服务器以调试模式运行，会输出详细的日志信息。在生产环境中，建议设置 `GIN_MODE=release` 以提高性能。

## 贡献

我们欢迎来自网络安全和 Go 社区的贡献，包括：
- 安全工具集成
- 性能优化
- 功能增强
- 文档改进

## 许可证

MIT License
