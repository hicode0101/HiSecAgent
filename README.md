# HiSecAgent - AI 驱动的网络安全自动化平台

## 项目概述

HiSecAgent 是一个由 HiCyberServer 和 HiCyberMCP 组成的 AI 驱动网络安全自动化平台，专为渗透测试、漏洞评估和安全研究设计。它采用 Go 语言实现，集成了多个安全工具和智能决策引擎，能够提供全面的安全评估和漏洞发现能力。

## 核心组件

### HiCyberServer

**服务器端**，提供核心安全功能：

- **智能决策引擎**：根据目标类型和技术栈自动选择最佳安全工具和参数
- **150+ 安全工具集成**：包括网络扫描、Web 应用安全、云安全等多个类别
- **实时进程管理**：监控和管理工具执行进程
- **RESTful API**：提供完整的 API 接口，支持与 AI 客户端集成
- **错误处理和恢复**：增强的错误处理和自动恢复机制
- **现代视觉输出**：彩色日志和实时进度显示

### HiCyberMCP

**MCP (Model Context Protocol) 客户端**，作为 AI 代理与服务器之间的通信接口：

- **通信桥梁**：建立与 HiCyberServer 服务器的连接，处理请求和响应
- **工具注册**：提供对多个安全工具的访问，包括：
  - 网络扫描工具（nmap、rustscan、masscan 等）
  - Web 应用安全工具（gobuster、nuclei、sqlmap 等）
  - 云安全工具（prowler、trivy、scout-suite 等）
  - 二进制分析工具
  - 密码破解工具
  - 文件操作和载荷生成
- **错误处理**：实现了增强的错误处理和恢复机制
- **日志系统**：提供详细的日志输出，增强用户体验
- **AI 客户端集成**：支持与 Claude、GPT、VS Code Copilot 等 AI 客户端集成

## 工作流程

1. **AI 代理连接**：Claude、GPT 或其他 MCP 兼容的代理通过 MCP 协议连接到 HiCyberMCP
2. **请求转发**：HiCyberMCP 将 AI 代理的请求转发给 HiCyberServer
3. **智能分析**：HiCyberServer 的决策引擎分析目标，选择最佳工具和参数
4. **工具执行**：HiCyberServer 执行安全工具，处理输出和错误
5. **结果返回**：执行结果通过 HiCyberMCP 返回给 AI 代理
6. **AI 分析**：AI 代理分析结果并生成报告或进一步的测试建议

## 快速开始

### 环境要求

- Go 1.20 或更高版本
- 安装了相关的安全工具（如 nmap、gobuster、nuclei 等）

### 运行服务器

```bash
cd HiCyberServer
go mod tidy
go run main.go
```

默认情况下，服务器会在 `127.0.0.1:8888` 上运行。

### 运行 MCP 客户端

```bash
cd HiCyberMCP
go mod tidy
go run main.go --server http://localhost:8888
```

### 与 AI 客户端集成

#### Claude Desktop 或 Cursor 集成

编辑 `~/.config/Claude/claude_desktop_config.json`：

```json
{
  "mcpServers": {
    "hicyber": {
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

#### VS Code Copilot 集成

配置 VS Code 设置：

```json
{
  "servers": {
    "hicyber": {
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

## 核心功能

### 智能目标分析

- 自动识别目标类型（Web 应用、网络主机、API 端点等）
- 检测目标使用的技术栈和 CMS 类型
- 计算攻击面得分和风险级别
- 生成详细的目标分析报告

### 安全工具执行

- **网络扫描**：nmap、dirb、ffuf、amass、subfinder 等
- **Web 应用安全**：gobuster、nuclei、nikto、sqlmap、wpscan 等
- **云安全**：prowler、trivy 等
- **密码破解**：hydra、john、hashcat 等
- **文件操作**：创建、修改、删除、列出文件
- **载荷生成**：生成测试载荷

### 实时进程管理

- 监控工具执行状态
- 提供详细的进程信息
- 支持进程终止
- 实时仪表盘显示

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

3. **AI 代理无法连接**：
   - 检查 HiCyberServer 服务器是否正在运行
   - 验证服务器 URL 和端口配置
   - 检查网络连接和防火墙设置

### 调试模式

启用调试模式以获取详细日志：

```bash
# 服务器调试模式
go run main.go

# MCP 客户端调试模式
go run main.go --server http://localhost:8888 --debug
```

## 贡献

我们欢迎来自网络安全和 Go 社区的贡献，包括：
- 安全工具集成
- AI 代理集成
- 性能优化
- 功能增强
- 文档改进

## 许可证

MIT License

## 总结

HiSecAgent 是一个强大的 AI 驱动的网络安全自动化平台，通过集成 150+ 安全工具和智能决策引擎，提供了全面的安全评估和漏洞发现能力。它采用现代化的架构设计，包括服务器端和客户端组件，能够与主流 AI 客户端集成，为安全专业人员提供高效、智能的安全测试工具。

作为一个开源项目，HiSecAgent 欢迎来自网络安全和 Go 社区的贡献，不断改进和扩展其功能，为网络安全领域提供更强大的工具支持。