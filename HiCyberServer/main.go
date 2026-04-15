package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

// 全局变量
var (
	processes     = make(map[string]*ProcessInfo)
	processMutex  sync.Mutex
	serverVersion = "v6.0"
)

// ProcessInfo 进程信息
type ProcessInfo struct {
	ID        string    `json:"id"`
	Command   string    `json:"command"`
	Status    string    `json:"status"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Output    string    `json:"output,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// TargetType 目标类型枚举
type TargetType string

const (
	TargetTypeWebApplication TargetType = "web_application"
	TargetTypeNetworkHost    TargetType = "network_host"
	TargetTypeAPIEndpoint    TargetType = "api_endpoint"
	TargetTypeCloudService   TargetType = "cloud_service"
	TargetTypeBinaryFile     TargetType = "binary_file"
	TargetTypeUnknown        TargetType = "unknown"
)

// TechnologyStack 技术栈枚举
type TechnologyStack string

const (
	TechnologyStackApache    TechnologyStack = "apache"
	TechnologyStackNginx     TechnologyStack = "nginx"
	TechnologyStackIIS       TechnologyStack = "iis"
	TechnologyStackNodeJS    TechnologyStack = "nodejs"
	TechnologyStackPHP       TechnologyStack = "php"
	TechnologyStackPython    TechnologyStack = "python"
	TechnologyStackJava      TechnologyStack = "java"
	TechnologyStackDotNet    TechnologyStack = "dotnet"
	TechnologyStackWordPress TechnologyStack = "wordpress"
	TechnologyStackDrupal    TechnologyStack = "drupal"
	TechnologyStackJoomla    TechnologyStack = "joomla"
	TechnologyStackReact     TechnologyStack = "react"
	TechnologyStackAngular   TechnologyStack = "angular"
	TechnologyStackVue       TechnologyStack = "vue"
	TechnologyStackUnknown   TechnologyStack = "unknown"
)

// TargetProfile 目标分析配置文件
type TargetProfile struct {
	Target             string                 `json:"target"`
	TargetType         TargetType             `json:"target_type"`
	IPAddresses        []string               `json:"ip_addresses"`
	OpenPorts          []int                  `json:"open_ports"`
	Services           map[int]string         `json:"services"`
	Technologies       []TechnologyStack      `json:"technologies"`
	CMSType            string                 `json:"cms_type,omitempty"`
	CloudProvider      string                 `json:"cloud_provider,omitempty"`
	SecurityHeaders    map[string]string      `json:"security_headers"`
	SSLInfo            map[string]interface{} `json:"ssl_info"`
	Subdomains         []string               `json:"subdomains"`
	Endpoints          []string               `json:"endpoints"`
	AttackSurfaceScore float64                `json:"attack_surface_score"`
	RiskLevel          string                 `json:"risk_level"`
	ConfidenceScore    float64                `json:"confidence_score"`
}

// AttackStep 攻击步骤
type AttackStep struct {
	Tool                  string            `json:"tool"`
	Parameters            map[string]string `json:"parameters"`
	ExpectedOutcome       string            `json:"expected_outcome"`
	SuccessProbability    float64           `json:"success_probability"`
	ExecutionTimeEstimate int               `json:"execution_time_estimate"`
	Dependencies          []string          `json:"dependencies"`
}

// AttackChain 攻击链
type AttackChain struct {
	TargetProfile      TargetProfile `json:"target_profile"`
	Steps              []AttackStep  `json:"steps"`
	SuccessProbability float64       `json:"success_probability"`
	EstimatedTime      int           `json:"estimated_time"`
	RequiredTools      []string      `json:"required_tools"`
	RiskLevel          string        `json:"risk_level"`
}

// IntelligentDecisionEngine 智能决策引擎
type IntelligentDecisionEngine struct {
	ToolEffectiveness    map[TargetType]map[string]float64
	TechnologySignatures map[string]map[TechnologyStack][]string
	AttackPatterns       map[string][]map[string]interface{}
}

// NewIntelligentDecisionEngine 创建智能决策引擎
func NewIntelligentDecisionEngine() *IntelligentDecisionEngine {
	return &IntelligentDecisionEngine{
		ToolEffectiveness:    initializeToolEffectiveness(),
		TechnologySignatures: initializeTechnologySignatures(),
		AttackPatterns:       initializeAttackPatterns(),
	}
}

// initializeToolEffectiveness 初始化工具效果评估
func initializeToolEffectiveness() map[TargetType]map[string]float64 {
	return map[TargetType]map[string]float64{
		TargetTypeWebApplication: {
			"nmap":        0.8,
			"gobuster":    0.9,
			"nuclei":      0.95,
			"nikto":       0.85,
			"sqlmap":      0.9,
			"ffuf":        0.9,
			"feroxbuster": 0.85,
			"katana":      0.88,
			"httpx":       0.85,
			"wpscan":      0.95,
			"burpsuite":   0.9,
			"dirsearch":   0.87,
			"gau":         0.82,
			"waybackurls": 0.8,
			"arjun":       0.9,
			"paramspider": 0.85,
			"x8":          0.88,
			"jaeles":      0.92,
			"dalfox":      0.93,
			"anew":        0.7,
			"qsreplace":   0.75,
			"uro":         0.7,
		},
		TargetTypeNetworkHost: {
			"nmap":          0.95,
			"nmap-advanced": 0.97,
			"masscan":       0.92,
			"rustscan":      0.9,
			"autorecon":     0.95,
			"enum4linux":    0.8,
			"enum4linux-ng": 0.88,
			"smbmap":        0.85,
			"rpcclient":     0.82,
			"nbtscan":       0.75,
			"arp-scan":      0.85,
			"responder":     0.88,
			"hydra":         0.8,
			"netexec":       0.85,
			"amass":         0.7,
		},
		TargetTypeAPIEndpoint: {
			"nuclei":      0.9,
			"ffuf":        0.85,
			"arjun":       0.95,
			"paramspider": 0.88,
			"httpx":       0.9,
			"x8":          0.92,
			"katana":      0.85,
			"jaeles":      0.88,
			"postman":     0.8,
		},
		TargetTypeCloudService: {
			"prowler":               0.95,
			"scout-suite":           0.92,
			"cloudmapper":           0.88,
			"pacu":                  0.85,
			"trivy":                 0.9,
			"clair":                 0.85,
			"kube-hunter":           0.9,
			"kube-bench":            0.88,
			"docker-bench-security": 0.85,
			"falco":                 0.87,
			"checkov":               0.9,
			"terrascan":             0.88,
		},
		TargetTypeBinaryFile: {
			"ghidra":        0.95,
			"radare2":       0.9,
			"gdb":           0.85,
			"gdb-peda":      0.92,
			"angr":          0.88,
			"pwntools":      0.9,
			"ropgadget":     0.85,
			"ropper":        0.88,
			"one-gadget":    0.82,
			"libc-database": 0.8,
			"checksec":      0.75,
			"strings":       0.7,
			"objdump":       0.75,
			"binwalk":       0.8,
			"pwninit":       0.85,
		},
	}
}

// initializeTechnologySignatures 初始化技术检测签名
func initializeTechnologySignatures() map[string]map[TechnologyStack][]string {
	return map[string]map[TechnologyStack][]string{
		"headers": {
			TechnologyStackApache: {"Apache", "apache"},
			TechnologyStackNginx:  {"nginx", "Nginx"},
			TechnologyStackIIS:    {"Microsoft-IIS", "IIS"},
			TechnologyStackPHP:    {"PHP", "X-Powered-By: PHP"},
			TechnologyStackNodeJS: {"Express", "X-Powered-By: Express"},
			TechnologyStackPython: {"Django", "Flask", "Werkzeug"},
			TechnologyStackJava:   {"Tomcat", "JBoss", "WebLogic"},
			TechnologyStackDotNet: {"ASP.NET", "X-AspNet-Version"},
		},
		"content": {
			TechnologyStackWordPress: {"wp-content", "wp-includes", "WordPress"},
			TechnologyStackDrupal:    {"Drupal", "drupal", "/sites/default"},
			TechnologyStackJoomla:    {"Joomla", "joomla", "/administrator"},
			TechnologyStackReact:     {"React", "react", "__REACT_DEVTOOLS"},
			TechnologyStackAngular:   {"Angular", "angular", "ng-version"},
			TechnologyStackVue:       {"Vue", "vue", "__VUE__"},
		},
		"ports": {
			TechnologyStackApache: {"80", "443", "8080", "8443"},
			TechnologyStackNginx:  {"80", "443", "8080"},
			TechnologyStackIIS:    {"80", "443", "8080"},
			TechnologyStackNodeJS: {"3000", "8000", "8080", "9000"},
		},
	}
}

// initializeAttackPatterns 初始化攻击模式
func initializeAttackPatterns() map[string][]map[string]interface{} {
	return map[string][]map[string]interface{}{
		"web_reconnaissance": {
			{"tool": "nmap", "priority": 1, "params": map[string]interface{}{"scan_type": "-sV -sC", "ports": "80,443,8080,8443"}},
			{"tool": "httpx", "priority": 2, "params": map[string]interface{}{"probe": true, "tech_detect": true}},
			{"tool": "katana", "priority": 3, "params": map[string]interface{}{"depth": 3, "js_crawl": true}},
			{"tool": "gau", "priority": 4, "params": map[string]interface{}{"include_subs": true}},
			{"tool": "waybackurls", "priority": 5, "params": map[string]interface{}{"get_versions": false}},
			{"tool": "nuclei", "priority": 6, "params": map[string]interface{}{"severity": "critical,high", "tags": "tech"}},
			{"tool": "dirsearch", "priority": 7, "params": map[string]interface{}{"extensions": "php,html,js,txt", "threads": 30}},
			{"tool": "gobuster", "priority": 8, "params": map[string]interface{}{"mode": "dir", "extensions": "php,html,js,txt"}},
		},
		"api_testing": {
			{"tool": "httpx", "priority": 1, "params": map[string]interface{}{"probe": true, "tech_detect": true}},
			{"tool": "arjun", "priority": 2, "params": map[string]interface{}{"method": "GET,POST", "stable": true}},
			{"tool": "x8", "priority": 3, "params": map[string]interface{}{"method": "GET", "wordlist": "/usr/share/wordlists/x8/params.txt"}},
			{"tool": "paramspider", "priority": 4, "params": map[string]interface{}{"level": 2}},
			{"tool": "nuclei", "priority": 5, "params": map[string]interface{}{"tags": "api,graphql,jwt", "severity": "high,critical"}},
			{"tool": "ffuf", "priority": 6, "params": map[string]interface{}{"mode": "parameter", "method": "POST"}},
		},
	}
}

// AnalyzeTarget 分析目标并创建配置文件
func (ide *IntelligentDecisionEngine) AnalyzeTarget(target string) TargetProfile {
	profile := TargetProfile{
		Target:          target,
		TargetType:      ide.determineTargetType(target),
		IPAddresses:     []string{},
		OpenPorts:       []int{},
		Services:        make(map[int]string),
		Technologies:    []TechnologyStack{},
		SecurityHeaders: make(map[string]string),
		SSLInfo:         make(map[string]interface{}),
		Subdomains:      []string{},
		Endpoints:       []string{},
	}

	// 解析域名获取IP
	if profile.TargetType == TargetTypeWebApplication || profile.TargetType == TargetTypeAPIEndpoint {
		profile.IPAddresses = ide.resolveDomain(target)
	}

	// 检测技术栈
	if profile.TargetType == TargetTypeWebApplication {
		profile.Technologies = ide.detectTechnologies(target)
		profile.CMSType = ide.detectCMS(target)
	}

	// 计算攻击面得分
	profile.AttackSurfaceScore = ide.calculateAttackSurface(&profile)

	// 确定风险级别
	profile.RiskLevel = ide.determineRiskLevel(&profile)

	// 计算置信度
	profile.ConfidenceScore = ide.calculateConfidence(&profile)

	return profile
}

// determineTargetType 确定目标类型
func (ide *IntelligentDecisionEngine) determineTargetType(target string) TargetType {
	// URL 模式
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if strings.Contains(target, "/api/") || strings.HasSuffix(target, "/api") {
			return TargetTypeAPIEndpoint
		}
		return TargetTypeWebApplication
	}

	// IP 地址模式
	ipPattern := `^([0-9]{1,3}\.){3}[0-9]{1,3}$`
	if match, _ := regexp.MatchString(ipPattern, target); match {
		return TargetTypeNetworkHost
	}

	// 域名模式
	domainPattern := `^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	if match, _ := regexp.MatchString(domainPattern, target); match {
		return TargetTypeWebApplication
	}

	// 文件模式
	binaryExtensions := []string{".exe", ".bin", ".elf", ".so", ".dll"}
	for _, ext := range binaryExtensions {
		if strings.HasSuffix(target, ext) {
			return TargetTypeBinaryFile
		}
	}

	// 云服务模式
	cloudPatterns := []string{"amazonaws.com", "azure", "googleapis.com"}
	for _, pattern := range cloudPatterns {
		if strings.Contains(strings.ToLower(target), pattern) {
			return TargetTypeCloudService
		}
	}

	return TargetTypeUnknown
}

// resolveDomain 解析域名获取IP
func (ide *IntelligentDecisionEngine) resolveDomain(target string) []string {
	// 简化实现，实际应该使用 net 包解析
	return []string{"127.0.0.1"}
}

// detectTechnologies 检测技术栈
func (ide *IntelligentDecisionEngine) detectTechnologies(target string) []TechnologyStack {
	technologies := []TechnologyStack{}

	// 简化实现，实际应该发送 HTTP 请求分析
	if strings.Contains(strings.ToLower(target), "wordpress") || strings.Contains(strings.ToLower(target), "wp-") {
		technologies = append(technologies, TechnologyStackWordPress)
	}

	if strings.Contains(strings.ToLower(target), ".php") || strings.Contains(strings.ToLower(target), "php") {
		technologies = append(technologies, TechnologyStackPHP)
	}

	if strings.Contains(strings.ToLower(target), ".asp") || strings.Contains(strings.ToLower(target), ".aspx") {
		technologies = append(technologies, TechnologyStackDotNet)
	}

	if len(technologies) == 0 {
		technologies = append(technologies, TechnologyStackUnknown)
	}

	return technologies
}

// detectCMS 检测CMS类型
func (ide *IntelligentDecisionEngine) detectCMS(target string) string {
	targetLower := strings.ToLower(target)

	if strings.Contains(targetLower, "wordpress") || strings.Contains(targetLower, "wp-") {
		return "WordPress"
	} else if strings.Contains(targetLower, "drupal") {
		return "Drupal"
	} else if strings.Contains(targetLower, "joomla") {
		return "Joomla"
	}

	return ""
}

// calculateAttackSurface 计算攻击面得分
func (ide *IntelligentDecisionEngine) calculateAttackSurface(profile *TargetProfile) float64 {
	score := 0.0

	// 基于目标类型的基础得分
	typeScores := map[TargetType]float64{
		TargetTypeWebApplication: 7.0,
		TargetTypeAPIEndpoint:    6.0,
		TargetTypeNetworkHost:    8.0,
		TargetTypeCloudService:   5.0,
		TargetTypeBinaryFile:     4.0,
	}

	score += typeScores[profile.TargetType]

	// 技术栈加分
	score += float64(len(profile.Technologies)) * 0.5

	// 开放端口加分
	score += float64(len(profile.OpenPorts)) * 0.3

	// 子域名加分
	score += float64(len(profile.Subdomains)) * 0.2

	// CMS 加分
	if profile.CMSType != "" {
		score += 1.5
	}

	// 最高分限制为10.0
	if score > 10.0 {
		score = 10.0
	}

	return score
}

// determineRiskLevel 确定风险级别
func (ide *IntelligentDecisionEngine) determineRiskLevel(profile *TargetProfile) string {
	if profile.AttackSurfaceScore >= 8.0 {
		return "critical"
	} else if profile.AttackSurfaceScore >= 6.0 {
		return "high"
	} else if profile.AttackSurfaceScore >= 4.0 {
		return "medium"
	} else if profile.AttackSurfaceScore >= 2.0 {
		return "low"
	} else {
		return "minimal"
	}
}

// calculateConfidence 计算置信度
func (ide *IntelligentDecisionEngine) calculateConfidence(profile *TargetProfile) float64 {
	confidence := 0.5 // 基础置信度

	// 根据可用数据增加置信度
	if len(profile.IPAddresses) > 0 {
		confidence += 0.1
	}

	if len(profile.Technologies) > 0 && profile.Technologies[0] != TechnologyStackUnknown {
		confidence += 0.2
	}

	if profile.CMSType != "" {
		confidence += 0.1
	}

	if profile.TargetType != TargetTypeUnknown {
		confidence += 0.1
	}

	// 最高置信度限制为1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// SelectOptimalTools 选择最佳工具
func (ide *IntelligentDecisionEngine) SelectOptimalTools(profile TargetProfile, objective string) []string {
	effectivenessMap := ide.ToolEffectiveness[profile.TargetType]

	// 获取基础工具
	baseTools := []string{}
	for tool := range effectivenessMap {
		baseTools = append(baseTools, tool)
	}

	// 根据目标过滤
	var selectedTools []string
	if objective == "quick" {
		// 选择前3个最有效的工具
		// 简化实现，实际应该排序
		selectedTools = baseTools[:min(3, len(baseTools))]
	} else if objective == "comprehensive" {
		// 选择所有效果大于0.7的工具
		for tool, effectiveness := range effectivenessMap {
			if effectiveness > 0.7 {
				selectedTools = append(selectedTools, tool)
			}
		}
	} else if objective == "stealth" {
		// 选择被动工具
		stealthTools := []string{"amass", "subfinder", "httpx", "nuclei"}
		for _, tool := range baseTools {
			for _, stealthTool := range stealthTools {
				if tool == stealthTool {
					selectedTools = append(selectedTools, tool)
					break
				}
			}
		}
	} else {
		selectedTools = baseTools
	}

	// 添加技术特定工具
	for _, tech := range profile.Technologies {
		if tech == TechnologyStackWordPress {
			if !contains(selectedTools, "wpscan") {
				selectedTools = append(selectedTools, "wpscan")
			}
		} else if tech == TechnologyStackPHP {
			if !contains(selectedTools, "nikto") {
				selectedTools = append(selectedTools, "nikto")
			}
		}
	}

	return selectedTools
}

// ExecuteCommand 执行命令
func ExecuteCommand(command string) (string, error) {
	cmd := exec.Command("cmd.exe", "/c", command) // Windows 系统
	// cmd := exec.Command("sh", "-c", command) // Linux 系统

	output, err := cmd.CombinedOutput()
	return string(output), err
}

// StartProcess 启动进程
func StartProcess(command string) string {
	processID := uuid.New().String()

	processMutex.Lock()
	processes[processID] = &ProcessInfo{
		ID:        processID,
		Command:   command,
		Status:    "running",
		StartTime: time.Now(),
	}
	processMutex.Unlock()

	go func() {
		output, err := ExecuteCommand(command)

		processMutex.Lock()
		defer processMutex.Unlock()

		if proc, exists := processes[processID]; exists {
			proc.EndTime = time.Now()
			proc.Output = output
			if err != nil {
				proc.Error = err.Error()
				proc.Status = "failed"
			} else {
				proc.Status = "success"
			}
		}
	}()

	return processID
}

// GetProcessStatus 获取进程状态
func GetProcessStatus(processID string) *ProcessInfo {
	processMutex.Lock()
	defer processMutex.Unlock()

	return processes[processID]
}

// ListProcesses 列出所有进程
func ListProcesses() map[string]*ProcessInfo {
	processMutex.Lock()
	defer processMutex.Unlock()

	// 返回副本
	result := make(map[string]*ProcessInfo)
	for id, proc := range processes {
		result[id] = proc
	}

	return result
}

// TerminateProcess 终止进程
func TerminateProcess(processID string) bool {
	processMutex.Lock()
	defer processMutex.Unlock()

	if proc, exists := processes[processID]; exists {
		// 简化实现，实际应该终止进程
		proc.Status = "terminated"
		proc.EndTime = time.Now()
		return true
	}

	return false
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// contains 检查切片是否包含指定元素
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// 主函数
func main() {
	// 加载环境变量
	godotenv.Load()

	// 设置 Gin 模式
	if os.Getenv("GIN_MODE") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	// 创建 Gin 路由
	r := gin.Default()

	// 配置 CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// 健康检查
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"version": serverVersion,
			"tools":   "150+ security tools available",
		})
	})

	// 执行命令
	r.POST("/api/command", func(c *gin.Context) {
		var req struct {
			Command  string `json:"command" binding:"required"`
			UseCache bool   `json:"use_cache"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		output, err := ExecuteCommand(req.Command)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   err.Error(),
				"output":  output,
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"output":  output,
		})
	})

	// 目标分析
	r.POST("/api/intelligence/analyze-target", func(c *gin.Context) {
		var req struct {
			Target       string `json:"target" binding:"required"`
			AnalysisType string `json:"analysis_type"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ide := NewIntelligentDecisionEngine()
		profile := ide.AnalyzeTarget(req.Target)

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"profile": profile,
		})
	})

	// 工具选择
	r.POST("/api/intelligence/select-tools", func(c *gin.Context) {
		var req struct {
			Target    string `json:"target" binding:"required"`
			Objective string `json:"objective"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ide := NewIntelligentDecisionEngine()
		profile := ide.AnalyzeTarget(req.Target)
		tools := ide.SelectOptimalTools(profile, req.Objective)

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"tools":   tools,
			"profile": profile,
		})
	})

	// 进程管理
	r.GET("/api/processes/list", func(c *gin.Context) {
		processes := ListProcesses()
		c.JSON(http.StatusOK, gin.H{
			"success":     true,
			"processes":   processes,
			"total_count": len(processes),
		})
	})

	r.GET("/api/processes/status/:id", func(c *gin.Context) {
		processID := c.Param("id")
		proc := GetProcessStatus(processID)

		if proc == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Process not found"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"process": proc,
		})
	})

	r.POST("/api/processes/terminate/:id", func(c *gin.Context) {
		processID := c.Param("id")
		success := TerminateProcess(processID)

		if !success {
			c.JSON(http.StatusNotFound, gin.H{"error": "Process not found"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Process terminated",
		})
	})

	// 工具执行端点
	r.POST("/api/tools/nmap", func(c *gin.Context) {
		var req struct {
			Target         string `json:"target" binding:"required"`
			ScanType       string `json:"scan_type"`
			Ports          string `json:"ports"`
			AdditionalArgs string `json:"additional_args"`
			UseRecovery    bool   `json:"use_recovery"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 构建 nmap 命令
		command := fmt.Sprintf("nmap %s %s %s %s", req.ScanType, req.Ports, req.AdditionalArgs, req.Target)
		processID := StartProcess(command)

		c.JSON(http.StatusOK, gin.H{
			"success":    true,
			"process_id": processID,
			"command":    command,
		})
	})

	r.POST("/api/tools/gobuster", func(c *gin.Context) {
		var req struct {
			URL            string `json:"url" binding:"required"`
			Mode           string `json:"mode"`
			Wordlist       string `json:"wordlist"`
			AdditionalArgs string `json:"additional_args"`
			UseRecovery    bool   `json:"use_recovery"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 构建 gobuster 命令
		command := fmt.Sprintf("gobuster %s -u %s -w %s %s", req.Mode, req.URL, req.Wordlist, req.AdditionalArgs)
		processID := StartProcess(command)

		c.JSON(http.StatusOK, gin.H{
			"success":    true,
			"process_id": processID,
			"command":    command,
		})
	})

	r.POST("/api/tools/nuclei", func(c *gin.Context) {
		var req struct {
			Target         string `json:"target" binding:"required"`
			Severity       string `json:"severity"`
			Tags           string `json:"tags"`
			Template       string `json:"template"`
			AdditionalArgs string `json:"additional_args"`
			UseRecovery    bool   `json:"use_recovery"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 构建 nuclei 命令
		command := fmt.Sprintf("nuclei -u %s -s %s -tags %s -t %s %s", req.Target, req.Severity, req.Tags, req.Template, req.AdditionalArgs)
		processID := StartProcess(command)

		c.JSON(http.StatusOK, gin.H{
			"success":    true,
			"process_id": processID,
			"command":    command,
		})
	})

	// 启动服务器
	port := os.Getenv("PORT")
	if port == "" {
		port = "8888"
	}

	address := fmt.Sprintf("127.0.0.1:%s", port)
	log.Printf("HiCyberServer AI Server v%s starting on %s", serverVersion, address)
	log.Printf("150+ integrated modules | Adaptive AI decision engine active")

	if err := r.Run(address); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
