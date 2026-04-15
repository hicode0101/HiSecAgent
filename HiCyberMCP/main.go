package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"time"
)

// 全局变量
var (
	serverURL  = "http://127.0.0.1:8888"
	timeout    = 300 // 5分钟默认超时
	maxRetries = 3   // 最大重试次数
)

// HiCyberServerClient 与 HiCyberServer AI API 服务器通信的客户端
type HiCyberServerClient struct {
	serverURL string
	timeout   int
	client    *http.Client
}

// NewHiCyberServerClient 创建新的 HiCyberServer 客户端
func NewHiCyberServerClient(serverURL string, timeout int) *HiCyberServerClient {
	return &HiCyberServerClient{
		serverURL: serverURL,
		timeout:   timeout,
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
	}
}

// SafeGet 执行 GET 请求
func (h *HiCyberServerClient) SafeGet(endpoint string, params map[string]string) (map[string]interface{}, error) {
	url := h.serverURL + "/" + endpoint

	// 构建查询参数
	if len(params) > 0 {
		url += "?"
		first := true
		for key, value := range params {
			if !first {
				url += "&"
			}
			url += key + "=" + value
			first = false
		}
	}

	resp, err := h.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// SafePost 执行 POST 请求
func (h *HiCyberServerClient) SafePost(endpoint string, data map[string]interface{}) (map[string]interface{}, error) {
	url := h.serverURL + "/" + endpoint

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// ExecuteCommand 执行通用命令
func (h *HiCyberServerClient) ExecuteCommand(command string, useCache bool) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"command":   command,
		"use_cache": useCache,
	}
	return h.SafePost("api/command", data)
}

// CheckHealth 检查服务器健康状态
func (h *HiCyberServerClient) CheckHealth() (map[string]interface{}, error) {
	return h.SafeGet("health", nil)
}

// NmapScan 执行 Nmap 扫描
func (h *HiCyberServerClient) NmapScan(target, scanType, ports, additionalArgs string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"target":          target,
		"scan_type":       scanType,
		"ports":           ports,
		"additional_args": additionalArgs,
		"use_recovery":    true,
	}
	return h.SafePost("api/tools/nmap", data)
}

// GobusterScan 执行 Gobuster 扫描
func (h *HiCyberServerClient) GobusterScan(url, mode, wordlist, additionalArgs string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"url":             url,
		"mode":            mode,
		"wordlist":        wordlist,
		"additional_args": additionalArgs,
		"use_recovery":    true,
	}
	return h.SafePost("api/tools/gobuster", data)
}

// NucleiScan 执行 Nuclei 漏洞扫描
func (h *HiCyberServerClient) NucleiScan(target, severity, tags, template, additionalArgs string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"target":          target,
		"severity":        severity,
		"tags":            tags,
		"template":        template,
		"additional_args": additionalArgs,
		"use_recovery":    true,
	}
	return h.SafePost("api/tools/nuclei", data)
}

// ProwlerScan 执行 Prowler 云安全评估
func (h *HiCyberServerClient) ProwlerScan(provider, profile, region, checks, outputDir, outputFormat, additionalArgs string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"provider":        provider,
		"profile":         profile,
		"region":          region,
		"checks":          checks,
		"output_dir":      outputDir,
		"output_format":   outputFormat,
		"additional_args": additionalArgs,
	}
	return h.SafePost("api/tools/prowler", data)
}

// TrivyScan 执行 Trivy 容器漏洞扫描
func (h *HiCyberServerClient) TrivyScan(scanType, target, outputFormat, severity, outputFile, additionalArgs string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"scan_type":       scanType,
		"target":          target,
		"output_format":   outputFormat,
		"severity":        severity,
		"output_file":     outputFile,
		"additional_args": additionalArgs,
	}
	return h.SafePost("api/tools/trivy", data)
}

// CreateFile 创建文件
func (h *HiCyberServerClient) CreateFile(filename, content string, binary bool) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"filename": filename,
		"content":  content,
		"binary":   binary,
	}
	return h.SafePost("api/files/create", data)
}

// ModifyFile 修改文件
func (h *HiCyberServerClient) ModifyFile(filename, content string, append bool) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"filename": filename,
		"content":  content,
		"append":   append,
	}
	return h.SafePost("api/files/modify", data)
}

// DeleteFile 删除文件
func (h *HiCyberServerClient) DeleteFile(filename string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"filename": filename,
	}
	return h.SafePost("api/files/delete", data)
}

// ListFiles 列出文件
func (h *HiCyberServerClient) ListFiles(directory string) (map[string]interface{}, error) {
	params := map[string]string{
		"directory": directory,
	}
	return h.SafeGet("api/files/list", params)
}

// GeneratePayload 生成载荷
func (h *HiCyberServerClient) GeneratePayload(payloadType string, size int, pattern, filename string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"type":    payloadType,
		"size":    size,
		"pattern": pattern,
	}
	if filename != "" {
		data["filename"] = filename
	}
	return h.SafePost("api/payloads/generate", data)
}

// InstallPythonPackage 安装 Python 包
func (h *HiCyberServerClient) InstallPythonPackage(packageName, envName string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"package":  packageName,
		"env_name": envName,
	}
	return h.SafePost("api/python/install", data)
}

// ExecutePythonScript 执行 Python 脚本
func (h *HiCyberServerClient) ExecutePythonScript(script, envName, filename string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"script":   script,
		"env_name": envName,
	}
	if filename != "" {
		data["filename"] = filename
	}
	return h.SafePost("api/python/execute", data)
}

// DirbScan 执行 Dirb 扫描
func (h *HiCyberServerClient) DirbScan(url, wordlist, additionalArgs string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"url":             url,
		"wordlist":        wordlist,
		"additional_args": additionalArgs,
	}
	return h.SafePost("api/tools/dirb", data)
}

// NiktoScan 执行 Nikto 扫描
func (h *HiCyberServerClient) NiktoScan(target, additionalArgs string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"target":          target,
		"additional_args": additionalArgs,
	}
	return h.SafePost("api/tools/nikto", data)
}

// SqlmapScan 执行 SQLMap 扫描
func (h *HiCyberServerClient) SqlmapScan(url, data, additionalArgs string) (map[string]interface{}, error) {
	dataPayload := map[string]interface{}{
		"url":             url,
		"data":            data,
		"additional_args": additionalArgs,
	}
	return h.SafePost("api/tools/sqlmap", dataPayload)
}

// MetasploitRun 执行 Metasploit 模块
func (h *HiCyberServerClient) MetasploitRun(module string, options map[string]interface{}) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"module":  module,
		"options": options,
	}
	return h.SafePost("api/tools/metasploit", data)
}

// HydraAttack 执行 Hydra 密码破解
func (h *HiCyberServerClient) HydraAttack(target, service, username, usernameFile, password, passwordFile, additionalArgs string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"target":          target,
		"service":         service,
		"username":        username,
		"username_file":   usernameFile,
		"password":        password,
		"password_file":   passwordFile,
		"additional_args": additionalArgs,
	}
	return h.SafePost("api/tools/hydra", data)
}

// JohnCrack 执行 John the Ripper 密码破解
func (h *HiCyberServerClient) JohnCrack(hashFile, wordlist, formatType, additionalArgs string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"hash_file":       hashFile,
		"wordlist":        wordlist,
		"format":          formatType,
		"additional_args": additionalArgs,
	}
	return h.SafePost("api/tools/john", data)
}

// WpscanAnalyze 执行 WPScan 扫描
func (h *HiCyberServerClient) WpscanAnalyze(url, additionalArgs string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"url":             url,
		"additional_args": additionalArgs,
	}
	return h.SafePost("api/tools/wpscan", data)
}

// Enum4linuxScan 执行 Enum4linux 扫描
func (h *HiCyberServerClient) Enum4linuxScan(target, additionalArgs string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"target":          target,
		"additional_args": additionalArgs,
	}
	return h.SafePost("api/tools/enum4linux", data)
}

// FfufScan 执行 FFuf 扫描
func (h *HiCyberServerClient) FfufScan(url, wordlist, mode, matchCodes, additionalArgs string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"url":             url,
		"wordlist":        wordlist,
		"mode":            mode,
		"match_codes":     matchCodes,
		"additional_args": additionalArgs,
	}
	return h.SafePost("api/tools/ffuf", data)
}

// NetexecScan 执行 NetExec 扫描
func (h *HiCyberServerClient) NetexecScan(target, protocol, username, password, hashValue, module, additionalArgs string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"target":          target,
		"protocol":        protocol,
		"username":        username,
		"password":        password,
		"hash":            hashValue,
		"module":          module,
		"additional_args": additionalArgs,
	}
	return h.SafePost("api/tools/netexec", data)
}

// AmassScan 执行 Amass 扫描
func (h *HiCyberServerClient) AmassScan(domain, mode, additionalArgs string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"domain":          domain,
		"mode":            mode,
		"additional_args": additionalArgs,
	}
	return h.SafePost("api/tools/amass", data)
}

// HashcatCrack 执行 Hashcat 密码破解
func (h *HiCyberServerClient) HashcatCrack(hashFile, hashType, attackMode, wordlist, mask, additionalArgs string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"hash_file":       hashFile,
		"hash_type":       hashType,
		"attack_mode":     attackMode,
		"wordlist":        wordlist,
		"mask":            mask,
		"additional_args": additionalArgs,
	}
	return h.SafePost("api/tools/hashcat", data)
}

// SubfinderScan 执行 Subfinder 扫描
func (h *HiCyberServerClient) SubfinderScan(domain string, silent, allSources bool, additionalArgs string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"domain":          domain,
		"silent":          silent,
		"all_sources":     allSources,
		"additional_args": additionalArgs,
	}
	return h.SafePost("api/tools/subfinder", data)
}

// 主函数
func main() {
	// 解析命令行参数
	serverFlag := flag.String("server", serverURL, "HiCyberServer server URL")
	timeoutFlag := flag.Int("timeout", timeout, "Request timeout in seconds")
	//debugFlag := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

	// 更新全局变量
	serverURL = *serverFlag
	timeout = *timeoutFlag

	// 创建客户端
	client := NewHiCyberServerClient(serverURL, timeout)

	// 尝试连接服务器
	connected := false
	for i := 0; i < maxRetries; i++ {
		log.Printf("尝试连接到 HiCyberServer AI API 服务器: %s (尝试 %d/%d)", serverURL, i+1, maxRetries)
		health, err := client.CheckHealth()
		if err == nil {
			log.Printf("成功连接到 HiCyberServer AI API 服务器: %s", serverURL)
			if status, ok := health["status"].(string); ok {
				log.Printf("服务器健康状态: %s", status)
			}
			if version, ok := health["version"].(string); ok {
				log.Printf("服务器版本: %s", version)
			}
			connected = true
			break
		}
		log.Printf("连接失败: %v", err)
		time.Sleep(2 * time.Second)
	}

	if !connected {
		log.Printf("警告: 无法连接到 HiCyberServer AI API 服务器，工具可能会失败")
	}

	// 这里可以添加 MCP 服务器的设置和启动代码
	// 由于 Go 中没有直接的 FastMCP 实现，这里需要根据具体的 MCP 协议实现

	// 示例：模拟 MCP 服务器启动
	log.Println("HiCyberMCP 客户端初始化完成")
	log.Println("可用工具:")
	log.Println("- nmap_scan: 网络扫描")
	log.Println("- gobuster_scan: 目录扫描")
	log.Println("- nuclei_scan: 漏洞扫描")
	log.Println("- prowler_scan: 云安全评估")
	log.Println("- trivy_scan: 容器漏洞扫描")
	log.Println("- 以及更多工具...")

	// 保持程序运行
	select {}
}
