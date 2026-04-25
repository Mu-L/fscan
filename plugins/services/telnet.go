//go:build plugin_telnet || !plugin_selective

package services

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/plugins"
)

// Telnet协议时间常量
const (
	telnetReadDelay      = 200 * time.Millisecond  // 读取间隔延迟
	telnetRetryDelay     = 500 * time.Millisecond  // 重试延迟
	telnetAuthDelay      = 1000 * time.Millisecond // 认证后等待延迟
	telnetReadTimeout    = 2 * time.Second         // 读取超时
	telnetBannerTimeout  = 3 * time.Second         // Banner读取超时
	telnetRCECmdTimeout  = 5 * time.Second         // RCE命令执行超时
	telnetRCEExtraTimeout = 10 * time.Second       // RCE验证额外超时
	telnetMaxAttempts    = 10                      // 最大尝试次数
)

// TelnetPlugin Telnet扫描插件
type TelnetPlugin struct {
	plugins.BasePlugin
}

func NewTelnetPlugin() *TelnetPlugin {
	return &TelnetPlugin{
		BasePlugin: plugins.NewBasePlugin("telnet"),
	}
}

func (p *TelnetPlugin) Scan(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()

	if config.DisableBrute {
		return p.identifyService(ctx, info, config, state)
	}

	// 检测未授权访问
	if result := p.testUnauthAccess(ctx, info, config, state); result != nil && result.Success {
		common.LogVuln(i18n.Tr("telnet_service", target, result.Banner))
		// 验证命令执行能力
		if ok, osType, evidence := p.verifyCommandExecution(ctx, info, "", "", config, state); ok {
			common.LogVuln(i18n.Tr("telnet_unauth_rce", target, osType, evidence))
		}
		return result
	}

	// 生成密码字典
	credentials := plugins.GenerateCredentials("telnet", config)
	if len(credentials) == 0 {
		return &ScanResult{
			Success: false,
			Service: "telnet",
			Error:   fmt.Errorf("没有可用的测试凭据"),
		}
	}

	// 转换凭据类型
	creds := make([]Credential, len(credentials))
	for i, c := range credentials {
		creds[i] = Credential{Username: c.Username, Password: c.Password}
	}

	// 使用公共框架进行并发凭据测试
	authFn := p.createAuthFunc(info, config, state)
	testConfig := DefaultConcurrentTestConfig(config)

	result := TestCredentialsConcurrently(ctx, creds, authFn, "telnet", testConfig)

	if result.Success {
		common.LogVuln(i18n.Tr("telnet_credential", target, result.Username, result.Password))
		// 验证命令执行能力
		if ok, osType, evidence := p.verifyCommandExecution(ctx, info, result.Username, result.Password, config, state); ok {
			common.LogVuln(i18n.Tr("telnet_credential_rce", target, result.Username, result.Password, osType, evidence))
		}
	}

	return result
}

// createAuthFunc 创建Telnet认证函数
func (p *TelnetPlugin) createAuthFunc(info *common.HostInfo, config *common.Config, state *common.State) AuthFunc {
	return func(ctx context.Context, cred Credential) *AuthResult {
		return p.doTelnetAuth(ctx, info, cred, config, state)
	}
}

// doTelnetAuth 执行Telnet认证
func (p *TelnetPlugin) doTelnetAuth(ctx context.Context, info *common.HostInfo, cred Credential, config *common.Config, state *common.State) *AuthResult {
	target := info.Target()

	resultChan := make(chan *AuthResult, 1)

	go func() {
		conn, err := common.WrapperTcpWithTimeout("tcp", target, config.Timeout)
		if err != nil {
			state.IncrementTCPFailedPacketCount()
			resultChan <- &AuthResult{
				Success:   false,
				ErrorType: classifyTelnetErrorType(err),
				Error:     err,
			}
			return
		}

		_ = conn.SetDeadline(time.Now().Add(config.Timeout))

		if p.performTelnetAuth(conn, cred.Username, cred.Password) {
			state.IncrementTCPSuccessPacketCount()
			resultChan <- &AuthResult{
				Success:   true,
				Conn:      &telnetConnWrapper{conn},
				ErrorType: ErrorTypeUnknown,
				Error:     nil,
			}
		} else {
			_ = conn.Close()
			state.IncrementTCPFailedPacketCount()
			resultChan <- &AuthResult{
				Success:   false,
				ErrorType: ErrorTypeAuth,
				Error:     fmt.Errorf("认证失败"),
			}
		}
	}()

	select {
	case result := <-resultChan:
		return result
	case <-ctx.Done():
		// context 被取消，启动清理协程等待并关闭可能创建的连接
		go func() {
			result := <-resultChan
			if result != nil && result.Conn != nil {
				_ = result.Conn.Close()
			}
		}()
		return &AuthResult{
			Success:   false,
			ErrorType: ErrorTypeNetwork,
			Error:     ctx.Err(),
		}
	}
}

// telnetConnWrapper 包装Telnet连接以实现io.Closer
type telnetConnWrapper struct {
	conn net.Conn
}

func (w *telnetConnWrapper) Close() error {
	return w.conn.Close()
}

// classifyTelnetErrorType Telnet错误分类
func classifyTelnetErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	telnetAuthErrors := []string{
		"authentication failed",
		"authentication failure",
		"auth failed",
		"login failed",
		"invalid credentials",
		"invalid password",
		"invalid username",
		"access denied",
		"login incorrect",
		"permission denied",
		"bad password",
		"wrong password",
		"incorrect login",
		"login failure",
		"invalid login",
		"authentication error",
		"unauthorized",
		"credentials rejected",
	}

	return ClassifyError(err, telnetAuthErrors, CommonNetworkErrors)
}

// testUnauthAccess 测试Telnet未授权访问
func (p *TelnetPlugin) testUnauthAccess(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()

	resultChan := make(chan *ScanResult, 1)

	go func() {
		conn, err := common.WrapperTcpWithTimeout("tcp", target, config.Timeout)
		if err != nil {
			state.IncrementTCPFailedPacketCount()
			resultChan <- nil
			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(config.Timeout))

		buffer := make([]byte, 1024)
		attempts := 0
		maxAttempts := telnetMaxAttempts

		for attempts < maxAttempts {
			attempts++

			_ = conn.SetReadDeadline(time.Now().Add(telnetBannerTimeout))
			n, err := conn.Read(buffer)
			if err != nil {
				time.Sleep(telnetRetryDelay)
				continue
			}

			response := string(buffer[:n])
			cleaned := p.cleanResponse(response)
			cleanedLower := strings.ToLower(cleaned)

			p.handleIACNegotiation(conn, buffer[:n])

			if p.isShellPrompt(cleaned) {
				state.IncrementTCPSuccessPacketCount()
				resultChan <- &ScanResult{
					Success: true,
					Type:    plugins.ResultTypeVuln,
					Service: "telnet",
					Banner:  "Telnet远程终端服务 (未授权访问)",
				}
				return
			}

			if strings.Contains(cleanedLower, "login") ||
				strings.Contains(cleanedLower, "username") ||
				strings.Contains(cleaned, ":") {
				break
			}

			time.Sleep(telnetRetryDelay)
		}

		resultChan <- nil
	}()

	select {
	case result := <-resultChan:
		return result
	case <-ctx.Done():
		return nil
	}
}

// performTelnetAuth 执行Telnet认证
func (p *TelnetPlugin) performTelnetAuth(conn net.Conn, username, password string) bool {
	buffer := make([]byte, 1024)

	loginPromptReceived := false
	attempts := 0
	maxAttempts := telnetMaxAttempts

	for attempts < maxAttempts && !loginPromptReceived {
		attempts++

		_ = conn.SetReadDeadline(time.Now().Add(telnetReadTimeout))
		n, err := conn.Read(buffer)
		if err != nil {
			time.Sleep(telnetReadDelay)
			continue
		}

		response := string(buffer[:n])
		p.handleIACNegotiation(conn, buffer[:n])
		cleaned := p.cleanResponse(response)
		cleanedLower := strings.ToLower(cleaned)

		if p.isShellPrompt(cleaned) {
			return true
		}

		if strings.Contains(cleanedLower, "login") ||
			strings.Contains(cleanedLower, "username") ||
			strings.Contains(cleaned, ":") {
			loginPromptReceived = true
			break
		}

		time.Sleep(telnetReadDelay)
	}

	if !loginPromptReceived {
		return false
	}

	_, err := conn.Write([]byte(username + "\r\n"))
	if err != nil {
		return false
	}

	time.Sleep(telnetRetryDelay)
	passwordPromptReceived := false
	attempts = 0
	maxPasswordAttempts := 5

	for attempts < maxPasswordAttempts && !passwordPromptReceived {
		attempts++

		_ = conn.SetReadDeadline(time.Now().Add(telnetReadTimeout))
		n, readErr := conn.Read(buffer)
		if readErr != nil {
			time.Sleep(telnetReadDelay)
			continue
		}

		response := string(buffer[:n])
		cleaned := p.cleanResponse(response)

		if strings.Contains(strings.ToLower(cleaned), "password") ||
			strings.Contains(cleaned, ":") {
			passwordPromptReceived = true
			break
		}

		time.Sleep(telnetReadDelay)
	}

	if !passwordPromptReceived {
		return false
	}

	_, err = conn.Write([]byte(password + "\r\n"))
	if err != nil {
		return false
	}

	time.Sleep(telnetAuthDelay)
	attempts = 0
	maxResultAttempts := 5

	for attempts < maxResultAttempts {
		attempts++

		_ = conn.SetReadDeadline(time.Now().Add(telnetReadTimeout))
		n, err := conn.Read(buffer)
		if err != nil {
			time.Sleep(telnetReadDelay)
			continue
		}

		response := string(buffer[:n])
		cleaned := p.cleanResponse(response)

		if p.isLoginSuccess(cleaned) {
			return true
		}

		if p.isLoginFailed(cleaned) {
			return false
		}

		time.Sleep(telnetReadDelay)
	}

	return false
}

// handleIACNegotiation 处理IAC协商
func (p *TelnetPlugin) handleIACNegotiation(conn net.Conn, data []byte) {
	for i := 0; i < len(data); i++ {
		if data[i] == 255 && i+2 < len(data) {
			cmd := data[i+1]
			opt := data[i+2]

			switch cmd {
			case 251: // WILL
				_, _ = conn.Write([]byte{255, 254, opt})
			case 253: // DO
				_, _ = conn.Write([]byte{255, 252, opt})
			}
			i += 2
		}
	}
}

// cleanResponse 清理telnet响应中的IAC命令
func (p *TelnetPlugin) cleanResponse(data string) string {
	var result strings.Builder

	for i := 0; i < len(data); i++ {
		b := data[i]
		if b == 255 && i+2 < len(data) {
			i += 2
			continue
		}
		if (b >= 32 && b <= 126) || b == '\r' || b == '\n' || b == '\t' {
			result.WriteByte(b)
		}
	}

	return strings.TrimSpace(result.String())
}

// isShellPrompt 检查是否为shell提示符
func (p *TelnetPlugin) isShellPrompt(data string) bool {
	if data == "" {
		return false
	}

	data = strings.ToLower(strings.TrimSpace(data))

	shellPrompts := []string{"$", "#", ">", "~$", "]$", ")#", "bash", "shell", "cmd"}

	for _, prompt := range shellPrompts {
		if strings.Contains(data, prompt) {
			return true
		}
	}

	return false
}

// isLoginSuccess 检查登录是否成功
func (p *TelnetPlugin) isLoginSuccess(data string) bool {
	if data == "" {
		return false
	}

	data = strings.ToLower(strings.TrimSpace(data))

	if p.isShellPrompt(data) {
		return true
	}

	successIndicators := []string{
		"welcome", "last login", "successful", "logged in",
		"login successful", "authentication successful",
		"welcome to", "successfully logged", "login ok",
		"connected to", "logged on",
	}

	for _, indicator := range successIndicators {
		if strings.Contains(data, indicator) {
			return true
		}
	}

	return false
}

// isLoginFailed 检查登录是否失败
func (p *TelnetPlugin) isLoginFailed(data string) bool {
	if data == "" {
		return false
	}

	data = strings.ToLower(strings.TrimSpace(data))

	failureIndicators := []string{
		"incorrect", "failed", "denied", "invalid", "wrong", "bad", "error",
		"authentication failed", "login failed", "access denied",
		"permission denied", "authentication error", "login incorrect",
		"invalid password", "invalid username", "unauthorized",
		"login failure", "connection refused",
	}

	for _, indicator := range failureIndicators {
		if strings.Contains(data, indicator) {
			return true
		}
	}

	repeatPrompts := []string{"login:", "username:", "user:", "name:"}

	for _, prompt := range repeatPrompts {
		if strings.Contains(data, prompt) {
			return true
		}
	}

	return false
}

// identifyService Telnet服务识别
func (p *TelnetPlugin) identifyService(ctx context.Context, info *common.HostInfo, config *common.Config, state *common.State) *ScanResult {
	target := info.Target()

	resultChan := make(chan *ScanResult, 1)

	go func() {
		conn, err := common.WrapperTcpWithTimeout("tcp", target, config.Timeout)
		if err != nil {
			state.IncrementTCPFailedPacketCount()
			resultChan <- &ScanResult{
				Success: false,
				Service: "telnet",
				Error:   err,
			}
			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(config.Timeout))

		buffer := make([]byte, 2048)
		n, err := conn.Read(buffer)
		if err != nil {
			state.IncrementTCPFailedPacketCount()
			resultChan <- &ScanResult{
				Success: false,
				Service: "telnet",
				Error:   err,
			}
			return
		}

		state.IncrementTCPSuccessPacketCount()

		p.handleIACNegotiation(conn, buffer[:n])
		cleaned := p.cleanResponse(string(buffer[:n]))
		cleanedLower := strings.ToLower(cleaned)

		var banner string

		if p.isShellPrompt(cleaned) {
			banner = "Telnet远程终端服务 (未授权访问)"
		} else if strings.Contains(cleanedLower, "login") ||
			strings.Contains(cleanedLower, "username") ||
			strings.Contains(cleanedLower, "user") {
			banner = "Telnet远程终端服务 (需要认证)"
		} else if strings.Contains(cleanedLower, "password") {
			banner = "Telnet远程终端服务 (只需密码)"
		} else if cleaned != "" {
			displayCleaned := cleaned
			if len(displayCleaned) > 50 {
				displayCleaned = displayCleaned[:50] + "..."
			}
			banner = fmt.Sprintf("Telnet远程终端服务 (自定义欢迎: %s)", displayCleaned)
		} else {
			banner = "Telnet远程终端服务"
		}

		if p.isShellPrompt(cleaned) {
			common.LogVuln(i18n.Tr("telnet_service", target, banner))
		} else {
			common.LogSuccess(i18n.Tr("telnet_service", target, banner))
		}

		resultChan <- &ScanResult{
			Success: true,
			Type:    plugins.ResultTypeService,
			Service: "telnet",
			Banner:  banner,
		}
	}()

	select {
	case result := <-resultChan:
		return result
	case <-ctx.Done():
		return &ScanResult{
			Success: false,
			Service: "telnet",
			Error:   ctx.Err(),
		}
	}
}

// verifyCommandExecution 验证Telnet命令执行能力（RCE检测）
func (p *TelnetPlugin) verifyCommandExecution(ctx context.Context, info *common.HostInfo, username, password string, config *common.Config, state *common.State) (bool, string, string) {
	target := info.Target()

	type rceResult struct {
		ok       bool
		osType   string
		evidence string
	}

	resultChan := make(chan rceResult, 1)

	go func() {
		conn, err := common.WrapperTcpWithTimeout("tcp", target, config.Timeout)
		if err != nil {
			resultChan <- rceResult{}
			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(config.Timeout + telnetRCEExtraTimeout))

		// 需要认证时先登录
		if username != "" || password != "" {
			if !p.performTelnetAuth(conn, username, password) {
				resultChan <- rceResult{}
				return
			}
		} else {
			// 未授权访问：等待并消费初始 banner/prompt
			p.drainBuffer(conn)
		}

		// 等待 shell 稳定后清空缓冲区
		time.Sleep(telnetRetryDelay)
		p.drainBuffer(conn)

		// 尝试 Linux/Unix 命令
		output, err := p.sendCommand(conn, "echo CMD_START && id && uname -a && echo CMD_END\r\n", telnetRCECmdTimeout)
		if err == nil && strings.Contains(output, "CMD_START") {
			if osType := p.detectOSType(output); osType != "" {
				resultChan <- rceResult{true, osType, p.extractEvidence(output)}
				return
			}
		}

		// 尝试 Windows 命令
		output, err = p.sendCommand(conn, "echo CMD_START && whoami && ver && echo CMD_END\r\n", telnetRCECmdTimeout)
		if err == nil && strings.Contains(output, "CMD_START") {
			lower := strings.ToLower(output)
			if strings.Contains(lower, "windows") || strings.Contains(lower, "microsoft") {
				resultChan <- rceResult{true, "Windows", p.extractEvidence(output)}
				return
			}
		}

		// 尝试网络设备命令
		output, err = p.sendCommand(conn, "show version\r\n", telnetRCECmdTimeout)
		if err == nil {
			if strings.Contains(output, "Cisco IOS") {
				resultChan <- rceResult{true, "Cisco IOS", p.extractEvidence(output)}
				return
			}
			if strings.Contains(output, "Huawei") || strings.Contains(output, "VRP") {
				resultChan <- rceResult{true, "Huawei VRP", p.extractEvidence(output)}
				return
			}
		}

		resultChan <- rceResult{}
	}()

	select {
	case r := <-resultChan:
		return r.ok, r.osType, r.evidence
	case <-ctx.Done():
		return false, "", ""
	}
}

// sendCommand 发送命令并读取输出
func (p *TelnetPlugin) sendCommand(conn net.Conn, cmd string, timeout time.Duration) (string, error) {
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return "", err
	}

	time.Sleep(telnetAuthDelay)

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var result strings.Builder
	buffer := make([]byte, 4096)

	// 多次读取以收集完整输出
	for i := 0; i < 3; i++ {
		n, err := conn.Read(buffer)
		if n > 0 {
			p.handleIACNegotiation(conn, buffer[:n])
			result.WriteString(p.cleanResponse(string(buffer[:n])))
		}
		if err != nil {
			break
		}
		time.Sleep(telnetReadDelay)
	}

	return result.String(), nil
}

// detectOSType 从命令输出推断系统类型
func (p *TelnetPlugin) detectOSType(output string) string {
	lower := strings.ToLower(output)

	if strings.Contains(output, "uid=") || strings.Contains(output, "gid=") {
		if strings.Contains(lower, "busybox") {
			return "Linux/BusyBox"
		}
		return "Linux"
	}

	if strings.Contains(lower, "linux") || strings.Contains(lower, "gnu") {
		return "Linux"
	}

	if strings.Contains(lower, "windows") || strings.Contains(lower, "microsoft") {
		return "Windows"
	}

	if strings.Contains(output, "Cisco IOS") {
		return "Cisco IOS"
	}

	if strings.Contains(output, "Huawei") || strings.Contains(output, "VRP") {
		return "Huawei VRP"
	}

	return ""
}

// extractEvidence 从命令输出中提取关键证据信息
func (p *TelnetPlugin) extractEvidence(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "CMD_START" || line == "CMD_END" {
			continue
		}
		// 跳过回显的命令本身
		if strings.HasPrefix(line, "echo ") || strings.HasPrefix(line, "id") || strings.HasPrefix(line, "show ") {
			continue
		}
		if len(line) > 100 {
			return line[:100] + "..."
		}
		return line
	}
	return ""
}

// drainBuffer 消费连接中的待读数据
func (p *TelnetPlugin) drainBuffer(conn net.Conn) {
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(telnetReadTimeout))
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			p.handleIACNegotiation(conn, buf[:n])
		}
		if err != nil {
			break
		}
	}
}

func init() {
	RegisterPluginWithPorts("telnet", func() Plugin {
		return NewTelnetPlugin()
	}, []int{23, 2323})
}
