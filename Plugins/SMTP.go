package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

// SmtpScan 执行 SMTP 服务扫描
func SmtpScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	threads := Common.BruteThreads

	// 先测试匿名访问
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		flag, err := SmtpConn(info, "", "")
		if flag && err == nil {
			return err
		}
		if err != nil {
			if retryErr := Common.CheckErrs(err); retryErr != nil {
				if retryCount == maxRetries-1 {
					return err
				}
				continue
			}
		}
		break
	}

	// 创建任务通道
	taskChan := make(chan struct {
		user string
		pass string
	}, len(Common.Userdict["smtp"])*len(Common.Passwords))

	resultChan := make(chan error, threads)

	// 生成所有用户名密码组合任务
	for _, user := range Common.Userdict["smtp"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			taskChan <- struct {
				user string
				pass string
			}{user, pass}
		}
	}
	close(taskChan)

	// 启动工作线程
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			starttime := time.Now().Unix()

			for task := range taskChan {
				// 重试循环
				for retryCount := 0; retryCount < maxRetries; retryCount++ {
					// 检查是否超时
					if time.Now().Unix()-starttime > int64(Common.Timeout) {
						resultChan <- fmt.Errorf("扫描超时")
						return
					}

					// 执行SMTP连接
					done := make(chan struct {
						success bool
						err     error
					})

					go func(user, pass string) {
						flag, err := SmtpConn(info, user, pass)
						done <- struct {
							success bool
							err     error
						}{flag, err}
					}(task.user, task.pass)

					// 等待结果或超时
					var err error
					select {
					case result := <-done:
						err = result.err
						if result.success && err == nil {
							resultChan <- nil
							return
						}
					case <-time.After(time.Duration(Common.Timeout) * time.Second):
						err = fmt.Errorf("连接超时")
					}

					// 处理错误情况
					if err != nil {
						errlog := fmt.Sprintf("SMTP服务 %v:%v 尝试失败 用户名: %v 密码: %v 错误: %v",
							info.Host, info.Ports, task.user, task.pass, err)
						Common.LogError(errlog)

						// 检查是否需要重试
						if retryErr := Common.CheckErrs(err); retryErr != nil {
							if retryCount == maxRetries-1 {
								resultChan <- err
								return
							}
							continue // 继续重试
						}
					}

					break // 如果不需要重试，跳出重试循环
				}
			}
			resultChan <- nil
		}()
	}

	// 等待所有线程完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 检查结果
	for err := range resultChan {
		if err != nil {
			tmperr = err
			if retryErr := Common.CheckErrs(err); retryErr != nil {
				return err
			}
		}
	}

	return tmperr
}

// SmtpConn 尝试 SMTP 连接
func SmtpConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// 构造地址
	addr := fmt.Sprintf("%s:%s", host, port)

	// 创建带超时的连接
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// 创建SMTP客户端
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return false, err
	}
	defer client.Close()

	// 如果提供了认证信息
	if user != "" {
		auth := smtp.PlainAuth("", user, pass, host)
		err = client.Auth(auth)
		if err != nil {
			return false, err
		}
	}

	// 验证是否可以发送邮件
	err = client.Mail("test@test.com")
	if err != nil {
		return false, err
	}

	// 如果成功
	result := fmt.Sprintf("SMTP服务 %v:%v ", host, port)
	if user != "" {
		result += fmt.Sprintf("爆破成功 用户名: %v 密码: %v", user, pass)
	} else {
		result += "允许匿名访问"
	}
	Common.LogSuccess(result)

	return true, nil
}
