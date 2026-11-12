package main

import (
	"crypto/rc4"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	SignInURL         = "https://www.hifini.net/sg_sign.htm"
	CookieEnvVariable = "COOKIE"
	UserAgent         = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

func main() {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Timeout: 15 * time.Second,
		Jar:     jar,
	}

	// 1. 把环境变量里的基础 Cookie 注入 jar（bbs_sid、bbs_token 等）
	baseCookie := os.Getenv(CookieEnvVariable)
	if baseCookie == "" {
		log.Println("COOKIE不存在，请检查是否添加")
		os.Exit(3)
	}
	u, _ := url.Parse("https://www.hifini.net")
	if err := injectCookie(jar, u, baseCookie); err != nil {
		log.Printf("注入基础 Cookie 失败: %v\n", err)
		os.Exit(3)
	}

	// 2. 执行签到（内部包含 guard/guardret/guardok 协商）
	success, msg := SignIn(client)
	if success {
		log.Println("签到成功:", msg)
	} else {
		log.Println("签到失败:", msg)
		os.Exit(3)
	}
}

// SignIn 新逻辑：先协商 guardok，再签到
func SignIn(client *http.Client) (bool, string) {
	// 第一步：访问签到页，可能直接成功，也可能触发 guard
	ok, body, err := doRequest(client, "POST", SignInURL, nil, nil)
	if err != nil {
		return false, fmt.Sprintf("首次请求失败: %v", err)
	}

	// 如果直接包含"成功"，说明 Cookie 仍然有效，无需 guard 协商
	if strings.Contains(body, "成功") {
		return true, "签到成功"
	}

	// 如果响应不是 auto.js 拦截页，说明签到失败（可能 Cookie 过期）
	if !strings.Contains(body, "/_guard/auto.js") {
		return false, fmt.Sprintf("响应不符合预期: %s", truncate(body, 200))
	}

	log.Println("检测到 guard 拦截，开始协商 guardret/guardok")

	// 第二步：从 Cookie jar 中读取 guard
	u, _ := url.Parse(SignInURL)
	var guard string
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == "guard" {
			guard = c.Value
			break
		}
	}
	if guard == "" {
		return false, "未能从 Cookie 中获取 guard"
	}

	// 第三步：根据 guard 计算 guardret
	guardret, err := buildGuardRet(guard)
	if err != nil {
		return false, fmt.Sprintf("生成 guardret 失败: %v", err)
	}
	log.Printf("guard=%s guardret=%s\n", truncate(guard, 20), truncate(guardret, 30))

	// 第四步：把 guardret 写入 Cookie jar
	guardretCookie := &http.Cookie{
		Name:   "guardret",
		Value:  guardret,
		Path:   "/",
		Domain: "www.hifini.net",
	}
	client.Jar.SetCookies(u, []*http.Cookie{guardretCookie})

	// 第五步：带上 guard + guardret 再次请求，换取 guardok
	ok, body, err = doRequest(client, "POST", SignInURL, nil, nil)
	if err != nil {
		return false, fmt.Sprintf("guardok 协商请求失败: %v", err)
	}
	if !ok {
		return false, fmt.Sprintf("guardok 协商失败，响应: %s", truncate(body, 200))
	}

	// 第六步：再次签到
	ok, body, err = doRequest(client, "POST", SignInURL, nil, nil)
	if err != nil {
		return false, fmt.Sprintf("签到请求失败: %v", err)
	}
	if strings.Contains(body, "成功") {
		return true, "签到成功（经 guardok 协商）"
	}

	return false, fmt.Sprintf("签到未成功，最终响应: %s", truncate(body, 200))
}

// buildGuardRet 对应前端逻辑：
// key = guard[0:8]
// n = parseInt(guard.substr(12), 10)
// arg = n*2 + 18 - 2  => n*2 + 16
// return base64(RC4(arg.String(), key))
func buildGuardRet(guard string) (string, error) {
	if len(guard) < 13 {
		return "", fmt.Errorf("guard 长度不足")
	}
	key := guard[:8]
	raw := guard[12:]
	n, err := strconv.Atoi(raw)
	if err != nil {
		return "", fmt.Errorf("guard 第12位后不是合法数字: %v", err)
	}

	arg := strconv.Itoa(n*2 + 16)
	encrypted, err := rc4Encrypt([]byte(arg), []byte(key))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// rc4Encrypt Go 标准库 RC4 加解密（同一函数）
func rc4Encrypt(plain, key []byte) ([]byte, error) {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plain))
	cipher.XORKeyStream(out, plain)
	return out, nil
}

// doRequest 统一请求，返回状态码是否 2xx 和响应体字符串
func doRequest(client *http.Client, method, rawURL string, body io.Reader, extraHeader map[string]string) (bool, string, error) {
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		return false, "", err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-requested-with", "XMLHttpRequest")
	req.Header.Set("Referer", "https://www.hifini.net/")
	for k, v := range extraHeader {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}

	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	return ok, string(data), nil
}

// injectCookie 把 "k1=v1; k2=v2" 注入 cookiejar
func injectCookie(jar http.CookieJar, u *url.URL, cookieStr string) error {
	parts := strings.Split(cookieStr, ";")
	var cookies []*http.Cookie
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		cookies = append(cookies, &http.Cookie{
			Name:   strings.TrimSpace(kv[0]),
			Value:  strings.TrimSpace(kv[1]),
			Path:   "/",
			Domain: "www.hifini.net",
		})
	}
	jar.SetCookies(u, cookies)
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}