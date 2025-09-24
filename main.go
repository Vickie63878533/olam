package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultOpenAIURL = "https://ollama.com"
	contentTypeText  = "text/plain; charset=utf-8"
)

var (
	targetURL   *url.URL
	keyList     *KeyList
	CHECK_MODEL string // 全局变量用于/check端点
)

// KeyList manages a list of API keys.
type KeyList struct {
	mu   sync.RWMutex
	keys []string
	// Optional: store original keys to reset if needed, or for logging
	// originalKeys []string
}

// NewKeyListFromEnv creates a new KeyList from the TOKEN_LIST environment variable.
// The environment variable should contain a comma-separated list of keys.
func NewKeyListFromEnv(envVarName string) (*KeyList, error) {
	tokenListStr := os.Getenv(envVarName)
	if tokenListStr == "" {
		return nil, fmt.Errorf("environment variable %s not set or empty", envVarName)
	}

	keys := strings.Split(tokenListStr, ",")
	if len(keys) == 0 || (len(keys) == 1 && keys[0] == "") {
		return nil, fmt.Errorf("no keys found in environment variable %s after splitting", envVarName)
	}

	// Trim whitespace from each key
	cleanedKeys := make([]string, 0, len(keys))
	for _, k := range keys {
		trimmedKey := strings.TrimSpace(k)
		if trimmedKey != "" {
			cleanedKeys = append(cleanedKeys, trimmedKey)
		}
	}

	if len(cleanedKeys) == 0 {
		return nil, fmt.Errorf("no valid keys found in environment variable %s after trimming", envVarName)
	}

	return &KeyList{
		keys: cleanedKeys,
		// originalKeys: append([]string{}, cleanedKeys...), // Store a copy if needed
	}, nil
}

// GetRandomKey returns a random key from the list.
// It returns an empty string and an error if no keys are available.
func (kl *KeyList) GetRandomKey() (string, error) {
	kl.mu.RLock()
	defer kl.mu.RUnlock()

	if len(kl.keys) == 0 {
		return "", fmt.Errorf("no keys available")
	}

	randomIndex := rand.Intn(len(kl.keys))
	return kl.keys[randomIndex], nil
}

// RemoveKey removes a specific key from the list.
// It returns true if the key was found and removed, false otherwise.
func (kl *KeyList) RemoveKey(keyToRemove string) bool {
	kl.mu.Lock()
	defer kl.mu.Unlock()

	initialLen := len(kl.keys)
	updatedKeys := make([]string, 0, initialLen)
	found := false

	for _, key := range kl.keys {
		if key == keyToRemove {
			found = true
			// Skip adding this key to updatedKeys
			log.Printf("Removing unavailable key: %s", keyToRemove)
			continue
		}
		updatedKeys = append(updatedKeys, key)
	}

	kl.keys = updatedKeys
	return found
}

// AvailableKeys returns a comma-separated string of currently available keys.
func (kl *KeyList) AvailableKeys() string {
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	return strings.Join(kl.keys, ",")
}

// GetAllKeys returns a copy of all keys.
func (kl *KeyList) GetAllKeys() []string {
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	keysCopy := make([]string, len(kl.keys))
	copy(keysCopy, kl.keys)
	return keysCopy
}

// RandomlyPrintAvailableKeys prints all available keys with a 1/20 chance.
// Keys are printed as a comma-separated string.
func (kl *KeyList) RandomlyPrintAvailableKeys() {
	// rand.Intn(20) generates a number between 0 and 19.
	// So, a 1/20 chance means checking if the result is, for example, 0.
	if rand.Intn(20) == 0 {
		kl.mu.RLock()
		defer kl.mu.RUnlock()
		if len(kl.keys) > 0 {
			fmt.Printf("Available keys (randomly printed): %s\n", strings.Join(kl.keys, ","))
		} else {
			fmt.Println("No keys available (randomly printed).")
		}
	}
}

// init 在 main 函数之前执行，用于初始化配置
func init() {
	// 从环境变量获取目标 URL
	openaiURLStr := os.Getenv("OPENAI_URL")
	if openaiURLStr == "" {
		openaiURLStr = defaultOpenAIURL
		log.Printf("OPENAI_URL not set, using default: %s", defaultOpenAIURL)
	}

	var err error
	targetURL, err = url.Parse(openaiURLStr)
	if err != nil {
		log.Fatalf("Error parsing OPENAI_URL '%s': %v", openaiURLStr, err)
	}
	log.Printf("Forwarding requests to: %s", targetURL.String())

	keyList, err = NewKeyListFromEnv("TOKEN_LIST")
	if err != nil {
		log.Fatalf("Failed to initialize key list: %v", err)
	}

	CHECK_MODEL = os.Getenv("CHECK_MODEL")
}

// selectAPIKey 从提供的密钥列表中随机选择一个密钥
// 如果 headerAuthKey 非空，则优先使用它（并处理可能的多个密钥）
// 否则，从环境变量配置的密钥中选择
func selectAPIKey() (string, error) {
	key, err := keyList.GetRandomKey()
	return key, err
}

// handleRequest 是主要的 HTTP 请求处理器
func handleRequest(w http.ResponseWriter, r *http.Request) {
	// 获取请求路径
	path := r.URL.Path

	// 检查是否为根路径或空路径的直接访问
	if !strings.HasPrefix(path, "/api") {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}

	// 选择 API 密钥
	apiKey, err := selectAPIKey()
	if err != nil {
		log.Printf("API key selection error: %v", err)
		http.Error(w, "请提供有效的 API 密钥 (Please provide a valid API key in Authorization header or configure TOKEN_LIST)", http.StatusForbidden)
		w.Header().Set("Content-Type", contentTypeText)
		return
	}
	log.Printf("Using API key : %s", apiKey)

	keyList.RandomlyPrintAvailableKeys()

	// 创建反向代理
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// 自定义 Director 函数来修改请求
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req) // 执行默认的 Director 逻辑 (如设置 X-Forwarded-For 等)

		// 设置目标请求的 URL scheme, host 和 path
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		req.URL.Path = targetURL.Path + path // 使用原始请求的路径拼接到目标域名后

		// 修改 Host 头部
		req.Host = targetURL.Host

		// 设置 Authorization 头部
		req.Header.Set("Authorization", "Bearer "+apiKey)

		req.Header.Del("Cf-Connecting-Ip")
		req.Header.Del("Cf-Ipcountry")
		req.Header.Del("Cf-Visitor")
		req.Header.Del("X-Forwarded-Proto")
		req.Header.Del("X-Real-Ip")
		req.Header.Del("X-Forwarded-For")
		req.Header.Del("X-Forwarded-Port")
		req.Header.Del("X-Stainless-Arch")
		req.Header.Del("X-Stainless-Package-Version")
		req.Header.Del("X-Direct-Url")
		req.Header.Del("X-Middleware-Subrequest")
		req.Header.Del("X-Stainless-Runtime")
		req.Header.Del("X-Stainless-Lang")
		req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1")

		//log.Printf("Forwarding request: %s %s%s to %s%s", req.Method, req.Host, req.URL.Path, targetURL.Scheme, targetURL.Host+path)
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		// resp.Request is the *outgoing* request that was sent to the target.
		// This request object should contain the context we set in the Director.
		if resp.Request == nil {
			log.Println("WARN: ModifyResponse: resp.Request is nil. Cannot check for API key context.")
			return nil // Nothing to do if we don't have the original request.
		}

		if resp.StatusCode == http.StatusForbidden { // 403
			log.Printf("INFO: ModifyResponse: Upstream returned 403 for key: '%s'. Attempting to remove it.", apiKey)
			// keyList.RemoveKey(apiKey)
			return nil
		}

		if resp.StatusCode == http.StatusUnprocessableEntity { // 422
			log.Printf("INFO: ModifyResponse: Upstream returned 422 for key: '%s'. Attempting to remove it.", apiKey)
			// keyList.RemoveKey(apiKey)
			return nil
		}
		return nil // Return nil to indicate no error during response modification
	}

	// 可选：自定义 ErrorHandler
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		http.Error(rw, "Error forwarding request.", http.StatusBadGateway)
	}

	// 执行转发
	proxy.ServeHTTP(w, r)
}

// handleCheck 检查所有 key 的状态
func handleCheck(w http.ResponseWriter, r *http.Request) {
	if CHECK_MODEL == "" {
		http.Error(w, "CHECK_MODEL environment variable is not set.", http.StatusInternalServerError)
		return
	}

	allKeys := keyList.GetAllKeys()
	var aliveKeys []string
	var failedKeys []string

	var wg sync.WaitGroup
	var mu sync.Mutex

	client := &http.Client{
		Timeout: 30 * time.Second, // 设置一个合理的超时
	}

	checkURL := targetURL.String() + "/v1/chat/completions"

	for _, key := range allKeys {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()

			// 构造请求体
			requestBody, err := json.Marshal(map[string]interface{}{
				"model": CHECK_MODEL,
				"messages": []map[string]string{
					{"role": "user", "content": "Hi"},
				},
				"max_tokens": 5,
			})
			if err != nil {
				log.Printf("Error creating request body for key %s: %v", key, err)
				return
			}

			req, err := http.NewRequest("POST", checkURL, bytes.NewBuffer(requestBody))
			if err != nil {
				log.Printf("Error creating request for key %s: %v", key, err)
				return
			}

			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+key)

			resp, err := client.Do(req)
			if err != nil {
				mu.Lock()
				failedKeys = append(failedKeys, fmt.Sprintf("%s request_error %v", key, err))
				mu.Unlock()
				return
			}
			defer resp.Body.Close()

			mu.Lock()
			if resp.StatusCode == http.StatusOK {
				aliveKeys = append(aliveKeys, key)
			} else {
				bodyBytes, _ := io.ReadAll(resp.Body)
				failedKeys = append(failedKeys, fmt.Sprintf("%s %d %s", key, resp.StatusCode, string(bodyBytes)))
			}
			mu.Unlock()

		}(key)
		time.Sleep(100 * time.Millisecond)
	}

	wg.Wait()

	var responseBuilder strings.Builder
	responseBuilder.WriteString("alive:\n")
	for _, key := range aliveKeys {
		responseBuilder.WriteString(key)
		responseBuilder.WriteString("\n")
	}

	responseBuilder.WriteString("\nfail:\n")
	for _, failInfo := range failedKeys {
		responseBuilder.WriteString(failInfo)
		responseBuilder.WriteString("\n")
	}

	w.Header().Set("Content-Type", contentTypeText)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(responseBuilder.String()))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // 默认端口
		log.Printf("PORT environment variable not set, using default %s", port)
	}

	http.HandleFunc("/", handleRequest)
	http.HandleFunc("/check", handleCheck) // 直接为 /check 注册处理器

	server := &http.Server{
		Addr:         ":" + port,
		ReadTimeout:  300 * time.Second,
		WriteTimeout: 300 * time.Second, // 对于流式响应，可能需要更长或无超时
		IdleTimeout:  600 * time.Second,
	}

	log.Printf("Starting server on port %s...", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Could not listen on %s: %v\n", port, err)
	}
}
