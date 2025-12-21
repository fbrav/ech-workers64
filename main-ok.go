package main

import (
    "bufio"
    "bytes"
    "context"
    "crypto/tls"
    "crypto/x509"
    "encoding/base64"
    "encoding/binary"
    "errors"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "net/url"
    "os"
    "sort"
    "strings"
    "sync"
    "time"

    "github.com/gorilla/websocket"
)

// ======================== 全局参数与状态 ========================

var (
    // 启动参数
    listenAddr  string
    serverAddr  string
    token       string
    dnsServer   string
    echDomain   string
    xSocks5     string
    xHttp       string
    xGlobeProxy string
    xFallbackIP string

    // 多 IP 支持
    ipList      string
    ipFile      string
    ipURL       string                    // 网络地址载入 IP 列表
    ipUpdateDur time.Duration             // 网络地址更新频率
    maxFastIPs  int                       // 快速主用 IP 数量
    serverIPs   []string                  // 全部配置的 IP（初始源 + 网络/文件更新）
    healthyIPs  []string                  // 当前健康主用 IP 列表（用于轮询与并发）
    failedIPs   = make(map[string]int)    // 连续失败计数（用于自动剔除）
    ipIndex     int
    ipMu        sync.Mutex

    // ECH 配置缓存
    echListMu sync.RWMutex
    echList   []byte

    // 统计信息
    ipStatistics = make(map[string]*ipStats)
)

// 节点统计
type ipStats struct {
    success      int
    fail         int
    totalLatency time.Duration
}

func init() {
    flag.StringVar(&listenAddr, "l", "127.0.0.1:30000", "代理监听地址 (支持 SOCKS5 和 HTTP)")
    flag.StringVar(&serverAddr, "f", "", "服务端地址 (格式: x.x.workers.dev，默认端口443，可包含路径)")
    flag.StringVar(&ipList, "ip", "", "指定服务端 IP 列表，逗号分隔 (如: 1.1.1.1,2.2.2.2:443)")
    flag.StringVar(&ipFile, "ipfile", "", "指定服务端 IP 文件路径，每行一个 IP，可为 'ip:port' 或 'ip port'")
    flag.StringVar(&ipURL, "ipurl", "", "指定服务端 IP 列表网络地址（文本，每行一个 IP，可为 'ip:port' 或 'ip port'）")
    flag.DurationVar(&ipUpdateDur, "ipupdate", 24*time.Hour, "网络地址更新频率，默认24小时")
    flag.IntVar(&maxFastIPs, "fast", 10, "筛选作为主用的最快 IP 数量，默认10")
    flag.StringVar(&token, "token", "", "身份验证令牌（作为 WebSocket 子协议）")
    flag.StringVar(&dnsServer, "dns", "dns.alidns.com/dns-query", "ECH 查询 DoH 服务器")
    flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "ECH 查询域名")
    flag.StringVar(&xSocks5, "socks5", "", "自定义请求头 X-Socks5 的值")
    flag.StringVar(&xHttp, "http", "", "自定义请求头 X-Http 的值")
    flag.StringVar(&xGlobeProxy, "globeproxy", "", "自定义请求头 X-GlobeProxy 的值")
    flag.StringVar(&xFallbackIP, "fallbackip", "", "自定义请求头 X-Fallback-IP 的值")
}

func main() {
    flag.Parse()

    if serverAddr == "" {
        log.Fatal("必须指定服务端地址 -f\n\n示例:\n  ./client -l 127.0.0.1:1080 -f your-worker.workers.dev -token your-token")
    }

    // 加载 IP 列表（命令行、文件或网络）
    loadIPs()
    log.Printf("[启动] 已加载服务端 IP 总数: %d（主用: %d）", len(serverIPs), len(healthyIPs))

    // 准备 ECH
    log.Printf("[启动] 正在获取 ECH 配置...")
    if err := prepareECH(); err != nil {
        log.Fatalf("[启动] 获取 ECH 配置失败: %v", err)
    }

    // 启动健康检查与统计导出协程
    go healthCheckLoop() // 定期尝试恢复被剔除 IP 并补齐主用列表
    go statsLoop()       // 定期打印并导出统计 CSV

    // 启动代理服务器
    runProxyServer(listenAddr)
}

// ======================== IP 列表管理与持久化 ========================

func loadIPs() {
    var ips []string

    // 1) 命令行逗号分隔
    if ipList != "" {
        ips = strings.Split(ipList, ",")
    } else if ipFile != "" {
        // 2) 文件
        ips = loadIPsFromFile(ipFile)
    } else if ipURL != "" {
        // 3) 网络地址
        ips = loadIPsFromURL(ipURL)
        // 定时网络更新
        go autoUpdateIPs(ipURL, ipUpdateDur)
    }

    // 统一解析 ip:port 或 ip port 格式；空行与注释跳过
    parsed := parseIPLines(ips)

    // 去重
    ipSet := make(map[string]struct{})
    for _, ip := range parsed {
        ipSet[ip] = struct{}{}
    }
    serverIPs = serverIPs[:0]
    for ip := range ipSet {
        serverIPs = append(serverIPs, ip)
    }

    // 初始预筛选最快的前 maxFastIPs 作为主用，剩余作为备用
    healthyIPs = selectFastestIPs(serverIPs, maxFastIPs)
    if len(healthyIPs) == 0 && len(serverIPs) > 0 {
        // 若测速均失败，回退取前 maxFastIPs 个原始列表作为主用
        for i := 0; i < len(serverIPs) && i < maxFastIPs; i++ {
            healthyIPs = append(healthyIPs, serverIPs[i])
        }
    }
}

func parseIPLines(lines []string) []string {
    var out []string
    for _, v := range lines {
        v = strings.TrimSpace(v)
        if v == "" || strings.HasPrefix(v, "#") {
            continue
        }
        // 支持逗号分隔的一行
        if strings.Contains(v, ",") {
            parts := strings.Split(v, ",")
            for _, p := range parts {
                p = strings.TrimSpace(p)
                if p == "" || strings.HasPrefix(p, "#") {
                    continue
                }
                out = append(out, normalizeIPPort(p))
            }
            continue
        }
        out = append(out, normalizeIPPort(v))
    }
    return out
}

func normalizeIPPort(s string) string {
    // 支持 "ip:port" 或 "ip port"
    if strings.Contains(s, ":") {
        // 直接返回，后续按 server 默认端口补齐
        return strings.TrimSpace(s)
    }
    fields := strings.Fields(s)
    if len(fields) == 2 {
        return net.JoinHostPort(fields[0], fields[1])
    }
    // 单纯 IP，无端口；在使用处会补默认端口
    return strings.TrimSpace(s)
}

func loadIPsFromFile(filename string) []string {
    f, err := os.Open(filename)
    if err != nil {
        log.Fatalf("无法读取 IP 文件: %v", err)
    }
    defer f.Close()

    var ips []string
    sc := bufio.NewScanner(f)
    for sc.Scan() {
        line := strings.TrimSpace(sc.Text())
        if line != "" {
            ips = append(ips, line)
        }
    }
    if err := sc.Err(); err != nil {
        log.Fatalf("读取 IP 文件出错: %v", err)
    }
    return ips
}

func loadIPsFromURL(src string) []string {
    // 支持 http/https 文本；每行一条，可为 ip:port 或 ip port
    resp, err := http.Get(src)
    if err != nil {
        log.Printf("获取 IP 列表失败: %v", err)
        return nil
    }
    defer resp.Body.Close()

    var ips []string
    sc := bufio.NewScanner(resp.Body)
    for sc.Scan() {
        line := strings.TrimSpace(sc.Text())
        if line != "" {
            ips = append(ips, line)
        }
    }
    if err := sc.Err(); err != nil {
        log.Printf("读取网络 IP 列表出错: %v", err)
    }
    return ips
}

func autoUpdateIPs(src string, dur time.Duration) {
    ticker := time.NewTicker(dur)
    defer ticker.Stop()
    for {
        <-ticker.C
        newLines := loadIPsFromURL(src)
        if len(newLines) == 0 {
            log.Printf("[IP更新] 网络列表为空或获取失败，跳过本次更新")
            continue
        }
        newParsed := parseIPLines(newLines)

        // 去重并替换 serverIPs
        newSet := make(map[string]struct{})
        for _, ip := range newParsed {
            newSet[ip] = struct{}{}
        }
        serverIPs = serverIPs[:0]
        for ip := range newSet {
            serverIPs = append(serverIPs, ip)
        }

        // 重新筛选主用列表
        newHealthy := selectFastestIPs(serverIPs, maxFastIPs)
        if len(newHealthy) == 0 && len(serverIPs) > 0 {
            for i := 0; i < len(serverIPs) && i < maxFastIPs; i++ {
                newHealthy = append(newHealthy, serverIPs[i])
            }
        }

        ipMu.Lock()
        healthyIPs = newHealthy
        // 清空失败计数，避免旧状态干扰
        failedIPs = make(map[string]int)
        ipMu.Unlock()

        log.Printf("[IP更新] 已刷新 IP 列表，共 %d 个，选取最快 %d 个作为主用", len(serverIPs), maxFastIPs)
    }
}

func selectFastestIPs(ips []string, n int) []string {
    if len(ips) == 0 || n <= 0 {
        return nil
    }
    host, defaultPort, _, _ := parseServerAddr(serverAddr)

    type result struct {
        ip      string
        latency time.Duration
    }
    results := []result{}
    var wg sync.WaitGroup
    mu := sync.Mutex{}

    // 并发 TCP 探测到服务端端口（若 IP 无端口，则使用服务端默认端口）
    for _, ip := range ips {
        ipStr := ip
        wg.Add(1)
        go func(ipStr string) {
            defer wg.Done()
            ipAddr, ipPort, err := parseServerIP(ipStr)
            if err != nil {
                return
            }
            if ipPort == "" {
                ipPort = defaultPort
            }
            start := time.Now()
            conn, err := net.DialTimeout("tcp", net.JoinHostPort(ipAddr, ipPort), 2*time.Second)
            if err == nil {
                latency := time.Since(start)
                mu.Lock()
                results = append(results, result{ip: net.JoinHostPort(ipAddr, ipPort), latency: latency})
                mu.Unlock()
                _ = conn.Close()
            }
        }(ipStr)
    }
    wg.Wait()

    if len(results) == 0 {
        // 无法探测到任何可达 IP，返回空以便上层回退
        log.Printf("[筛选] 无可达 IP，无法进行延迟排名")
        return nil
    }

    sort.Slice(results, func(i, j int) bool {
        return results[i].latency < results[j].latency
    })

    var fastest []string
    for i := 0; i < len(results) && i < n; i++ {
        fastest = append(fastest, results[i].ip)
    }
    log.Printf("[筛选] 服务端 %s 选择最快前 %d 个 IP 作为主用", host, len(fastest))
    return fastest
}

func removeIP(ip string) {
    ipMu.Lock()
    defer ipMu.Unlock()
    for i, v := range healthyIPs {
        if v == ip {
            healthyIPs = append(healthyIPs[:i], healthyIPs[i+1:]...)
            break
        }
    }
    log.Printf("[LB] 已剔除失效 IP: %s；主用剩余: %d", ip, len(healthyIPs))
}

func addHealthyIP(ip string) {
    ipMu.Lock()
    defer ipMu.Unlock()
    for _, v := range healthyIPs {
        if v == ip {
            return
        }
    }
    healthyIPs = append(healthyIPs, ip)
    log.Printf("[LB] 已补充 IP: %s，当前主用节点数: %d", ip, len(healthyIPs))
}

// 当主用数量低于目标值时，从备用池中补齐最快的
func refillHealthyFromBackup() {
    ipMu.Lock()
    currentHealthy := make(map[string]struct{}, len(healthyIPs))
    for _, h := range healthyIPs {
        currentHealthy[h] = struct{}{}
    }
    // 构造备用池：serverIPs 中不在 healthy 的
    var backup []string
    for _, ip := range serverIPs {
        if _, ok := currentHealthy[ip]; !ok {
            backup = append(backup, ip)
        }
    }
    ipMu.Unlock()

    if len(backup) == 0 {
        return
    }

    need := maxFastIPs - len(healthyIPs)
    if need <= 0 {
        return
    }
    fastest := selectFastestIPs(backup, need)
    for _, ip := range fastest {
        addHealthyIP(ip)
    }
}

// ======================== 统计模块（打印与导出 CSV） ========================

func recordSuccess(ip string, latency time.Duration) {
    ipMu.Lock()
    defer ipMu.Unlock()
    stat, ok := ipStatistics[ip]
    if !ok {
        stat = &ipStats{}
        ipStatistics[ip] = stat
    }
    stat.success++
    stat.totalLatency += latency
}

func recordFailure(ip string) {
    ipMu.Lock()
    defer ipMu.Unlock()
    stat, ok := ipStatistics[ip]
    if !ok {
        stat = &ipStats{}
        ipStatistics[ip] = stat
    }
    stat.fail++
}

func printStats() {
    ipMu.Lock()
    defer ipMu.Unlock()
    log.Println("===== 节点统计 =====")
    for ip, stat := range ipStatistics {
        avgLatency := time.Duration(0)
        if stat.success > 0 {
            avgLatency = stat.totalLatency / time.Duration(stat.success)
        }
        log.Printf("IP: %-21s | 成功: %4d | 失败: %4d | 平均延迟: %v", ip, stat.success, stat.fail, avgLatency)
    }
    log.Println("===================")
}

func exportStatsCSV(filename string) {
    ipMu.Lock()
    defer ipMu.Unlock()
    f, err := os.Create(filename)
    if err != nil {
        log.Printf("[Stats] 导出 CSV 失败: %v", err)
        return
    }
    defer f.Close()
    fmt.Fprintln(f, "IP,成功次数,失败次数,平均延迟(ms)")
    for ip, stat := range ipStatistics {
        avgLatency := int64(0)
        if stat.success > 0 {
            avgLatency = stat.totalLatency.Milliseconds() / int64(stat.success)
        }
        fmt.Fprintf(f, "%s,%d,%d,%d\n", ip, stat.success, stat.fail, avgLatency)
    }
    log.Printf("[Stats] 已导出统计到 %s", filename)
}

func statsLoop() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()
    for {
        <-ticker.C
        printStats()
        exportStatsCSV("ip_stats.csv")
    }
}

// ======================== ECH 支持与 DoH 解析 ========================

const typeHTTPS = 65

func prepareECH() error {
    echBase64, err := queryHTTPSRecord(echDomain, dnsServer)
    if err != nil {
        return fmt.Errorf("DNS 查询失败: %w", err)
    }
    if echBase64 == "" {
        return errors.New("未找到 ECH 参数")
    }
    raw, err := base64.StdEncoding.DecodeString(echBase64)
    if err != nil {
        return fmt.Errorf("ECH 解码失败: %w", err)
    }
    echListMu.Lock()
    echList = raw
    echListMu.Unlock()
    log.Printf("[ECH] 配置已加载，长度: %d 字节", len(raw))
    return nil
}

func refreshECH() error {
    log.Printf("[ECH] 刷新配置...")
    return prepareECH()
}

func getECHList() ([]byte, error) {
    echListMu.RLock()
    defer echListMu.RUnlock()
    if len(echList) == 0 {
        return nil, errors.New("ECH 配置未加载")
    }
    return echList, nil
}

func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
    roots, err := x509.SystemCertPool()
    if err != nil {
        return nil, fmt.Errorf("加载系统根证书失败: %w", err)
    }
    return &tls.Config{
        MinVersion: tls.VersionTLS13,
        ServerName: serverName,
        EncryptedClientHelloConfigList: echList,
        EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error {
            return errors.New("服务器拒绝 ECH")
        },
        RootCAs: roots,
    }, nil
}

// 通过 DoH 查询 HTTPS 记录以获取 ECH
func queryHTTPSRecord(domain, dnsServer string) (string, error) {
    dohURL := dnsServer
    if !strings.HasPrefix(dohURL, "https://") && !strings.HasPrefix(dohURL, "http://") {
        dohURL = "https://" + dohURL
    }
    return queryDoH(domain, dohURL)
}

func queryDoH(domain, dohURL string) (string, error) {
    u, err := url.Parse(dohURL)
    if err != nil {
        return "", fmt.Errorf("无效的 DoH URL: %v", err)
    }
    dnsQuery := buildDNSQuery(domain, typeHTTPS)
    dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery)

    q := u.Query()
    q.Set("dns", dnsBase64)
    u.RawQuery = q.Encode()

    req, err := http.NewRequest("GET", u.String(), nil)
    if err != nil {
        return "", fmt.Errorf("创建请求失败: %v", err)
    }
    req.Header.Set("Accept", "application/dns-message")
    req.Header.Set("Content-Type", "application/dns-message")

    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        return "", fmt.Errorf("DoH 请求失败: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("DoH 服务器返回错误: %d", resp.StatusCode)
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("读取 DoH 响应失败: %v", err)
    }

    return parseDNSResponse(body)
}

func buildDNSQuery(domain string, qtype uint16) []byte {
    query := make([]byte, 0, 512)
    // Header: ID=1, RD=1, QDCOUNT=1
    query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    for _, label := range strings.Split(domain, ".") {
        query = append(query, byte(len(label)))
        query = append(query, []byte(label)...)
    }
    query = append(query, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01)
    return query
}

func parseDNSResponse(response []byte) (string, error) {
    if len(response) < 12 {
        return "", errors.New("响应过短")
    }
    ancount := binary.BigEndian.Uint16(response[6:8])
    if ancount == 0 {
        return "", errors.New("无应答记录")
    }

    offset := 12
    for offset < len(response) && response[offset] != 0 {
        offset += int(response[offset]) + 1
    }
    offset += 5

    for i := 0; i < int(ancount); i++ {
        if offset >= len(response) {
            break
        }
        if response[offset]&0xC0 == 0xC0 {
            offset += 2
        } else {
            for offset < len(response) && response[offset] != 0 {
                offset += int(response[offset]) + 1
            }
            offset++
        }
        if offset+10 > len(response) {
            break
        }
        rrType := binary.BigEndian.Uint16(response[offset : offset+2])
        offset += 8
        dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
        offset += 2
        if offset+int(dataLen) > len(response) {
            break
        }
        data := response[offset : offset+int(dataLen)]
        offset += int(dataLen)

        if rrType == typeHTTPS {
            if ech := parseHTTPSRecord(data); ech != "" {
                return ech, nil
            }
        }
    }
    return "", nil
}

func parseHTTPSRecord(data []byte) string {
    if len(data) < 2 {
        return ""
    }
    offset := 2
    if offset < len(data) && data[offset] == 0 {
        offset++
    } else {
        for offset < len(data) && data[offset] != 0 {
            offset += int(data[offset]) + 1
        }
        offset++
    }
    for offset+4 <= len(data) {
        key := binary.BigEndian.Uint16(data[offset : offset+2])
        length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
        offset += 4
        if offset+int(length) > len(data) {
            break
        }
        value := data[offset : offset+int(length)]
        offset += int(length)
        if key == 5 {
            return base64.StdEncoding.EncodeToString(value)
        }
    }
    return ""
}

// ======================== Cloudflare DoH 代理（UDP DNS 转发） ========================

func queryDoHForProxy(dnsQuery []byte) ([]byte, error) {
    _, port, _, err := parseServerAddr(serverAddr)
    if err != nil {
        return nil, err
    }

    // DoH URL
    dohURL := fmt.Sprintf("https://cloudflare-dns.com:%s/dns-query", port)

    echBytes, err := getECHList()
    if err != nil {
        return nil, fmt.Errorf("获取 ECH 配置失败: %w", err)
    }
    tlsCfg, err := buildTLSConfigWithECH("cloudflare-dns.com", echBytes)
    if err != nil {
        return nil, fmt.Errorf("构建 TLS 配置失败: %w", err)
    }

    transport := &http.Transport{
        TLSClientConfig: tlsCfg,
    }

    // 轮询挑选一个健康 IP 进行 DoH 连接；如健康为空，立即尝试补齐。
    ip := pickServerIP()
    if ip == "" {
        refillHealthyFromBackup()
        ip = pickServerIP()
    }
    if ip != "" {
        transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
            ipAddr, ipPort, err := parseServerIP(ip)
            if err != nil {
                return nil, err
            }
            if ipPort == "" {
                _, defaultPort, _ := net.SplitHostPort(addr)
                ipPort = defaultPort
            }
            dialer := &net.Dialer{Timeout: 10 * time.Second}
            return dialer.DialContext(ctx, network, net.JoinHostPort(ipAddr, ipPort))
        }
    }

    client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

    req, err := http.NewRequest("POST", dohURL, bytes.NewReader(dnsQuery))
    if err != nil {
        return nil, err
    }
    req.Header.Set("Content-Type", "application/dns-message")
    req.Header.Set("Accept", "application/dns-message")

    resp, err := client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("DoH 请求失败: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("DoH 响应错误: %d", resp.StatusCode)
    }

    return io.ReadAll(resp.Body)
}

// ======================== WebSocket 连接（并发 + 轮询 + 剔除 + 补充） ========================

func parseServerAddr(addr string) (host, port, path string, err error) {
    path = "/"
    slashIdx := strings.Index(addr, "/")
    if slashIdx != -1 {
        path = addr[slashIdx:]
        addr = addr[:slashIdx]
    }
    host, port, err = net.SplitHostPort(addr)
    if err != nil {
        host = addr
        port = "443"
    }
    return host, port, path, nil
}

func parseServerIP(ipAddr string) (ip, port string, err error) {
    ip, port, err = net.SplitHostPort(ipAddr)
    if err != nil {
        ip = ipAddr
        port = ""
    }
    return ip, port, nil
}

func pickServerIP() string {
    ipMu.Lock()
    defer ipMu.Unlock()
    if len(healthyIPs) == 0 {
        return ""
    }
    ip := healthyIPs[ipIndex]
    ipIndex = (ipIndex + 1) % len(healthyIPs)
    return ip
}

func dialWebSocketWithECH(maxRetries int) (*websocket.Conn, error) {
    host, port, path, err := parseServerAddr(serverAddr)
    if err != nil {
        return nil, err
    }
    wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

    for attempt := 1; attempt <= maxRetries; attempt++ {
        echBytes, echErr := getECHList()
        if echErr != nil {
            if attempt < maxRetries {
                _ = refreshECH()
                continue
            }
            return nil, echErr
        }

        tlsCfg, tlsErr := buildTLSConfigWithECH(host, echBytes)
        if tlsErr != nil {
            return nil, tlsErr
        }

        headers := http.Header{}
        if xSocks5 != "" {
            headers.Set("X-Socks5", xSocks5)
        }
        if xHttp != "" {
            headers.Set("X-Http", xHttp)
        }
        if xGlobeProxy != "" {
            headers.Set("X-GlobeProxy", xGlobeProxy)
        }
        if xFallbackIP != "" {
            headers.Set("X-Fallback-IP", xFallbackIP)
        }

        // 并发尝试所有健康 IP，谁先成功就用谁；若无主用则先补齐
        ipMu.Lock()
        currentHealthy := append([]string{}, healthyIPs...)
        ipMu.Unlock()
        if len(currentHealthy) == 0 {
            refillHealthyFromBackup()
            ipMu.Lock()
            currentHealthy = append([]string{}, healthyIPs...)
            ipMu.Unlock()
        }
        if len(currentHealthy) == 0 && len(serverIPs) > 0 {
            // 仍为空，直接从全部池里筛选一批主用
            ipMu.Lock()
            healthyIPs = selectFastestIPs(serverIPs, maxFastIPs)
            currentHealthy = append([]string{}, healthyIPs...)
            ipMu.Unlock()
        }

        resultChan := make(chan *websocket.Conn, len(currentHealthy))
        errChan := make(chan string, len(currentHealthy))

        for _, ipAddr := range currentHealthy {
            go func(ipAddr string) {
                dialer := websocket.Dialer{
                    TLSClientConfig: tlsCfg,
                    Subprotocols: func() []string {
                        if token == "" {
                            return nil
                        }
                        return []string{token}
                    }(),
                    HandshakeTimeout: 10 * time.Second,
                }
                ip, ipPort, err := parseServerIP(ipAddr)
                if err != nil {
                    recordFailure(ipAddr)
                    errChan <- ipAddr
                    return
                }
                if ipPort == "" {
                    ipPort = port
                }
                dialer.NetDial = func(network, address string) (net.Conn, error) {
                    return net.DialTimeout(network, net.JoinHostPort(ip, ipPort), 10*time.Second)
                }

                start := time.Now()
                wsConn, _, dialErr := dialer.Dial(wsURL, headers)
                latency := time.Since(start)

                if dialErr != nil {
                    recordFailure(ipAddr)
                    errChan <- ipAddr
                    return
                }
                recordSuccess(ipAddr, latency)
                resultChan <- wsConn
            }(ipAddr)
        }

        // 等待第一个成功的连接；若超时则处理失败剔除逻辑，并尝试补充主用
        select {
        case wsConn := <-resultChan:
            return wsConn, nil
        case <-time.After(5 * time.Second):
            // 汇总失败并剔除超过阈值的 IP
            for i := 0; i < len(currentHealthy); i++ {
                select {
                case ipAddr := <-errChan:
                    ipMu.Lock()
                    failedIPs[ipAddr]++
                    over := failedIPs[ipAddr] > 3
                    ipMu.Unlock()
                    if over {
                        removeIP(ipAddr)
                        log.Printf("[LB] 忽略失效 IP: %s", ipAddr)
                    }
                default:
                }
            }
            // 尝试补齐主用
            refillHealthyFromBackup()
            if attempt < maxRetries {
                _ = refreshECH()
                continue
            }
            return nil, errors.New("所有指定主用 IP 都连接失败")
        }
    }
    return nil, errors.New("连接失败，已达最大重试次数")
}

// ======================== 定期健康检查（自愈 + 补齐主用） ========================

func healthCheckLoop() {
    ticker := time.NewTicker(10 * time.Minute)
    defer ticker.Stop()
    for {
        <-ticker.C
        checkRemovedIPs()
        refillHealthyFromBackup()
    }
}

func checkRemovedIPs() {
    // 找出已被剔除的 IP（在 failedIPs 中出现，但不在 healthyIPs 中）
    ipMu.Lock()
    removed := []string{}
    healthySet := make(map[string]struct{}, len(healthyIPs))
    for _, h := range healthyIPs {
        healthySet[h] = struct{}{}
    }
    for ip := range failedIPs {
        if _, ok := healthySet[ip]; !ok {
            removed = append(removed, ip)
        }
    }
    ipMu.Unlock()

    if len(removed) == 0 {
        return
    }

    for _, ipAddr := range removed {
        if testIP(ipAddr) {
            // 恢复：加入健康列表，清零失败计数
            addHealthyIP(ipAddr)
            ipMu.Lock()
            failedIPs[ipAddr] = 0
            ipMu.Unlock()
            log.Printf("[LB] 恢复 IP: %s", ipAddr)
        }
    }
}

func testIP(ipAddr string) bool {
    host, port, _, _ := parseServerAddr(serverAddr)
    echBytes, err := getECHList()
    if err != nil {
        return false
    }
    tlsCfg, err := buildTLSConfigWithECH(host, echBytes)
    if err != nil {
        return false
    }
    ip, ipPort, err := parseServerIP(ipAddr)
    if err != nil {
        return false
    }
    if ipPort == "" {
        ipPort = port
    }
    dialer := websocket.Dialer{
        TLSClientConfig:  tlsCfg,
        HandshakeTimeout: 5 * time.Second,
    }
    dialer.NetDial = func(network, address string) (net.Conn, error) {
        return net.DialTimeout(network, net.JoinHostPort(ip, ipPort), 5*time.Second)
    }
    wsURL := fmt.Sprintf("wss://%s:%s/", host, port)
    wsConn, _, err := dialer.Dial(wsURL, nil)
    if err == nil && wsConn != nil {
        wsConn.Close()
        return true
    }
    return false
}

// ======================== 统一代理服务器 ========================

func runProxyServer(addr string) {
    listener, err := net.Listen("tcp", addr)
    if err != nil {
        log.Fatalf("[代理] 监听失败: %v", err)
    }
    defer listener.Close()

    log.Printf("[代理] 服务器启动: %s (支持 SOCKS5 和 HTTP)", addr)
    log.Printf("[代理] 后端服务器: %s", serverAddr)

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("[代理] 接受连接失败: %v", err)
            continue
        }
        go handleConnection(conn)
    }
}

func handleConnection(conn net.Conn) {
    defer conn.Close()

    clientAddr := conn.RemoteAddr().String()
    conn.SetDeadline(time.Now().Add(30 * time.Second))

    // 读取第一个字节判断协议
    buf := make([]byte, 1)
    n, err := conn.Read(buf)
    if err != nil || n == 0 {
        return
    }
    firstByte := buf[0]

    switch firstByte {
    case 0x05:
        handleSOCKS5(conn, clientAddr, firstByte)
    case 'C', 'G', 'P', 'H', 'D', 'O', 'T':
        handleHTTP(conn, clientAddr, firstByte)
    default:
        log.Printf("[代理] %s 未知协议: 0x%02x", clientAddr, firstByte)
    }
}

// ======================== 工具函数 ========================

func isNormalCloseError(err error) bool {
    if err == nil {
        return false
    }
    if err == io.EOF {
        return true
    }
    errStr := err.Error()
    return strings.Contains(errStr, "use of closed network connection") ||
        strings.Contains(errStr, "broken pipe") ||
        strings.Contains(errStr, "connection reset by peer") ||
        strings.Contains(errStr, "normal closure")
}

// ======================== SOCKS5 处理 ========================

const (
    modeSOCKS5      = 1 // SOCKS5 代理
    modeHTTPConnect = 2 // HTTP CONNECT 隧道
    modeHTTPProxy   = 3 // HTTP 普通代理（GET/POST等）
)

func handleSOCKS5(conn net.Conn, clientAddr string, firstByte byte) {
    if firstByte != 0x05 {
        log.Printf("[SOCKS5] %s 版本错误: 0x%02x", clientAddr, firstByte)
        return
    }

    // 读取认证方法数量
    buf := make([]byte, 1)
    if _, err := io.ReadFull(conn, buf); err != nil {
        return
    }
    nmethods := buf[0]
    methods := make([]byte, nmethods)
    if _, err := io.ReadFull(conn, methods); err != nil {
        return
    }

    // 响应无需认证
    if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
        return
    }

    // 读取请求
    buf = make([]byte, 4)
    if _, err := io.ReadFull(conn, buf); err != nil {
        return
    }
    if buf[0] != 5 {
        return
    }
    command := buf[1]
    atyp := buf[3]

    var host string
    switch atyp {
    case 0x01: // IPv4
        buf = make([]byte, 4)
        if _, err := io.ReadFull(conn, buf); err != nil {
            return
        }
        host = net.IP(buf).String()
    case 0x03: // 域名
        buf = make([]byte, 1)
        if _, err := io.ReadFull(conn, buf); err != nil {
            return
        }
        domainBuf := make([]byte, buf[0])
        if _, err := io.ReadFull(conn, domainBuf); err != nil {
            return
        }
        host = string(domainBuf)
    case 0x04: // IPv6
        buf = make([]byte, 16)
        if _, err := io.ReadFull(conn, buf); err != nil {
            return
        }
        host = net.IP(buf).String()
    default:
        conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
        return
    }

    // 读取端口
    buf = make([]byte, 2)
    if _, err := io.ReadFull(conn, buf); err != nil {
        return
    }
    port := int(buf[0])<<8 | int(buf[1])

    switch command {
    case 0x01: // CONNECT
        var target string
        if atyp == 0x04 {
            target = fmt.Sprintf("[%s]:%d", host, port)
        } else {
            target = fmt.Sprintf("%s:%d", host, port)
        }
        log.Printf("[SOCKS5] %s -> %s", clientAddr, target)

        if err := handleTunnel(conn, target, clientAddr, modeSOCKS5, ""); err != nil {
            if !isNormalCloseError(err) {
                log.Printf("[SOCKS5] %s 代理失败: %v", clientAddr, err)
            }
        }

    case 0x03: // UDP ASSOCIATE
        handleUDPAssociate(conn, clientAddr)

    default:
        conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
        return
    }
}

func handleUDPAssociate(tcpConn net.Conn, clientAddr string) {
    udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
    if err != nil {
        log.Printf("[UDP] %s 解析地址失败: %v", clientAddr, err)
        tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
        return
    }

    udpConn, err := net.ListenUDP("udp", udpAddr)
    if err != nil {
        log.Printf("[UDP] %s 监听失败: %v", clientAddr, err)
        tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
        return
    }

    localAddr := udpConn.LocalAddr().(*net.UDPAddr)
    port := localAddr.Port
    log.Printf("[UDP] %s UDP ASSOCIATE 监听端口: %d", clientAddr, port)

    response := []byte{0x05, 0x00, 0x00, 0x01}
    response = append(response, 127, 0, 0, 1) // 127.0.0.1
    response = append(response, byte(port>>8), byte(port&0xff))
    if _, err := tcpConn.Write(response); err != nil {
        udpConn.Close()
        return
    }

    stopChan := make(chan struct{})
    go handleUDPRelay(udpConn, clientAddr, stopChan)

    buf := make([]byte, 1)
    tcpConn.Read(buf)

    close(stopChan)
    udpConn.Close()
    log.Printf("[UDP] %s UDP ASSOCIATE 连接关闭", clientAddr)
}

func handleUDPRelay(udpConn *net.UDPConn, clientAddr string, stopChan chan struct{}) {
    buf := make([]byte, 65535)
    for {
        select {
        case <-stopChan:
            return
        default:
        }
        udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
        n, addr, err := udpConn.ReadFromUDP(buf)
        if err != nil {
            if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
                continue
            }
            return
        }
        if n < 10 {
            continue
        }
        data := buf[:n]
        if data[2] != 0x00 { // FRAG 必须为 0
            continue
        }
        atyp := data[3]
        var headerLen int
        var dstHost string
        var dstPort int

        switch atyp {
        case 0x01: // IPv4
            if n < 10 {
                continue
            }
            dstHost = net.IP(data[4:8]).String()
            dstPort = int(data[8])<<8 | int(data[9])
            headerLen = 10
        case 0x03: // 域名
            if n < 5 {
                continue
            }
            domainLen := int(data[4])
            if n < 7+domainLen {
                continue
            }
            dstHost = string(data[5 : 5+domainLen])
            dstPort = int(data[5+domainLen])<<8 | int(data[6+domainLen])
            headerLen = 7 + domainLen
        case 0x04: // IPv6
            if n < 22 {
                continue
            }
            dstHost = net.IP(data[4:20]).String()
            dstPort = int(data[20])<<8 | int(data[21])
            headerLen = 22
        default:
            continue
        }

        udpData := data[headerLen:]
        target := fmt.Sprintf("%s:%d", dstHost, dstPort)

        if dstPort == 53 {
            log.Printf("[UDP-DNS] %s -> %s (DoH 查询)", clientAddr, target)
            go handleDNSQuery(udpConn, addr, udpData, data[:headerLen])
        } else {
            log.Printf("[UDP] %s -> %s (暂不支持非 DNS UDP)", clientAddr, target)
        }
    }
}

func handleDNSQuery(udpConn *net.UDPConn, clientAddr *net.UDPAddr, dnsQuery []byte, socks5Header []byte) {
    dnsResponse, err := queryDoHForProxy(dnsQuery)
    if err != nil {
        log.Printf("[UDP-DNS] DoH 查询失败: %v", err)
        return
    }
    response := make([]byte, 0, len(socks5Header)+len(dnsResponse))
    response = append(response, socks5Header...)
    response = append(response, dnsResponse...)
    if _, err := udpConn.WriteToUDP(response, clientAddr); err != nil {
        log.Printf("[UDP-DNS] 发送响应失败: %v", err)
        return
    }
    log.Printf("[UDP-DNS] DoH 查询成功，响应 %d 字节", len(dnsResponse))
}

// ======================== HTTP 处理 ========================

func handleHTTP(conn net.Conn, clientAddr string, firstByte byte) {
    reader := bufio.NewReader(io.MultiReader(
        strings.NewReader(string(firstByte)),
        conn,
    ))

    requestLine, err := reader.ReadString('\n')
    if err != nil {
        return
    }
    parts := strings.Fields(requestLine)
    if len(parts) < 3 {
        return
    }
    method := parts[0]
    requestURL := parts[1]
    httpVersion := parts[2]

    headers := make(map[string]string)
    var headerLines []string
    for {
        line, err := reader.ReadString('\n')
        if err != nil {
            return
        }
        line = strings.TrimRight(line, "\r\n")
        if line == "" {
            break
        }
        headerLines = append(headerLines, line)
        if idx := strings.Index(line, ":"); idx > 0 {
            key := strings.TrimSpace(line[:idx])
            value := strings.TrimSpace(line[idx+1:])
            headers[strings.ToLower(key)] = value
        }
    }

    switch method {
    case "CONNECT":
        log.Printf("[HTTP-CONNECT] %s -> %s", clientAddr, requestURL)
        if err := handleTunnel(conn, requestURL, clientAddr, modeHTTPConnect, ""); err != nil {
            if !isNormalCloseError(err) {
                log.Printf("[HTTP-CONNECT] %s 代理失败: %v", clientAddr, err)
            }
        }

    case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE":
        log.Printf("[HTTP-%s] %s -> %s", method, clientAddr, requestURL)

        var target string
        var path string

        if strings.HasPrefix(requestURL, "http://") {
            urlWithoutScheme := strings.TrimPrefix(requestURL, "http://")
            idx := strings.Index(urlWithoutScheme, "/")
            if idx > 0 {
                target = urlWithoutScheme[:idx]
                path = urlWithoutScheme[idx:]
            } else {
                target = urlWithoutScheme
                path = "/"
            }
        } else {
            target = headers["host"]
            path = requestURL
        }

        if target == "" {
            conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
            return
        }
        if !strings.Contains(target, ":") {
            target += ":80"
        }

        var requestBuilder strings.Builder
        requestBuilder.WriteString(fmt.Sprintf("%s %s %s\r\n", method, path, httpVersion))
        for _, line := range headerLines {
            key := strings.Split(line, ":")[0]
            keyLower := strings.ToLower(strings.TrimSpace(key))
            if keyLower != "proxy-connection" && keyLower != "proxy-authorization" {
                requestBuilder.WriteString(line)
                requestBuilder.WriteString("\r\n")
            }
        }
        requestBuilder.WriteString("\r\n")

        if contentLength := headers["content-length"]; contentLength != "" {
            var length int
            fmt.Sscanf(contentLength, "%d", &length)
            if length > 0 && length < 10*1024*1024 {
                body := make([]byte, length)
                if _, err := io.ReadFull(reader, body); err == nil {
                    requestBuilder.Write(body)
                }
            }
        }

        firstFrame := requestBuilder.String()
        if err := handleTunnel(conn, target, clientAddr, modeHTTPProxy, firstFrame); err != nil {
            if !isNormalCloseError(err) {
                log.Printf("[HTTP-%s] %s 代理失败: %v", method, clientAddr, err)
            }
        }

    default:
        log.Printf("[HTTP] %s 不支持的方法: %s", clientAddr, method)
        conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
    }
}

// ======================== 隧道处理（WS 双向转发） ========================

func handleTunnel(conn net.Conn, target, clientAddr string, mode int, firstFrame string) error {
    wsConn, err := dialWebSocketWithECH(2)
    if err != nil {
        sendErrorResponse(conn, mode)
        return err
    }
    defer wsConn.Close()

    var mu sync.Mutex

    // 保活
    stopPing := make(chan bool)
    go func() {
        ticker := time.NewTicker(10 * time.Second)
        defer ticker.Stop()
        for {
            select {
            case <-ticker.C:
                mu.Lock()
                _ = wsConn.WriteMessage(websocket.PingMessage, nil)
                mu.Unlock()
            case <-stopPing:
                return
            }
        }
    }()
    defer close(stopPing)

    _ = conn.SetDeadline(time.Time{})

    // 仅 SOCKS5 模式尝试读取首帧
    if firstFrame == "" && mode == modeSOCKS5 {
        _ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
        buffer := make([]byte, 32768)
        n, _ := conn.Read(buffer)
        _ = conn.SetReadDeadline(time.Time{})
        if n > 0 {
            firstFrame = string(buffer[:n])
        }
    }

    // 发送连接请求
    connectMsg := fmt.Sprintf("CONNECT:%s|%s", target, firstFrame)
    mu.Lock()
    err = wsConn.WriteMessage(websocket.TextMessage, []byte(connectMsg))
    mu.Unlock()
    if err != nil {
        sendErrorResponse(conn, mode)
        return err
    }

    // 等待响应
    _, msg, err := wsConn.ReadMessage()
    if err != nil {
        sendErrorResponse(conn, mode)
        return err
    }
    response := string(msg)
    if strings.HasPrefix(response, "ERROR:") {
        sendErrorResponse(conn, mode)
        return errors.New(response)
    }
    if response != "CONNECTED" {
        sendErrorResponse(conn, mode)
        return fmt.Errorf("意外响应: %s", response)
    }

    // 发送成功响应
    if err := sendSuccessResponse(conn, mode); err != nil {
        return err
    }
    log.Printf("[代理] %s 已连接: %s", clientAddr, target)

    // 双向转发
    done := make(chan bool, 2)

    // Client -> Server
    go func() {
        buf := make([]byte, 32768)
        for {
            n, err := conn.Read(buf)
            if err != nil {
                mu.Lock()
                _ = wsConn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
                mu.Unlock()
                done <- true
                return
            }
            mu.Lock()
            err = wsConn.WriteMessage(websocket.BinaryMessage, buf[:n])
            mu.Unlock()
            if err != nil {
                done <- true
                return
            }
        }
    }()

    // Server -> Client
    go func() {
        for {
            mt, msg, err := wsConn.ReadMessage()
            if err != nil {
                done <- true
                return
            }
            if mt == websocket.TextMessage {
                if string(msg) == "CLOSE" {
                    done <- true
                    return
                }
            }
            if _, err := conn.Write(msg); err != nil {
                done <- true
                return
            }
        }
    }()

    <-done
    log.Printf("[代理] %s 已断开: %s", clientAddr, target)
    return nil
}

// ======================== 响应辅助函数 ========================

func sendErrorResponse(conn net.Conn, mode int) {
    switch mode {
    case modeSOCKS5:
        _, _ = conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
    case modeHTTPConnect, modeHTTPProxy:
        _, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
    }
}

func sendSuccessResponse(conn net.Conn, mode int) error {
    switch mode {
    case modeSOCKS5:
        _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
        return err
    case modeHTTPConnect:
        _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
        return err
    case modeHTTPProxy:
        return nil
    }
    return nil
}
