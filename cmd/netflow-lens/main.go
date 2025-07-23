package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/andy-zhangtao/NetFlow-Lens/internal/server"
)

var (
	Version   = "dev"
	BuildTime = ""
	GitCommit = ""
)

func main() {
	var (
		port    = flag.Int("port", 8080, "HTTP服务器监听端口")
		version = flag.Bool("version", false, "显示版本信息")
		help    = flag.Bool("help", false, "显示帮助信息")
	)
	flag.Parse()

	if *version {
		fmt.Printf("NetFlow Lens %s\n", Version)
		fmt.Printf("构建时间: %s\n", BuildTime)
		fmt.Printf("Git提交: %s\n", GitCommit)
		return
	}

	if *help {
		fmt.Println("NetFlow Lens - 网络流量可视化学习工具")
		fmt.Println()
		fmt.Println("用法:")
		fmt.Printf("  %s [选项]\n", "netflow-lens")
		fmt.Println()
		fmt.Println("选项:")
		flag.PrintDefaults()
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  netflow-lens              # 使用默认端口8080启动")
		fmt.Println("  netflow-lens -port 9090   # 使用端口9090启动")
		fmt.Println("  netflow-lens -version     # 显示版本信息")
		return
	}

	// 验证端口范围
	if *port < 1 || *port > 65535 {
		log.Fatalf("无效的端口号: %d，端口号必须在1-65535范围内", *port)
	}

	log.Printf("Starting NetFlow Lens v%s...", Version)

	srv := server.NewServer()

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Server starting on %s", addr)
	log.Printf("访问 http://localhost:%d 开始使用", *port)

	if err := http.ListenAndServe(addr, srv); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
