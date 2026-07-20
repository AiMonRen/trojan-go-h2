package main

import (
	"flag"
	"os"

	_ "github.com/voidluo/trojan-go/component"
	"github.com/voidluo/trojan-go/internal/webserver"
	"github.com/voidluo/trojan-go/log"
	"github.com/voidluo/trojan-go/option"
)

func main() {
	// web 子命令：以外挂模式启动独立 Web 管理后台
	// 用法：trojan-go web -config /path/to/web_config.yaml
	if len(os.Args) >= 2 && os.Args[1] == "web" {
		configPath := ""
		for i := 2; i < len(os.Args)-1; i++ {
			if os.Args[i] == "-config" {
				configPath = os.Args[i+1]
				break
			}
		}
		if configPath == "" {
			log.Fatal("web 模式需要指定 -config 参数")
		}
		if err := webserver.RunStandalone(configPath); err != nil {
			log.Fatal("启动 Web 管理后台失败:", err)
		}
		os.Exit(0)
	}

	// 默认模式：遍历已注册的 option.Handler（-config / -server / -api / -version）
	// 按优先级从高到低逐一尝试，首次成功即阻塞运行代理服务器
	flag.Parse()
	for {
		h, err := option.PopOptionHandler()
		if err != nil {
			log.Fatal("invalid options")
		}
		err = h.Handle()
		if err == nil {
			break
		}
	}
}
