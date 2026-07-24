package main

import (
	"flag"
	"os"

	_ "github.com/voidluo/trojan-go/component"
	"github.com/voidluo/trojan-go/internal/webserver"
	"github.com/voidluo/trojan-go/log"
	"github.com/voidluo/trojan-go/option"
)

func serviceArgs(args []string, defaultListen string) (configPath, listenAddress string) {
	listenAddress = defaultListen
	for i := 0; i < len(args)-1; i++ {
		switch args[i] {
		case "-config":
			configPath = args[i+1]
		case "-listen":
			listenAddress = args[i+1]
		}
	}
	return configPath, listenAddress
}

func main() {
	// Service commands use the existing deployment database as cold data. The
	// legacy web command remains available only for the embedded compatibility runtime.
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "web", "admin-service":
			configPath, listenAddress := serviceArgs(os.Args[2:], "127.0.0.1:8081")
			if configPath == "" {
				log.Fatal("admin-service 模式需要指定 -config 参数")
			}
			var err error
			if os.Args[1] == "web" {
				err = webserver.RunStandalone(configPath)
			} else {
				err = webserver.RunAdminService(configPath, listenAddress)
			}
			if err != nil {
				log.Fatal("启动 admin-service 失败:", err)
			}
			return
		case "gateway-service":
			configPath, listenAddress := serviceArgs(os.Args[2:], "0.0.0.0:443")
			if configPath == "" {
				log.Fatal("gateway-service 模式需要指定 -config 参数")
			}
			if err := webserver.RunGatewayService(configPath, listenAddress); err != nil {
				log.Fatal("启动 gateway-service 失败:", err)
			}
			return
		case "control-service":
			configPath, listenAddress := serviceArgs(os.Args[2:], "127.0.0.1:8082")
			workerMode := false
			adminAddress := "127.0.0.1:8081"
			for i := 0; i < len(os.Args)-1; i++ {
				switch os.Args[i] {
				case "-admin":
					adminAddress = os.Args[i+1]
				case "-worker":
					workerMode = true
				}
			}
			var err error
			if workerMode {
				if configPath == "" {
					log.Fatal("Worker control-service 模式需要指定 -config 参数")
				}
				err = webserver.RunWorkerControlService(configPath, listenAddress)
			} else {
				err = webserver.RunControlService(listenAddress, adminAddress)
			}
			if err != nil {
				log.Fatal("启动 control-service 失败:", err)
			}
			return
		}
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
