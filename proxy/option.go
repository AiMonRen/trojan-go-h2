package proxy

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/log"
	"github.com/voidluo/trojan-go/option"
	"github.com/voidluo/trojan-go/version"
)

type Option struct {
	path *string
}

func (o *Option) Name() string { return Name }

func detectAndReadConfig(file string) ([]byte, bool, error) {
	isJSON := false
	switch {
	case strings.HasSuffix(file, ".json"):
		isJSON = true
	case strings.HasSuffix(file, ".yaml"), strings.HasSuffix(file, ".yml"):
	default:
		return nil, false, common.NewError("unsupported config format: " + file)
	}
	data, err := os.ReadFile(file)
	return data, isJSON, err
}

// RunWithSignals runs the proxy and closes it on process termination.
func RunWithSignals(p *Proxy) error {
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- p.Run() }()
	select {
	case err := <-done:
		return err
	case <-signalCtx.Done():
		_ = p.Close()
		return <-done
	}
}

func (o *Option) Handle() error {
	paths := []string{"config.json", "config.yml", "config.yaml"}
	isJSON := false
	var data []byte
	var err error
	if *o.path == "" {
		for _, path := range paths {
			data, isJSON, err = detectAndReadConfig(path)
			if err == nil {
				break
			}
		}
	} else {
		data, isJSON, err = detectAndReadConfig(*o.path)
	}
	if err != nil {
		return err
	}
	if data == nil {
		return common.NewError("no valid config")
	}
	log.Info("trojan-go", version.Version, "initializing")
	p, err := NewProxyFromConfigData(data, isJSON)
	if err != nil {
		return err
	}
	return RunWithSignals(p)
}

func (o *Option) Priority() int { return -1 }

func init() {
	option.RegisterHandler(&Option{
		path: flag.String("config", "", "Trojan-Go config filename (.yaml/.yml/.json)"),
	})
	option.RegisterHandler(&StdinOption{
		format:       flag.String("stdin-format", "disabled", "Read from standard input (yaml/json)"),
		suppressHint: flag.Bool("stdin-suppress-hint", false, "Suppress hint text"),
	})
}

type StdinOption struct {
	format       *string
	suppressHint *bool
}

func (o *StdinOption) Name() string { return Name + "_STDIN" }

func (o *StdinOption) Handle() error {
	isJSON, err := o.isFormatJSON()
	if err != nil {
		return err
	}
	if o.suppressHint == nil || !*o.suppressHint {
		fmt.Printf("Trojan-Go %s (%s/%s)\n", version.Version, runtime.GOOS, runtime.GOARCH)
	}
	data, err := io.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		return err
	}
	p, err := NewProxyFromConfigData(data, isJSON)
	if err != nil {
		return err
	}
	return RunWithSignals(p)
}

func (o *StdinOption) Priority() int { return 0 }

func (o *StdinOption) isFormatJSON() (bool, error) {
	if o.format == nil {
		return false, common.NewError("format specifier is nil")
	}
	if *o.format == "disabled" {
		return false, common.NewError("reading from stdin is disabled")
	}
	return strings.EqualFold(*o.format, "json"), nil
}

var _ option.Handler = (*Option)(nil)
var _ option.Handler = (*StdinOption)(nil)
