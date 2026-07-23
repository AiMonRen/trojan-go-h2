package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	// 1. 设置环境变量并编译
	fmt.Println("正在编译 Trojan-Go (Linux amd64)...")
	build("./cmd/trojan-go", "build/linux-amd64/trojan-go")

	fmt.Println("正在编译 Trojan CLI (Linux amd64)...")
	build("./cmd/trojan", "build/linux-amd64/trojan")

	fmt.Println("正在拷贝示例配置文件...")
	if err := copyFile("example/server.yaml", "build/linux-amd64/example/server.yaml"); err != nil {
		fmt.Printf("拷贝配置文件失败: %v\n", err)
	}

	// 2. 打包 ZIP 并设置 Linux 权限
	zipPath := "build/trojan-go-linux-amd64.zip"
	fmt.Printf("正在打包至 %s 并设置执行权限...\n", zipPath)
	if err := createZipWithPermissions("build/linux-amd64", zipPath); err != nil {
		fmt.Printf("打包失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n✓ 全部完成！")
	fmt.Printf("发布包路径: %s\n", zipPath)
}

func build(src, out string) {
	cmd := exec.Command("go", "build", "-tags", "full", "-trimpath", "-ldflags", "-s -w -buildid=", "-o", out, src)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("编译失败 (%s): %v\n", src, err)
		os.Exit(1)
	}
}

func createZipWithPermissions(srcDir, zipPath string) error {
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	archive := zip.NewWriter(zipFile)
	defer archive.Close()

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		// 设置相对路径
		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(relPath)
		header.Method = zip.Deflate

		// 关键：设置 Unix 权限位
		// 0100755: 常规文件 (0100000) + 权限 (0755)
		// 在 ZIP 头部，ExternalAttributes 的高 16 位存储 Unix 权限位
		var unixMode uint32 = 0100755
		header.ExternalAttrs = unixMode << 16

		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		return err
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
