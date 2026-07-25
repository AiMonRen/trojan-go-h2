package memory

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/config"
)

func TestTakeTrafficCheckpointFailureKeepsCounters(t *testing.T) {
	ctx := config.WithConfig(context.Background(), Name, &Config{})
	auth, err := NewAuthenticator(ctx)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if err := auth.AddUser("take-traffic"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	_, user := auth.AuthUser("take-traffic")
	user.AddTraffic64(100, 200)
	checkpointErr := errors.New("checkpoint failed")
	sent, recv, err := user.TakeTraffic(func(sent, recv uint64) error {
		if sent != 100 || recv != 200 {
			t.Fatalf("checkpoint values = %d/%d", sent, recv)
		}
		return checkpointErr
	})
	if !errors.Is(err, checkpointErr) || sent != 100 || recv != 200 {
		t.Fatalf("TakeTraffic = %d/%d err=%v", sent, recv, err)
	}
	if sent, recv := user.GetTraffic(); sent != 100 || recv != 200 {
		t.Fatalf("failed checkpoint changed counters: %d/%d", sent, recv)
	}
	if _, _, err := user.TakeTraffic(func(uint64, uint64) error { return nil }); err != nil {
		t.Fatalf("successful checkpoint: %v", err)
	}
	if sent, recv := user.GetTraffic(); sent != 0 || recv != 0 {
		t.Fatalf("successful checkpoint did not clear counters: %d/%d", sent, recv)
	}
}

func TestMemoryAuth(t *testing.T) {
	cfg := &Config{
		Passwords: nil,
	}
	ctx := config.WithConfig(context.Background(), Name, cfg)
	auth, err := NewAuthenticator(ctx)
	common.Must(err)
	auth.AddUser("user1")
	valid, user := auth.AuthUser("user1")
	if !valid {
		t.Fatal("add, auth")
	}
	if user.Hash() != "user1" {
		t.Fatal("Hash")
	}
	user.AddTraffic(100, 200)
	sent, recv := user.GetTraffic()
	if sent != 100 || recv != 200 {
		t.Fatal("traffic")
	}
	sent, recv = user.ResetTraffic()
	if sent != 100 || recv != 200 {
		t.Fatal("ResetTraffic")
	}
	sent, recv = user.GetTraffic()
	if sent != 0 || recv != 0 {
		t.Fatal("ResetTraffic")
	}

	user.AddIP("1234")
	user.AddIP("5678")
	if user.GetIP() != 0 {
		t.Fatal("GetIP")
	}

	user.SetIPLimit(2)
	user.AddIP("1234")
	user.AddIP("5678")
	user.DelIP("1234")
	if user.GetIP() != 1 {
		t.Fatal("DelIP")
	}
	user.DelIP("5678")

	user.SetIPLimit(2)
	if !user.AddIP("1") || !user.AddIP("2") {
		t.Fatal("AddIP")
	}
	if user.AddIP("3") {
		t.Fatal("AddIP")
	}
	if !user.AddIP("2") {
		t.Fatal("AddIP")
	}

	user.SetTraffic(1234, 4321)
	if a, b := user.GetTraffic(); a != 1234 || b != 4321 {
		t.Fatal("SetTraffic")
	}

	user.ResetTraffic()
	go func() {
		for {
			k := 100
			time.Sleep(time.Second / time.Duration(k))
			user.AddTraffic(2000/k, 1000/k)
		}
	}()
	time.Sleep(time.Second * 4)
	if sent, recv := user.GetSpeed(); sent > 3000 || sent < 1000 || recv > 1500 || recv < 500 {
		t.Error("GetSpeed", sent, recv)
	} else {
		t.Log("GetSpeed", sent, recv)
	}

	user.SetSpeedLimit(30, 20)
	time.Sleep(time.Second * 4)
	if sent, recv := user.GetSpeed(); sent > 60 || recv > 40 {
		t.Error("SetSpeedLimit", sent, recv)
	} else {
		t.Log("SetSpeedLimit", sent, recv)
	}

	user.SetSpeedLimit(0, 0)
	time.Sleep(time.Second * 4)
	if sent, recv := user.GetSpeed(); sent < 30 || recv < 20 {
		t.Error("SetSpeedLimit", sent, recv)
	} else {
		t.Log("SetSpeedLimit", sent, recv)
	}

	auth.AddUser("user2")
	valid, _ = auth.AuthUser("user2")
	if !valid {
		t.Fatal()
	}
	auth.DelUser("user2")
	valid, _ = auth.AuthUser("user2")
	if valid {
		t.Fatal()
	}
	auth.AddUser("user3")
	users := auth.ListUsers()
	if len(users) != 2 {
		t.Fatal()
	}
	user.Close()
	auth.Close()
}

func TestConcurrentIPLimitNeverExceeded(t *testing.T) {
	cfg := &Config{}
	ctx := config.WithConfig(context.Background(), Name, cfg)
	auth, err := NewAuthenticator(ctx)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer auth.Close()
	if err := auth.AddUser("limited-user"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	_, user := auth.AuthUser("limited-user")
	user.SetIPLimit(8)

	var accepted atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 128; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if user.AddIP(fmt.Sprintf("192.0.2.%d", i)) {
				accepted.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if got := int(accepted.Load()); got != 8 {
		t.Fatalf("accepted %d unique IPs, want 8", got)
	}
	if got := user.GetIP(); got != 8 {
		t.Fatalf("tracked %d unique IPs, want 8", got)
	}
}

func TestConcurrentDuplicateIPCountedOnce(t *testing.T) {
	cfg := &Config{}
	ctx := config.WithConfig(context.Background(), Name, cfg)
	auth, err := NewAuthenticator(ctx)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	defer auth.Close()
	if err := auth.AddUser("duplicate-user"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	_, user := auth.AuthUser("duplicate-user")
	user.SetIPLimit(1)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 128; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if !user.AddIP("198.51.100.10") {
				t.Error("duplicate IP should remain accepted")
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := user.GetIP(); got != 1 {
		t.Fatalf("tracked %d IPs, want 1", got)
	}
}

func BenchmarkMemoryUsage(b *testing.B) {
	cfg := &Config{
		Passwords: nil,
	}
	ctx := config.WithConfig(context.Background(), Name, cfg)
	auth, err := NewAuthenticator(ctx)
	common.Must(err)

	m1 := runtime.MemStats{}
	m2 := runtime.MemStats{}
	runtime.ReadMemStats(&m1)
	for i := 0; i < b.N; i++ {
		common.Must(auth.AddUser(common.SHA224String("hash" + strconv.Itoa(i))))
	}
	runtime.ReadMemStats(&m2)

	b.ReportMetric(float64(m2.Alloc-m1.Alloc)/1024/1024, "MiB(Alloc)")
	b.ReportMetric(float64(m2.TotalAlloc-m1.TotalAlloc)/1024/1024, "MiB(TotalAlloc)")
}
