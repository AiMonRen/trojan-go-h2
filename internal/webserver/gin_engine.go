package webserver

import "github.com/gin-gonic/gin"

var trustedLoopbackProxies = []string{"127.0.0.0/8", "::1/128"}

// newTrustedGinEngine accepts forwarded client addresses only from the local
// Gateway/Control service chain. Direct remote clients cannot spoof ClientIP
// with X-Forwarded-For or X-Real-IP.
func newTrustedGinEngine() *gin.Engine {
	engine := gin.New()
	if err := engine.SetTrustedProxies(trustedLoopbackProxies); err != nil {
		panic("configure trusted loopback proxies: " + err.Error())
	}
	return engine
}
