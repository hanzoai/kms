package zip

import (
	"fmt"
	"net"
)

// ZAPRegistry returns (creating if needed) the per-App zaprpc service
// registry. Use this to attach generated *_server.go ZAP services.
//
//	zap := app.ZAPRegistry()
//	zap.Register(validatev1.NewServer(impl))
func (a *App) ZAPRegistry() *zaprpcRegistry {
	if a.zapReg == nil {
		a.zapReg = newZAPRegistry()
	}
	return a.zapReg
}

// ZAPListen serves the ZAP RPC plane on the given address. The HTTP
// server (Fiber) keeps running on its own listener — one binary, two
// transports.
//
// **STATUS**: stub. The dispatcher in zaprpc.Registry is wired and
// callable; the on-the-wire ZAP server (binary framing, multiplexing,
// streaming) lands in a follow-up PR once zapc-generated server types
// stabilize. Calling ZAPListen today reserves the port, logs, and
// returns an error so misconfigured deployments fail loud.
func (a *App) ZAPListen(addr string) error {
	if a.zapReg == nil || len(a.zapReg.Names()) == 0 {
		return fmt.Errorf("zip: ZAPListen called but no ZAP services registered")
	}
	a.logger.Info("zip ZAP plane registered (network listener stub)",
		"addr", addr, "services", a.zapReg.Names())

	// Reserve the port up-front so misconfigured deployments fail fast.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("zip: ZAP listen %s: %w", addr, err)
	}
	a.zapListener = ln
	a.appendCloser(func() error { return ln.Close() })

	// Full wire dispatch lands in follow-up PR.
	return fmt.Errorf("zip: ZAP wire dispatch not yet implemented — registry usable via app.ZAPRegistry()")
}
