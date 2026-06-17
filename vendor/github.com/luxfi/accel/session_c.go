//go:build cgo

package accel

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/luxfi/accel/internal/capi"
)

var (
	libInitOnce sync.Once
	libInitErr  error
)

// translateCapiError converts capi errors to accel errors for proper error checking.
func translateCapiError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, capi.ErrNoBackends):
		return ErrNoBackends
	case errors.Is(err, capi.ErrOutOfMemory):
		return ErrOutOfMemory
	case errors.Is(err, capi.ErrInvalidArgument):
		return ErrInvalidArgument
	case errors.Is(err, capi.ErrNotSupported):
		return ErrNotSupported
	case errors.Is(err, capi.ErrKernelFailed):
		return ErrKernelFailed
	default:
		return err
	}
}

func initLibrary() error {
	libInitOnce.Do(func() {
		libInitErr = capi.Init()
		if libInitErr == nil {
			// Try to load plugins from standard paths
			loadPlugins()
		}
	})
	return libInitErr
}

func shutdown() {
	closeDefaultSession()
	capi.Shutdown()
}

func version() string {
	return capi.Version()
}

func lastError() string {
	return capi.GetError()
}

func backendCount() int {
	return capi.BackendCount()
}

func deviceCountForBackend(b BackendType) int {
	return capi.DeviceCount(int(b))
}

func availableBackends() []BackendType {
	n := capi.BackendCount()
	backends := make([]BackendType, 0, n)
	for i := 0; i < n; i++ {
		backends = append(backends, BackendType(capi.BackendTypeAt(i)))
	}
	return backends
}

func allDevices() []DeviceInfo {
	var devices []DeviceInfo
	for _, b := range availableBackends() {
		count := capi.DeviceCount(int(b))
		for i := 0; i < count; i++ {
			if info, err := capi.GetDeviceInfo(int(b), i); err == nil {
				devices = append(devices, DeviceInfo{
					Backend:          b,
					Index:            i,
					Name:             info.Name,
					Vendor:           info.Vendor,
					IsDiscrete:       info.IsDiscrete,
					IsUnifiedMemory:  info.IsUnifiedMemory,
					TotalMemory:      info.TotalMemory,
					MaxWorkgroupSize: info.MaxWorkgroupSize,
					SIMDWidth:        info.SIMDWidth,
				})
			}
		}
	}
	return devices
}

// Plugin search paths by platform.
var pluginPaths = map[string][]string{
	"darwin": {
		"/usr/local/lib/lux/plugins",
		"/opt/homebrew/lib/lux/plugins",
		"~/.lux/plugins",
	},
	"linux": {
		"/usr/local/lib/lux/plugins",
		"/usr/lib/lux/plugins",
		"~/.lux/plugins",
	},
	"windows": {
		"C:\\Program Files\\Lux\\plugins",
		"~/.lux/plugins",
	},
}

// Plugin library names by backend.
var pluginNames = map[BackendType][]string{
	BackendMetal:  {"lux_metal.plugin"},
	BackendWebGPU: {"lux_webgpu.plugin"},
	BackendCUDA:   {"lux_cuda.plugin"},
}

// loadPlugins attempts to load backend plugins from standard paths.
func loadPlugins() {
	// Check environment variable first
	if pluginPath := os.Getenv("LUX_PLUGIN_PATH"); pluginPath != "" {
		loadPluginsFromDir(pluginPath)
	}

	// Then check standard paths
	paths := pluginPaths[runtime.GOOS]
	for _, dir := range paths {
		// Expand home directory
		if len(dir) > 0 && dir[0] == '~' {
			if home, err := os.UserHomeDir(); err == nil {
				dir = filepath.Join(home, dir[2:])
			}
		}
		loadPluginsFromDir(dir)
	}
}

func loadPluginsFromDir(dir string) {
	// Try each backend's plugin names
	for _, names := range pluginNames {
		for _, name := range names {
			path := filepath.Join(dir, name)
			if _, err := os.Stat(path); err == nil {
				// Plugin exists, try to load it
				if err := capi.LoadBackend(path); err == nil {
					// Successfully loaded
					break
				}
			}
		}
	}
}

// LoadPlugin explicitly loads a backend plugin from a path.
func LoadPlugin(path string) error {
	return capi.LoadBackend(path)
}

// cgoSessionHandle implements sessionHandle using CGO.
type cgoSessionHandle struct {
	session    *capi.Session
	mlOps      *cgoMLOps
	cryptoOps  *cgoCryptoOps
	zkOps      *cgoZKOps
	latticeOps *cgoLatticeOps
	fheOps     *cgoFHEOps
	dexOps     *cgoDEXOps
}

func newSession(opts ...SessionOption) (*Session, error) {
	if err := initLibrary(); err != nil {
		return nil, err
	}

	cfg := &sessionConfig{backend: BackendAuto}
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.backend != BackendAuto {
		return newSessionWithBackend(cfg.backend, opts...)
	}

	cs, err := capi.CreateSession()
	if err != nil {
		return nil, &Error{Op: "NewSession", Err: translateCapiError(err)}
	}

	return buildSession(cs, BackendAuto)
}

func newSessionWithBackend(backend BackendType, opts ...SessionOption) (*Session, error) {
	if err := initLibrary(); err != nil {
		return nil, err
	}

	cs, err := capi.CreateSessionWithBackend(int(backend))
	if err != nil {
		return nil, &Error{Op: "NewSessionWithBackend", Backend: backend, Err: translateCapiError(err)}
	}

	return buildSession(cs, backend)
}

func newSessionWithDevice(backend BackendType, deviceIndex int, opts ...SessionOption) (*Session, error) {
	if err := initLibrary(); err != nil {
		return nil, err
	}

	cs, err := capi.CreateSessionWithDevice(int(backend), deviceIndex)
	if err != nil {
		return nil, &Error{Op: "NewSessionWithDevice", Backend: backend, Err: translateCapiError(err)}
	}

	return buildSession(cs, backend)
}

func buildSession(cs *capi.Session, backend BackendType) (*Session, error) {
	// Initialize all ops eagerly to avoid data races on lazy init
	handle := &cgoSessionHandle{
		session:    cs,
		mlOps:      &cgoMLOps{session: cs},
		cryptoOps:  &cgoCryptoOps{session: cs},
		zkOps:      &cgoZKOps{session: cs},
		latticeOps: &cgoLatticeOps{session: cs},
		fheOps:     &cgoFHEOps{session: cs},
		dexOps:     &cgoDEXOps{session: cs},
	}

	s := &Session{
		handle: handle,
	}

	// Get device info
	if info, err := capi.GetDeviceInfo(int(backend), 0); err == nil {
		s.device = DeviceInfo{
			Backend:          BackendType(info.Backend),
			Name:             info.Name,
			Vendor:           info.Vendor,
			IsDiscrete:       info.IsDiscrete,
			IsUnifiedMemory:  info.IsUnifiedMemory,
			TotalMemory:      info.TotalMemory,
			MaxWorkgroupSize: info.MaxWorkgroupSize,
			SIMDWidth:        info.SIMDWidth,
		}
	}

	// Set finalizer for cleanup
	runtime.SetFinalizer(s, func(s *Session) {
		s.Close()
	})

	return s, nil
}

func (h *cgoSessionHandle) sync() error {
	return h.session.Sync()
}

func (h *cgoSessionHandle) syncContext(ctx context.Context) error {
	done := make(chan error, 1)
	go func() {
		done <- h.session.Sync()
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *cgoSessionHandle) close() error {
	h.session.Destroy()
	return nil
}

func (h *cgoSessionHandle) ml() MLOps           { return h.mlOps }
func (h *cgoSessionHandle) crypto() CryptoOps   { return h.cryptoOps }
func (h *cgoSessionHandle) zk() ZKOps           { return h.zkOps }
func (h *cgoSessionHandle) lattice() LatticeOps { return h.latticeOps }
func (h *cgoSessionHandle) fhe() FHEOps         { return h.fheOps }
func (h *cgoSessionHandle) dex() DEXOps         { return h.dexOps }

func (h *cgoSessionHandle) createTensor(dtype DType, shape []int) (tensorHandle, error) {
	t, err := capi.CreateTensor(h.session, int(dtype), shape)
	if err != nil {
		return nil, err
	}
	return &cgoTensorHandle{tensor: t}, nil
}

func (h *cgoSessionHandle) createTensorWithData(dtype DType, shape []int, data []byte) (tensorHandle, error) {
	t, err := capi.CreateTensorWithData(h.session, int(dtype), shape, data)
	if err != nil {
		return nil, err
	}
	return &cgoTensorHandle{tensor: t}, nil
}
