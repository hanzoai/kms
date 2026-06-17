package accel

// Version is the library version.
const Version = "0.1.0"

// Init initializes the accel library. Must be called before any other operations.
// Safe to call multiple times; subsequent calls are no-ops.
func Init() error {
	return initLibrary()
}

// Shutdown releases all library resources. Call when done using the library.
func Shutdown() {
	shutdown()
}

// Available returns true if at least one GPU backend is available.
func Available() bool {
	return backendCount() > 0
}

// Backends returns a list of available backend types.
func Backends() []BackendType {
	return availableBackends()
}

// Devices returns information about all available devices across all backends.
func Devices() []DeviceInfo {
	return allDevices()
}

// DeviceCount returns the total number of available devices.
func DeviceCount() int {
	var count int
	for _, b := range Backends() {
		count += deviceCountForBackend(b)
	}
	return count
}

// NewSession creates a new acceleration session with auto-detected best backend.
func NewSession(opts ...SessionOption) (*Session, error) {
	return newSession(opts...)
}

// NewSessionWithBackend creates a session using a specific backend.
func NewSessionWithBackend(backend BackendType, opts ...SessionOption) (*Session, error) {
	return newSessionWithBackend(backend, opts...)
}

// NewSessionWithDevice creates a session using a specific device.
func NewSessionWithDevice(backend BackendType, deviceIndex int, opts ...SessionOption) (*Session, error) {
	return newSessionWithDevice(backend, deviceIndex, opts...)
}

// GetVersion returns the C library version string.
func GetVersion() string {
	return version()
}

// GetLastError returns the last error message from the C library.
func GetLastError() string {
	return lastError()
}

// SelectBackend returns the best backend for the given operations.
// If ops is empty, returns the highest priority available backend.
func SelectBackend(ops ...OperationType) (BackendType, error) {
	return SelectBestBackend(ops, false)
}

// MustSelectBackend returns the best backend or panics on error.
func MustSelectBackend(ops ...OperationType) BackendType {
	b, err := SelectBackend(ops...)
	if err != nil {
		panic(err)
	}
	return b
}

// Capabilities returns the capabilities for a specific backend.
func Capabilities(backend BackendType) (*BackendCapabilities, error) {
	return GetCapabilities(backend)
}
