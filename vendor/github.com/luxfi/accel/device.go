package accel

// DeviceInfo contains information about a compute device.
type DeviceInfo struct {
	Backend          BackendType
	Index            int
	Name             string
	Vendor           string
	IsDiscrete       bool
	IsUnifiedMemory  bool
	TotalMemory      uint64 // bytes
	MaxBufferSize    uint64 // bytes
	MaxWorkgroupSize uint32
	SIMDWidth        uint32
	Capabilities     DeviceCaps
}

// DeviceCaps represents device capability flags.
type DeviceCaps uint32

const (
	CapFP16         DeviceCaps = 1 << iota // Half-precision float support
	CapFP64                                // Double precision support
	CapSubgroups                           // Subgroup/warp operations
	CapInt64Atomics                        // 64-bit atomic operations
)

// Has returns true if the device has the specified capability.
func (c DeviceCaps) Has(cap DeviceCaps) bool {
	return c&cap != 0
}

// MemoryGB returns total memory in gigabytes.
func (d *DeviceInfo) MemoryGB() float64 {
	return float64(d.TotalMemory) / (1024 * 1024 * 1024)
}
