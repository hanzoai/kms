// Package zaprpc is the ZAP RPC dispatch surface exposed by zip.App.
// ZAP is Hanzo's binary RPC transport (HIP-001x). zip.App.ZAPListen()
// serves all registered ZAP services on a dedicated TCP port; one zip
// binary speaks HTTP/JSON for human/REST clients AND ZAP RPC for
// machine clients.
//
// **STATUS**: dispatcher and registry stubbed; full integration with
// zapc-generated server code lands in a follow-up PR. The contract here
// is stable enough to plumb today.
package zaprpc

import (
	"context"
	"errors"
)

// Service is the minimal ZAP service interface zip can dispatch to.
// zapc-generated <svc>_server.go satisfies this naturally.
type Service interface {
	// Name returns the service identifier (e.g. "validate.v1").
	Name() string
	// Handle dispatches one RPC call on the service. method is the
	// fully-qualified method name; payload is the wire-encoded ZAP
	// request body; the returned bytes are the wire-encoded response.
	Handle(ctx context.Context, method string, payload []byte) ([]byte, error)
}

// Registry holds the set of services served by one zip.App.ZAPListen.
type Registry struct {
	services map[string]Service
}

// NewRegistry constructs an empty registry.
func NewRegistry() *Registry {
	return &Registry{services: map[string]Service{}}
}

// Register adds a service. Calling twice with the same name overwrites
// (caller bug).
func (r *Registry) Register(s Service) {
	r.services[s.Name()] = s
}

// Get returns the service for name, or nil.
func (r *Registry) Get(name string) Service {
	return r.services[name]
}

// Names returns the registered service names.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.services))
	for n := range r.services {
		out = append(out, n)
	}
	return out
}

// ErrNoService is returned by Dispatch when the service is unregistered.
var ErrNoService = errors.New("zaprpc: service not registered")

// Dispatch invokes the named service+method against the registry. The
// real ZAP wire-decode happens upstream of this function; Dispatch is
// the seam zip.App.ZAPListen uses to route a parsed envelope to the
// right handler. Surface is stable for service callers; the network
// integration lands in the follow-up PR.
func (r *Registry) Dispatch(ctx context.Context, service, method string, payload []byte) ([]byte, error) {
	s, ok := r.services[service]
	if !ok {
		return nil, ErrNoService
	}
	return s.Handle(ctx, method, payload)
}
