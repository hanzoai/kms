package zip

import (
	"context"
	"reflect"

	"github.com/gofiber/fiber/v3"

	"github.com/hanzoai/zip/internal/jsonenc"
)

// TypedHandler is the generic handler signature: takes an *In, returns
// (*Out, error). zip generates OpenAPI 3.1 spec from the In/Out types
// and registers a Fiber route that unmarshals body → In, runs the
// handler, and marshals Out → JSON response.
type TypedHandler[In, Out any] func(ctx context.Context, in *In) (*Out, error)

// registeredOp is the bookkeeping zip keeps for OpenAPI generation.
// One op per typed route.
type registeredOp struct {
	Method      string
	Path        string
	OperationID string
	Summary     string
	Tags        []string
	InType      reflect.Type
	OutType     reflect.Type
}

// Get registers a GET typed handler at path.
func Get[In, Out any](app *App, path string, fn TypedHandler[In, Out], opts ...OpOption) {
	registerTyped(app, "GET", path, fn, opts...)
}

// Post registers a POST typed handler at path.
func Post[In, Out any](app *App, path string, fn TypedHandler[In, Out], opts ...OpOption) {
	registerTyped(app, "POST", path, fn, opts...)
}

// Put registers a PUT typed handler at path.
func Put[In, Out any](app *App, path string, fn TypedHandler[In, Out], opts ...OpOption) {
	registerTyped(app, "PUT", path, fn, opts...)
}

// Patch registers a PATCH typed handler at path.
func Patch[In, Out any](app *App, path string, fn TypedHandler[In, Out], opts ...OpOption) {
	registerTyped(app, "PATCH", path, fn, opts...)
}

// Delete registers a DELETE typed handler at path.
func Delete[In, Out any](app *App, path string, fn TypedHandler[In, Out], opts ...OpOption) {
	registerTyped(app, "DELETE", path, fn, opts...)
}

// OpOption configures a typed handler registration (OpenAPI metadata).
type OpOption func(*registeredOp)

// WithSummary sets the operation summary in OpenAPI.
func WithSummary(s string) OpOption { return func(op *registeredOp) { op.Summary = s } }

// WithTags sets the operation tags in OpenAPI.
func WithTags(tags ...string) OpOption { return func(op *registeredOp) { op.Tags = tags } }

// WithOperationID sets the operation ID in OpenAPI.
func WithOperationID(id string) OpOption {
	return func(op *registeredOp) { op.OperationID = id }
}

func registerTyped[In, Out any](app *App, method, path string, fn TypedHandler[In, Out], opts ...OpOption) {
	var inZero In
	var outZero Out
	op := &registeredOp{
		Method:  method,
		Path:    path,
		InType:  reflect.TypeOf(inZero),
		OutType: reflect.TypeOf(outZero),
	}
	for _, o := range opts {
		o(op)
	}
	app.ops = append(app.ops, op)

	handler := func(c fiber.Ctx) error {
		var in In
		if method != "GET" && method != "HEAD" {
			if len(c.Body()) > 0 {
				if err := jsonenc.Unmarshal(c.Body(), &in); err != nil {
					return ErrBadRequest("invalid json body: " + err.Error())
				}
			}
		}
		// Validate via struct tags.
		if err := validate(&in); err != nil {
			return ErrBadRequest(err.Error())
		}
		out, err := fn(c.Context(), &in)
		if err != nil {
			return err
		}
		if out == nil {
			c.Status(204)
			return nil
		}
		return c.JSON(out)
	}
	app.fiber.Add([]string{method}, path, handler)
}
