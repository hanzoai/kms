package zip

import (
	"reflect"
	"sort"
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/hanzoai/zip/internal/jsonenc"
)

// OpenAPIConfig configures the auto-generated /.well-known/openapi.json
// endpoint zip serves when typed handlers are registered.
type OpenAPIConfig struct {
	// Title appears in the OpenAPI info block.
	Title string
	// Description appears in the OpenAPI info block.
	Description string
	// Version appears in the OpenAPI info block (e.g. "v1.0.0").
	Version string
	// Disabled suppresses the /.well-known/openapi.json route and /docs.
	Disabled bool
}

// installOpenAPIRoutes wires /.well-known/openapi.json and /docs.
// Called from Listen / Serve. Idempotent if there are no typed ops.
func (a *App) installOpenAPIRoutes() {
	if a.cfg.OpenAPI.Disabled || len(a.ops) == 0 {
		return
	}
	spec := a.buildOpenAPI()
	specJSON, _ := jsonenc.Marshal(spec)

	a.fiber.Get("/.well-known/openapi.json", func(fc fiber.Ctx) error {
		fc.Set("Content-Type", "application/json")
		return fc.Send(specJSON)
	})
	a.fiber.Get("/docs", func(fc fiber.Ctx) error {
		fc.Set("Content-Type", "text/html; charset=utf-8")
		return fc.SendString(swaggerHTML)
	})
}

// buildOpenAPI walks the registered typed ops and builds an OpenAPI 3.1
// spec as a plain map (json.Marshal serializes anything map-shaped).
func (a *App) buildOpenAPI() map[string]any {
	cfg := a.cfg.OpenAPI
	if cfg.Title == "" {
		cfg.Title = a.cfg.AppName
	}
	if cfg.Title == "" {
		cfg.Title = "zip API"
	}
	if cfg.Version == "" {
		cfg.Version = "0.0.0"
	}

	paths := map[string]map[string]any{}
	schemas := map[string]any{}

	// Sort ops by path,method for deterministic output.
	ops := append([]*registeredOp{}, a.ops...)
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].Path != ops[j].Path {
			return ops[i].Path < ops[j].Path
		}
		return ops[i].Method < ops[j].Method
	})

	for _, op := range ops {
		path := op.Path
		// OpenAPI uses {name} for path params; fiber uses :name. Translate.
		path = strings.ReplaceAll(path, "/:", "/{")
		if strings.Contains(path, "{") && !strings.Contains(path, "}") {
			// Was ":name" -> "{name" needs the closing brace.
			path = closeColonParams(op.Path)
		}

		if _, ok := paths[path]; !ok {
			paths[path] = map[string]any{}
		}
		opObj := map[string]any{
			"operationId": op.OperationID,
			"summary":     op.Summary,
		}
		if op.OperationID == "" {
			opObj["operationId"] = defaultOpID(op.Method, op.Path)
		}
		if len(op.Tags) > 0 {
			opObj["tags"] = op.Tags
		}

		// Request body.
		if op.Method != "GET" && op.Method != "HEAD" && op.Method != "DELETE" {
			inName := typeName(op.InType)
			if op.InType != nil && inName != "" {
				schemas[inName] = schemaOf(op.InType, schemas)
				opObj["requestBody"] = map[string]any{
					"required": true,
					"content": map[string]any{
						"application/json": map[string]any{
							"schema": map[string]any{"$ref": "#/components/schemas/" + inName},
						},
					},
				}
			}
		}

		// 200 response.
		outName := typeName(op.OutType)
		if op.OutType != nil && outName != "" {
			schemas[outName] = schemaOf(op.OutType, schemas)
			opObj["responses"] = map[string]any{
				"200": map[string]any{
					"description": "ok",
					"content": map[string]any{
						"application/json": map[string]any{
							"schema": map[string]any{"$ref": "#/components/schemas/" + outName},
						},
					},
				},
			}
		} else {
			opObj["responses"] = map[string]any{
				"204": map[string]any{"description": "no content"},
			}
		}

		paths[path][strings.ToLower(op.Method)] = opObj
	}

	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       cfg.Title,
			"description": cfg.Description,
			"version":     cfg.Version,
		},
		"paths": paths,
		"components": map[string]any{
			"schemas": schemas,
		},
	}
}

func defaultOpID(method, path string) string {
	clean := strings.ReplaceAll(path, "/", "_")
	clean = strings.ReplaceAll(clean, "{", "")
	clean = strings.ReplaceAll(clean, "}", "")
	clean = strings.ReplaceAll(clean, ":", "")
	return strings.ToLower(method) + clean
}

func closeColonParams(path string) string {
	// Convert ":name" segments to "{name}".
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if strings.HasPrefix(p, ":") {
			parts[i] = "{" + p[1:] + "}"
		}
	}
	return strings.Join(parts, "/")
}

func typeName(t reflect.Type) string {
	if t == nil {
		return ""
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Name() == "" {
		return ""
	}
	return t.Name()
}

// schemaOf builds a minimal JSON Schema for t. Handles structs, primitives,
// slices, and pointers. Anonymous types become "object" without a ref.
func schemaOf(t reflect.Type, registry map[string]any) map[string]any {
	if t == nil {
		return map[string]any{"type": "object"}
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Slice, reflect.Array:
		return map[string]any{
			"type":  "array",
			"items": schemaOf(t.Elem(), registry),
		}
	case reflect.Map:
		return map[string]any{
			"type":                 "object",
			"additionalProperties": schemaOf(t.Elem(), registry),
		}
	case reflect.Struct:
		props := map[string]any{}
		required := []string{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name := jsonFieldName(f)
			if name == "-" {
				continue
			}
			props[name] = schemaOf(f.Type, registry)
			if tag := f.Tag.Get("validate"); strings.Contains(tag, "required") {
				required = append(required, name)
			}
		}
		out := map[string]any{
			"type":       "object",
			"properties": props,
		}
		if len(required) > 0 {
			out["required"] = required
		}
		return out
	}
	return map[string]any{"type": "object"}
}

func jsonFieldName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" {
		return f.Name
	}
	if i := strings.IndexByte(tag, ','); i >= 0 {
		tag = tag[:i]
	}
	if tag == "" {
		return f.Name
	}
	return tag
}

// swaggerHTML is the minimal Swagger UI shell. Loads the UI from a CDN
// and points it at /.well-known/openapi.json. About 30 lines — no bundled
// JS in the binary.
const swaggerHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>API Docs</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function () {
      window.ui = SwaggerUIBundle({
        url: "/.well-known/openapi.json",
        dom_id: "#swagger-ui",
        deepLinking: true,
      });
    };
  </script>
</body>
</html>
`
