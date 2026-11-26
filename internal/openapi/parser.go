package openapi

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

type Parameter struct {
	Name     string `json:"name"`
	In       string `json:"in"`
	Required bool   `json:"required"`
}

type Endpoint struct {
	Path             string      `json:"path"`
	Method           string      `json:"method"`
	OperationID      string      `json:"operation_id,omitempty"`
	Summary          string      `json:"summary,omitempty"`
	Parameters       []Parameter `json:"parameters"`
	HasRequestBody   bool        `json:"has_request_body"`
	SecurityDeclared bool        `json:"security_declared"`
	SecuritySchemes  []string    `json:"security_schemes"`
}

type ParsedSpec struct {
	Title          string     `json:"title"`
	Version        string     `json:"version"`
	OpenAPIVersion string     `json:"openapi_version"`
	Description    string     `json:"description,omitempty"`
	EndpointCount  int        `json:"endpoint_count"`
	Endpoints      []Endpoint `json:"endpoints"`
}

// Parse reads and validates an OpenAPI specification.
// It supports JSON and YAML without making network requests.
func Parse(data []byte) (*ParsedSpec, error) {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = false

	doc, err := loader.LoadFromData(data)
	if err != nil {
		return nil, fmt.Errorf("unable to parse OpenAPI document: %w", err)
	}

	if err := doc.Validate(context.Background()); err != nil {
		return nil, fmt.Errorf("invalid OpenAPI document: %w", err)
	}

	result := &ParsedSpec{
		Title:          doc.Info.Title,
		Version:        doc.Info.Version,
		OpenAPIVersion: doc.OpenAPI,
		Description:    doc.Info.Description,
		Endpoints:      make([]Endpoint, 0),
	}

	paths := doc.Paths.Map()
	pathNames := make([]string, 0, len(paths))

	for path := range paths {
		pathNames = append(pathNames, path)
	}

	sort.Strings(pathNames)

	for _, path := range pathNames {
		item := paths[path]

		operations := []struct {
			method string
			op     *openapi3.Operation
		}{
			{"GET", item.Get},
			{"POST", item.Post},
			{"PUT", item.Put},
			{"PATCH", item.Patch},
			{"DELETE", item.Delete},
			{"HEAD", item.Head},
			{"OPTIONS", item.Options},
			{"TRACE", item.Trace},
		}

		for _, entry := range operations {
			if entry.op == nil {
				continue
			}

			op := entry.op

			endpoint := Endpoint{
				Path:           path,
				Method:         entry.method,
				OperationID:    op.OperationID,
				Summary:        op.Summary,
				Parameters:     make([]Parameter, 0),
				HasRequestBody: op.RequestBody != nil,
			}

			// Operation-level security overrides global security.
			if op.Security != nil {
				endpoint.SecurityDeclared = len(*op.Security) > 0
				endpoint.SecuritySchemes = securityNames(*op.Security)
			} else {
				endpoint.SecurityDeclared = len(doc.Security) > 0
				endpoint.SecuritySchemes = securityNames(doc.Security)
			}

			for _, param := range op.Parameters {
				if param == nil || param.Value == nil {
					continue
				}

				endpoint.Parameters = append(endpoint.Parameters, Parameter{
					Name:     param.Value.Name,
					In:       param.Value.In,
					Required: param.Value.Required,
				})
			}

			result.Endpoints = append(result.Endpoints, endpoint)
		}
	}

	result.EndpointCount = len(result.Endpoints)

	return result, nil
}

// securityNames extracts the names of security schemes.
func securityNames(requirements openapi3.SecurityRequirements) []string {
	names := make(map[string]struct{})

	for _, requirement := range requirements {
		for name := range requirement {
			names[name] = struct{}{}
		}
	}

	result := make([]string, 0, len(names))

	for name := range names {
		result = append(result, name)
	}

	sort.Strings(result)

	return result
}

// HasMissingSecurity identifies endpoints without declared security.
func HasMissingSecurity(spec *ParsedSpec) []string {
	findings := make([]string, 0)

	if spec == nil {
		return findings
	}

	for _, endpoint := range spec.Endpoints {
		if !endpoint.SecurityDeclared {
			findings = append(findings, fmt.Sprintf(
				"%s %s has no declared security requirement",
				endpoint.Method,
				endpoint.Path,
			))
		}
	}

	return findings
}

// NormalizeMethod standardizes HTTP method names.
func NormalizeMethod(method string) string {
	return strings.ToUpper(strings.TrimSpace(method))
}
