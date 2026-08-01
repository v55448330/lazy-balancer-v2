package mcpserver

import "net/http"

const restAPIPathPrefix = "/api/v1"

type ToolSpec struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	ReadOnly    bool   `json:"read_only"`
}

func ListToolSpecs() []ToolSpec {
	result := make([]ToolSpec, len(tools))
	for index, spec := range tools {
		result[index] = ToolSpec{
			Name:        spec.name,
			Description: spec.description,
			Method:      spec.method,
			Path:        restAPIPathPrefix + spec.path,
			ReadOnly:    spec.method == http.MethodGet,
		}
	}
	return result
}
