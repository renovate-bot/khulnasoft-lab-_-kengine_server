package apiDocs //nolint:stylecheck

import (
	"net/http"

	"github.com/khulnasoft-lab/kengine_server/model"
)

func (d *OpenAPIDocs) AddInternalAuthOperations() {
	d.AddOperation("getConsoleApiToken", http.MethodGet, "/kengine/internal/console-api-token",
		"Get api-token for console agent", "Get api-token for console agent",
		http.StatusOK, []string{tagInternal}, nil, nil, new(model.APIAuthRequest))
}
