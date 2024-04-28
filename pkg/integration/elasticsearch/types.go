package elasticsearch

import (
	"github.com/go-playground/validator/v10"
	"github.com/khulnasoft-lab/kengine_server/reporters"
)

type ElasticSearch struct {
	Config           Config                  `json:"config"`
	IntegrationType  string                  `json:"integration_type"`
	NotificationType string                  `json:"notification_type"`
	Filters          reporters.FieldsFilters `json:"filters"`
	Message          string                  `json:"message"`
}

type Config struct {
	EndpointURL string `json:"endpoint_url" validate:"required,url" required:"true"`
	AuthHeader  string `json:"auth_header"`
	Index       string `json:"index" validate:"required,min=1" required:"true"`
}

func (e ElasticSearch) ValidateConfig(validate *validator.Validate) error {
	return validate.Struct(e.Config)
}
