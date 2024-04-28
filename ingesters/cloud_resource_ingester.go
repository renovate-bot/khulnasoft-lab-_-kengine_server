package ingesters

import (
	"context"
	"encoding/json"

	"github.com/khulnasoft-lab/kengine_utils/directory"
	"github.com/khulnasoft-lab/kengine_utils/log"
	"github.com/khulnasoft-lab/kengine_utils/utils"
	ingestersUtil "github.com/khulnasoft-lab/kengine_utils/utils/ingesters"
	"github.com/twmb/franz-go/pkg/kgo"
)

type CloudResourceIngester struct{}

func NewCloudResourceIngester() KafkaIngester[[]ingestersUtil.CloudResource] {
	return &CloudResourceIngester{}
}

func (tc *CloudResourceIngester) Ingest(
	ctx context.Context,
	cs []ingestersUtil.CloudResource,
	ingestC chan *kgo.Record,
) error {

	tenantID, err := directory.ExtractNamespace(ctx)
	if err != nil {
		return err
	}

	rh := []kgo.RecordHeader{
		{Key: "namespace", Value: []byte(tenantID)},
	}

	for _, c := range cs {
		cb, err := json.Marshal(c)
		if err != nil {
			log.Error().Msg(err.Error())
		} else {
			ingestC <- &kgo.Record{
				Topic:   utils.CloudResource,
				Value:   cb,
				Headers: rh,
			}
		}
	}

	return nil
}
