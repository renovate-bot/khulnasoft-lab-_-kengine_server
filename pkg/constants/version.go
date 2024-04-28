package constants

import (
	"fmt"

	"github.com/khulnasoft-lab/kengine_utils/log"
	"golang.org/x/mod/semver"
)

var (
	Version   string
	Commit    string
	BuildTime string
)

func init() {
	if !semver.IsValid(fmt.Sprintf("v%s", Version)) {
		log.Warn().Msgf("Provided console version %s is not valid", Version)
	}
}
