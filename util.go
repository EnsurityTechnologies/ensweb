package ensweb

import (
	"net/http"

	"github.com/EnsurityTechnologies/helper/jsonutil"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func JSONDecodeErr(resp *http.Response) (*ErrMessage, error) {
	var model ErrMessage
	err := jsonutil.DecodeJSONFromReader(resp.Body, &model)
	if err != nil {
		return nil, err
	}
	return &model, nil
}

// ToTitleCase properly converts a string into title case
func ToTitleCase(s string) string {
	caser := cases.Title(language.English)
	return caser.String(s)
}
