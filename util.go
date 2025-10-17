package ensweb

import (
	"net/http"
	"unicode"

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

func CapitalizeFirst(s string) string {
	if len(s) == 0 {
		return s
	}
	runes := []rune(s)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}
