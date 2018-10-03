package urlauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"time"
)

const (
	timestampFormat = "20060102150405"
)

// SignURL signs a given URL string using the supplied secret for verification by the Level3 CDN. Start-time and Expiration-time
// criteria will be included in the signature if non-nil. Ignored params will be present in the resulting signed-URL, but will not
// factor into the computed URL signature (the Level3 CDN config must also know to ignore them).
func SignURL(plainURL, secret string, secretID int, ignoredParams []string, startTime, expirationTime *time.Time) (string, error) {
	if len(plainURL) == 0 {
		return "", errors.New("URL was empty, expected a non-empty URL for signing")
	}

	if len(secret) == 0 {
		return "", errors.New("Secret was empty, expected a non-empty secret for signing")
	}

	inputURL, err := url.Parse(plainURL)
	if err != nil {
		return "", fmt.Errorf("Error parsing plain URL prior to signing: %v", err)
	}

	allQueryValues, err := url.ParseQuery(inputURL.RawQuery)
	if err != nil {
		return "", err
	}

	if startTime != nil {
		allQueryValues.Set("stime", startTime.UTC().Format(timestampFormat))
	}
	if expirationTime != nil {
		allQueryValues.Set("etime", expirationTime.UTC().Format(timestampFormat))
	}

	// create a copy of the query-params, minus any params that must be ignored
	sparseQueryValues := make(url.Values)
	for k, v := range allQueryValues {
		if stringInSlice(k, ignoredParams) {
			continue
		}
		sparseQueryValues[k] = v
	}
	inputURL.RawQuery = sparseQueryValues.Encode()

	fmt.Printf("Signing: %s\n", inputURL.RequestURI())
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(inputURL.RequestURI()))
	allQueryValues.Set("encoded", fmt.Sprintf("%d%s", secretID, hex.EncodeToString(mac.Sum(nil))[:20]))
	inputURL.RawQuery = allQueryValues.Encode()

	return inputURL.String(), nil
}

func stringInSlice(str string, list []string) bool {
	for _, v := range list {
		if v == str {
			return true
		}
	}
	return false
}
