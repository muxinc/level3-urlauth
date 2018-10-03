# Level3/CenturyLink URL Authentication Library

This library includes Golang functions to digitally sign a URL in a manner that allows it to be verified by the 
Level3 CDN. This prevents tampering and allows for automatic expiration of URLs served with the Level3 CDN.

Details on the Level3 URL authentication feature are available on the [Level3 MediaPortal](https://mediaportal.level3.com/webhelp/help/Content/HTML/CDNDeliveryServices/CachingServiceOverview/CDNAssetSecurity/URLTokenAuthentication.htm).

## Example
```go
import ("github.com/muxinc/level3-urlauth/urlauth")

inputURL := "https://www.example.com/foo?client_id=abc123&foo=bar"
secret := "supersecret"
secretID := 1
ignoredParams := []string{"client_id"}
startTime := time.Now().Sub(time.Minute * 5)
expirationTime := startTime.Add(time.Hour * 6)
signedURL, err := urlauth.SignURL(inputURL, secret, secretID, ignoredParams, startTime, expirationTime)
```
