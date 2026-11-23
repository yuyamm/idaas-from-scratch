package authn

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// HIBPClient checks passwords against Have I Been Pwned using k-anonymity:
// only the first 5 hex characters of the SHA-1 hash leave this process.
type HIBPClient struct {
	baseURL string
	http    *http.Client
}

func NewHIBPClient(baseURL string, c *http.Client) *HIBPClient {
	if baseURL == "" {
		baseURL = "https://api.pwnedpasswords.com"
	}
	return &HIBPClient{baseURL: strings.TrimRight(baseURL, "/"), http: c}
}

func (c *HIBPClient) IsBreached(ctx context.Context, password string) (bool, error) {
	sum := sha1.Sum([]byte(password))
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := hash[:5], hash[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/range/"+prefix, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Add-Padding", "true")
	resp, err := c.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("hibp: status %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		got, count, _ := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if strings.EqualFold(got, suffix) && count != "0" {
			return true, nil
		}
	}
	return false, sc.Err()
}
