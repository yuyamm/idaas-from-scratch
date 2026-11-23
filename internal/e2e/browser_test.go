package e2e

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// browser is a minimal user agent: it keeps cookies, follows redirects and
// submits HTML forms. Redirects to stopAt (the RP's redirect URI) are not
// followed so tests can read the authorization response.
type browser struct {
	t      *testing.T
	client *http.Client
}

type form struct {
	action string
	method string
	fields url.Values
}

type page struct {
	url      *url.URL
	status   int
	body     string
	location string // set when stopped at an external redirect
	forms    []form
}

func newBrowser(t *testing.T, base *http.Client, stopAt ...string) *browser {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Transport: base.Transport, Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		for _, p := range stopAt {
			if strings.HasPrefix(req.URL.String(), p) {
				return http.ErrUseLastResponse
			}
		}
		return nil
	}}
	return &browser{t: t, client: c}
}

func (b *browser) do(req *http.Request) *page {
	b.t.Helper()
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	p := &page{url: resp.Request.URL, status: resp.StatusCode, body: string(body), location: resp.Header.Get("Location")}
	p.forms = parseForms(p.url, p.body)
	return p
}

func (b *browser) get(rawURL string) *page {
	b.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	return b.do(req)
}

// submit fills the form whose action contains actionPart and submits it.
func (b *browser) submit(p *page, actionPart string, values map[string]string) *page {
	b.t.Helper()
	for _, f := range p.forms {
		if !strings.Contains(f.action, actionPart) {
			continue
		}
		fields := url.Values{}
		for k, v := range f.fields {
			fields[k] = v
		}
		for k, v := range values {
			fields.Set(k, v)
		}
		req, _ := http.NewRequest(http.MethodPost, f.action, strings.NewReader(fields.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return b.do(req)
	}
	b.t.Fatalf("no form with action containing %q on %s (status %d):\n%s", actionPart, p.url, p.status, p.body)
	return nil
}

func parseForms(base *url.URL, body string) []form {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}
	var forms []form
	var cur *form
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			attr := func(k string) string {
				for _, a := range n.Attr {
					if a.Key == k {
						return a.Val
					}
				}
				return ""
			}
			switch n.Data {
			case "form":
				action, _ := base.Parse(attr("action"))
				forms = append(forms, form{action: action.String(), method: attr("method"), fields: url.Values{}})
				cur = &forms[len(forms)-1]
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c)
				}
				cur = nil
				return
			case "input":
				if cur != nil && attr("name") != "" && attr("type") != "submit" {
					cur.fields.Set(attr("name"), attr("value"))
				}
			case "button":
				if cur != nil && attr("name") != "" {
					cur.fields.Set(attr("name"), attr("value"))
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return forms
}
