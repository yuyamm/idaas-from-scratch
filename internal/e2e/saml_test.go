package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"

	"github.com/yuyamm/idaas-from-scratch/internal/identity"
)

func newSP(t *testing.T, h *harness) *saml.ServiceProvider {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sp.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	resp, err := h.httpClient().Get(h.issuer() + "/saml/metadata")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var idpMD saml.EntityDescriptor
	if err := xml.Unmarshal(raw, &idpMD); err != nil {
		t.Fatalf("IdP metadata: %v\n%s", err, raw)
	}
	acs, _ := url.Parse("https://sp.example/saml/acs")
	md, _ := url.Parse("https://sp.example/saml/metadata")
	return &saml.ServiceProvider{EntityID: md.String(), Key: key, Certificate: cert, AcsURL: *acs, MetadataURL: *md, IDPMetadata: &idpMD}
}

func registerSP(t *testing.T, h *harness, sp *saml.ServiceProvider) {
	t.Helper()
	md, _ := xml.Marshal(sp.Metadata())
	a := h.admin()
	a.must(201, a.call("POST", "/tenants/"+h.tenant.ID.String()+"/saml-service-providers", map[string]any{"metadata_xml": string(md)}))
}

// acsPost extracts the auto-posted SAMLResponse and lets the SP validate it.
func acsPost(t *testing.T, sp *saml.ServiceProvider, p *page, requestID string) *saml.Assertion {
	t.Helper()
	for _, f := range p.forms {
		if f.action == sp.AcsURL.String() {
			req := httptest.NewRequest(http.MethodPost, f.action, strings.NewReader(f.fields.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.ParseForm()
			a, err := sp.ParseResponse(req, []string{requestID})
			if err != nil {
				var ire *saml.InvalidResponseError
				if errors.As(err, &ire) {
					err = ire.PrivateErr
				}
				t.Fatalf("SP rejected the response: %v", err)
			}
			if f.fields.Get("RelayState") != "relay-1" {
				t.Fatalf("RelayState = %q", f.fields.Get("RelayState"))
			}
			return a
		}
	}
	t.Fatalf("no form posting to the ACS (status %d):\n%s", p.status, p.body)
	return nil
}

func attr(a *saml.Assertion, name string) string {
	for _, st := range a.AttributeStatements {
		for _, at := range st.Attributes {
			if (at.Name == name || at.FriendlyName == name) && len(at.Values) > 0 {
				return at.Values[0].Value
			}
		}
	}
	return ""
}

// Requirement: SAML SPs log users in with SP-initiated SSO over the
// HTTP-Redirect binding; the signed assertion carries the user's identity.
func TestE2E_SAMLRedirectBinding(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	u := h.user("alice")
	sp := newSP(t, h)
	registerSP(t, h, sp)

	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		t.Fatal(err)
	}
	redirectURL, _ := req.Redirect("relay-1", sp)
	b := newBrowser(t, h.httpClient())
	p := passwordLogin(b, b.get(redirectURL.String()), "alice")
	a := acsPost(t, sp, p, req.ID)
	if a.Subject.NameID.Value != u.ID.String() || attr(a, "mail") != "alice@example.com" {
		t.Fatalf("NameID=%s mail=%s", a.Subject.NameID.Value, attr(a, "mail"))
	}
}

// Requirement: SP-initiated SSO also works over the HTTP-POST binding, and
// unknown SPs are rejected.
func TestE2E_SAMLPostBindingAndUnknownSP(t *testing.T) {
	h := newHarness(t, identity.Settings{})
	h.user("alice")
	sp := newSP(t, h)
	registerSP(t, h, sp)
	b := newBrowser(t, h.httpClient())
	passwordLogin(b, b.get(h.issuer()+"/account"), "alice") // existing IdP session

	req, _ := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPPostBinding), saml.HTTPPostBinding, saml.HTTPPostBinding)
	form := &page{url: mustURL(h.issuer()), forms: parseForms(mustURL(h.issuer()), string(req.Post("relay-1")))}
	acsPost(t, sp, b.submit(form, "/saml/sso", nil), req.ID)

	stranger := newSP(t, h)
	stranger.EntityID = "https://stranger.example/metadata"
	req, _ = stranger.MakeAuthenticationRequest(stranger.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	u, _ := req.Redirect("relay-1", stranger)
	if p := b.get(u.String()); p.status < 400 {
		t.Fatalf("unknown SP accepted: status %d", p.status)
	}
	_ = context.Background()
}

func mustURL(s string) *url.URL {
	u, _ := url.Parse(s)
	return u
}
