package gstorage

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	b64 "encoding/base64"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the base Google Storage URL.
	DefaultBaseURL = "https://storage.googleapis.com"

	// DefaultExpiration is the default expiration for signed URLs.
	DefaultExpiration = 1 * time.Hour
)

// SigningParams are the signing params for generating a signed URL.
type SigningParams struct {
	// BaseURL is the URL to use for building the URL. If not supplied, then
	// DefaultBaseURL will be used instead.
	BaseURL string

	// Method is the HTTP method (GET, PUT, ...).
	Method string

	// Hash is the md5 hash of the file content for an upload.
	Hash string

	// ContentType is the content type of the uploaded file.
	ContentType string

	// Expiration is the expiration time of a generated signature.
	Expiration time.Time

	// Headers are the extra headers.
	Headers map[string]string

	// Bucket is the storage bucket.
	Bucket string

	// Object is the object path.
	Object string
}

// HeaderString sorts the headers in order, returning an ordered, usable string
// for use with signing.
func (p SigningParams) HeaderString() string {
	h := make([]string, len(p.Headers))
	headers := make(map[string]string)
	var i int
	for k, v := range p.Headers {
		k = strings.TrimSpace(strings.ToLower(k))
		if k != "x-goog-encryption-key" && k != "x-goog-encryption-key-sha256" {
			headers[k] = v
			h[i] = k
		}
		i++
	}
	if len(h) != 0 {
		sort.Slice(h, func(i, j int) bool {
			return strings.Compare(h[i], h[j]) < 0
		})
		for i, k := range h {
			h[i] += ":" + strings.TrimSpace(headers[k])
		}
		return strings.Join(h, "\n") + "\n"
	}
	return ""
}

// ObjectPath returns the canonical path.
func (p SigningParams) ObjectPath() string {
	return "/" + strings.Trim(p.Bucket, "/") + "/" + strings.TrimPrefix(p.Object, "/")
}

// String satisfies stringer returning the formatted string suitable for use
// with the URLSigner.
func (p SigningParams) String() string {
	return p.Method + "\n" +
		p.Hash + "\n" +
		p.ContentType + "\n" +
		strconv.FormatInt(p.Expiration.Unix(), 10) + "\n" +
		p.HeaderString() +
		p.ObjectPath()
}

// URLSigner provides a type that can generate signed URLs for use with Google
// Cloud Storage.
type URLSigner struct {
	PrivateKey  *rsa.PrivateKey
	ClientEmail string
}

// NewURLSigner creates a new URLSigner
func NewURLSigner(opts ...Option) (*URLSigner, error) {
	u := &URLSigner{}
	// apply opts
	for _, o := range opts {
		if err := o(u); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// SigningParams signs using the URLSigner.
func (u *URLSigner) SigningParams(p *SigningParams) (string, error) {
	// hash
	h := crypto.SHA256.New()
	if _, err := h.Write([]byte(p.String())); err != nil {
		return "", err
	}
	// sign
	sig, err := rsa.SignPKCS1v15(rand.Reader, u.PrivateKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		return "", err
	}
	// base64 encode
	return b64.StdEncoding.EncodeToString(sig), nil
}

// Sign creates the signature for the provided method, hash, contentType, bucket,
// and path accordingly.
func (u *URLSigner) Sign(method, hash, contentType, bucket, path string, headers map[string]string) (string, error) {
	return u.SigningParams(&SigningParams{
		Method:      method,
		Hash:        hash,
		ContentType: contentType,
		Headers:     headers,
		Bucket:      bucket,
		Object:      path,
	})
}

// Make makes a URL for the specified signing params.
func (u *URLSigner) Make(p *SigningParams, d time.Duration) (string, error) {
	// set default expiration if duration supplied
	if d != 0 {
		p.Expiration = time.Now().Add(d)
	}
	// create sig
	sig, err := u.SigningParams(p)
	if err != nil {
		return "", err
	}
	// create query
	v := url.Values{}
	v.Set("GoogleAccessId", u.ClientEmail)
	v.Set("Expires", strconv.FormatInt(p.Expiration.Unix(), 10))
	v.Set("Signature", sig)
	// base
	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return baseURL + p.ObjectPath() + "?" + v.Encode(), nil
}

// MakeURL creates a signed URL for the method.
func (u *URLSigner) MakeURL(method, bucket, path string, d time.Duration, headers map[string]string) (string, error) {
	return u.Make(&SigningParams{
		Method:  method,
		Headers: headers,
		Bucket:  bucket,
		Object:  path,
	}, d)
}

// DownloadPath generates a signed path for downloading an object.
func (u *URLSigner) DownloadPath(bucket, path string) (string, error) {
	return u.MakeURL("GET", bucket, path, DefaultExpiration, nil)
}

// UploadPath generates a signed path for uploading an object.
func (u *URLSigner) UploadPath(bucket, path string) (string, error) {
	return u.MakeURL("PUT", bucket, path, DefaultExpiration, nil)
}

// DeletePath generates a signed path for deleting an object.
func (u *URLSigner) DeletePath(bucket, path string) (string, error) {
	return u.MakeURL("DELETE", bucket, path, DefaultExpiration, nil)
}
