package gstorage

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	b64 "encoding/base64"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// BaseURL is the base Google Storage URL.
	BaseURL = "https://storage.googleapis.com"

	// DefaultExpiration is the default expiration for signed URLs.
	DefaultExpiration = 1 * time.Hour
)

// SignParams are the signing params for generating a signed URL.
type SignParams struct {
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
func (p SignParams) HeaderString() string {
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
		return strings.Join(h, "\n") + "\n"
	}

	return ""
}

// ObjectPath returns the canonical path.
func (p SignParams) ObjectPath() string {
	return "/" + strings.Trim(p.Bucket, "/") + "/" + strings.TrimPrefix(p.Object, "/")
}

// String satisifies stringer returning the formatted string suitable for use
// with the URLSigner.
func (p SignParams) String() string {
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
	var err error

	u := &URLSigner{}

	// apply opts
	for _, o := range opts {
		err = o(u)
		if err != nil {
			return nil, err
		}
	}

	return u, nil
}

// SignParams signs using the URLSigner.
func (u *URLSigner) SignParams(p *SignParams) (string, error) {
	var err error

	// hash
	h := crypto.SHA256.New()
	_, err = h.Write([]byte(p.String()))
	if err != nil {
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
	return u.SignParams(&SignParams{
		Method:      method,
		Hash:        hash,
		ContentType: contentType,
		Headers:     headers,
		Bucket:      bucket,
		Object:      path,
	})
}

// MakeURL creates a signed URL for the method.
func (u *URLSigner) MakeURL(method, bucket, path string, d time.Duration, headers map[string]string) (string, error) {
	// set default expiration if 0
	if d == 0 {
		d = DefaultExpiration
	}

	// create signing params
	exp := time.Now().Add(d)
	p := &SignParams{
		Method:     method,
		Expiration: exp,
		Headers:    headers,
		Bucket:     bucket,
		Object:     path,
	}

	// create sig
	sig, err := u.SignParams(p)
	if err != nil {
		return "", err
	}

	// create url values
	v := url.Values{}
	v.Set("GoogleAccessId", u.ClientEmail)
	v.Set("Expires", strconv.FormatInt(exp.Unix(), 10))
	v.Set("Signature", sig)

	return BaseURL + p.ObjectPath() + "?" + v.Encode(), nil
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
