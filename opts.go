package gstorage

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/knq/jwt/gserviceaccount"
	"github.com/knq/pemutil"
)

// Option represents a URLSigner option.
type Option func(*URLSigner) error

// GoogleServiceAccountCredentialsJSON is an option that loads Google Service
// Account credentials from a JSON encoded buf.
//
// Google Service Account credentials can be downloaded from the Google Cloud
// console: https://console.cloud.google.com/iam-admin/serviceaccounts/
func GoogleServiceAccountCredentialsJSON(buf []byte) Option {
	return func(u *URLSigner) error {
		var err error

		// load service account credentials
		gsa, err := gserviceaccount.FromJSON(buf)
		if err != nil {
			return err
		}

		// simple check
		if gsa.ClientEmail == "" || gsa.PrivateKey == "" {
			return errors.New("google service accoount credentials missing client_email or private_key")
		}

		// load key
		store := pemutil.Store{}
		err = pemutil.PEM{[]byte(gsa.PrivateKey)}.Load(store)
		if err != nil {
			return err
		}

		// grab privKey
		var ok bool
		u.PrivateKey, ok = store[pemutil.RSAPrivateKey].(*rsa.PrivateKey)
		if !ok {
			return errors.New("google service account credentials has an invalid private_key")
		}

		u.ClientEmail = gsa.ClientEmail

		return nil
	}
}

// GoogleServiceAccountCredentialsFile is an option that loads Google Service
// Account credentials for from the specified file.
//
// Google Service Account credentials can be downloaded from the Google Cloud
// console: https://console.cloud.google.com/iam-admin/serviceaccounts/
func GoogleServiceAccountCredentialsFile(path string) Option {
	return func(u *URLSigner) error {
		buf, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("could not read google service account credentials file: %v", err)
		}

		return GoogleServiceAccountCredentialsJSON(buf)(u)
	}
}
