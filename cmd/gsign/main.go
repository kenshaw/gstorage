// Command gsign signs URLs using a
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/kenshaw/gstorage"
	"github.com/mattn/go-isatty"
)

func main() {
	flagCreds := flag.String("creds", "", "google service account credentials")
	flagMethod := flag.String("X", "GET", "http method [GET, PUT, DELETE]")
	flagBucket := flag.String("bucket", "my-test-bucket", "bucket")
	flagPath := flag.String("path", "/test/file.txt", "path")
	flagExp := flag.Duration("exp", 1*time.Hour, "expiration duration")
	flag.Parse()
	if err := run(*flagCreds, *flagMethod, *flagBucket, *flagPath, *flagExp); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(creds, method, bucket, path string, exp time.Duration) error {
	signer, err := gstorage.NewURLSigner(
		gstorage.GoogleServiceAccountCredentialsFile(creds),
	)
	if err != nil {
		return err
	}
	// generate url
	out, err := signer.MakeURL(method, bucket, path, exp, nil)
	if err != nil {
		return err
	}
	// make the output a little nicer
	if isatty.IsTerminal(os.Stdout.Fd()) {
		out += "\n"
	}
	_, err = fmt.Fprintf(os.Stdout, "%s", out)
	return err
}
