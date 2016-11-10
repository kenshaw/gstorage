package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/knq/gstorage"
)

var (
	flagCreds  = flag.String("creds", "", "google service account credentials")
	flagMethod = flag.String("X", "GET", "http method [GET, PUT, DELETE]")
	flagBucket = flag.String("bucket", "my-test-bucket", "bucket")
	flagPath   = flag.String("path", "/test/file.txt", "path")
	flagExp    = flag.Duration("exp", 1*time.Hour, "expiration duration")
)

func main() {
	var err error

	flag.Parse()

	// create signer
	signer, err := gstorage.NewURLSigner(
		gstorage.GoogleServiceAccountCredentialsFile(*flagCreds),
	)
	if err != nil {
		log.Fatal(err)
	}

	// generate url
	path, err := signer.MakeURL(*flagMethod, *flagBucket, *flagPath, *flagExp, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(os.Stdout, "%s\n", path)
}
