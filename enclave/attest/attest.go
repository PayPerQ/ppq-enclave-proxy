// attest requests a hardware attestation document from the Nitro Security
// Module (NSM) and prints it base64-encoded on stdout.
//
// The enclave calls this to prove to a remote client "I am a genuine Nitro
// enclave running image PCR0=…, and here is the key material I commit to."
//
//   --nonce       hex, client-supplied freshness nonce (echoed into the doc)
//   --public-key  hex, material the enclave binds itself to (we pass the
//                 SHA-256 of the TLS cert's SubjectPublicKeyInfo, so the client
//                 can confirm the TLS endpoint IS this attested enclave)
//
// The document is a COSE_Sign1 structure signed by the AWS Nitro Attestation
// PKI; the client verifies that signature chain + the PCRs.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

func main() {
	nonceHex := flag.String("nonce", "", "hex-encoded nonce")
	pubHex := flag.String("public-key", "", "hex-encoded public key material to bind")
	userDataHex := flag.String("user-data", "", "hex-encoded user data to bind")
	flag.Parse()

	var nonce, pub, userData []byte
	var err error
	if *nonceHex != "" {
		if nonce, err = hex.DecodeString(*nonceHex); err != nil {
			fmt.Fprintln(os.Stderr, "bad nonce hex:", err)
			os.Exit(2)
		}
	}
	if *pubHex != "" {
		if pub, err = hex.DecodeString(*pubHex); err != nil {
			fmt.Fprintln(os.Stderr, "bad public-key hex:", err)
			os.Exit(2)
		}
	}
	if *userDataHex != "" {
		if userData, err = hex.DecodeString(*userDataHex); err != nil {
			fmt.Fprintln(os.Stderr, "bad user-data hex:", err)
			os.Exit(2)
		}
	}

	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		fmt.Fprintln(os.Stderr, "open nsm session:", err)
		os.Exit(1)
	}
	defer sess.Close()

	res, err := sess.Send(&request.Attestation{
		Nonce:     nonce,
		PublicKey: pub,
		UserData:  userData,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "attestation request:", err)
		os.Exit(1)
	}
	if res.Attestation == nil || res.Attestation.Document == nil {
		fmt.Fprintln(os.Stderr, "empty attestation document")
		os.Exit(1)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(res.Attestation.Document))
}
