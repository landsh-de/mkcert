// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// ##################################################################
// # Hardening-Changes by vitus in 20211224
// #
// # - Changed cipher for pkcs12 "PEMCipher3DES" to "PEMCipherAES256"
// # - Changed rsa key-length for ROOT-CA   3072 to 4096
// # - Changed rsa key-length for USER-CERT 2048 to 4096
// # - Changed hash-algorithm for RSA to SHA512
// # - Changed ECDSA-Curve to P-256 with hash-algorithm to SHA-256
// # - Added code for ECDSA-Curve P-521 with hash-algorithm SHA-512
// # - The p-256 and p-521 implementations in "Go" will use
// #   constant-time algorithms. They both were checked and
// #   implemented by "DJB" and "AGL" (i think) ...
// # - Added Bernstein's "Curve25519" as ed25519 to cert generation.
// #   Ed25519 is not supported by "zlint" ...
// # - Added -NOCA option in order to create selfsigned cert without
// #   CA-cert (handling is much easier for usage).
// ##################################################################
// smimeCapabilities NOT IMPLEMENTED, DUE TO SECURITY CONSIDERATIONS.
// https://datatracker.ietf.org/doc/html/rfc4262#section-4
// Also we connot gurantee that the hardened algorithms are used by
// the client, because all proposals are a "SHOULD"-implementation.
// This extension also MUST NOT be marked critical.
// https://datatracker.ietf.org/doc/html/rfc4262
// ==================================================================
// Definition:
// https://datatracker.ietf.org/doc/html/rfc8551#section-2.5.2
// https://datatracker.ietf.org/doc/html/rfc6664
// ==================================================================
// For decoding a cert, use asn1js and load "asn1js/index.html"
// in browser:
// https://github.com/lapo-luchini/asn1js/archive/refs/heads/trunk.zip
// ##################################################################

package main

import (
	"crypto"
	"crypto/ecdsa"
    	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

var userAndHostname string

func init() {
	u, err := user.Current()
	if err == nil {
		userAndHostname = u.Username + "@"
	}
	if h, err := os.Hostname(); err == nil {
		userAndHostname += h
	}
	if err == nil && u.Name != "" && u.Name != u.Username {
		userAndHostname += " (" + u.Name + ")"
	}
}

// Use public key from implementation, when ed25519 is flagged.
// From: https://github.com/golang/go/blob/master/src/crypto/tls/generate_cert.go#L41
func (m *mkcert) publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func (m *mkcert) GetSignatureAlgorithm() x509.SignatureAlgorithm {
	// https://pkg.go.dev/crypto/x509#SignatureAlgorithm
	if m.ecdsa {
        	// Because of "ecdsa signature encoding correctness"-check in "zlint",
        	// https://github.com/zmap/zlint/blob/master/v3/lints/mozilla/lint_mp_ecdsa_signature_encoding_correct.go#L35
        	// ... if the signing key is P-256, the signature MUST use ECDSA with SHA-256
        	// and if the signing key is P-521, the signature MUST use ECDSA with SHA-512
        	// P-384 will NOT be used here, because the implementation does not use
        	// constant-time algorithms. P-256 (SHA-256) and P-521 (SHA-512) are ok:
        	// https://cs.opensource.google/go/go/+/refs/tags/go1.17.2:src/crypto/elliptic/elliptic.go;l=470
        	// ===============
        	// elliptic.P521()
        	// ===============
	    	// log.Printf("SignatureAlgorithm-Option: \"%s\"\n\n", "ECDSAWithSHA512")
		// SigAlg := x509.ECDSAWithSHA512
		// ===============
		// elliptic.P256()
		// ===============
	    	log.Printf("SignatureAlgorithm-Option: \"%s\"\n\n", "ECDSAWithSHA256")
		SigAlg := x509.ECDSAWithSHA256
		return SigAlg
    } else if m.ed25519 {
		log.Printf("SignatureAlgorithm-Option: \"%s\"\n\n", "PureEd25519")
		SigAlg := x509.PureEd25519
		return SigAlg
	} else {
		log.Printf("SignatureAlgorithm-Option: \"%s\"\n\n", "SHA512WithRSA")
		SigAlg := x509.SHA512WithRSA
		return SigAlg
	}
}

func (m *mkcert) makeCert(hosts []string) {

    if !m.noca {
        if m.caKey == nil {
            log.Fatalln("ERROR: can't create new certificates because the CA key (MKCERT_CA-key.pem) is missing")
        }
    }

	priv, err := m.generateKey(false)
	fatalIfErr(err, "failed to generate certificate key")

    // Use other way to retrieve public-key, when using Curve25519, because
    // we only retrieve the private-key from generateKey() here and may use
    // the ed25519-way to get public-key from priv ...
    // pub := priv.(crypto.Signer).Public()
    pub := m.publicKey(priv)

	spkiASN1, err := x509.MarshalPKIXPublicKey(pub)
	fatalIfErr(err, "failed to encode public key")

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	fatalIfErr(err, "failed to decode public key")

	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)

	// Certificates last for 2 years and 3 months, which is always less than
	// 825 days, the limit that macOS/iOS apply to all certificates,
	// including custom roots. See https://support.apple.com/en-us/HT210176.
	expiration := time.Now().AddDate(2, 3, 0)

	tpl := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		SignatureAlgorithm: m.GetSignatureAlgorithm(),
		Subject: pkix.Name{
		Organization:       []string{m.Organization},
		// OrganizationalUnit: []string{userAndHostname},
		OrganizationalUnit: []string{m.OrganizationUnit},
            	Country:            []string{m.Country},
		// CommonName:         m.CommonName + " certificate",
		CommonName:         m.CommonName,
		},
		SubjectKeyId:   skid[:],
        	AuthorityKeyId: skid[:],
		NotBefore: time.Now(), NotAfter: expiration,
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(h); err == nil && email.Address == h {
			tpl.EmailAddresses = append(tpl.EmailAddresses, h)
		} else if uriName, err := url.Parse(h); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			tpl.URIs = append(tpl.URIs, uriName)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}

	if m.client {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if len(tpl.IPAddresses) > 0 || len(tpl.DNSNames) > 0 || len(tpl.URIs) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if len(tpl.EmailAddresses) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
	}

	// IIS (the main target of PKCS #12 files), only shows the deprecated
	// Common Name in the UI. See issue #115.
	if m.pkcs12 {
        // Do that only, when CommonName was not provided in commandline
        // or has default value; otherwise we will use the Args[]-stuff here ...
        if m.CommonName == "" || m.CommonName == "MKCERT SELFCERT" {
            tpl.Subject.CommonName = hosts[0]
        }
	}

    // https://pkg.go.dev/crypto/x509#CreateCertificate
    // Predefinition necessary, because of local scope of if { var := func() } - statements ...
    var cert []byte

    if !m.noca {
        // Use CA-cert for parent (3rd param of x509.CreateCertificate()):
        cert, err = x509.CreateCertificate(rand.Reader, tpl, m.caCert, pub, m.caKey)
        fatalIfErr(err, "Failed to generate certificate ...\nThe \"Signature-Algorithm\" does not match the private key-type of the \"CA\",\nthat was previously generated before this request. To use the same\nalgorithm of the CA, you may change the option from \"-ecdsa\" or \"-ed25519\"\nto leave it blank for \"RSA\" or use \"-ecdsa\" to use \"Elliptic-Curve DSA\" or\n\"-ed25519\" to use \"Pure Ed25519 DSA\", when CA-key was generated with that Algo.\nError")
    } else {
        // If parent (3rd param of x509.CreateCertificate()) is equal to
        // template then the certificate is self-signed.
        // Details:
        // https://pkg.go.dev/crypto/x509#CreateCertificate
        // https://cs.opensource.google/go/go/+/refs/tags/go1.17.5:src/crypto/x509/x509.go;l=1452
        // Use own template for parent (3rd param of x509.CreateCertificate()):
        cert, err = x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
        fatalIfErr(err, "Failed to generate certificate ...\nThe \"Signature-Algorithm\" does not match the private key-type of this request.\nTo use the same\nalgorithm, you may change the option from \"-ecdsa\" or \"-ed25519\"\nto leave it blank for \"RSA\" or use \"-ecdsa\" to use \"Elliptic-Curve DSA\" or\n\"-ed25519\" to use \"Pure Ed25519 DSA\", when key was generated with that Algo.\nError")
    }

    certFile, keyFile, p12File := m.fileNames(hosts)

    if !m.pkcs12 {
        certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
        privDER, err := x509.MarshalPKCS8PrivateKey(priv)
        fatalIfErr(err, "failed to encode certificate key")
        var privPEMBlock *pem.Block
        if m.password == "" {
            privPEMBlock = &pem.Block{Type: "PRIVATE KEY", Bytes: privDER}
        } else {
            // TODO: check which cipher is most used/compatible.
            //       Now chosen very conservative choice of 3DES.
            // TODO: can we fix the deprecation warning:
            //       documentation does not specify an alternative.
            // AS OF 20211006: CHANGED 3DES to AES256 by vitus ... but ...
            // PEMBlock encryption is deprecated:
            // ################################################################################ !!
            // !! https://github.com/golang/go/commit/57af9745bfad2c20ed6842878e373d6c5b79285a  !!
            // !! still using old aes-cbc block-mode in rfc of pkcs12                           !!
            // !! See: https://www.rfc-editor.org/rfc/rfc7292.html#appendix-C                   !!
            // By https://github.com/SSLMate/go-pkcs12/blob/master/safebags.go#L66, we got an   !!
            //    encoded "oidPBEWithSHAAnd3KeyTripleDESCBC" and ...                            !!
            // by https://github.com/SSLMate/go-pkcs12/blob/master/pkcs12.go#L690, we got an    !!
            //    encoded "oidPBEWithSHAAnd40BitRC2CBC"                                         !!
            // you may analyze this stuff with dumpasn1 (gcc -o dumpasn1.exe dumpasn1.c):       !!
            // https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.c                                !!
            // https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg                              !!
            // ################################################################################ !!
            privPEMBlock, err = x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", privDER,
                []byte(m.password), x509.PEMCipherAES256)
            fatalIfErr(err, "failed to encrypt certificate key")
        }
        privPEM := pem.EncodeToMemory(privPEMBlock)

        if certFile == keyFile {
            err = ioutil.WriteFile(keyFile, append(certPEM, privPEM...), 0600)
            fatalIfErr(err, "failed to save certificate and key")
        } else {
            err = ioutil.WriteFile(certFile, certPEM, 0644)
            fatalIfErr(err, "failed to save certificate")
            err = ioutil.WriteFile(keyFile, privPEM, 0600)
            fatalIfErr(err, "failed to save certificate key")
        }
    } else {
        domainCert, _ := x509.ParseCertificate(cert)
        // https://pkg.go.dev/software.sslmate.com/src/go-pkcs12#Encode
        // https://github.com/SSLMate/go-pkcs12/blob/master/pkcs12.go#L441
        // Info: Windows started supporting .pfx cert exports using PBES2 +
        // PBKDF2 + AES256 encryption and SHA256 PRF. Note that PBES2 + PBKDF2
        // is only used in password privacy mode:
        // https://github.com/SSLMate/go-pkcs12/commit/5c6b0d1b55f5c30f36f63fa88f127a08d13a856d
        var pfxData []byte

        if !m.noca {
            // Use CA-cert for pkcs12 encoding:
            pfxData, err = pkcs12.Encode(rand.Reader, priv, domainCert, []*x509.Certificate{m.caCert}, m.password)
        } else {
            // Use my selfsingned cert for pkcs12 encoding:
            // pfxData, err = pkcs12.Encode(rand.Reader, priv, domainCert, nil, m.password)
            pfxData, err = pkcs12.Encode(rand.Reader, priv, domainCert, []*x509.Certificate{domainCert}, m.password)

        }

        fatalIfErr(err, "failed to generate PKCS#12")
        err = ioutil.WriteFile(p12File, pfxData, 0644)
        fatalIfErr(err, "failed to save PKCS#12")
    }

    m.printHosts(hosts)

    if !m.pkcs12 {
        if certFile == keyFile {
            log.Printf("\nThe certificate and key are at \"%s\"\n", certFile)
        } else {
            log.Printf("\nThe certificate is at \"%s\"\nand the key at \"%s\"\n", certFile, keyFile)
        }
    } else {
        log.Printf("\nThe PKCS#12 bundle is at \"%s\"\n", p12File)
        log.Printf("\nThe legacy PKCS#12 encryption password is the often hardcoded default \"changeit\"\n")
    }

    log.Printf("It will expire on %s\n", expiration.Format("2 January 2006"))
}

func (m *mkcert) printHosts(hosts []string) {
	secondLvlWildcardRegexp := regexp.MustCompile(`(?i)^\*\.[0-9a-z_-]+$`)
	log.Printf("\nCreated a new certificate valid for the following names")
	for _, h := range hosts {
		log.Printf(" - %q", h)
		if secondLvlWildcardRegexp.MatchString(h) {
			log.Printf("\nWarning: many browsers don't support second-level wildcards like %q", h)
		}
	}

	for _, h := range hosts {
		if strings.HasPrefix(h, "*.") {
			log.Printf("\nReminder: X.509 wildcards only go one level deep, so this won't match a.b.%s", h[2:])
			break
		}
	}
}

func (m *mkcert) generateKey(rootCA bool) (crypto.PrivateKey, error) {
	if m.ecdsa {
        // ===============
        // elliptic.P521()
        // ===============
		// return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
        // ===============
        // elliptic.P256()
        // ===============
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
    if m.ed25519 {
        // "ed25519.GenerateKey"
        // The underlying ED25519 GenerateKey method doesn't has the
        // same interface as RSA or ECDSA. Both of those return pointers
        // to private keys, where ED25519 returns public key, private key,
        // error, not using pointers. I.e. see:
        // https://github.com/hashicorp/terraform-provider-tls/pull/85#issuecomment-811269511
        // https://github.com/hashicorp/terraform-provider-tls/commit/c0a5747172c8e548908e01dfb320213c5084d457
        // https://golang.hotexamples.com/de/search/ed25519.GenerateKey
        // https://github.com/RoPe93/repbin/blob/master/cmd/repserver/handlers/server.go (line:182)
        // ==================================================================
        // EDpublicKey, EDprivateKey, err := ed25519.GenerateKey(rand.Reader)
        // _ = EDpublicKey // do not use EDpublicKey
        _, EDprivateKey, err := ed25519.GenerateKey(rand.Reader)
        return EDprivateKey, err
    }
	if rootCA {
        if m.ecdsa {
            // ===============
            // elliptic.P521()
            // ===============
            // return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
            // ===============
            // elliptic.P256()
            // ===============
            return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
        }
        if m.ed25519 {
            // "ed25519.GenerateKey"
            // The underlying ED25519 GenerateKey method doesn't has the
            // same interface as RSA or ECDSA. Both of those return pointers
            // to private keys, where ED25519 returns public key, private key,
            // error, not using pointers. I.e. see:
            // https://github.com/hashicorp/terraform-provider-tls/pull/85#issuecomment-811269511
            // https://github.com/hashicorp/terraform-provider-tls/commit/c0a5747172c8e548908e01dfb320213c5084d457
            // https://golang.hotexamples.com/de/search/ed25519.GenerateKey
            // https://github.com/RoPe93/repbin/blob/master/cmd/repserver/handlers/server.go (line:182)
            // ==================================================================
            // EDpublicKey, EDprivateKey, err := ed25519.GenerateKey(rand.Reader)
            // _ = EDpublicKey // do not use EDpublicKey
            _, EDprivateKey, err := ed25519.GenerateKey(rand.Reader)
        return EDprivateKey, err
        }
		return rsa.GenerateKey(rand.Reader, 4096)
	}
	return rsa.GenerateKey(rand.Reader, 4096)
}

func (m *mkcert) fileNames(hosts []string) (certFile, keyFile, p12File string) {
	defaultName := strings.Replace(hosts[0], ":", "_", -1)
	defaultName = strings.Replace(defaultName, "*", "_wildcard", -1)
	if len(hosts) > 1 {
		defaultName += "+" + strconv.Itoa(len(hosts)-1)
	}
	if m.client {
		defaultName += "-client"
	}

	certFile = "./" + defaultName + ".pem"
	if m.certFile != "" {
		certFile = m.certFile
	}
	keyFile = "./" + defaultName + "-key.pem"
	if m.keyFile != "" {
		keyFile = m.keyFile
	}
	p12File = "./" + defaultName + ".p12"
	if m.p12File != "" {
		p12File = m.p12File
	}

	return
}

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	fatalIfErr(err, "failed to generate serial number")
	return serialNumber
}

func (m *mkcert) makeCertFromCSR() {
	if m.caKey == nil {
		log.Fatalln("ERROR: can't create new certificates because the CA key (MKCERT_CA-key.pem) is missing")
	}

	csrPEMBytes, err := ioutil.ReadFile(m.csrPath)
	fatalIfErr(err, "failed to read the CSR")
	csrPEM, _ := pem.Decode(csrPEMBytes)
	if csrPEM == nil {
		log.Fatalln("ERROR: failed to read the CSR: unexpected content")
	}
	if csrPEM.Type != "CERTIFICATE REQUEST" &&
		csrPEM.Type != "NEW CERTIFICATE REQUEST" {
		log.Fatalln("ERROR: failed to read the CSR: expected CERTIFICATE REQUEST, got " + csrPEM.Type)
	}
	csr, err := x509.ParseCertificateRequest(csrPEM.Bytes)
	fatalIfErr(err, "failed to parse the CSR")
	fatalIfErr(csr.CheckSignature(), "invalid CSR signature")

	expiration := time.Now().AddDate(2, 3, 0)
	tpl := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		SignatureAlgorithm: m.GetSignatureAlgorithm(),
		Subject: csr.Subject,
		ExtraExtensions: csr.Extensions, // includes requested SANs, KUs and EKUs

		NotBefore: time.Now(), NotAfter: expiration,

		// If the CSR does not request a SAN extension, fix it up for them as
		// the Common Name field does not work in modern browsers. Otherwise,
		// this will get overridden.
		DNSNames: []string{csr.Subject.CommonName},

		// Likewise, if the CSR does not set KUs and EKUs, fix it up as Apple
		// platforms require serverAuth for TLS.
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if m.client {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if len(csr.EmailAddresses) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, m.caCert, csr.PublicKey, m.caKey)
	fatalIfErr(err, "Failed to generate certificate ...\nThe \"SignatureAlgorithm\" does not match the private key-type of the \"CA\",\nthat was previously generated before this request ... To use the same\nalgorithm, you may change the option from \"-ecdsa\" to leave it blank for\n\"RSA\" or use \"-ecdsa\" to use \"Elliptic-Curve DSA\" ...\nError")

	var hosts []string
	hosts = append(hosts, csr.DNSNames...)
	hosts = append(hosts, csr.EmailAddresses...)
	for _, ip := range csr.IPAddresses {
		hosts = append(hosts, ip.String())
	}
	for _, uri := range csr.URIs {
		hosts = append(hosts, uri.String())
	}
	certFile, _, _ := m.fileNames(hosts)

	err = ioutil.WriteFile(certFile, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
	fatalIfErr(err, "failed to save certificate")

	m.printHosts(hosts)

	log.Printf("\nThe certificate is at \"%s\"\n", certFile)

	log.Printf("It will expire on %s\n", expiration.Format("2 January 2006"))
}

// loadCA will load or create the CA at CAROOT.
func (m *mkcert) loadCA() {
	if !pathExists(filepath.Join(m.CAROOT, rootName)) {
		m.newCA()
	}

	certPEMBlock, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootName))
	fatalIfErr(err, "failed to read the CA certificate")
	certDERBlock, _ := pem.Decode(certPEMBlock)
	if certDERBlock == nil || certDERBlock.Type != "CERTIFICATE" {
		log.Fatalln("ERROR: failed to read the CA certificate: unexpected content")
	}
	m.caCert, err = x509.ParseCertificate(certDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the CA certificate")

	if !pathExists(filepath.Join(m.CAROOT, rootKeyName)) {
		return // keyless mode, where only -install works
	}

	keyPEMBlock, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootKeyName))
	fatalIfErr(err, "failed to read the CA key")
	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	if keyDERBlock == nil || keyDERBlock.Type != "PRIVATE KEY" {
		log.Fatalln("ERROR: failed to read the CA key: unexpected content")
	}
	m.caKey, err = x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the CA key")
}

func (m *mkcert) newCA() {
	priv, err := m.generateKey(true)
	fatalIfErr(err, "failed to generate the CA key")

    // Use other way to retrieve public-key, when using Curve25519, because
    // we only retrieve the private-key from generateKey() here and may use
    // the ed25519-way to get public-key from priv ...
    // pub := priv.(crypto.Signer).Public()
    pub := m.publicKey(priv)

	spkiASN1, err := x509.MarshalPKIXPublicKey(pub)
	fatalIfErr(err, "failed to encode public key")

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	fatalIfErr(err, "failed to decode public key")

	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)

	tpl := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		SignatureAlgorithm: m.GetSignatureAlgorithm(),
		Subject: pkix.Name{
			Organization:       []string{m.Organization},
		//  OrganizationalUnit: []string{userAndHostname},
			OrganizationalUnit: []string{m.OrganizationUnit},
            Country:            []string{m.Country},

			// The CommonName is required by iOS to show the certificate in the
			// "Certificate Trust Settings" menu.
			// https://github.com/FiloSottile/mkcert/issues/47
		//  CommonName: m.CommonName + " CA",
			CommonName: m.CommonName,

		},
		SubjectKeyId:   skid[:],
        AuthorityKeyId: skid[:],

		NotAfter:  time.Now().AddDate(10, 0, 0),
		NotBefore: time.Now(),

		KeyUsage: x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	fatalIfErr(err, "failed to generate CA certificate")

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	fatalIfErr(err, "failed to encode CA key")
	err = ioutil.WriteFile(filepath.Join(m.CAROOT, rootKeyName), pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0400)
	fatalIfErr(err, "failed to save CA key")

	err = ioutil.WriteFile(filepath.Join(m.CAROOT, rootName), pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
	fatalIfErr(err, "failed to save CA key")

	log.Printf("Created a new local CA ...\n")
}

func (m *mkcert) caUniqueName() string {
	// return m.CommonName + " CA " + m.caCert.SerialNumber.String()
	return m.CommonName + " " + m.caCert.SerialNumber.String()
}
