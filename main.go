// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command mkcert is a simple zero-config tool to make selfcert certificates.
package main

import (
	"crypto"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"

	"golang.org/x/net/idna"
)

const shortUsage = `Usage of mkcert:

	$ mkcert -version
	Show version number and details.

	$ mkcert -install [-option n, -option n+1, ...]
	Install the local CA in the system trust store.

	$ mkcert example.org
	Generate "example.org.pem" and "example.org-key.pem".

	$ mkcert example.com myapp.dev localhost 127.0.0.1 ::1
	Generate "example.com+4.pem" and "example.com+4-key.pem".

	$ mkcert "*.example.it"
	Generate "_wildcard.example.it.pem" and "_wildcard.example.it-key.pem".

	$ mkcert -uninstall
	Uninstall the local CA (but do not delete it).

`

const advancedUsage = `Advanced options:

	-cert-file FILE, -key-file FILE, -p12-file FILE
		Customize the output paths.

	-client
		Generate a certificate for client authentication.

	-ecdsa
		Generate a certificate with an ECDSA key.

	-ed25519
		Generate a certificate with an Ed25519 key.

	-pkcs12
		Generate a ".p12" PKCS #12 file, also know as a ".pfx" file,
		containing certificate and key for legacy applications.

	-csr CSR
		Generate a certificate based on the supplied CSR. Conflicts with
		all other flags and arguments except -install and -cert-file.

	-o ORGANIZATION
		The value for section Organization ('O') in the certificate
		subject.

	-ou ORGANIZATIONAL_UNIT
		The value for section Organizational Unit ('OU') in the
		certificate subject.

	-country COUNTRY
		The value for section Country ('C') in the certificate subject.

	-cn COMMONNAME
		The value for section CommonName ('CN') in the
		certificate subject.

	-password PASSWORD
		The password used to encrypt the private key-file. By
		default the password is empty and therefore the private
		key is not encrypted. Java keystores typically expect
        the password 'changeit' by default.

	-CAROOT
		Print the CA certificate and key storage location.

	$CAROOT (environment variable)
		Set the CA certificate and key storage location.
		(This allows maintaining multiple local CAs in parallel.)

	$TRUST_STORES (environment variable)
		A comma-separated list of trust stores to install the
		local root CA into. Options are: "system", "java" and
		"nss" (includes Firefox). Autodetected by default.

	-NOCA
		Do not create and do not use a ROOTCA-certificate for
		certificate-creation.

	Examples:
	RSA 4096 SHA512 WITHOUT CA ...........:
	mkcert -pkcs12 -password "password" -o "my_org" -ou "my_ou" \
	-country "de" -cn "vname.nname.@my_ou.my_org.de" \
	-NOCA "vname.nname.@my_ou.my_org.de"

	RSA 4096 SHA512 WITH CA ..............:
	mkcert -pkcs12 -password "password" -o "my_org" -ou "my_ou" \
	-country "de" -cn "vname.nname.@my_ou.my_org.de" \
	"vname.nname.@my_ou.my_org.de"

	ECDSA (ECDH_P256) SHA256 WITHOUT CA...:
	mkcert -pkcs12 -password "password" -o "my_org" -ou "my_ou" \
	-country "de" -cn "vname.nname.@my_ou.my_org.de" -NOCA \
	"vname.nname.@my_ou.my_org.de"

	ECDSA (ECDH_P256) SHA256 WITH CA......:
	mkcert -pkcs12 -password "password" -o "my_org" -ou "my_ou" \
	-country "de" -cn "vname.nname.@my_ou.my_org.de" \
	"vname.nname.@my_ou.my_org.de"
`

// Version can be set at link time to override debug.BuildInfo.Main.Version,
// which is "(devel)" when building from within the module. See
// golang.org/issue/29814 and golang.org/issue/29228.
var Version string = `
mkcert V1.4.7.0 (Reloaded Version by Veit Berwig).

Based on mkcert v1.4.3 Copyright 2018 by ...
The mkcert Authors. Original version copyright by
Filippo Valsorda, software engineer on the Go
security team at Google. Changes in this version:

- Larger key-size for RSA (4096 bit)
- Cert generation without CA-certificate (single self-signed)
- RSA suite with hash SHA-512
- ECDSA suite with curve P-256 and SHA-256
  (This implementation uses constant-time algorithms)
- AES256 as cipher for pkcs12/pfx-store
- Organisation and Common-Name support
- Custom Organisational-Unit support
- Custom Country support
- SubjectKeyId in both certs added
- AuthorityKeyId in both certs added
- Support for Bernstein Curve25519 in cert
- Secure operation, when provided without args (no action)
- CA lifetime set to 4 years
- CA Cert- and Key-filename indexed with local username (OS)
- Additional creation of DER-encoded .crt-certfiles (pub)

RSA keys will use....: RSA 4096 bit with SHA512
ECDSA keys will use..: NIST-P256 (named) with SHA256
Ed25519 keys will use: PureEd25519 with SHA512`

func main() {
	log.SetFlags(0)
	var (
		installFlag   = flag.Bool("install", false, "")
		uninstallFlag = flag.Bool("uninstall", false, "")
		pkcs12Flag    = flag.Bool("pkcs12", false, "")
		ecdsaFlag     = flag.Bool("ecdsa", false, "")
		ed25519Flag   = flag.Bool("ed25519", false, "")
		clientFlag    = flag.Bool("client", false, "")
		helpFlag      = flag.Bool("help", false, "")
		carootFlag    = flag.Bool("CAROOT", false, "")
		csrFlag       = flag.String("csr", "", "")
		certFileFlag  = flag.String("cert-file", "", "")
		keyFileFlag   = flag.String("key-file", "", "")
		p12FileFlag   = flag.String("p12-file", "", "")
		versionFlag   = flag.Bool("version", false, "")
		oFlag         = flag.String("o", "MKCERT SELFCERT", "")
		ouFlag        = flag.String("ou", "MKCERT SELFCERT", "")
		countryFlag   = flag.String("country", "DE", "")
		cnFlag        = flag.String("cn", "MKCERT SELFCERT", "")
		passwordFlag  = flag.String("password", "", "")
		nocaFlag      = flag.Bool("NOCA", false, "")
	)

	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), shortUsage)
		fmt.Fprintln(flag.CommandLine.Output(), `For more options, run "mkcert -help".`)
	}
	flag.Parse()
	if *helpFlag {
		fmt.Print(shortUsage)
		fmt.Print(advancedUsage)
		return
	}
	if *versionFlag {
		if Version != "" {
			fmt.Println(Version)
			return
		}
		if buildInfo, ok := debug.ReadBuildInfo(); ok {
			fmt.Println(buildInfo.Main.Version)
			return
		}
		fmt.Println("(unknown)")
		return
	}
	if *carootFlag {
		if *installFlag || *uninstallFlag {
			log.Fatalln("ERROR: you can't set -[un]install and -CAROOT at the same time")
		}
		fmt.Println(getCAROOT())
		return
	}
	if *installFlag && *uninstallFlag {
		log.Fatalln("ERROR: you can't set -install and -uninstall at the same time")
	}
	// Prevent using "pkcs12" WITH "EDDSA", because "pkcs12"  doesn't support Curve25519
	if *pkcs12Flag && *ed25519Flag {
		log.Fatalln("ERROR: pkcs12-container does not support curve25519")
	}
	// Prevent using "ECDSA" AND "EDDSA" at the same time
	if *ecdsaFlag && *ed25519Flag {
		log.Fatalln("ERROR: you can't set -ecdsa and -ed25519 at the same time")
	}
	if *csrFlag != "" && (*pkcs12Flag || *ecdsaFlag || *ed25519Flag || *clientFlag || *nocaFlag) {
		log.Fatalln("ERROR: can only combine -csr with -install and -cert-file")
	}
	if *csrFlag != "" && flag.NArg() != 0 {
		log.Fatalln("ERROR: can't specify extra arguments when using -csr")
	}
	if *nocaFlag {
		if *installFlag || *uninstallFlag {
			log.Fatalln("ERROR: you can't set -NOCA and -[un]install at the same time")
		}
	}

	// Show version without action, when no args are provided.
	// ========================================================
	// This is for proper secure operation without action, when
	// user clicks or run the binary without args ...
	ArgValues := flag.Args()
	if len(ArgValues) == 0 {
			fmt.Println(Version)
			// fmt.Fprint(flag.CommandLine.Output(), shortUsage)
			fmt.Fprintln(flag.CommandLine.Output(), `For more options, run "mkcert -help".`)
			// return
			os.Exit(0)
	}
	// ========================================================

	// Create unique cert- / key-file, when current user is readable
	if user, err := user.Current(); err == nil {
		rootName = user.Name + "_CA.pem"
		rootNameDer = user.Name + "_CA.crt"
		rootKeyName = user.Name + "_CA-key.pem"
		// log.Printf(`Cert Root-Filename: "%s"`, rootName)
		// log.Printf(`Cert Root-Filename: "%s"`, rootNameDer)
		// log.Printf(`Cert Root-Keyname: "%s"`, rootKeyName)
	} else {
		rootName = "MKCERT_CA.pem"
		rootNameDer = "MKCERT_CA.crt"
		rootKeyName = "MKCERT_CA-key.pem"
		// log.Printf(`Cert Root-Filename: "%s"`, rootName)
		// log.Printf(`Cert Root-Filename: "%s"`, rootNameDer)
		// log.Printf(`Cert Root-Keyname: "%s"`, rootKeyName)
	}

	(&mkcert{
		installMode: *installFlag, uninstallMode: *uninstallFlag, csrPath: *csrFlag,
		noca: *nocaFlag, pkcs12: *pkcs12Flag, ecdsa: *ecdsaFlag, ed25519: *ed25519Flag,
		client: *clientFlag, certFile: *certFileFlag, keyFile: *keyFileFlag, p12File: *p12FileFlag,
		Organization: *oFlag, OrganizationUnit: *ouFlag, Country: *countryFlag, CommonName: *cnFlag,
		password: *passwordFlag,
	}).Run(flag.Args())
}

// const rootName = "MKCERT_CA.pem"
// const rootKeyName = "MKCERT_CA-key.pem"
var rootName = "MKCERT_CA.pem"
var rootNameDer = "MKCERT_CA.crt"
var rootKeyName = "MKCERT_CA-key.pem"

type mkcert struct {
	installMode, uninstallMode				bool
	pkcs12, ecdsa, ed25519, client			bool
	noca									bool
	keyFile, certFile, p12File, derFile		string
	csrPath									string

	CAROOT				string
	caCert				*x509.Certificate
	caKey				crypto.PrivateKey

	Organization		string
	OrganizationUnit	string
	Country				string
	CommonName			string

	password			string

	// unique cert- / key-file, when current user is readable
	rootName			string
	rootNameDer			string
	rootKeyName			string

	// The system cert pool is only loaded once. After installing the root, checks
	// will keep failing until the next execution. TODO: maybe execve?
	// https://github.com/golang/go/issues/24540 (thanks, myself)
	ignoreCheckFailure	bool
}

func (m *mkcert) Run(args []string) {
	// Using CA certificate for cert creation
	if !m.noca {
		m.CAROOT = getCAROOT()
		if m.CAROOT == "" {
			log.Fatalln("ERROR: failed to find the default CA location, set one as the CAROOT env var")
		}
		fatalIfErr(os.MkdirAll(m.CAROOT, 0755), "failed to create the CAROOT")
		m.loadCA()

		if m.installMode {
			m.install()
			if len(args) == 0 {
				return
			}
		} else if m.uninstallMode {
			m.uninstall()
			return
		} else {
			var warning bool
			if storeEnabled("system") && !m.checkPlatform() {
				warning = true
				log.Println("Note: the local CA is not installed in the system trust store.")
			}
			if storeEnabled("nss") && hasNSS && CertutilInstallHelp != "" && !m.checkNSS() {
				warning = true
				log.Printf("Note: the local CA is not installed in the %s trust store.", NSSBrowsers)
			}
			if storeEnabled("java") && hasJava && !m.checkJava() {
				warning = true
				log.Println("Note: the local CA is not installed in the Java trust store.")
			}
			if warning {
				log.Println("Run \"mkcert -install\" for certificates to be trusted automatically")
			}
		}

		if m.csrPath != "" {
			m.makeCertFromCSR()
			return
		}
	// Using selfsigned certificate
	} else {
		m.CAROOT = getCAROOT()
		if m.CAROOT == "" {
			log.Fatalln("ERROR: failed to find the default CA location, set one as the CAROOT env var")
		}
		fatalIfErr(os.MkdirAll(m.CAROOT, 0755), "failed to create the CAROOT")
	}

	if len(args) == 0 {
		flag.Usage()
		return
	}

	hostnameRegexp := regexp.MustCompile(`(?i)^(\*\.)?[0-9a-z_-]([0-9a-z._-]*[0-9a-z_-])?$`)
	for i, name := range args {
		if ip := net.ParseIP(name); ip != nil {
			continue
		}
		if email, err := mail.ParseAddress(name); err == nil && email.Address == name {
			continue
		}
		if uriName, err := url.Parse(name); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			continue
		}
		punycode, err := idna.ToASCII(name)
		if err != nil {
			log.Fatalf("ERROR: %q is not a valid hostname, IP, URL or email: %s", name, err)
		}
		args[i] = punycode
		if !hostnameRegexp.MatchString(punycode) {
			log.Fatalf("ERROR: %q is not a valid hostname, IP, URL or email", name)
		}
	}

	m.makeCert(args)
}

func getCAROOT() string {
	if env := os.Getenv("CAROOT"); env != "" {
		return env
	}

	var dir string
	switch {
	case runtime.GOOS == "windows":
		dir = os.Getenv("LocalAppData")
	case os.Getenv("XDG_DATA_HOME") != "":
		dir = os.Getenv("XDG_DATA_HOME")
	case runtime.GOOS == "darwin":
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, "Library", "Application Support")
	default: // Unix
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, ".local", "share")
	}
	return filepath.Join(dir, "mkcert")
}

func (m *mkcert) install() {
	if storeEnabled("system") {
		if m.checkPlatform() {
			log.Print("The local CA is already installed in the system trust store!")
		} else {
			if m.installPlatform() {
				log.Print("The local CA is now installed in the system trust store!")
			}
			m.ignoreCheckFailure = true // TODO: replace with a check for a successful install
		}
	}
	if storeEnabled("nss") && hasNSS {
		if m.checkNSS() {
			log.Printf("The local CA is already installed in the %s trust store!", NSSBrowsers)
		} else {
			if hasCertutil && m.installNSS() {
				log.Printf("The local CA is now installed in the %s trust store (requires browser restart)!", NSSBrowsers)
			} else if CertutilInstallHelp == "" {
				log.Printf(`Note: %s support is not available on your platform.`, NSSBrowsers)
			} else if !hasCertutil {
				log.Printf(`Warning: "certutil" is not available, so the CA can't be automatically installed in %s!`, NSSBrowsers)
				log.Printf(`Install "certutil" with "%s" and re-run "mkcert -install"`, CertutilInstallHelp)
			}
		}
	}
	if storeEnabled("java") && hasJava {
		if m.checkJava() {
			log.Println("The local CA is already installed in Java's trust store!")
		} else {
			if hasKeytool {
				m.installJava()
				log.Println("The local CA is now installed in Java's trust store!")
			} else {
				log.Println(`Warning: "keytool" is not available, so the CA can't be automatically installed in Java's trust store!`)
			}
		}
	}
	log.Print("")
}

func (m *mkcert) uninstall() {
	if storeEnabled("nss") && hasNSS {
		if hasCertutil {
			m.uninstallNSS()
		} else if CertutilInstallHelp != "" {
			log.Print("")
			log.Printf(`Warning: "certutil" is not available, so the CA can't be automatically uninstalled from %s (if it was ever installed)!`, NSSBrowsers)
			log.Printf(`You can install "certutil" with "%s" and re-run "mkcert -uninstall"`, CertutilInstallHelp)
			log.Print("")
		}
	}
	if storeEnabled("java") && hasJava {
		if hasKeytool {
			m.uninstallJava()
		} else {
			log.Print("")
			log.Println(`Warning: "keytool" is not available, so the CA can't be automatically uninstalled from Java's trust store (if it was ever installed)!`)
			log.Print("")
		}
	}
	if storeEnabled("system") && m.uninstallPlatform() {
		log.Print("The local CA is now uninstalled from the system trust store(s)!")
		log.Print("")
	} else if storeEnabled("nss") && hasCertutil {
		log.Printf("The local CA is now uninstalled from the %s trust store(s)!", NSSBrowsers)
		log.Print("")
	}
}

func (m *mkcert) checkPlatform() bool {
	if m.ignoreCheckFailure {
		return true
	}

	_, err := m.caCert.Verify(x509.VerifyOptions{})
	return err == nil
}

func storeEnabled(name string) bool {
	stores := os.Getenv("TRUST_STORES")
	if stores == "" {
		return true
	}
	for _, store := range strings.Split(stores, ",") {
		if store == name {
			return true
		}
	}
	return false
}

func fatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s", msg, err)
	}
}

func fatalIfCmdErr(err error, cmd string, out []byte) {
	if err != nil {
		log.Fatalf("ERROR: failed to execute \"%s\": %s\n%s\n", cmd, err, out)
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func binaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

var sudoWarningOnce sync.Once

func commandWithSudo(cmd ...string) *exec.Cmd {
	if u, err := user.Current(); err == nil && u.Uid == "0" {
		return exec.Command(cmd[0], cmd[1:]...)
	}
	if !binaryExists("sudo") {
		sudoWarningOnce.Do(func() {
			log.Println(`Warning: "sudo" is not available, and mkcert is not running as root. The (un)install operation might fail.`)
		})
		return exec.Command(cmd[0], cmd[1:]...)
	}
	return exec.Command("sudo", append([]string{"--prompt=Sudo password:", "--"}, cmd...)...)
}
