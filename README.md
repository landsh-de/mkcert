# mkcert

This is a reloaded version of mkcert :-)<br><br>
This fork of mkcert is part of my preparatory work for integration of <a href="https://gpg4win.de" rel="nofollow">Gpg4Win / GnuPG VS-Desktop</a> in the context of "VS-NfD" (aka "de-vs") conformity and hardenings.

In order to comply with the technical requirements of the <a href="https://www.bsi.bund.de/DE/Themen/Oeffentliche-Verwaltung/Zulassung/Liste-zugelassener-Produkte/liste-zugelassener-produkte_node.html" rel="nofollow">BSI (Federal Office for Information Security)</a> for X.509-certificates, i added some hardenings here. I also added "ed25519" for testing.<br>

### Some informations to the Brainpool-Curves (designed and authorized by the BSI) and that are still conformant to the VS-NfD (de-vs) mode.

### I did not implement the creation of Brainpool-Curves in "mkcert", because of security considerations ...

* The implementation is potentially insecure. See informations by the <a href="https://bada55.cr.yp.to/brainpool.html" rel="nofollow">BADA55 Research Team</a>.
* See additional security considerations to the group of Brainpool Curves represented by <a href="http://safecurves.cr.yp.to/rigid.html" rel="nofollow">"brainpoolP256t1"</a> at "SafeCurves Rigidity" by "Daniel J. Bernstein" and "Tanja Lange".
* <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-13377#vulnCurrentDescriptionTitle" rel="nofollow">DragonBlood Vulnerabilities</a> of the WPA3 Wi-Fi standard in a context of Brainpool-Curves.
* <a href="https://wpa3.mathyvanhoef.com" rel="nofollow">Details</a> to parts of DragonBlood Vulnerabilities in WPA3, caused by Bainpool-usage also at the <a href="https://www.heise.de/security/meldung/Dragonblood-Neue-Luecken-in-WLAN-Verschluesselung-WPA3-koennten-WPA3-1-noetig-machen-4489397.html#nav_brainpool_kurven__1" rel="nofollow">Heise Security Forum</a>.
* In the latest <a href="https://www.wi-fi.org/file/wi-fi-protected-access-security-considerations" rel="nofollow">"Security Considerations"</a> of the Wi-Fi Alliance, you <b>WILL NOT FIND</b> Diffie-Hellman Groups of 27-30 (<b>Brainpool groups</b>) anymore.

<br>

Be aware, that the generated X.509 certificates (RSA) are not fully conformant to the "de-vs" mode, because of their self-signed status but I think the RSA-4096-SHA512-certs are technical conformant to the requirements ...

This stuff is based on mkcert v1.4.3 Copyright 2018 by the mkcert Authors.<br>Original version copyright by Filippo Valsorda, software engineer on the Go security team at Google.

Changes in this version:

- Larger key-size for RSA (4096 bit)
- RSA suite with hash SHA-512
- ECDSA suite with curve P-256 and SHA-256<br>
  <b>(This GO-implementation uses constant-time algorithms !)</b>
- AES256 as cipher for pkcs12/pfx-store<br>
  <b>(Due to old weak specs in <a href="https://www.rfc-editor.org/rfc/rfc7292.html#appendix-C" rel="nofollow">rfc7292</a> of "pkcs12",<br>it is recommended to encrypt the pfx-store with an<br> additional hardened encryption scheme here.)</b>
- Organisation and Common-Name support
- Custom Organisational-Unit support
- Custom Country support
- SubjectKeyId in both certs added
- AuthorityKeyId in both certs added
- Support for Curve25519 in cert (experimental)
- Secure operation, when provided without args (no action)
- Removed extra special characters in commandline ...
- Cert generation without CA-certificate with option "-NOCA" possible (single self-signed)
- CA lifetime set to 4 years
- CA Cert- and Key-filename indexed with local username (OS)
- Additional creation of DER-encoded .crt-certfiles (pub)

```
RSA keys will use.......: RSA 4096 bit with SHA512
ECDSA keys will use.....: NIST-P256 (named) with SHA256
Ed25519 keys will use...: PureEd25519 with SHA512 (experimental)
```
```
$ mkcert -help
Show detailed help and options.

$ mkcert -version
Show version number and details.

$ mkcert -install [-option n, -option n+1, ...]
Install the local CA in the system trust store in combination with the examples below.
```

### Advanced options:
```
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
  The value for section Organizational Unit ('OU') in the certificate
  subject.

 -country COUNTRY
  The value for section Country ('C') in the certificate subject.

 -cn COMMONNAME
  The value for section CommonName ('CN') in the certificate
  subject.

 -password PASSWORD
  The password used to encrypt the private key-file.
  By default the password is empty and therefore the private key
  is not encrypted. Java keystores typically expect the password
  'ChangeIt' by default.

 -CAROOT
  Print the CA certificate and key storage location.

  $CAROOT (environment variable)
  Set the CA certificate and key storage location.
  (This allows maintaining multiple local CAs in parallel.)

  $TRUST_STORES (environment variable)
  A comma-separated list of trust stores to install the local root CA
  into. Options are: "system", "java" and "nss" (includes Firefox).
  Autodetected by default.

 -NOCA
  Do not create and do not use a ROOTCA-certificate for certificate-creation.

```

 ### Examples:
 
  RSA 4096 SHA512 WITHOUT CA:
  ===========================
  mkcert -pkcs12 -password "password" -o "my_org" -ou "my_ou" -country "de" -cn "vname.nname@my_ou.my_org.de" -NOCA "vname.nname@my_ou.my_org.de"

  RSA 4096 SHA512 WITH CA:
  ========================
  mkcert -pkcs12 -password "password" -o "my_org" -ou "my_ou" -country "de" -cn "vname.nname@my_ou.my_org.de" "vname.nname@my_ou.my_org.de"

  ECDSA (ECDH_P256) SHA256 WITHOUT CA:
  ====================================
  mkcert -ecdsa -pkcs12 -password "password" -o "my_org" -ou "my_ou" -country "de" -cn "vname.nname@my_ou.my_org.de" -NOCA "vname.nname@my_ou.my_org.de"

  ECDSA (ECDH_P256) SHA256 WITH CA:
  =================================
  mkcert -ecdsa -pkcs12 -password "password" -o "my_org" -ou "my_ou" -country "de" -cn "vname.nname@my_ou.my_org.de" "vname.nname@my_ou.my_org.de"


## Original Readme 
### (be aware, that i've changed some functionalities like i've described above) ...

<br><br><br><br>

mkcert is a simple tool for making locally-trusted development certificates. It requires no configuration.

```
$ mkcert -install
Created a new local CA 💥
The local CA is now installed in the system trust store! ⚡️
The local CA is now installed in the Firefox trust store (requires browser restart)! 🦊

$ mkcert example.com "*.example.com" example.test localhost 127.0.0.1 ::1

Created a new certificate valid for the following names 📜
 - "example.com"
 - "*.example.com"
 - "example.test"
 - "localhost"
 - "127.0.0.1"
 - "::1"

The certificate is at "./example.com+5.pem" and the key at "./example.com+5-key.pem" ✅
```

<p align="center"><img width="498" alt="Chrome and Firefox screenshot" src="https://user-images.githubusercontent.com/1225294/51066373-96d4aa80-15be-11e9-91e2-f4e44a3a4458.png"></p>

Using certificates from real certificate authorities (CAs) for development can be dangerous or impossible (for hosts like `example.test`, `localhost` or `127.0.0.1`), but self-signed certificates cause trust errors. Managing your own CA is the best solution, but usually involves arcane commands, specialized knowledge and manual steps.

mkcert automatically creates and installs a local CA in the system root store, and generates locally-trusted certificates. mkcert does not automatically configure servers to use the certificates, though, that's up to you.

## Installation

> **Warning**: the `rootCA-key.pem` file that mkcert automatically generates gives complete power to intercept secure requests from your machine. Do not share it.

### macOS

On macOS, use [Homebrew](https://brew.sh/)

```
brew install mkcert
brew install nss # if you use Firefox
```

or [MacPorts](https://www.macports.org/).

```
sudo port selfupdate
sudo port install mkcert
sudo port install nss # if you use Firefox
```

### Linux

On Linux, first install `certutil`.

```
sudo apt install libnss3-tools
    -or-
sudo yum install nss-tools
    -or-
sudo pacman -S nss
    -or-
sudo zypper install mozilla-nss-tools
```

Then you can install using [Homebrew on Linux](https://docs.brew.sh/Homebrew-on-Linux)

```
brew install mkcert
```

or build from source (requires Go 1.13+)

```
git clone https://github.com/FiloSottile/mkcert && cd mkcert
go build -ldflags "-X main.Version=$(git describe --tags)"
```

or use [the pre-built binaries](https://github.com/FiloSottile/mkcert/releases).

For Arch Linux users, [`mkcert`](https://www.archlinux.org/packages/community/x86_64/mkcert/) is available on the official Arch Linux repository.

```
sudo pacman -Syu mkcert
```

### Windows

On Windows, use [Chocolatey](https://chocolatey.org)

```
choco install mkcert
```

or use Scoop

```
scoop bucket add extras
scoop install mkcert
```

or build from source (requires Go 1.10+), or use [the pre-built binaries](https://github.com/FiloSottile/mkcert/releases).

If you're running into permission problems try running `mkcert` as an Administrator.

## Supported root stores

mkcert supports the following root stores:

* macOS system store
* Windows system store
* Linux variants that provide either
    * `update-ca-trust` (Fedora, RHEL, CentOS) or
    * `update-ca-certificates` (Ubuntu, Debian, OpenSUSE, SLES) or
    * `trust` (Arch)
* Firefox (macOS and Linux only)
* Chrome and Chromium
* Java (when `JAVA_HOME` is set)

To only install the local root CA into a subset of them, you can set the `TRUST_STORES` environment variable to a comma-separated list. Options are: "system", "java" and "nss" (includes Firefox).

## Advanced topics

### Advanced options

```
	-cert-file FILE, -key-file FILE, -p12-file FILE
	    Customize the output paths.

	-client
	    Generate a certificate for client authentication.

	-ecdsa
	    Generate a certificate with an ECDSA key.

	-pkcs12
	    Generate a ".p12" PKCS #12 file, also know as a ".pfx" file,
	    containing certificate and key for legacy applications.

	-csr CSR
	    Generate a certificate based on the supplied CSR. Conflicts with
	    all other flags and arguments except -install and -cert-file.
```

> **Note:** You _must_ place these options before the domain names list.

#### Example

```
mkcert -key-file key.pem -cert-file cert.pem example.com *.example.com
```

### S/MIME

mkcert automatically generates an S/MIME certificate if one of the supplied names is an email address.

```
mkcert filippo@example.com
```

### Mobile devices

For the certificates to be trusted on mobile devices, you will have to install the root CA. It's the `rootCA.pem` file in the folder printed by `mkcert -CAROOT`.

On iOS, you can either use AirDrop, email the CA to yourself, or serve it from an HTTP server. After opening it, you need to [install the profile in Settings > Profile Downloaded](https://github.com/FiloSottile/mkcert/issues/233#issuecomment-690110809) and then [enable full trust in it](https://support.apple.com/en-nz/HT204477).

For Android, you will have to install the CA and then enable user roots in the development build of your app. See [this StackOverflow answer](https://stackoverflow.com/a/22040887/749014).

### Using the root with Node.js

Node does not use the system root store, so it won't accept mkcert certificates automatically. Instead, you will have to set the [`NODE_EXTRA_CA_CERTS`](https://nodejs.org/api/cli.html#cli_node_extra_ca_certs_file) environment variable.

```
export NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem"
```

### Changing the location of the CA files

The CA certificate and its key are stored in an application data folder in the user home. You usually don't have to worry about it, as installation is automated, but the location is printed by `mkcert -CAROOT`.

If you want to manage separate CAs, you can use the environment variable `$CAROOT` to set the folder where mkcert will place and look for the local CA files.

### Installing the CA on other systems

Installing in the trust store does not require the CA key, so you can export the CA certificate and use mkcert to install it in other machines.

* Look for the `rootCA.pem` file in `mkcert -CAROOT`
* copy it to a different machine
* set `$CAROOT` to its directory
* run `mkcert -install`

Remember that mkcert is meant for development purposes, not production, so it should not be used on end users' machines, and that you should *not* export or share `rootCA-key.pem`.
