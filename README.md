# Enhanced Identity-based Anonymous Authentication Scheme Resilient to Semi-Trusted Server Attack

## Abstract

This project is a Java prototype of a mutual authentication and key agreement scheme for
Mobile Edge Computing (MEC), based on the scheme proposed by Xie et al. (IEEE Transactions
on Information Forensics and Security, 2024). Three parties take part:

- **TE**: Terminal Equipment (the end user's device)
- **MECS**: Mobile Edge Computing Server
- **RC**: Registration Center

All communication runs over the [I2P](https://geti2p.net/) anonymous network, so parties
address each other by I2P destinations instead of IP addresses. Before RC accepts a TE or
MECS, it verifies a CMS (PKCS#7) digital signature from that party. RC and each party then
derive a shared secret with Elliptic Curve Diffie–Hellman (ECDH) on `brainpoolP256r1`.
Files are exchanged encrypted with AES-GCM under that shared key.

## Team

| Member | Contribution |
| --- | --- |
| K. Shanmukh Phani Prabhas | Anonymity via I2P |
| P. Shivani | Digital signatures |
| A. Sai Manideep | ECC key exchange and AES-GCM file encryption |

## Tech stack

From [`pom.xml`](pom.xml):

| Component | Version |
| --- | --- |
| Java | 17 (`maven.compiler.source/target`) |
| Build | Maven |
| Bouncy Castle provider (`org.bouncycastle:bcprov-jdk18on`) | 1.77 |
| Bouncy Castle PKIX/CMS (`org.bouncycastle:bcpkix-jdk18on`) | 1.77 |
| I2P core (`net.i2p:i2p`) | 2.4.0 |
| I2P streaming (`net.i2p.client:streaming`) | 2.4.0 |

Cryptographic primitives used in the code:

- **Signatures:** CMS signed data built with Bouncy Castle (`SHA1withECDSA` content signer), keys loaded from a PKCS#12 keystore
- **Key agreement:** `ECDH` (Bouncy Castle provider), deriving an `AES` secret key
- **Encryption:** `AES/GCM/NoPadding` with a 16-byte IV
- **Key storage:** EC public keys in X.509 PEM, private keys in encrypted PKCS#8 PEM

## How it works

1. **RC** opens an I2P server socket and prints its I2P destination (Base64).
2. **TE** asks for that destination and connects to it over I2P. It signs the message
   `"Client Credentials"` with alias `key2` from the keystore and writes the result to
   `Signature/TE.sign`.
3. **RC** reads `Signature/TE.sign` and verifies the CMS signature. If the signature is
   valid, it replies `"Signature Verified"` and derives the RC–TE shared key with ECDH.
   Otherwise it exits.
4. **TE** derives the same key from its private key and RC's public key, then shows a menu:
   send a file, receive a file, or exit.
5. **MECS** follows the same steps with message `"Client2 Credentials"`, keystore alias
   `key3`, and `Signature/MECS.sign`, giving a separate RC–MECS shared key.

File transfer:

- **TE ↔ RC:** a fresh random IV, the ciphertext length and the AES-GCM ciphertext are sent
  over the I2P stream.
- **MECS ↔ RC:** the IV and ciphertext are written to `ex.enc` on disk, and the receiver
  decrypts them into `output.txt`.

> **Note:** RC reads the signature files from its own working directory. TE and MECS write
> those files to their working directories. So all three processes must currently be
> started from the same project directory.

## Project structure

```
.
├── pom.xml
├── Keys/                     # key material (git-ignored, see "Generate keys")
├── Signature/                # TE.sign / MECS.sign, written at runtime (git-ignored)
└── src/main/java/org/example/
    ├── RC.java               # Registration Center: I2P server, verifies signatures, starts handlers
    ├── TE.java               # Terminal Equipment client
    ├── MECS.java             # Mobile Edge Computing Server client
    ├── digitalsignature/
    │   ├── SignMessage.java      # builds CMS signed data from a PKCS#12 keystore
    │   └── verifyMessage.java    # verifies CMS signed data
    ├── keygenerator/
    │   ├── KeyGenerator.java       # loads RC / TE / MECS EC key pairs from Keys/
    │   └── SecretKeyGenerator.java # ECDH -> AES secret key
    ├── transferfileservices/
    │   ├── transferFile.java        # RC-side handler (one thread per client)
    │   ├── transferFileClient.java  # TE-side menu and file transfer
    │   └── transferFileClient2.java # MECS-side menu and file transfer
    └── Main.java, Client.java, Client2.java, KeyGenerator.java, SecretKeyGenerator.java,
        SignMessage.java, verifyMessage.java, transferFile*.java, Initialize.java
                              # earlier prototype versions in the root package
                              # (RC / TE / MECS use the sub-packages above)
```

## Running

### Prerequisites

- JDK 17 and Maven
- A running I2P router. The app connects through I2CP using
  `I2PSocketManagerFactory.createManager()`, which by default means `127.0.0.1:7654`.
- OpenSSL and `keytool` for generating keys

### 1. Start the I2P router

Install I2P from <https://geti2p.net/> and start the router. Wait until it has integrated
with the network; the router console is at <http://127.0.0.1:7657>.

### 2. Generate keys into `Keys/`

The code loads the following files. Passphrases are currently hard-coded in
`keygenerator/KeyGenerator.java`, `TE.java` and `MECS.java`; use the values listed here.

| File | Used by | Passphrase |
| --- | --- | --- |
| `Keys/public.pem`, `Keys/private.pem` | RC key pair | `admin` |
| `Keys/public_te.pem`, `Keys/private_te.pem` | TE key pair | `client1` |
| `Keys/public_mecs.pem`, `Keys/private_mecs.pem` | MECS key pair | `client2` |
| `keys/server.p12` (PKCS#12, aliases `key2` = TE, `key3` = MECS) | signing | `admin` |

All EC keys must use the same curve, because ECDH needs it. The existing setup uses
`brainpoolP256r1`.

```bash
cd Keys

# EC key pairs (encrypted PKCS#8 private key + X.509 public key)
gen() { # $1 = name suffix, $2 = passphrase
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:brainpoolP256r1 \
    | openssl pkcs8 -topk8 -v2 aes-256-cbc -passout pass:"$2" -out "private$1.pem"
  openssl pkey -in "private$1.pem" -passin pass:"$2" -pubout -out "public$1.pem"
}
gen ""      admin     # RC
gen _te     client1   # TE
gen _mecs   client2   # MECS

# Self-signed certificates + PKCS#12 keystore with aliases key2 (TE) and key3 (MECS)
openssl req -new -x509 -days 365 -key private_te.pem   -passin pass:client1 -subj "/CN=TE"   -out TE.crt
openssl req -new -x509 -days 365 -key private_mecs.pem -passin pass:client2 -subj "/CN=MECS" -out mecs.crt
openssl pkcs12 -export -inkey private_te.pem   -passin pass:client1 -in TE.crt   -name key2 -passout pass:admin -out TE.p12
openssl pkcs12 -export -inkey private_mecs.pem -passin pass:client2 -in mecs.crt -name key3 -passout pass:admin -out mecs.p12
keytool -importkeystore -srckeystore TE.p12   -srcstoretype PKCS12 -srcstorepass admin -destkeystore server.p12 -deststoretype PKCS12 -deststorepass admin
keytool -importkeystore -srckeystore mecs.p12 -srcstoretype PKCS12 -srcstorepass admin -destkeystore server.p12 -deststoretype PKCS12 -deststorepass admin
cd ..
```

> TE and MECS open the keystore as `keys/server.p12` (lower-case `k`). This works on the
> default case-insensitive macOS and Windows file systems. On Linux, create a `keys`
> symlink (`ln -s Keys keys`).

### 3. Build

```bash
mvn package
mvn dependency:copy-dependencies   # copies the Bouncy Castle and I2P jars to target/dependency/
```

### 4. Run: RC first, then TE, then MECS

Use three terminals, all in the project root:

```bash
# Terminal 1: Registration Center (prints its I2P destination)
java -cp "target/classes:target/dependency/*" org.example.RC

# Terminal 2: Terminal Equipment (paste RC's destination when prompted)
java -cp "target/classes:target/dependency/*" org.example.TE

# Terminal 3: MECS, started after TE has been verified (paste the same destination)
java -cp "target/classes:target/dependency/*" org.example.MECS
```

On Windows, use `;` instead of `:` in the classpath.

After verification, TE and MECS each show a menu for sending files to RC and receiving
files from RC.

## Reference

Xie et al., *IEEE Transactions on Information Forensics and Security* (TIFS), 2024.
