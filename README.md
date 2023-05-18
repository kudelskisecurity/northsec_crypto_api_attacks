# CryptoAPI attacks

## CVE-2020-0601

Advisory: [Windows CryptoAPI Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0601)

Our blog post on [CVE-2020-0601](https://research.kudelskisecurity.com/2020/01/15/cve-2020-0601-the-chainoffools-attack-explained-with-poc) and the [PoC](https://github.com/kudelskisecurity/chainoffools).

Our [demo website](http://chainoffools.ktp.dev/) to test if you have the patch installed. (Linux & MacOS users were never impacted.)

## CVE-2022-34689

Advisory: [Windows CryptoAPI Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-34689)

Initial [blog post by Akamai Research](https://www.akamai.com/blog/security-research/exploiting-critical-spoofing-vulnerability-microsoft-cryptoapi).

Coming soon.

## NorthSec 2023

Slides are in [presentation folder](presentation/).

## Notes

After the vulnerability, the usage of explicit parameters have been removed from Openssl:
```
$ openssl verify -verbose -CAfile ca-rogue.pem client-cert.pem
C = CH, ST = Vaud, L = Lausanne, O = Kudelski Security PoC, OU = Research Team, CN = github.com
error 94 at 1 depth lookup: Certificate public key has explicit ECC parameters
error client-cert.pem: verification failed
```

See https://lightshipsec.com/explicitly-parameterized-ecdsa-x-509-certificates/ and https://github.com/openssl/openssl/issues/12139.

