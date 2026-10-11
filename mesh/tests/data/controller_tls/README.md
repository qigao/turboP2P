# Controller H2/mTLS test identities

These public test keys are fixtures only. OpenSSL 3 generated P-256 root and
leaf keys (`genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`), SHA-256
signatures and 3650-day certificates on 2026-10-11. Root signing keys are not
retained. The server and operator use separate trust anchors. Server leaves
have serverAuth EKU; operator leaves have clientAuth EKU. The valid server
SANs are localhost and 127.0.0.1; wrong-host has only wrong.example. The rogue
operator has an unrelated issuer. P-256 operator issuers exercise the released
GmSSL TLS 1.3 CertificateRequest path. Tests copy credentials to private
owner-only temporary files, including the key, before CLI admission.
