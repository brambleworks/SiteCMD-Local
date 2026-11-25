These DER files contain a self-signed certificate and its disposable test-only
RSA private key. They serve local TLS regression tests and have no production
use or trust. The certificate covers `public.example`, `localhost`, `127.0.0.1`,
and `::1`; the public hostname resolves only to the test's loopback listener.
