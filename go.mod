module github.com/Privasys/cli

go 1.25.0

require (
	enclave-os-mini/clients/go v0.0.0
	github.com/Privasys/enclave-vaults-client/go v0.0.0-00010101000000-000000000000
	github.com/descope/virtualwebauthn v1.0.5
	github.com/go-webauthn/webauthn v0.17.4
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	github.com/spf13/cobra v1.10.2
	github.com/zalando/go-keyring v0.2.8
	golang.org/x/sys v0.45.0
	gopkg.in/yaml.v3 v3.0.1
)

// The RA-TLS client library is a sibling checkout (the release workflow checks
// out Privasys/ra-tls-clients next to this repo). Client-side challenge-response
// additionally requires the Privasys Go fork built with -tags ratls.
replace enclave-os-mini/clients/go => ../ra-tls-clients/go

require (
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.2.6 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.52.0 // indirect
)

replace github.com/Privasys/enclave-vaults-client/go => ../enclave-vaults-client/go
