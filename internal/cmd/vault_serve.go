// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/Privasys/cli/internal/api"
	"github.com/Privasys/cli/internal/auth"
	"github.com/Privasys/cli/internal/secrets"
)

// vault serve runs a local, Azure Key Vault-shaped REST proxy for one vault — the
// "standard skin" over the attested vHSM. It is a CLIENT-SIDE proxy on purpose:
// the data-plane operations (sign / wrapKey / unwrapKey / get-public) go DIRECT
// from this process to the constellation over RA-TLS, so the platform is never in
// the key data path. The proxy holds the owner's session and translates REST into
// the vault calls.
//
// Impedance vs Azure (documented): Azure `sign` takes a pre-hashed digest; this
// vault's Sign hashes the message itself (ECDSA-P256-SHA256), so the facade signs
// the supplied `value` as a MESSAGE, not a digest. A true "sign pre-hashed" mode
// is a follow-up.

func newVaultServeCmd() *cobra.Command {
	var addr, vaultID string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run a local Azure Key Vault-shaped REST proxy for a vault (the vHSM, standard skin)",
		Long: `Starts a local HTTP server exposing an Azure Key Vault-shaped REST API for one
vault. Point a tool or SDK at it; the proxy translates to the attested vault over
RA-TLS. The data plane stays direct (this process is the client) — the platform
never sees key material or operations.

Endpoints (base http://<addr>):
  GET    /keys
  POST   /keys/{name}/create        {"kty":"EC"|"oct"|"secret"}
  GET    /keys/{name}               -> JWK (signing keys)
  POST   /keys/{name}/sign          {"alg":"ES256","value":"<base64url message>"}
  POST   /keys/{name}/wrapKey       {"value":"<base64url plaintext>","iv":"<optional base64url 12-byte IV>"}
  POST   /keys/{name}/unwrapKey     {"value":"<base64url ciphertext>","iv":"<base64url>"}
  POST   /keys/{name}/rotate
  DELETE /keys/{name}`,
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := loadEnv(cmd)
			if err != nil {
				return err
			}
			if vaultID == "" {
				return fmt.Errorf("--vault <id> is required")
			}
			client, err := apiClient(cmd, env)
			if err != nil {
				return err
			}
			f := &kvFacade{env: env, client: client, vaultID: vaultID}
			mux := http.NewServeMux()
			mux.HandleFunc("GET /keys", f.list)
			mux.HandleFunc("POST /keys/{name}/create", f.create)
			mux.HandleFunc("GET /keys/{name}", f.getPublic)
			mux.HandleFunc("POST /keys/{name}/sign", f.sign)
			mux.HandleFunc("POST /keys/{name}/wrapKey", f.wrap)
			mux.HandleFunc("POST /keys/{name}/unwrapKey", f.unwrap)
			mux.HandleFunc("POST /keys/{name}/rotate", f.rotate)
			mux.HandleFunc("DELETE /keys/{name}", f.destroy)
			srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
			fmt.Fprintf(cmd.ErrOrStderr(), "Privasys vHSM REST facade for vault %s on http://%s (data plane stays direct)\n", vaultID, addr)
			return srv.ListenAndServe()
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8200", "local listen address")
	cmd.Flags().StringVar(&vaultID, "vault", "", "vault id this facade serves (required)")
	return cmd
}

type kvFacade struct {
	env     *Env
	client  *api.Client
	vaultID string
}

func writeKVError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"message": err.Error()}})
}

func writeKVJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// sub returns the owner subject from the current session.
func (f *kvFacade) sub(ctx context.Context) (string, error) {
	tok, err := auth.AccessToken(ctx, f.env.Cfg.Issuer)
	if err != nil {
		return "", err
	}
	claims, err := auth.Claims(tok)
	if err != nil {
		return "", err
	}
	s, _ := claims["sub"].(string)
	if s == "" {
		return "", fmt.Errorf("no subject in session")
	}
	return s, nil
}

func (f *kvFacade) list(w http.ResponseWriter, r *http.Request) {
	keys, err := f.client.ListVaultKeys(r.Context(), f.vaultID)
	if err != nil {
		writeKVError(w, http.StatusBadGateway, err)
		return
	}
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{
			"kid":     fmt.Sprintf("%v", k["handle"]),
			"name":    k["name"],
			"version": k["version"],
			"keyType": k["key_type"],
		})
	}
	writeKVJSON(w, http.StatusOK, map[string]any{"value": out})
}

func (f *kvFacade) create(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var body struct {
		Kty   string `json:"kty"`
		Value string `json:"value"` // base64url secret material (kty=secret)
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	sub, err := f.sub(r.Context())
	if err != nil {
		writeKVError(w, http.StatusUnauthorized, err)
		return
	}
	attTok, _ := auth.AccessTokenForAudience(r.Context(), f.env.Cfg.Issuer, "attestation-server")
	mint := func(ctx context.Context, cnf string) (string, secrets.VaultAddressing, error) {
		return mintVaultKeyGrant(ctx, f.client, f.vaultID, name, kvKeyType(body.Kty), cnf, kvKeyType(body.Kty) == "", "", "")
	}
	params := secrets.VaultCreateParams{Sub: sub, AttToken: attTok, MintGrant: mint}
	var res *secrets.Result
	switch kvKeyType(body.Kty) {
	case "P256SigningKey":
		res, err = secrets.CreateSigningKeyInVault(r.Context(), params)
	case "Aes256GcmKey":
		res, err = secrets.CreateAesKeyInVault(r.Context(), params)
	default: // RawShare secret
		params.Exportable = true
		mat, derr := base64.RawURLEncoding.DecodeString(body.Value)
		if derr != nil || len(mat) == 0 {
			writeKVError(w, http.StatusBadRequest, fmt.Errorf("kty=secret needs base64url value"))
			return
		}
		params.Secret = mat
		res, err = secrets.CreateInVault(r.Context(), params)
	}
	if err != nil {
		writeKVError(w, http.StatusBadGateway, err)
		return
	}
	writeKVJSON(w, http.StatusOK, map[string]any{"kid": res.Handle, "name": name, "keyType": kvKeyType(body.Kty)})
}

func (f *kvFacade) getPublic(w http.ResponseWriter, r *http.Request) {
	p, err := f.addr(r, r.PathValue("name"))
	if err != nil {
		writeKVError(w, http.StatusBadGateway, err)
		return
	}
	res, err := secrets.GetPublicKeyInVault(r.Context(), p)
	if err != nil {
		writeKVError(w, http.StatusBadGateway, err)
		return
	}
	jwk, err := jwkFromPublicKey(res.KeyType, res.PublicKey)
	if err != nil {
		writeKVError(w, http.StatusBadRequest, err)
		return
	}
	writeKVJSON(w, http.StatusOK, map[string]any{"kid": p.Handle, "key": jwk})
}

func (f *kvFacade) sign(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Alg       string `json:"alg"`
		Value     string `json:"value"` // base64url message, or a digest when prehashed
		Version   int    `json:"version"`
		Prehashed bool   `json:"prehashed"` // value is a 32-byte SHA-256 digest, signed raw (CKM_ECDSA)
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKVError(w, http.StatusBadRequest, err)
		return
	}
	msg, err := base64.RawURLEncoding.DecodeString(body.Value)
	if err != nil {
		writeKVError(w, http.StatusBadRequest, fmt.Errorf("value must be base64url"))
		return
	}
	p, err := f.addrV(r, r.PathValue("name"), body.Version)
	if err != nil {
		writeKVError(w, http.StatusBadGateway, err)
		return
	}
	sign := secrets.SignInVault
	if body.Prehashed {
		sign = secrets.SignPrehashInVault
	}
	res, err := sign(r.Context(), p, msg)
	if err != nil {
		writeKVError(w, http.StatusBadGateway, err)
		return
	}
	writeKVJSON(w, http.StatusOK, map[string]any{"kid": p.Handle, "alg": res.Alg, "value": base64.RawURLEncoding.EncodeToString(res.Signature)})
}

func (f *kvFacade) wrap(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Value string `json:"value"`
		// Optional caller-supplied 12-byte GCM IV (base64url). PKCS#11
		// CKM_AES_GCM fixes the nonce caller-side; empty lets the vault
		// generate one (the default, and the safer choice).
		IV string `json:"iv"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKVError(w, http.StatusBadRequest, err)
		return
	}
	pt, err := base64.RawURLEncoding.DecodeString(body.Value)
	if err != nil {
		writeKVError(w, http.StatusBadRequest, fmt.Errorf("value must be base64url"))
		return
	}
	var reqIV []byte
	if body.IV != "" {
		reqIV, err = base64.RawURLEncoding.DecodeString(body.IV)
		if err != nil {
			writeKVError(w, http.StatusBadRequest, fmt.Errorf("iv must be base64url"))
			return
		}
	}
	p, err := f.addr(r, r.PathValue("name"))
	if err != nil {
		writeKVError(w, http.StatusBadGateway, err)
		return
	}
	ct, iv, _, err := secrets.WrapInVault(r.Context(), p, pt, nil, reqIV)
	if err != nil {
		writeKVError(w, http.StatusBadGateway, err)
		return
	}
	writeKVJSON(w, http.StatusOK, map[string]any{"kid": p.Handle, "value": base64.RawURLEncoding.EncodeToString(ct), "iv": base64.RawURLEncoding.EncodeToString(iv)})
}

func (f *kvFacade) unwrap(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Value   string `json:"value"`
		IV      string `json:"iv"`
		Version int    `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKVError(w, http.StatusBadRequest, err)
		return
	}
	ct, err := base64.RawURLEncoding.DecodeString(body.Value)
	if err != nil {
		writeKVError(w, http.StatusBadRequest, fmt.Errorf("value must be base64url"))
		return
	}
	iv, err := base64.RawURLEncoding.DecodeString(body.IV)
	if err != nil {
		writeKVError(w, http.StatusBadRequest, fmt.Errorf("iv must be base64url"))
		return
	}
	p, err := f.addrV(r, r.PathValue("name"), body.Version)
	if err != nil {
		writeKVError(w, http.StatusBadGateway, err)
		return
	}
	pt, _, err := secrets.UnwrapInVault(r.Context(), p, ct, iv, nil)
	if err != nil {
		writeKVError(w, http.StatusBadGateway, err)
		return
	}
	writeKVJSON(w, http.StatusOK, map[string]any{"kid": p.Handle, "value": base64.RawURLEncoding.EncodeToString(pt)})
}

func (f *kvFacade) rotate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	sub, err := f.sub(r.Context())
	if err != nil {
		writeKVError(w, http.StatusUnauthorized, err)
		return
	}
	keyType, err := getPrimaryVaultKeyType(r.Context(), f.client, f.vaultID, name)
	if err != nil {
		writeKVError(w, http.StatusNotFound, err)
		return
	}
	attTok, _ := auth.AccessTokenForAudience(r.Context(), f.env.Cfg.Issuer, "attestation-server")
	mint := func(ctx context.Context, cnf string) (string, secrets.VaultAddressing, error) {
		return rotateVaultKeyGrant(ctx, f.client, f.vaultID, name, cnf)
	}
	params := secrets.VaultCreateParams{Sub: sub, AttToken: attTok, MintGrant: mint}
	var res *secrets.Result
	switch keyType {
	case "P256SigningKey":
		res, err = secrets.CreateSigningKeyInVault(r.Context(), params)
	case "Aes256GcmKey":
		res, err = secrets.CreateAesKeyInVault(r.Context(), params)
	default:
		writeKVError(w, http.StatusBadRequest, fmt.Errorf("rotate over REST supports p256/aes keys (secrets need new material)"))
		return
	}
	if err != nil {
		writeKVError(w, http.StatusBadGateway, err)
		return
	}
	writeKVJSON(w, http.StatusOK, map[string]any{"kid": res.Handle, "name": name})
}

func (f *kvFacade) destroy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	p, err := f.addr(r, name)
	if err != nil {
		writeKVError(w, http.StatusBadGateway, err)
		return
	}
	if _, err := secrets.DestroyKeyInVault(r.Context(), p); err != nil {
		writeKVError(w, http.StatusBadGateway, err)
		return
	}
	if err := f.client.DeleteVaultKey(r.Context(), f.vaultID, name); err != nil {
		writeKVError(w, http.StatusBadGateway, err)
		return
	}
	writeKVJSON(w, http.StatusOK, map[string]any{"deletedKey": map[string]any{"kid": p.Handle}})
}

// addr / addrV build the dial params for an op on a key (primary / pinned version).
func (f *kvFacade) addr(r *http.Request, name string) (secrets.VaultOpParams, error) {
	return f.addrV(r, name, 0)
}

func (f *kvFacade) addrV(r *http.Request, name string, version int) (secrets.VaultOpParams, error) {
	return vaultKeyAddressing(r.Context(), nil, f.env, f.client, f.vaultID, name, version)
}

// kvKeyType maps an Azure-ish kty to the vault KeyType.
func kvKeyType(kty string) string {
	switch kty {
	case "EC", "EC-HSM", "p256", "P256":
		return "P256SigningKey"
	case "oct", "oct-HSM", "aes", "AES":
		return "Aes256GcmKey"
	default:
		return "" // secret (RawShare); the platform defaults
	}
}
