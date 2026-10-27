// Package headless joins HeteroNetwork over HTTP without opening a WAN UDP
// socket, creating a kernel interface, or requesting network capabilities.
package headless

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type NodeRecord struct {
	Candidates         []json.RawMessage `json:"endpoint_candidates"`
	AllowedIPs         []string          `json:"-"`
	Destination        string            `json:"-"`
	DestinationNode    string            `json:"-"`
	NodeID             string            `json:"node_id"`
	VPNIP              string            `json:"vpn_ip"`
	IdentityPublicKey  string            `json:"identity_public_key"`
	WireGuardPublicKey string            `json:"wireguard_public_key"`
}
type signature struct {
	SignedAt  string `json:"signed_at"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}
type query struct {
	NodeID    string     `json:"node_id"`
	Signature *signature `json:"request_signature,omitempty"`
}
type action struct {
	Operation        string   `json:"operation"`
	Address          string   `json:"address,omitempty"`
	Target           string   `json:"target,omitempty"`
	BatchID          string   `json:"batch_id,omitempty"`
	Packets          []string `json:"packets,omitempty"`
	Acknowledgements *[]ack   `json:"acknowledgements,omitempty"`
	WaitMS           *uint64  `json:"wait_ms,omitempty"`
	Ephemeral        *bool    `json:"ephemeral,omitempty"`
	HTTPOnly         *bool    `json:"http_only,omitempty"`
	After            *string  `json:"after,omitempty"`
	Limit            *uint16  `json:"limit,omitempty"`
}
type ack struct {
	Source  string `json:"source"`
	BatchID string `json:"batch_id"`
}
type envelope struct {
	Source  string   `json:"source"`
	Target  string   `json:"target"`
	BatchID string   `json:"batch_id"`
	Packets []string `json:"packets"`
}
type meshResponse struct {
	Nodes           []NodeRecord `json:"nodes"`
	NextCursor      *string      `json:"next_cursor"`
	AllowedIPs      []string     `json:"allowed_ips"`
	Destination     string       `json:"destination"`
	DestinationNode string       `json:"destination_node"`
	Node            *NodeRecord  `json:"node"`
	Accepted        *bool        `json:"accepted"`
	Envelopes       []envelope   `json:"envelopes"`
}

type API struct {
	control, mesh string
	nodeID        string
	identity      ed25519.PrivateKey
	client        *http.Client
}

func neturlHost(value string) (netip.Addr, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(parsed.Hostname())
}

func encode(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

func newAPI(endpoint, mesh string, identity ed25519.PrivateKey, client *http.Client, allowInsecure bool) (*API, error) {
	if len(identity) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid node identity")
	}
	if mesh == "" {
		mesh = endpoint
	}
	for index, value := range []string{endpoint, mesh} {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
			return nil, errors.New("endpoint must be an HTTP(S) origin without credentials")
		}
		if parsed.Scheme != "https" && !(parsed.Scheme == "http" && (index == 1 || allowInsecure)) {
			return nil, errors.New("enrollment and peer discovery require HTTPS")
		}
	}
	if client == nil {
		client = &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone(), Timeout: 25 * time.Second}
	}
	copied := *client
	copied.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	digest := sha256.Sum256(identity.Public().(ed25519.PublicKey))
	return &API{control: strings.TrimRight(endpoint, "/"), mesh: strings.TrimRight(mesh, "/"), nodeID: "node-" + hex.EncodeToString(digest[:16]), identity: identity, client: &copied}, nil
}

func (api *API) sign(value action) ([]byte, error) {
	binding, err := encode([]any{"http-mesh-v1", value})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(binding)
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return nil, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(append(digest[:], random...))
	at := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	payload := struct {
		Kind     string `json:"kind"`
		NodeID   string `json:"node_id"`
		SignedAt string `json:"signed_at"`
		Nonce    string `json:"nonce"`
	}{"http_mesh", api.nodeID, at, nonce}
	signed, err := encode(payload)
	if err != nil {
		return nil, err
	}
	request := struct {
		Query  query  `json:"query"`
		Action action `json:"action"`
	}{query{api.nodeID, &signature{at, nonce, base64.StdEncoding.EncodeToString(ed25519.Sign(api.identity, signed))}}, value}
	return encode(request)
}

type HTTPError struct{ Status int }

func (e HTTPError) Error() string { return fmt.Sprintf("HeteroNetwork HTTP API returned %d", e.Status) }

func (api *API) request(ctx context.Context, method, endpoint string, body []byte, target any) error {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := api.client.Do(request)
	if err != nil {
		return errors.New("HeteroNetwork HTTP API is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return HTTPError{response.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 {
		return errors.New("invalid or oversized API response")
	}
	if target == nil {
		return nil
	}
	return json.Unmarshal(data, target)
}

func (api *API) meshRequest(ctx context.Context, value action) (meshResponse, error) {
	body, err := api.sign(value)
	if err != nil {
		return meshResponse{}, err
	}
	endpoint := api.mesh
	if value.Operation == "peer" || value.Operation == "lease" || value.Operation == "leave" || value.Operation == "routes" {
		endpoint = api.control
	}
	var result meshResponse
	err = api.request(ctx, http.MethodPost, endpoint+"/v1/http-mesh", body, &result)
	return result, err
}

func (api *API) peer(ctx context.Context, address string) (NodeRecord, error) {
	result, err := api.meshRequest(ctx, action{Operation: "peer", Address: address})
	if err != nil {
		return NodeRecord{}, err
	}
	if result.Node == nil {
		return NodeRecord{}, errors.New("peer is unavailable")
	}
	result.Node.AllowedIPs = result.AllowedIPs
	result.Node.Destination = result.Destination
	result.Node.DestinationNode = result.DestinationNode
	if result.Node.Destination == "" {
		result.Node.Destination = result.Node.VPNIP
	}
	if result.Node.DestinationNode == "" {
		result.Node.DestinationNode = result.Node.NodeID
	}
	return *result.Node, nil
}

func (api *API) join(ctx context.Context, token json.RawMessage, wireguardPublic []byte, ephemeral bool) (NodeRecord, error) {
	var capabilities struct {
		Mesh int `json:"http_mesh_protocol"`
	}
	if err := api.request(ctx, http.MethodGet, api.control+"/v1/transport-capabilities", nil, &capabilities); err != nil {
		return NodeRecord{}, err
	}
	if capabilities.Mesh != 1 {
		return NodeRecord{}, errors.New("control plane does not support HTTP-only nodes")
	}
	// A persistent identity can resume without spending another join token.
	if existing, err := api.peer(ctx, api.nodeID); err == nil {
		if existing.WireGuardPublicKey != base64.StdEncoding.EncodeToString(wireguardPublic) {
			return NodeRecord{}, errors.New("persistent identity has a different registered WireGuard key")
		}
		httpOnly := len(existing.Candidates) == 0
		if _, err = api.meshRequest(ctx, action{Operation: "lease", Ephemeral: &ephemeral, HTTPOnly: &httpOnly}); err != nil {
			return NodeRecord{}, err
		}
		return existing, nil
	} else {
		var status HTTPError
		if !errors.As(err, &status) || status.Status != http.StatusNotFound {
			return NodeRecord{}, err
		}
	}
	if len(token) == 0 {
		return NodeRecord{}, errors.New("HETERONETWORK_JOIN_TOKEN is required for a new identity")
	}
	request := struct {
		Token        json.RawMessage `json:"token"`
		Registration any             `json:"registration"`
	}{token, struct {
		NodeID     string `json:"node_id"`
		Identity   string `json:"identity_public_key"`
		WireGuard  string `json:"wireguard_public_key"`
		Candidates []any  `json:"candidates"`
		Relay      any    `json:"relay_capability"`
		Routes     []any  `json:"requested_routes"`
	}{api.nodeID, base64.StdEncoding.EncodeToString(api.identity.Public().(ed25519.PublicKey)), base64.StdEncoding.EncodeToString(wireguardPublic), []any{}, nil, []any{}}}
	body, err := encode(request)
	if err != nil {
		return NodeRecord{}, err
	}
	var response struct {
		Node NodeRecord `json:"node"`
	}
	if err = api.request(ctx, http.MethodPost, api.control+"/v1/http-mesh/join", body, &response); err != nil {
		return NodeRecord{}, err
	}
	if response.Node.NodeID != api.nodeID {
		return NodeRecord{}, errors.New("join returned a different node identity")
	}
	httpOnly := len(response.Node.Candidates) == 0
	if _, err = api.meshRequest(ctx, action{Operation: "lease", Ephemeral: &ephemeral, HTTPOnly: &httpOnly}); err != nil {
		return NodeRecord{}, err
	}
	return response.Node, nil
}

func randomID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 15) | 64
	value[8] = (value[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[:4], value[4:6], value[6:8], value[8:10], value[10:]), nil
}
