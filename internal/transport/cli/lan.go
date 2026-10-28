package cli

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"

	"github.com/envport-dev/envport/internal/application"
	"github.com/envport-dev/envport/internal/domain"
	lanhost "github.com/envport-dev/envport/internal/lan"
	lanstore "github.com/envport-dev/envport/internal/storage/lan"
	"github.com/spf13/cobra"
)

func (r *runner) openStore(ctx context.Context, p application.Profile) (domain.ObjectStore, error) {
	if p.Driver != "lan" {
		return factory(ctx, p)
	}
	if r.noNetwork {
		return nil, errors.New("network disabled by --no-network")
	}
	var c lanhost.Config
	if json.Unmarshal(p.Options, &c) != nil {
		return nil, errors.New("invalid LAN profile")
	}
	i, ok := r.lanIdentities[c.CredentialRef]
	if !ok {
		var err error
		i, err = lanhost.LoadClientIdentity(r.db.Dir, c.CredentialRef, func() (string, error) { return secret("unlock") })
		if err != nil {
			return nil, err
		}
		if r.lanIdentities == nil {
			r.lanIdentities = make(map[domain.ID]lanhost.Identity)
		}
		r.lanIdentities[c.CredentialRef] = i
	}
	return lanstore.Open(ctx, c, i)
}

func (r *runner) addLANStorage(parent *cobra.Command) {
	group := &cobra.Command{Use: "lan", Short: "Create a local TLS identity for the built-in LAN host"}
	var output string
	request := &cobra.Command{Use: "request", Short: "Create a public authorization request; keep the private key encrypted locally", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if output == "" {
			return errors.New("--output is required")
		}
		req, err := lanhost.NewRequest(r.db.Dir, output, func() (string, error) { return secret("unlock") })
		if err != nil {
			return err
		}
		cert, err := lanhost.Certificate(req.Certificate, x509.ExtKeyUsageClientAuth)
		if err != nil {
			return err
		}
		return r.output(cmd, map[string]any{"request_id": req.ID, "request_fingerprint": lanhost.RequestFingerprint(req), "client_fingerprint": lanhost.Fingerprint(cert), "expires_at": req.Expires})
	}}
	request.Flags().StringVar(&output, "output", "", "New public request file")
	group.AddCommand(request)
	parent.AddCommand(group)
}

func (r *runner) addServe() {
	var data, listen string
	directory := func() string {
		if data != "" {
			return data
		}
		return filepath.Join(r.home, "lan-server")
	}
	serverSecret := func() (string, error) { return secret("server") }
	serve := &cobra.Command{Use: "serve", Short: "Run the built-in mutual-TLS LAN ciphertext host", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if r.noNetwork {
			return errors.New("--no-network prevents starting a LAN listener")
		}
		host, err := lanhost.OpenServer(directory(), serverSecret)
		if err != nil {
			return err
		}
		defer host.Close()
		info, err := lanhost.Inspect(directory())
		if err != nil {
			return err
		}
		return host.Run(cmd.Context(), listen, func(address net.Addr) {
			_ = r.output(cmd, map[string]any{"state": "listening", "listen": address.String(), "endpoint": info.Endpoint, "server_fingerprint": info.Fingerprint, "default_namespace": info.DefaultNamespace})
		})
	}}
	serve.PersistentFlags().StringVar(&data, "data", "", "Private host state directory (default: <home>/lan-server)")
	serve.Flags().StringVar(&listen, "listen", "127.0.0.1:7443", "Explicit private IP:port to bind (default loopback only)")
	var endpoint string
	init := &cobra.Command{Use: "init", Short: "Create an encrypted host TLS identity and an isolated personal namespace", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if endpoint == "" {
			return errors.New("--endpoint https://PRIVATE_IP:PORT is required")
		}
		info, err := lanhost.Init(cmd.Context(), directory(), endpoint, serverSecret)
		if err != nil {
			return err
		}
		return r.output(cmd, map[string]any{"endpoint": info.Endpoint, "server_fingerprint": info.Fingerprint, "default_namespace": info.DefaultNamespace})
	}}
	init.Flags().StringVar(&endpoint, "endpoint", "", "Advertised HTTPS private-IP endpoint; certificate is bound to it")
	serve.AddCommand(init)
	serve.AddCommand(&cobra.Command{Use: "inspect", Short: "Show public host fingerprint and namespace binding", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		info, err := lanhost.Inspect(directory())
		if err != nil {
			return err
		}
		return r.output(cmd, map[string]any{"endpoint": info.Endpoint, "server_fingerprint": info.Fingerprint, "default_namespace": info.DefaultNamespace})
	}})
	serve.AddCommand(&cobra.Command{Use: "namespaces", Short: "List isolated host storage namespaces", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		out, err := lanhost.Namespaces(cmd.Context(), directory())
		if err != nil {
			return err
		}
		return r.output(cmd, out)
	}})
	group := &cobra.Command{Use: "namespace", Short: "Manage isolated host storage namespaces"}
	group.AddCommand(&cobra.Command{Use: "create <name>", Short: "Create an independent storage namespace", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		out, err := lanhost.CreateNamespace(cmd.Context(), directory(), args[0])
		if err != nil {
			return err
		}
		return r.output(cmd, out)
	}})
	serve.AddCommand(group)
	var fingerprint, namespace, connectionOutput string
	var readOnly bool
	authorize := &cobra.Command{Use: "authorize <request>", Short: "Authorize a client after confirming its request fingerprint out of band", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if fingerprint == "" || connectionOutput == "" {
			return errors.New("--fingerprint, --namespace and --output are required")
		}
		connection, err := lanhost.Authorize(cmd.Context(), directory(), args[0], fingerprint, domain.ID(namespace), readOnly, connectionOutput, serverSecret)
		if err != nil {
			return err
		}
		cert, err := lanhost.Certificate(connection.Request.Certificate, x509.ExtKeyUsageClientAuth)
		if err != nil {
			return err
		}
		return r.output(cmd, map[string]any{"namespace": connection.Namespace, "client_fingerprint": lanhost.Fingerprint(cert), "read_only": connection.ReadOnly, "connection_file": connectionOutput})
	}}
	authorize.Flags().StringVar(&fingerprint, "fingerprint", "", "Confirmed request fingerprint from requesting device")
	authorize.Flags().StringVar(&namespace, "namespace", "", "Namespace ID to authorize")
	authorize.Flags().StringVar(&connectionOutput, "output", "", "New signed public connection file")
	authorize.Flags().BoolVar(&readOnly, "read-only", false, "Authorize reads and restores only")
	serve.AddCommand(authorize)
	serve.AddCommand(&cobra.Command{Use: "clients", Short: "List namespace-scoped transport authorizations", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		out, err := lanhost.Clients(cmd.Context(), directory())
		if err != nil {
			return err
		}
		return r.output(cmd, out)
	}})
	var revokeNamespace string
	var confirm bool
	revoke := &cobra.Command{Use: "revoke <client-fingerprint>", Short: "Revoke future LAN requests; copied vault keys remain usable elsewhere", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if !confirm {
			return errors.New("--confirm is required to revoke LAN storage access")
		}
		return lanhost.Revoke(cmd.Context(), directory(), domain.ID(revokeNamespace), args[0])
	}}
	revoke.Flags().StringVar(&revokeNamespace, "namespace", "", "Namespace to revoke access to")
	revoke.Flags().BoolVar(&confirm, "confirm", false, "Confirm revocation of storage access")
	serve.AddCommand(revoke)
	r.root.AddCommand(serve)
}

func isServeCommand(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		if c.Name() == "serve" && c.Parent() != nil && c.Parent().Parent() == nil {
			return true
		}
	}
	return false
}
