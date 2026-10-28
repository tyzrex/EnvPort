// Package cli adapts command parsing and terminal output to the application engine.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/envport-dev/envport/internal/application"
	"github.com/envport-dev/envport/internal/discovery"
	"github.com/envport-dev/envport/internal/domain"
	lanhost "github.com/envport-dev/envport/internal/lan"
	"github.com/envport-dev/envport/internal/persistence"
	"github.com/envport-dev/envport/internal/storage"
	"github.com/envport-dev/envport/internal/storage/filesystem"
	s3store "github.com/envport-dev/envport/internal/storage/s3"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"os"
	"os/signal"
	"syscall"
)

var Version = "0.1.0-dev"

type runner struct {
	home, vault     string
	json, noNetwork bool
	db              *persistence.DB
	app             *application.Service
	root            *cobra.Command
	lanIdentities   map[domain.ID]lanhost.Identity
}

func secret(kind string) (string, error) {
	name := "ENVPORT_PASSPHRASE"
	prompt := "Vault unlock passphrase"
	if kind == "server" {
		name = "ENVPORT_SERVER_PASSPHRASE"
		prompt = "LAN host unlock passphrase"
	}
	if kind == "recovery" {
		name = "ENVPORT_RECOVERY_PASSPHRASE"
		prompt = "Independent recovery passphrase"
	}
	if p := os.Getenv(name); p != "" {
		return p, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("%s is required for noninteractive use", name)
	}
	fmt.Fprint(os.Stderr, prompt+": ")
	b, e := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if e != nil {
		return "", errors.New("cannot read passphrase")
	}
	return string(b), nil
}
func factory(ctx context.Context, p application.Profile) (domain.ObjectStore, error) {
	switch p.Driver {
	case "filesystem":
		return filesystem.Open(p.Path)
	case "s3":
		var c s3store.Config
		if json.Unmarshal(p.Options, &c) != nil {
			return nil, errors.New("invalid storage profile")
		}
		return s3store.Open(ctx, c)
	default:
		return nil, errors.New("unsupported storage driver")
	}
}
func New() *cobra.Command {
	r := &runner{}
	root := &cobra.Command{Use: "envport", Short: "Encrypted, local-first environment-file backup and synchronization", Version: Version, SilenceUsage: true, SilenceErrors: true}
	r.root = root
	root.PersistentFlags().StringVar(&r.home, "home", application.DefaultStateDir(), "Private device state directory")
	root.PersistentFlags().StringVar(&r.vault, "vault", "", "Vault name or ID (defaults to active)")
	root.PersistentFlags().BoolVar(&r.json, "json", false, "Emit machine-readable JSON")
	root.PersistentFlags().BoolVar(&r.noNetwork, "no-network", false, "Refuse remote storage access")
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if isServeCommand(cmd) || cmd.Name() == "version" || cmd.Name() == "scan" || cmd.Name() == "completion" || cmd.Parent() != nil && cmd.Parent().Name() == "completion" {
			return nil
		}
		db, e := persistence.Open(r.home)
		if e != nil {
			return e
		}
		r.db = db
		r.app = application.New(db, r.openStore, secret)
		r.app.NoNetwork = r.noNetwork
		if err := r.app.EnsureInitialized(cmd.Context()); err != nil {
			_ = r.db.Close()
			r.db = nil
			return err
		}
		return nil
	}
	root.PersistentPostRunE = func(_ *cobra.Command, _ []string) error {
		if r.db != nil {
			return r.db.Close()
		}
		return nil
	}
	root.AddCommand(&cobra.Command{Use: "version", Short: "Show version", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return r.output(cmd, map[string]string{"version": Version})
	}})
	var byos, offline, lanMode bool
	initCmd := &cobra.Command{Use: "init", Short: "Initialize a private standalone installation", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		profiles, e := r.app.Profiles(cmd.Context())
		if e != nil {
			return e
		}
		if (byos && offline) || (byos && lanMode) || (offline && lanMode) {
			return errors.New("choose --offline, --byos or --lan")
		}
		if lanMode {
			return r.output(cmd, map[string]string{"state": "initialized", "next": "storage lan request --output <request.json>; authorize on LAN host; storage add lan --name home --connection <connection.json> --server-fingerprint <trusted fingerprint>"})
		}
		if byos {
			return r.output(cmd, map[string]string{"state": "initialized", "next": "storage add s3 --name <profile>; storage test <profile>; vault create personal --storage <profile>"})
		}
		if len(profiles) == 0 {
			if e = r.app.AddProfile(cmd.Context(), application.Profile{Name: "local", Driver: "filesystem", Path: r.db.Dir + "/objects"}); e != nil {
				return e
			}
		}
		return r.output(cmd, map[string]string{"state": "initialized", "next": "vault create personal --storage local; keys export --output <recovery.age>"})
	}}
	initCmd.Flags().BoolVar(&offline, "offline", false, "Standalone offline mode (default)")
	initCmd.Flags().BoolVar(&byos, "byos", false, "Standalone BYOS setup without a local fallback vault")
	initCmd.Flags().BoolVar(&lanMode, "lan", false, "LAN setup with the built-in host; no cloud account or local fallback profile")
	root.AddCommand(initCmd)
	scan := &cobra.Command{Use: "scan <roots...>", Short: "Read-only discovery under explicit roots", Args: cobra.MinimumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		result, e := discovery.Scan(cmd.Context(), args)
		if e != nil {
			return e
		}
		return r.output(cmd, result)
	}}
	root.AddCommand(scan)
	r.addStorage()
	r.addVaults()
	r.addProjects()
	r.addOperations()
	r.addKeys()
	r.addDevices()
	r.addMigration()
	r.addServe()
	r.wrapCommands(root)
	return root
}
func (r *runner) output(cmd *cobra.Command, v any) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	if !r.json {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(v)
}
func (r *runner) selected(cmd *cobra.Command) (application.Vault, error) {
	return r.app.Vault(cmd.Context(), r.vault)
}
func (r *runner) addVaults() {
	group := &cobra.Command{Use: "vault", Short: "Manage isolated vaults"}
	var profile string
	create := &cobra.Command{Use: "create <name>", Args: cobra.ExactArgs(1), Short: "Create an independent vault", RunE: func(cmd *cobra.Command, args []string) error {
		v, e := r.app.CreateVault(cmd.Context(), args[0], profile)
		if e != nil {
			return e
		}
		return r.output(cmd, v)
	}}
	create.Flags().StringVar(&profile, "storage", "local", "Storage profile")
	group.AddCommand(create)
	group.AddCommand(&cobra.Command{Use: "list", Short: "List local vaults", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		v, e := r.app.Vaults(cmd.Context())
		if e != nil {
			return e
		}
		return r.output(cmd, v)
	}})
	group.AddCommand(&cobra.Command{Use: "use <name>", Short: "Select active vault", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error { return r.app.Use(cmd.Context(), args[0]) }})
	group.AddCommand(&cobra.Command{Use: "inspect", Short: "Inspect selected vault without exposing keys", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		v, e := r.selected(cmd)
		if e != nil {
			return e
		}
		return r.output(cmd, v)
	}})
	var recovery, grant, issuerFingerprint, joinProfile string
	join := &cobra.Command{Use: "join <name>", Short: "Join with an encrypted recovery bundle and separate storage access", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if grant != "" {
			if recovery != "" {
				return errors.New("choose one of --recovery or --grant")
			}
			v, e := r.app.JoinDevice(cmd.Context(), args[0], joinProfile, grant, issuerFingerprint)
			if e != nil {
				return e
			}
			return r.output(cmd, v)
		}
		if recovery == "" {
			return errors.New("--recovery or --grant is required")
		}
		v, e := r.app.Join(cmd.Context(), args[0], joinProfile, recovery)
		if e != nil {
			return e
		}
		return r.output(cmd, v)
	}}
	join.Flags().StringVar(&grant, "grant", "", "Encrypted device grant")
	join.Flags().StringVar(&issuerFingerprint, "issuer-fingerprint", "", "Out-of-band trusted signing-key fingerprint")
	join.Flags().StringVar(&recovery, "recovery", "", "Encrypted recovery bundle path")
	join.Flags().StringVar(&joinProfile, "storage", "local", "Storage profile")
	group.AddCommand(join)
	r.root.AddCommand(group)
}
func (r *runner) addStorage() {
	group := &cobra.Command{Use: "storage", Short: "Configure independent storage profiles"}
	var name, path, endpoint, bucket, region, prefix, awsProfile string
	var pathStyle, allowHTTP bool
	var connection, serverFingerprint string
	add := &cobra.Command{Use: "add <filesystem|s3|lan>", Short: "Add filesystem, S3-compatible, or built-in LAN storage", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		p := application.Profile{Name: name, Driver: args[0], Path: path}
		if p.Driver == "s3" {
			c := s3store.Config{Endpoint: endpoint, Bucket: bucket, Region: region, Prefix: prefix, AWSProfile: awsProfile, PathStyle: pathStyle, AllowHTTP: allowHTTP}
			if r.noNetwork {
				return errors.New("S3 profile validation requires network-enabled mode")
			}
			st, e := s3store.Open(cmd.Context(), c)
			if e != nil {
				return e
			}
			st.Close()
			p.Path = ""
			p.Options, _ = json.Marshal(c)
			if allowHTTP {
				fmt.Fprintln(cmd.ErrOrStderr(), "Warning: HTTP exposes storage traffic and credentials to the network; use only isolated test services.")
			}
		}
		if p.Driver == "lan" {
			if connection == "" || serverFingerprint == "" {
				return errors.New("LAN profiles require --connection and out-of-band --server-fingerprint")
			}
			c, e := lanhost.ImportConnection(r.db.Dir, connection, serverFingerprint, func() (string, error) { return secret("unlock") })
			if e != nil {
				return e
			}
			p.Path = ""
			p.Options, _ = json.Marshal(c)
		}
		if e := r.app.AddProfile(cmd.Context(), p); e != nil {
			return e
		}
		return r.output(cmd, p)
	}}
	add.Flags().StringVar(&name, "name", "", "Profile name (required)")
	add.Flags().StringVar(&path, "path", "", "Filesystem directory")
	add.Flags().StringVar(&endpoint, "endpoint", "", "Custom HTTPS S3 endpoint")
	add.Flags().StringVar(&bucket, "bucket", "", "Private bucket")
	add.Flags().StringVar(&region, "region", "auto", "S3 region")
	add.Flags().StringVar(&prefix, "prefix", "envport", "Object prefix")
	add.Flags().StringVar(&awsProfile, "aws-profile", "", "AWS credential profile reference")
	add.Flags().BoolVar(&pathStyle, "path-style", true, "Use path-style S3 addressing")
	add.Flags().BoolVar(&allowHTTP, "allow-http", false, "Permit HTTP for isolated local tests")
	add.Flags().StringVar(&connection, "connection", "", "Signed LAN connection file from host authorization")
	add.Flags().StringVar(&serverFingerprint, "server-fingerprint", "", "Out-of-band trusted LAN host certificate fingerprint")
	group.AddCommand(add)
	r.addLANStorage(group)
	group.AddCommand(&cobra.Command{Use: "list", Short: "List profiles without credentials", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		p, e := r.app.Profiles(cmd.Context())
		if e != nil {
			return e
		}
		return r.output(cmd, p)
	}})
	group.AddCommand(&cobra.Command{Use: "test <name>", Short: "Verify object operations and concurrent conditional writes", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		p, e := r.app.Profile(cmd.Context(), args[0])
		if e != nil {
			return e
		}
		if r.noNetwork && p.Driver != "filesystem" {
			return errors.New("network disabled")
		}
		st, e := r.openStore(cmd.Context(), p)
		if e != nil {
			return e
		}
		defer st.Close()
		caps, e := storage.Probe(cmd.Context(), st)
		if e != nil {
			return e
		}
		if p.Driver == "s3" {
			var c s3store.Config
			_ = json.Unmarshal(p.Options, &c)
			c.Verified = caps.Verified
			p.Options, _ = json.Marshal(c)
			b, _ := json.Marshal(p)
			if _, e = r.db.ExecContext(cmd.Context(), "UPDATE storage_profiles SET config=? WHERE name=?", b, p.Name); e != nil {
				return e
			}
		}
		if p.Driver == "lan" {
			var c lanhost.Config
			if json.Unmarshal(p.Options, &c) != nil {
				return errors.New("invalid LAN profile")
			}
			c.Verified = caps.Verified
			p.Options, _ = json.Marshal(c)
			b, _ := json.Marshal(p)
			if _, e = r.db.ExecContext(cmd.Context(), "UPDATE storage_profiles SET config=? WHERE name=?", b, p.Name); e != nil {
				return e
			}
		}
		return r.output(cmd, caps)
	}})
	group.AddCommand(&cobra.Command{Use: "remove <name>", Short: "Remove an unused profile without deleting stored objects", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error { return r.app.RemoveProfile(cmd.Context(), args[0]) }})
	r.root.AddCommand(group)
}
func (r *runner) addProjects() {
	var local bool
	track := &cobra.Command{Use: "track <path>", Short: "Explicitly enroll discovered files", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		v, e := r.selected(cmd)
		if e != nil {
			return e
		}
		p, e := r.app.Track(cmd.Context(), v, args[0], local)
		if e != nil {
			return e
		}
		return r.output(cmd, p)
	}}
	track.Flags().BoolVar(&local, "local", false, "Assign explicit UUID identity without Git remote matching")
	r.root.AddCommand(track)
	r.root.AddCommand(&cobra.Command{Use: "projects", Short: "List local project mappings", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		v, e := r.selected(cmd)
		if e != nil {
			return e
		}
		p, e := r.app.Projects(cmd.Context(), v)
		if e != nil {
			return e
		}
		return r.output(cmd, p)
	}})
	group := &cobra.Command{Use: "project", Short: "Manage explicit project mappings"}
	group.AddCommand(&cobra.Command{Use: "map <project-id> <path>", Short: "Map a remote project to a checkout", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		v, e := r.selected(cmd)
		if e != nil {
			return e
		}
		return r.app.MapProject(cmd.Context(), v, domain.ID(args[0]), args[1])
	}})
	r.root.AddCommand(group)
	file := &cobra.Command{Use: "file", Short: "Manage tracked files"}
	var confirm bool
	remove := &cobra.Command{Use: "remove <file-id>", Short: "Stage an explicit remote tombstone; leave local bytes intact", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if !confirm {
			return errors.New("--confirm is required to stage a tombstone")
		}
		v, e := r.selected(cmd)
		if e != nil {
			return e
		}
		return r.app.RemoveFile(cmd.Context(), v, domain.ID(args[0]))
	}}
	remove.Flags().BoolVar(&confirm, "confirm", false, "Confirm explicit remote removal")
	file.AddCommand(remove)
	r.root.AddCommand(file)
}
func (r *runner) addKeys() {
	group := &cobra.Command{Use: "keys", Short: "Export and verify encrypted recovery bundles"}
	var output string
	export := &cobra.Command{Use: "export", Short: "Export a separately passphrase-protected recovery bundle", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if output == "" {
			return errors.New("--output is required")
		}
		v, e := r.selected(cmd)
		if e != nil {
			return e
		}
		if e = r.app.ExportRecovery(cmd.Context(), v, output); e != nil {
			return e
		}
		return r.output(cmd, map[string]string{"recovery": "exported and decryption verified", "action": "store bundle and its independent passphrase separately from this device"})
	}}
	export.Flags().StringVar(&output, "output", "", "Destination (must not exist)")
	group.AddCommand(export)
	group.AddCommand(&cobra.Command{Use: "verify <bundle>", Short: "Decrypt and verify recovery against selected vault", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		v, e := r.selected(cmd)
		if e != nil {
			return e
		}
		if e = r.app.VerifyRecovery(cmd.Context(), v, args[0]); e != nil {
			return e
		}
		return r.output(cmd, map[string]bool{"verified": true})
	}})
	r.root.AddCommand(group)
}
func (r *runner) addOperations() {
	for _, operation := range []string{"backup", "sync", "status"} {
		operation := operation
		var dry, accept bool
		cmd := &cobra.Command{Use: operation, Short: map[string]string{"backup": "Commit changed files as an immutable encrypted snapshot", "sync": "Plan and synchronize with three-way conflict detection", "status": "Preview local, base and remote state"}[operation], Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			v, e := r.selected(cmd)
			if e != nil {
				return e
			}
			if operation == "sync" && !dry {
				if e = r.app.Reconcile(cmd.Context(), v); e != nil {
					return e
				}
				v, e = r.selected(cmd)
				if e != nil {
					return e
				}
			}
			plan, e := r.app.PlanSync(cmd.Context(), v)
			if e != nil {
				return e
			}
			if dry || operation == "status" {
				return r.output(cmd, plan)
			}
			if !r.json {
				if e = r.output(cmd, plan); e != nil {
					return e
				}
			}
			res, e := r.app.Execute(cmd.Context(), v, plan, operation == "sync", accept)
			if e != nil {
				return e
			}
			return r.output(cmd, res)
		}}
		if operation != "status" {
			cmd.Flags().BoolVar(&dry, "dry-run", false, "Preview without changing files or remote objects")
		}
		if operation == "sync" {
			cmd.Flags().BoolVar(&accept, "accept-remote", false, "Explicitly replace unchanged existing files, preserving private preimages")
		}
		r.root.AddCommand(cmd)
	}
	var snapshot string
	var roots []string
	var dry, accept bool
	restoreCmd := &cobra.Command{Use: "restore", Short: "Preview or restore authenticated bytes into approved mappings", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		v, e := r.selected(cmd)
		if e != nil {
			return e
		}
		if len(roots) > 0 {
			if e = r.app.AutoMap(cmd.Context(), v, roots); e != nil {
				return e
			}
		}
		p, e := r.app.PlanRestore(cmd.Context(), v, domain.ID(snapshot))
		if e != nil {
			return e
		}
		if dry {
			return r.output(cmd, p)
		}
		if !r.json {
			if e = r.output(cmd, p); e != nil {
				return e
			}
		}
		res, e := r.app.ExecuteRestore(cmd.Context(), v, p, accept)
		if e != nil {
			return e
		}
		return r.output(cmd, res)
	}}
	restoreCmd.Flags().StringVar(&snapshot, "snapshot", "", "Historical snapshot ID")
	restoreCmd.Flags().StringSliceVar(&roots, "scan", nil, "Explicit checkout roots for Git mapping")
	restoreCmd.Flags().BoolVar(&dry, "dry-run", false, "Preview without writing secret files")
	restoreCmd.Flags().BoolVar(&accept, "accept-remote", false, "Replace existing files after preview; retain preimages")
	r.root.AddCommand(restoreCmd)
	r.root.AddCommand(&cobra.Command{Use: "history", Aliases: []string{"snapshots"}, Short: "List authenticated history without secret values", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		v, e := r.selected(cmd)
		if e != nil {
			return e
		}
		history, e := r.app.History(cmd.Context(), v)
		if e != nil {
			return e
		}
		type item struct {
			ID         domain.ID `json:"id"`
			Generation int64     `json:"generation"`
			Created    string    `json:"created_at"`
			Projects   int       `json:"projects"`
		}
		out := []item{}
		for _, m := range history {
			out = append(out, item{m.ID, m.Generation, m.Created.Format("2006-01-02T15:04:05Z"), len(m.Projects)})
		}
		return r.output(cmd, out)
	}})
	r.root.AddCommand(&cobra.Command{Use: "doctor", Short: "Verify database, keys, history and restore readiness", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		v, e := r.selected(cmd)
		if e != nil {
			return e
		}
		checks, e := r.app.Doctor(cmd.Context(), v)
		if e != nil {
			return e
		}
		if e = r.output(cmd, checks); e != nil {
			return e
		}
		for _, check := range checks {
			if !check.OK {
				return errors.New("doctor found issues")
			}
		}
		return nil
	}})
	var pruneDry bool
	prune := &cobra.Command{Use: "prune", Short: "Preview unreferenced objects; deletion is disabled", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if !pruneDry {
			return errors.New("only prune --dry-run is supported; garbage collection is disabled")
		}
		v, e := r.selected(cmd)
		if e != nil {
			return e
		}
		out, e := r.app.PrunePreview(cmd.Context(), v)
		if e != nil {
			return e
		}
		return r.output(cmd, out)
	}}
	prune.Flags().BoolVar(&pruneDry, "dry-run", false, "Preview only")
	r.root.AddCommand(prune)
	var keepLocal bool
	resolve := &cobra.Command{Use: "resolve <file-id>", Short: "Explicitly keep local bytes in a conflicted file; then run sync", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if !keepLocal {
			return errors.New("choose --keep-local; remote history remains recoverable")
		}
		v, e := r.selected(cmd)
		if e != nil {
			return e
		}
		return r.app.ResolveLocal(cmd.Context(), v, domain.ID(args[0]))
	}}
	resolve.Flags().BoolVar(&keepLocal, "keep-local", false, "Keep local bytes over observed remote version")
	r.root.AddCommand(resolve)
}
func Execute() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	cmd := New()
	if e := cmd.ExecuteContext(ctx); e != nil {
		fmt.Fprintln(os.Stderr, "Error:", e)
		switch {
		case errors.Is(e, domain.ErrConflict):
			return 3
		case errors.Is(e, domain.ErrPrecondition):
			return 4
		case errors.Is(e, domain.ErrCorrupt) || errors.Is(e, domain.ErrRollback):
			return 5
		default:
			return 1
		}
	}
	return 0
}

func (r *runner) addDevices() {
	group := &cobra.Command{Use: "devices", Short: "Pair devices using signed, encrypted grants and confirmed fingerprints"}
	var vaultID, requestOutput string
	request := &cobra.Command{Use: "request", Short: "Create a signed 30-minute join request on the new device", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if requestOutput == "" {
			return errors.New("--output is required")
		}
		info, e := r.app.RequestDevice(cmd.Context(), domain.ID(vaultID), requestOutput)
		if e != nil {
			return e
		}
		return r.output(cmd, info)
	}}
	request.Flags().StringVar(&vaultID, "vault-id", "", "Vault ID from existing device")
	request.Flags().StringVar(&requestOutput, "output", "", "New request file")
	group.AddCommand(request)
	var approvalOutput, fingerprint string
	approve := &cobra.Command{Use: "approve <request>", Short: "Approve only after comparing request fingerprint out of band", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if approvalOutput == "" || fingerprint == "" {
			return errors.New("--output and --fingerprint are required")
		}
		v, e := r.selected(cmd)
		if e != nil {
			return e
		}
		info, e := r.app.ApproveDevice(cmd.Context(), v, args[0], approvalOutput, fingerprint)
		if e != nil {
			return e
		}
		return r.output(cmd, info)
	}}
	approve.Flags().StringVar(&approvalOutput, "output", "", "Encrypted grant destination")
	approve.Flags().StringVar(&fingerprint, "fingerprint", "", "Confirmed request fingerprint from new device")
	group.AddCommand(approve)
	group.AddCommand(&cobra.Command{Use: "list", Short: "Inspect this installation identity and observed local approvals", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		id, e := r.app.Device(cmd.Context())
		if e != nil {
			return e
		}
		rows, e := r.db.QueryContext(cmd.Context(), "SELECT value FROM settings WHERE key LIKE 'approved_request:%' ORDER BY key")
		if e != nil {
			return e
		}
		defer rows.Close()
		approved := []string{}
		for rows.Next() {
			var device string
			if e = rows.Scan(&device); e != nil {
				return e
			}
			approved = append(approved, device)
		}
		if e = rows.Err(); e != nil {
			return e
		}
		return r.output(cmd, map[string]any{"this_device": id, "locally_approved_devices": approved, "revocation": "not implemented; copied vault keys cannot be revoked retroactively"})
	}})
	r.root.AddCommand(group)
}

func (r *runner) addMigration() {
	var source, snapshot, profile, name, recovery, receipt string
	var dry bool
	cmd := &cobra.Command{Use: "migrate-legacy", Short: "Read-only import of the starter's AES snapshot into a separate age vault", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if source == "" || snapshot == "" {
			return errors.New("--source and --snapshot are required")
		}
		out, e := r.app.MigrateLegacy(cmd.Context(), name, profile, source, domain.ID(snapshot), recovery, receipt, dry)
		if e != nil {
			return e
		}
		return r.output(cmd, out)
	}}
	cmd.Flags().StringVar(&source, "source", "", "Original starter ENVPORT_HOME (read-only)")
	cmd.Flags().StringVar(&snapshot, "snapshot", "", "Original snapshot ID")
	cmd.Flags().StringVar(&profile, "storage", "local", "Verified destination profile")
	cmd.Flags().StringVar(&name, "name", "migrated", "New independent vault name")
	cmd.Flags().StringVar(&recovery, "recovery-output", "", "New encrypted recovery bundle")
	cmd.Flags().StringVar(&receipt, "receipt", "", "New verification receipt")
	cmd.Flags().BoolVar(&dry, "dry-run", false, "Authenticate source without creating a vault")
	r.root.AddCommand(cmd)
}

// Close device state on failed commands too; Cobra post-run hooks run only on success.
func (r *runner) wrapCommands(parent *cobra.Command) {
	for _, cmd := range parent.Commands() {
		if cmd.RunE != nil {
			run := cmd.RunE
			cmd.RunE = func(cmd *cobra.Command, args []string) (err error) {
				defer func() {
					if r.db != nil {
						closeErr := r.db.Close()
						r.db = nil
						if err == nil {
							err = closeErr
						}
					}
				}()
				return run(cmd, args)
			}
		}
		r.wrapCommands(cmd)
	}
}
