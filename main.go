package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/josh/restic-api/api/backend"
	"github.com/josh/restic-api/api/backend/all"
	"github.com/josh/restic-api/api/backend/limiter"
	"github.com/josh/restic-api/api/backend/location"
	"github.com/josh/restic-api/api/backend/logger"
	"github.com/josh/restic-api/api/backend/rclone"
	"github.com/josh/restic-api/api/backend/retry"
	"github.com/josh/restic-api/api/backend/sema"
	"github.com/josh/restic-api/api/crypto"
	"github.com/josh/restic-api/api/errors"
	"github.com/josh/restic-api/api/global"
	resticopts "github.com/josh/restic-api/api/options"
	"github.com/josh/restic-api/api/repository"
	"github.com/josh/restic-api/api/restic"
	"github.com/josh/restic-api/api/textfile"
	"github.com/restic/chunker"
	"github.com/spf13/cobra"
)

// constants settable at build time.
var (
	AgeProgram    = "age"
	RcloneProgram = "rclone"
	Version       = "1.1.4"
)

// errNoRepository mirrors restic's sentinel for a missing backend or config
// file, so the same condition maps to the same exit code.
var errNoRepository = errors.New("repository does not exist")

type options struct {
	ageProgram         string
	rcloneProgram      string
	repo               string
	repositoryFile     string
	repoResolved       bool
	fromRepo           string
	password           string
	passwordEnv        string
	passwordFile       string
	passwordCommand    string
	insecureNoPassword bool
	identityFile       string
	identityCommand    string
	recipient          string
	recipientsFile     string
	host               string
	user               string
	output             string
	timeout            time.Duration
	keyHint            string
	extended           []string
	transport          backend.TransportOptions
	limits             limiter.Limits
	dryRun             bool
	json               bool
	chunkerPolynomial  string
	ifNotExists        bool
}

func newRootCommand() *cobra.Command {
	options := options{
		ageProgram:        AgeProgram,
		rcloneProgram:     RcloneProgram,
		repo:              os.Getenv("RESTIC_REPOSITORY"),
		repositoryFile:    os.Getenv("RESTIC_REPOSITORY_FILE"),
		fromRepo:          os.Getenv("RESTIC_FROM_REPOSITORY"),
		passwordEnv:       os.Getenv("RESTIC_PASSWORD"),
		passwordFile:      os.Getenv("RESTIC_PASSWORD_FILE"),
		passwordCommand:   os.Getenv("RESTIC_PASSWORD_COMMAND"),
		identityFile:      os.Getenv("RESTIC_AGE_IDENTITY_FILE"),
		identityCommand:   os.Getenv("RESTIC_AGE_IDENTITY_COMMAND"),
		recipient:         os.Getenv("RESTIC_AGE_RECIPIENT"),
		recipientsFile:    os.Getenv("RESTIC_AGE_RECIPIENTS_FILE"),
		user:              os.Getenv("RESTIC_AGE_USER"),
		host:              os.Getenv("RESTIC_AGE_HOST"),
		chunkerPolynomial: os.Getenv("RESTIC_AGE_CHUNKER_POLYNOMIAL"),
		keyHint:           os.Getenv("RESTIC_KEY_HINT"),
	}

	options.transport.TLSClientCertKeyFilename = os.Getenv("RESTIC_TLS_CLIENT_CERT")
	options.transport.HTTPUserAgent = os.Getenv("RESTIC_HTTP_USER_AGENT")
	if certs := os.Getenv("RESTIC_CACERT"); certs != "" {
		options.transport.RootCertFilenames = strings.Split(certs, ",")
	}

	if timeoutStr := os.Getenv("RESTIC_AGE_TIMEOUT"); timeoutStr != "" {
		if duration, err := time.ParseDuration(timeoutStr); err == nil {
			options.timeout = duration
		} else {
			fmt.Fprintf(os.Stderr, "warn: invalid timeout format in RESTIC_AGE_TIMEOUT: %s\n", err)
		}
	}

	if options.host == "" {
		if hostname, err := os.Hostname(); err == nil {
			options.host = hostname
		}
	}

	if options.user == "" {
		if user, err := user.Current(); err == nil {
			options.user = user.Username
		}
	}

	if options.ageProgram == "" || options.ageProgram == "age" {
		if path, err := exec.LookPath("age"); err == nil {
			options.ageProgram = path
		}
	}

	if options.rcloneProgram == "" || options.rcloneProgram == "rclone" {
		if path, err := exec.LookPath("rclone"); err == nil {
			options.rcloneProgram = path
		}
	}

	cmd := &cobra.Command{
		Use:   "restic-age-key",
		Short: "Manage age-based encryption keys for restic repositories",
		Long: `restic-age-key allows you to manage age-based encryption keys for restic repositories.
It supports listing existing keys, adding new keys, and retrieving passwords.`,
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		Version:           Version,
	}

	cmd.PersistentFlags().StringVar(&options.ageProgram, "age-program", options.ageProgram, "path to age binary")
	cmd.PersistentFlags().StringVar(&options.rcloneProgram, "rclone-program", options.rcloneProgram, "path to rclone")
	cmd.PersistentFlags().StringVar(&options.identityFile, "identity-file", options.identityFile, "age identity file (env: RESTIC_AGE_IDENTITY_FILE)")
	cmd.PersistentFlags().StringVar(&options.identityCommand, "identity-command", options.identityCommand, "age identity command (env: RESTIC_AGE_IDENTITY_COMMAND)")
	cmd.PersistentFlags().DurationVar(&options.timeout, "timeout", options.timeout, "command timeout (env: RESTIC_AGE_TIMEOUT)")
	cmd.PersistentFlags().BoolVar(&options.json, "json", false, "set output mode to JSON for commands that support it")
	cmd.PersistentFlags().StringVar(&options.keyHint, "key-hint", options.keyHint, "key ID of key to try decrypting first (env: RESTIC_KEY_HINT)")
	cmd.PersistentFlags().StringSliceVarP(&options.extended, "option", "o", nil, "set extended option (key=value, can be specified multiple times)")
	cmd.PersistentFlags().StringSliceVar(&options.transport.RootCertFilenames, "cacert", options.transport.RootCertFilenames, "file to load root certificates from (env: RESTIC_CACERT)")
	cmd.PersistentFlags().StringVar(&options.transport.TLSClientCertKeyFilename, "tls-client-cert", options.transport.TLSClientCertKeyFilename, "path to a file containing PEM encoded TLS client certificate and private key (env: RESTIC_TLS_CLIENT_CERT)")
	cmd.PersistentFlags().BoolVar(&options.transport.InsecureTLS, "insecure-tls", false, "skip TLS certificate verification when connecting to the repository (insecure)")
	cmd.PersistentFlags().StringVar(&options.transport.HTTPUserAgent, "http-user-agent", options.transport.HTTPUserAgent, "set a http user agent for outgoing http requests (env: RESTIC_HTTP_USER_AGENT)")
	cmd.PersistentFlags().DurationVar(&options.transport.StuckRequestTimeout, "stuck-request-timeout", 5*time.Minute, "duration after which to retry stuck requests")
	cmd.PersistentFlags().IntVar(&options.limits.UploadKb, "limit-upload", 0, "limits uploads to a maximum rate in KiB/s. (default: unlimited)")
	cmd.PersistentFlags().IntVar(&options.limits.DownloadKb, "limit-download", 0, "limits downloads to a maximum rate in KiB/s. (default: unlimited)")

	addDecryptRepoCommands := func(cmd *cobra.Command) {
		cmd.PreRunE = func(*cobra.Command, []string) error {
			return validatePasswordSources(options)
		}
		cmd.Flags().StringVarP(&options.repo, "repo", "r", options.repo, "restic repository location (env: RESTIC_REPOSITORY)")
		cmd.Flags().StringVar(&options.repositoryFile, "repository-file", options.repositoryFile, "file to read the repository location from (env: RESTIC_REPOSITORY_FILE)")
		cmd.Flags().StringVar(&options.password, "password", "", "restic repository password (env: RESTIC_PASSWORD)")
		cmd.Flags().StringVarP(&options.passwordFile, "password-file", "p", options.passwordFile, "restic repository password file (env: RESTIC_PASSWORD_FILE)")
		cmd.Flags().StringVar(&options.passwordCommand, "password-command", options.passwordCommand, "restic repository password command (env: RESTIC_PASSWORD_COMMAND)")
		cmd.Flags().BoolVar(&options.insecureNoPassword, "insecure-no-password", false, "use an empty password for the repository, must be passed to every restic command (insecure)")
	}

	listCommand := &cobra.Command{
		Use:   "list",
		Short: "List all keys in the repository",
		Long: `The list command lists all keys stored in the repository.

EXIT STATUS
===========

Exit status is 0 if the command was successful.
Exit status is 1 if there was any error.
Exit status is 10 if the repository does not exist.
Exit status is 11 if the repository is already locked.
Exit status is 12 if the password is incorrect.
`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCommand(cmd, args, options.timeout, func(ctx context.Context) error {
				return runKeyList(ctx, options)
			})
		},
	}
	addDecryptRepoCommands(listCommand)

	addCommand := &cobra.Command{
		Use:   "add",
		Short: "Add a new key to the repository",
		Long: `The add command adds a new age-encrypted key to the repository.

EXIT STATUS
===========

Exit status is 0 if the command was successful.
Exit status is 1 if there was any error.
Exit status is 10 if the repository does not exist.
Exit status is 11 if the repository is already locked.
Exit status is 12 if the password is incorrect.
`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCommand(cmd, args, options.timeout, func(ctx context.Context) error {
				return runKeyAdd(ctx, options)
			})
		},
	}
	addDecryptRepoCommands(addCommand)
	addCommand.Flags().StringVar(&options.recipient, "recipient", options.recipient, "age recipient public key (env: RESTIC_AGE_RECIPIENT)")
	addCommand.Flags().StringVar(&options.host, "host", options.host, "the hostname for new key")
	addCommand.Flags().StringVar(&options.user, "user", options.user, "the username for new key")
	addCommand.Flags().StringVar(&options.output, "output", "", "output file to write key id to")
	addCommand.Flags().BoolVar(&options.dryRun, "dry-run", false, "do not add key, just show what would be done")

	setCommand := &cobra.Command{
		Use:   "set",
		Short: "Set keys in the repository based on a recipients file",
		Long: `The set command adds missing pubkeys, updates user and host metadata for existing
pubkeys, and removes keys that aren't present in the recipients file.

EXIT STATUS
===========

Exit status is 0 if the command was successful.
Exit status is 1 if there was any error.
Exit status is 10 if the repository does not exist.
Exit status is 11 if the repository is already locked.
Exit status is 12 if the password is incorrect.
`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCommand(cmd, args, options.timeout, func(ctx context.Context) error {
				return runKeySet(ctx, options)
			})
		},
	}
	addDecryptRepoCommands(setCommand)
	setCommand.Flags().StringVar(&options.recipientsFile, "recipients-file", options.recipientsFile, "file containing age recipient public keys (env: RESTIC_AGE_RECIPIENTS_FILE)")
	setCommand.Flags().BoolVar(&options.dryRun, "dry-run", false, "do not add or remove keys, just show what would be done")

	passwordCommand := &cobra.Command{
		Use:   "password",
		Short: "Retrieve the password for a key",
		Long: `The password command decrypts and prints the repository password using an age identity.

EXIT STATUS
===========

Exit status is 0 if the command was successful.
Exit status is 1 if there was any error.
Exit status is 10 if the repository does not exist.
Exit status is 11 if the repository is already locked.
Exit status is 12 if the password is incorrect.
`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCommand(cmd, args, options.timeout, func(ctx context.Context) error {
				return runKeyPassword(ctx, options)
			})
		},
	}
	passwordCommand.Flags().StringVarP(&options.repo, "repo", "r", options.repo, "restic repository location (env: RESTIC_REPOSITORY)")
	passwordCommand.Flags().StringVar(&options.repositoryFile, "repository-file", options.repositoryFile, "file to read the repository location from (env: RESTIC_REPOSITORY_FILE)")
	passwordCommand.Flags().StringVar(&options.output, "output", "", "output file to write password to")

	fromPasswordCommand := &cobra.Command{
		Use:   "from-password",
		Short: "Retrieve the password for a key",
		Long: `The from-password command decrypts and prints the password of the repository given by --from-repo.

EXIT STATUS
===========

Exit status is 0 if the command was successful.
Exit status is 1 if there was any error.
Exit status is 10 if the repository does not exist.
Exit status is 11 if the repository is already locked.
Exit status is 12 if the password is incorrect.
`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCommand(cmd, args, options.timeout, func(ctx context.Context) error {
				if options.fromRepo == "" {
					return errors.Fatal("Please specify repository location (--from-repo or RESTIC_FROM_REPOSITORY)")
				}
				options.repo = options.fromRepo
				options.repoResolved = true
				return runKeyPassword(ctx, options)
			})
		},
	}
	fromPasswordCommand.Flags().StringVar(&options.fromRepo, "from-repo", options.fromRepo, "restic repository location (env: RESTIC_FROM_REPOSITORY)")
	fromPasswordCommand.Flags().StringVar(&options.output, "output", "", "output file to write password to")

	repoInitCommand := &cobra.Command{
		Use:   "repo-init",
		Short: "Initialize a new repository with an age encrypted key",
		Long: `The repo-init command creates a new repository whose key is encrypted to one or more age recipients.

EXIT STATUS
===========

Exit status is 0 if the command was successful.
Exit status is 1 if there was any error.
Exit status is 10 if the repository does not exist.
Exit status is 11 if the repository is already locked.
Exit status is 12 if the password is incorrect.
`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCommand(cmd, args, options.timeout, func(ctx context.Context) error {
				return runRepoInit(ctx, options)
			})
		},
	}
	repoInitCommand.PreRunE = func(*cobra.Command, []string) error {
		return validatePasswordSources(options)
	}
	repoInitCommand.Flags().StringVarP(&options.repo, "repo", "r", options.repo, "repository location (env: RESTIC_REPOSITORY)")
	repoInitCommand.Flags().StringVar(&options.repositoryFile, "repository-file", options.repositoryFile, "file to read the repository location from (env: RESTIC_REPOSITORY_FILE)")
	repoInitCommand.Flags().StringVar(&options.recipient, "recipient", options.recipient, "age recipient public key (env: RESTIC_AGE_RECIPIENT)")
	repoInitCommand.Flags().StringVar(&options.recipientsFile, "recipients-file", options.recipientsFile, "file containing age recipient public keys (env: RESTIC_AGE_RECIPIENTS_FILE)")
	repoInitCommand.Flags().StringVar(&options.user, "user", options.user, "username for key (env: RESTIC_AGE_USER)")
	repoInitCommand.Flags().StringVar(&options.host, "host", options.host, "hostname for key (env: RESTIC_AGE_HOST)")
	repoInitCommand.Flags().StringVar(&options.chunkerPolynomial, "chunker-polynomial", options.chunkerPolynomial, "chunker polynomial in hex format (e.g. 0x3DA3358B4DC173) (env: RESTIC_AGE_CHUNKER_POLYNOMIAL)")
	repoInitCommand.Flags().StringVar(&options.output, "output", "", "output file to write key ID to")
	repoInitCommand.Flags().BoolVar(&options.ifNotExists, "if-not-exists", false, "succeed if the repository already exists; --recipient is creation-only, while --recipients-file reconciles existing keys")

	cmd.AddCommand(
		listCommand,
		addCommand,
		setCommand,
		passwordCommand,
		fromPasswordCommand,
		repoInitCommand,
	)

	return cmd
}

// runCommand rejects stray positional arguments the way restic does, then runs
// fn under the configured timeout.
func runCommand(cmd *cobra.Command, args []string, timeout time.Duration, fn func(context.Context) error) error {
	if len(args) > 0 {
		name := cmd.Name()
		return fmt.Errorf("the %s command expects no arguments, only options - please see `restic-age-key help %s` for usage and flags", name, name)
	}

	if timeout <= 0 {
		return fn(cmd.Context())
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()
	return fn(ctx)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err := newRootCommand().ExecuteContext(ctx)
	if err == nil {
		return
	}

	fmt.Fprintf(os.Stderr, "%v\n", err)
	os.Exit(exitCode(err))
}

// exitCode maps errors to the exit codes documented by restic, so scripts can
// tell a missing repository from a locked one or a bad password.
func exitCode(err error) int {
	switch {
	case errors.Is(err, errNoRepository):
		return 10
	case restic.IsAlreadyLocked(err):
		return 11
	case errors.Is(err, repository.ErrNoKeyFound):
		return 12
	case errors.Is(err, context.Canceled):
		return 130
	default:
		return 1
	}
}

type AgeKey struct {
	Created  time.Time `json:"created"`
	Username string    `json:"username"`
	Hostname string    `json:"hostname"`

	KDF  string `json:"kdf"`
	N    int    `json:"N"`
	R    int    `json:"r"`
	P    int    `json:"p"`
	Salt []byte `json:"salt"`
	Data []byte `json:"data"`

	AgePubkey string `json:"age-pubkey"`
	AgeData   []byte `json:"age-data"`
}

type Recipient struct {
	ID     restic.ID
	Pubkey string `json:"pubkey"`
	Host   string `json:"host"`
	User   string `json:"user"`
}

type ListKey struct {
	IsCurrent bool   `json:"current"`
	ID        string `json:"id"`
	ShortID   string `json:"-"`
	AgePubkey string `json:"agePubkey"`
	Username  string `json:"userName"`
	Hostname  string `json:"hostName"`
	Created   string `json:"created"`
}

func runKeyList(ctx context.Context, opts options) error {
	if err := resolveRepo(&opts); err != nil {
		return err
	}

	repo, be, _, err := openRepositoryWithPassword(ctx, opts)
	if err != nil {
		return err
	}
	defer func() {
		_ = be.Close()
	}()

	var keys []ListKey

	currentKeyID := repo.KeyID()
	currentKeyIDStr := currentKeyID.String()

	err = repo.List(ctx, restic.KeyFile, func(id restic.ID, size int64) error {
		data, err := repo.LoadRaw(ctx, restic.KeyFile, id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "LoadKey() failed: %v\n", err)
			return nil
		}

		k := &AgeKey{}
		err = json.Unmarshal(data, k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "LoadKey() failed: %v\n", err)
			return nil
		}

		idStr := id.String()
		isCurrent := idStr == currentKeyIDStr

		keys = append(keys, ListKey{
			ID:        idStr,
			ShortID:   id.Str(),
			IsCurrent: isCurrent,
			AgePubkey: k.AgePubkey,
			Username:  k.Username,
			Hostname:  k.Hostname,
			Created:   k.Created.Local().Format(global.TimeFormat),
		})

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to list repository files: %w", err)
	}

	if opts.json {
		return json.NewEncoder(os.Stdout).Encode(keys)
	}

	headers := []string{" ID", "Age Pubkey", "User", "Host", "Created"}
	rows := make([][]string, 0, len(keys))

	for _, key := range keys {
		currentMarker := " "
		if key.IsCurrent {
			currentMarker = "*"
		}

		markedID := currentMarker + key.ShortID

		row := []string{
			markedID,
			key.AgePubkey,
			key.Username,
			key.Hostname,
			key.Created,
		}
		rows = append(rows, row)
	}

	printTable(headers, rows)

	return nil
}

type preparedAgeKey struct {
	id       restic.ID
	raw      []byte
	password string
}

type encryptedAgePassword struct {
	password string
	data     []byte
}

func prepareAgeKey(recipient, host, user string, master crypto.Key, encrypted encryptedAgePassword) (preparedAgeKey, error) {
	params, err := crypto.Calibrate(500*time.Millisecond, 60)
	if err != nil {
		return preparedAgeKey{}, fmt.Errorf("failed to calibrate crypto parameters: %w", err)
	}

	newkey := &AgeKey{
		Created: time.Now(),
		KDF:     "scrypt",
		N:       params.N,
		R:       params.R,
		P:       params.P,
	}

	newkey.Hostname = host
	if newkey.Hostname == "" {
		return preparedAgeKey{}, errors.New("hostname is empty")
	}

	newkey.Username = user
	if newkey.Username == "" {
		return preparedAgeKey{}, errors.New("username is empty")
	}

	newkey.Salt, err = crypto.NewSalt()
	if err != nil {
		return preparedAgeKey{}, fmt.Errorf("failed to generate new salt: %w", err)
	}

	newkey.AgePubkey = recipient
	newkey.AgeData = encrypted.data

	userKey, err := crypto.KDF(params, newkey.Salt, encrypted.password)
	if err != nil {
		return preparedAgeKey{}, fmt.Errorf("failed to generate key from password: %w", err)
	}

	buf, err := json.Marshal(&master)
	if err != nil {
		return preparedAgeKey{}, fmt.Errorf("failed to marshal repository key: %w", err)
	}

	nonce := crypto.NewRandomNonce()
	ciphertext := make([]byte, 0, crypto.CiphertextLength(len(buf)))
	ciphertext = append(ciphertext, nonce...)
	ciphertext = userKey.Seal(ciphertext, nonce, buf, nil)
	newkey.Data = ciphertext

	buf, err = json.Marshal(newkey)
	if err != nil {
		return preparedAgeKey{}, fmt.Errorf("failed to marshal new key: %w", err)
	}

	return preparedAgeKey{
		id:       restic.Hash(buf),
		raw:      buf,
		password: encrypted.password,
	}, nil
}

func savePreparedAgeKey(ctx context.Context, repo *repository.Repository, be backend.Backend, key preparedAgeKey, adoptExisting, dryRun bool) (bool, error) {
	if dryRun {
		return false, nil
	}

	h := backend.Handle{Type: restic.KeyFile, Name: key.id.String()}

	if adoptExisting {
		// Probe with Stat rather than Load: the retry backend treats a missing
		// file as permanent for Stat only, so a Load here would retry and log
		// on the common path where the key does not exist yet.
		_, err := be.Stat(ctx, h)
		switch {
		case err == nil:
			adopted, err := adoptExistingAgeKey(ctx, repo, be, key)
			if err != nil || adopted {
				return false, err
			}
		case be.IsNotExist(err):
		default:
			return false, fmt.Errorf("failed to check key before saving: %w", err)
		}
	}

	if err := be.Save(ctx, h, backend.NewByteReader(key.raw, be.Hasher())); err != nil {
		cleanupErr := cleanupUnverifiedKey(ctx, repo, be, key.id)
		if cleanupErr != nil {
			return false, fmt.Errorf("failed to save key to backend: %v; failed to remove it: %w", err, cleanupErr)
		}
		return false, fmt.Errorf("failed to save key to backend: %w", err)
	}

	return true, nil
}

// adoptExistingAgeKey inspects a key file that already carries the expected ID.
// It reports whether that file can be kept as-is; a corrupt file is removed so
// the caller can write it again.
func adoptExistingAgeKey(ctx context.Context, repo *repository.Repository, be backend.Backend, key preparedAgeKey) (bool, error) {
	saved, err := repo.LoadRaw(ctx, restic.KeyFile, key.id)
	switch {
	case err == nil:
		if !bytes.Equal(saved, key.raw) {
			return false, errors.New("existing key differs from expected content")
		}
		return true, nil
	case errors.Is(err, restic.ErrInvalidData):
		if err := repository.RemoveKey(ctx, repo, key.id); err != nil && !be.IsNotExist(err) {
			return false, fmt.Errorf("failed to remove corrupt key: %w", err)
		}
		return false, nil
	case be.IsNotExist(err):
		return false, nil
	default:
		return false, fmt.Errorf("failed to check key before saving: %w", err)
	}
}

func buildAndSaveAgeKey(ctx context.Context, recipient, host, user string, encrypted encryptedAgePassword, repo *repository.Repository, be backend.Backend, dryRun bool) (restic.ID, string, error) {
	if repo.Key() == nil {
		return restic.ID{}, "", errors.New("repo master key not loaded")
	}

	key, err := prepareAgeKey(recipient, host, user, *repo.Key(), encrypted)
	if err != nil {
		return restic.ID{}, "", err
	}

	if _, err := savePreparedAgeKey(ctx, repo, be, key, false, dryRun); err != nil {
		return restic.ID{}, "", err
	}

	return key.id, key.password, nil
}

func runKeyAdd(ctx context.Context, opts options) error {
	if err := resolveRepo(&opts); err != nil {
		return err
	}

	if err := validateOutputPaths(opts.output, []outputInput{
		{flag: "--identity-file", path: opts.identityFile},
		{flag: "--repository-file", path: opts.repositoryFile},
		{flag: "--password-file", path: opts.passwordFile},
	}); err != nil {
		return err
	}

	repo, be, currentPassword, err := openRepositoryWithPassword(ctx, opts)
	if err != nil {
		return err
	}
	defer func() {
		_ = be.Close()
	}()

	if opts.recipient == "" {
		return errors.Fatal("Please specify recipient (--recipient)")
	}
	if repo.Key() == nil {
		return errors.New("repo master key not loaded")
	}

	if opts.host == "" {
		return errors.New("hostname is empty")
	}
	if opts.user == "" {
		return errors.New("username is empty")
	}

	expectedMaster := *repo.Key()
	originalKeyID := repo.KeyID()
	password, ageData, err := ageEncryptRandomKey(ctx, opts.ageProgram, opts.recipient)
	if err != nil {
		return err
	}
	key, err := prepareAgeKey(opts.recipient, opts.host, opts.user, expectedMaster, encryptedAgePassword{password: password, data: ageData})
	if err != nil {
		return err
	}

	if !opts.dryRun {
		unlocker, lockedCtx, err := repository.Lock(ctx, repo, false, 0, func(string) {}, backendErrorLog)
		if err != nil {
			return fmt.Errorf("failed to lock repository: %w", err)
		}
		defer unlocker.Unlock()
		ctx = lockedCtx

		if _, err := verifyKeyAccess(ctx, be, originalKeyID, currentPassword, expectedMaster); err != nil {
			return fmt.Errorf("failed to verify repository key after acquiring lock: %w", err)
		}
	}

	if _, err := savePreparedAgeKey(ctx, repo, be, key, false, opts.dryRun); err != nil {
		return err
	}
	id := key.id

	if opts.dryRun {
		fmt.Fprintf(os.Stderr, "[DRY RUN] Add key %s for %s@%s\n", opts.recipient, opts.user, opts.host)
		return nil
	}

	fmt.Fprintf(os.Stderr, "Add key %s for %s@%s\n", opts.recipient, opts.user, opts.host)

	if opts.output != "" {
		file, err := os.OpenFile(opts.output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("failed to write key id to file: %w", err)
		}

		_, err = file.WriteString(id.Str() + "\n")
		if err != nil {
			_ = file.Close()
			return fmt.Errorf("failed to write key id to file: %w", err)
		}

		if err := file.Close(); err != nil {
			return fmt.Errorf("failed to write key id to file: %w", err)
		}
	}

	return nil
}

func runKeyPassword(ctx context.Context, opts options) error {
	if err := resolveRepo(&opts); err != nil {
		return err
	}

	if err := validateOutputPaths(opts.output, []outputInput{
		{flag: "--identity-file", path: opts.identityFile},
		{flag: "--repository-file", path: opts.repositoryFile},
	}); err != nil {
		return err
	}

	password, err := readPasswordViaIdentity(ctx, opts)
	if err != nil {
		return err
	}

	if opts.output != "" {
		file, err := os.OpenFile(opts.output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("failed to write password to file: %w", err)
		}

		if _, err := file.WriteString(password + "\n"); err != nil {
			_ = file.Close()
			return fmt.Errorf("failed to write password to file: %w", err)
		}

		if err := file.Close(); err != nil {
			return fmt.Errorf("failed to write password to file: %w", err)
		}
	} else {
		fmt.Printf("%s\n", password)
	}

	return nil
}

func runRepoInit(ctx context.Context, opts options) error {
	if err := resolveRepo(&opts); err != nil {
		return err
	}

	if opts.recipient == "" && opts.recipientsFile == "" {
		return errors.Fatal("Please specify recipient (--recipient) or recipients file (--recipients-file)")
	}

	if opts.recipient != "" && opts.recipientsFile != "" {
		return errors.Fatal("Cannot specify both --recipient and --recipients-file")
	}
	if err := validateOutputPaths(opts.output, []outputInput{
		{flag: "--identity-file", path: opts.identityFile},
		{flag: "--repository-file", path: opts.repositoryFile},
		{flag: "--recipients-file", path: opts.recipientsFile},
		{flag: "--password-file", path: opts.passwordFile},
	}); err != nil {
		return err
	}

	pol, err := parseChunkerPolynomial(opts.chunkerPolynomial)
	if err != nil {
		return fmt.Errorf("failed to get chunker polynomial: %w", err)
	}

	var recipients []Recipient
	if opts.recipientsFile != "" {
		recipients, err = readRecipientsFile(opts.recipientsFile)
		if err != nil {
			return fmt.Errorf("failed to read recipients file: %w", err)
		}

		if len(recipients) == 0 {
			return errors.Fatal("Recipients file contains no recipients")
		}

		recipients, _, err = prepareSetRecipients(recipients)
		if err != nil {
			return errors.Fatalf("Invalid recipients file: %v", err)
		}
	}

	var inspectErr error
	if opts.ifNotExists {
		state, err := inspectRepository(ctx, opts, opts.recipientsFile == "")
		if err != nil {
			if ctx.Err() != nil {
				return err
			}
			inspectErr = err
		}

		if err == nil && state.exists {
			if opts.recipientsFile != "" {
				if err := runKeySet(ctx, opts); err != nil {
					return err
				}
			} else {
				if len(state.ageKeys) == 0 {
					return errors.New("repository is incompletely initialized: no age-encrypted keys found")
				}

				if opts.output != "" {
					ids, missing := matchingAgeKeyIDs(state.ageKeys, []Recipient{{Pubkey: opts.recipient}})
					if len(missing) > 0 {
						return fmt.Errorf("recipient %s is not present in the existing repository", opts.recipient)
					}
					if err := writeRepoInitKeyIDs(opts.output, ids); err != nil {
						return err
					}
				}
			}

			fmt.Fprintf(os.Stderr, "repository already initialized at %s\n", repositoryDisplayLocation(opts.repo))
			return nil
		}
	}

	preflight := recipients
	if opts.recipientsFile == "" {
		preflight = []Recipient{{Pubkey: opts.recipient}}
	}
	encryptedPasswords := make(map[string]encryptedAgePassword, len(preflight))
	for _, recipient := range preflight {
		host := recipient.Host
		if host == "" {
			host = opts.host
		}
		if host == "" {
			return errors.New("hostname is empty")
		}

		user := recipient.User
		if user == "" {
			user = opts.user
		}
		if user == "" {
			return errors.New("username is empty")
		}

		password, data, err := ageEncryptRandomKey(ctx, opts.ageProgram, recipient.Pubkey)
		if err != nil {
			return fmt.Errorf("invalid age recipient %s: %w", recipient.Pubkey, err)
		}
		encryptedPasswords[recipient.Pubkey] = encryptedAgePassword{password: password, data: data}
	}

	if inspectErr != nil {
		return inspectErr
	}

	if pol == nil {
		pol, err = getChunkerPolynomial(opts)
		if err != nil {
			return fmt.Errorf("failed to get chunker polynomial: %w", err)
		}
	}

	var tempPasswordBuf [32]byte
	if _, err := rand.Read(tempPasswordBuf[:]); err != nil {
		return fmt.Errorf("failed to generate temporary password: %w", err)
	}
	tempPassword := hex.EncodeToString(tempPasswordBuf[:])

	repo, be, repoID, err := initializeRepository(ctx, opts, tempPassword, pol)
	if err != nil {
		return err
	}
	defer func() {
		_ = be.Close()
	}()

	if err := repo.SearchKey(ctx, tempPassword, 1, ""); err != nil {
		return fmt.Errorf("failed to load master key: %w", err)
	}

	var ageKeyIDs []restic.ID

	if opts.recipientsFile != "" {
		for _, recipient := range recipients {
			host := recipient.Host
			if host == "" {
				host = opts.host
			}
			user := recipient.User
			if user == "" {
				user = opts.user
			}

			encrypted, ok := encryptedPasswords[recipient.Pubkey]
			if !ok {
				return fmt.Errorf("no validated age encryption for recipient %s", recipient.Pubkey)
			}
			ageKeyID, _, err := buildAndSaveAgeKey(ctx, recipient.Pubkey, host, user, encrypted, repo, be, false)
			if err != nil {
				return fmt.Errorf("failed to create age key for %s: %w", recipient.Pubkey, err)
			}
			ageKeyIDs = append(ageKeyIDs, ageKeyID)
		}
	} else {
		encrypted, ok := encryptedPasswords[opts.recipient]
		if !ok {
			return fmt.Errorf("no validated age encryption for recipient %s", opts.recipient)
		}
		ageKeyID, _, err := buildAndSaveAgeKey(ctx, opts.recipient, opts.host, opts.user, encrypted, repo, be, false)
		if err != nil {
			return fmt.Errorf("failed to create age key: %w", err)
		}
		ageKeyIDs = append(ageKeyIDs, ageKeyID)
	}

	err = repo.List(ctx, restic.KeyFile, func(id restic.ID, size int64) error {
		for _, ageKeyID := range ageKeyIDs {
			if id.Equal(ageKeyID) {
				return nil
			}
		}
		h := backend.Handle{Type: restic.KeyFile, Name: id.String()}
		return be.Remove(ctx, h)
	})
	if err != nil {
		return fmt.Errorf("failed to remove temporary password key: %w", err)
	}

	fmt.Fprintf(os.Stderr, "created restic repository %s at %s\n", repoID.Str(), repositoryDisplayLocation(opts.repo))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Please note that knowledge of your age identity is required to access")
	fmt.Fprintln(os.Stderr, "the repository. Losing your identity means that your data is")
	fmt.Fprintln(os.Stderr, "irrecoverably lost.")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "repository version: 2")

	if opts.recipientsFile != "" {
		for i, ageKeyID := range ageKeyIDs {
			host := recipients[i].Host
			if host == "" {
				host = opts.host
			}
			user := recipients[i].User
			if user == "" {
				user = opts.user
			}
			fmt.Fprintf(os.Stderr, "  age key %s for %s@%s\n", ageKeyID.Str(), user, host)
		}
	} else {
		fmt.Fprintf(os.Stderr, "  age key %s for %s@%s\n", ageKeyIDs[0].Str(), opts.user, opts.host)
	}

	if opts.output != "" {
		if err := writeRepoInitKeyIDs(opts.output, ageKeyIDs); err != nil {
			return err
		}
	}

	return nil
}

func matchingAgeKeyIDs(ageKeys []Recipient, desired []Recipient) ([]restic.ID, []string) {
	desiredPubkeys := make(map[string]struct{}, len(desired))
	for _, recipient := range desired {
		desiredPubkeys[recipient.Pubkey] = struct{}{}
	}

	found := make(map[string]struct{}, len(desiredPubkeys))
	ids := make([]restic.ID, 0, len(ageKeys))
	for _, key := range ageKeys {
		if _, ok := desiredPubkeys[key.Pubkey]; !ok {
			continue
		}
		found[key.Pubkey] = struct{}{}
		ids = append(ids, key.ID)
	}

	missing := make([]string, 0)
	for pubkey := range desiredPubkeys {
		if _, ok := found[pubkey]; !ok {
			missing = append(missing, pubkey)
		}
	}

	sort.Slice(ids, func(i, j int) bool {
		return ids[i].String() < ids[j].String()
	})
	sort.Strings(missing)
	return ids, missing
}

func writeRepoInitKeyIDs(path string, ids []restic.ID) error {
	if len(ids) == 0 {
		return errors.New("no age key IDs available for output")
	}

	ids = append([]restic.ID(nil), ids...)
	sort.Slice(ids, func(i, j int) bool {
		return ids[i].String() < ids[j].String()
	})

	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	tempPath := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = file.Close()
			_ = os.Remove(tempPath)
		}
	}()

	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("failed to secure output file: %w", err)
	}

	lastID := ""
	for _, id := range ids {
		if id.String() == lastID {
			continue
		}
		if _, err := file.WriteString(id.Str() + "\n"); err != nil {
			_ = file.Close()
			return fmt.Errorf("failed to write to output file: %w", err)
		}
		lastID = id.String()
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to write to output file: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("failed to replace output file: %w", err)
	}
	cleanup = false
	return nil
}

type outputInput struct {
	flag string
	path string
}

func validateOutputPaths(output string, inputs []outputInput) error {
	if output == "" {
		return nil
	}

	for _, input := range inputs {
		if input.path == "" {
			continue
		}

		same, err := sameFilePath(output, input.path)
		if err != nil {
			return fmt.Errorf("failed to compare --output and %s: %w", input.flag, err)
		}
		if same {
			return fmt.Errorf("--output must not refer to the same file as %s", input.flag)
		}
	}
	return nil
}

func sameFilePath(pathA, pathB string) (bool, error) {
	absA, err := filepath.Abs(pathA)
	if err != nil {
		return false, err
	}
	absB, err := filepath.Abs(pathB)
	if err != nil {
		return false, err
	}
	if filepath.Clean(absA) == filepath.Clean(absB) {
		return true, nil
	}

	infoA, errA := os.Stat(absA)
	if errA != nil && !errors.Is(errA, os.ErrNotExist) {
		return false, errA
	}
	infoB, errB := os.Stat(absB)
	if errB != nil && !errors.Is(errB, os.ErrNotExist) {
		return false, errB
	}
	if errA == nil && errB == nil {
		return os.SameFile(infoA, infoB), nil
	}
	return false, nil
}

func parseChunkerPolynomial(hexStr string) (*chunker.Pol, error) {
	if hexStr == "" {
		return nil, nil
	}

	digits := strings.TrimPrefix(strings.TrimPrefix(hexStr, "0x"), "0X")
	val, err := strconv.ParseUint(digits, 16, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid chunker polynomial: %w", err)
	}

	pol := chunker.Pol(val)
	if pol.Deg() != 53 || !pol.Irreducible() {
		return nil, fmt.Errorf("invalid chunker polynomial: %s is not an irreducible polynomial of degree 53", hexStr)
	}
	return &pol, nil
}

func getChunkerPolynomial(opts options) (*chunker.Pol, error) {
	pol, err := parseChunkerPolynomial(opts.chunkerPolynomial)
	if err != nil {
		return nil, err
	}

	if pol != nil {
		return pol, nil
	}

	randomPol, err := chunker.RandomPolynomial()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random polynomial: %w", err)
	}
	return &randomPol, nil
}

func initializeRepository(ctx context.Context, opts options, password string, pol *chunker.Pol) (*repository.Repository, backend.Backend, restic.ID, error) {
	be, err := createOrOpenBackend(ctx, opts, true)
	if err != nil {
		return nil, nil, restic.ID{}, err
	}

	repo, err := repository.New(be, repository.Options{})
	if err != nil {
		return nil, nil, restic.ID{}, fmt.Errorf("failed to initialize repository: %w", err)
	}

	err = repo.Init(ctx, 2, password, pol)
	if err != nil {
		return nil, nil, restic.ID{}, fmt.Errorf("failed to initialize repository: %w", err)
	}

	repoCfg := repo.Config()

	id, err2 := restic.ParseID(repoCfg.ID)
	if err2 != nil {
		return nil, nil, restic.ID{}, fmt.Errorf("failed to parse repository ID: %w", err2)
	}

	return repo, be, id, nil
}

type storedRecipient struct {
	Recipient
	raw []byte
}

type setKeySpec struct {
	pubkey string
	host   string
	user   string
}

type setKeyCreation struct {
	recipient       Recipient
	existing        storedRecipient
	prepared        preparedAgeKey
	updatesExisting bool
}

type setKeyInventory struct {
	recipients map[string][]storedRecipient
	invalid    map[restic.ID]error
}

func prepareSetRecipients(recipients []Recipient) ([]Recipient, map[string]Recipient, error) {
	unique := make([]Recipient, 0, len(recipients))
	byPubkey := make(map[string]Recipient, len(recipients))

	for _, recipient := range recipients {
		if recipient.Pubkey == "" {
			return nil, nil, errors.New("recipient pubkey is empty")
		}

		existing, ok := byPubkey[recipient.Pubkey]
		if !ok {
			byPubkey[recipient.Pubkey] = recipient
			unique = append(unique, recipient)
			continue
		}

		if existing.Host != recipient.Host || existing.User != recipient.User {
			return nil, nil, fmt.Errorf("conflicting entries for pubkey %s", recipient.Pubkey)
		}
	}

	return unique, byPubkey, nil
}

func rewriteAgeKeyMetadata(data []byte, host, user string) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, fmt.Errorf("failed to parse age key: %w", err)
	}
	if fields == nil {
		return nil, errors.New("failed to parse age key: expected JSON object")
	}

	hostname, err := json.Marshal(host)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal hostname: %w", err)
	}
	username, err := json.Marshal(user)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal username: %w", err)
	}

	fields["hostname"] = hostname
	fields["username"] = username

	updated, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated age key: %w", err)
	}

	return updated, nil
}

func saveUpdatedAgeKey(ctx context.Context, repo *repository.Repository, be backend.Backend, existing storedRecipient, recipient Recipient, dryRun bool) (restic.ID, bool, error) {
	data, err := rewriteAgeKeyMetadata(existing.raw, recipient.Host, recipient.User)
	if err != nil {
		return restic.ID{}, false, err
	}

	key := preparedAgeKey{id: restic.Hash(data), raw: data}
	saved, err := savePreparedAgeKey(ctx, repo, be, key, true, dryRun)
	return key.id, saved, err
}

func verifyKeyAccess(ctx context.Context, be backend.Backend, id restic.ID, password string, expectedMaster crypto.Key) (*repository.Repository, error) {
	probe, err := repository.New(be, repository.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize verification repository: %w", err)
	}

	if err := probe.SearchKey(ctx, password, 1, id.String()); err != nil {
		return nil, fmt.Errorf("failed to open key: %w", err)
	}
	if probe.KeyID() != id {
		return nil, fmt.Errorf("opened key %s instead of expected key %s", probe.KeyID().String(), id.String())
	}
	if probe.Key() == nil || *probe.Key() != expectedMaster {
		return nil, errors.New("key decrypts to a different repository master key")
	}

	return probe, nil
}

func cleanupUnverifiedKey(ctx context.Context, repo *repository.Repository, be backend.Backend, id restic.ID) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	if err := repository.RemoveKey(cleanupCtx, repo, id); err != nil && !be.IsNotExist(err) {
		return err
	}
	return nil
}

func recipientKeySpec(recipient Recipient) setKeySpec {
	return setKeySpec{
		pubkey: recipient.Pubkey,
		host:   recipient.Host,
		user:   recipient.User,
	}
}

func resolveNewSetRecipient(recipient Recipient, opts options) (Recipient, error) {
	if recipient.Host == "" {
		recipient.Host = opts.host
	}
	if recipient.User == "" {
		recipient.User = opts.user
	}
	if recipient.Host == "" {
		return Recipient{}, errors.New("hostname is empty")
	}
	if recipient.User == "" {
		return Recipient{}, errors.New("username is empty")
	}
	return recipient, nil
}

func resolveUpdatedSetRecipient(desired Recipient, existing storedRecipient) (Recipient, bool, error) {
	if desired.Host == "" {
		desired.Host = existing.Host
	}
	if desired.User == "" {
		desired.User = existing.User
	}
	if desired.Host == existing.Host && desired.User == existing.User {
		return desired, false, nil
	}
	if desired.Host == "" {
		return Recipient{}, false, errors.New("hostname is empty")
	}
	if desired.User == "" {
		return Recipient{}, false, errors.New("username is empty")
	}
	return desired, true, nil
}

func inspectSetKeys(ctx context.Context, repo *repository.Repository) (setKeyInventory, error) {
	inventory := setKeyInventory{
		recipients: make(map[string][]storedRecipient),
		invalid:    make(map[restic.ID]error),
	}

	err := repo.List(ctx, restic.KeyFile, func(id restic.ID, size int64) error {
		data, err := repo.LoadRaw(ctx, restic.KeyFile, id)
		if err != nil {
			if errors.Is(err, restic.ErrInvalidData) {
				inventory.invalid[id] = err
				return nil
			}
			return fmt.Errorf("failed to load key %s: %w", id.Str(), err)
		}

		var key AgeKey
		if err := json.Unmarshal(data, &key); err != nil {
			return fmt.Errorf("failed to parse key %s: %w", id.Str(), err)
		}
		if key.AgePubkey != "" {
			if len(key.AgeData) == 0 || len(key.Data) == 0 {
				return fmt.Errorf("age key %s is incomplete", id.Str())
			}
			inventory.recipients[key.AgePubkey] = append(inventory.recipients[key.AgePubkey], storedRecipient{
				Recipient: Recipient{
					ID:     id,
					Pubkey: key.AgePubkey,
					Host:   key.Hostname,
					User:   key.Username,
				},
				raw: data,
			})
		}
		return nil
	})
	if err != nil {
		return setKeyInventory{}, err
	}

	for pubkey := range inventory.recipients {
		sort.Slice(inventory.recipients[pubkey], func(i, j int) bool {
			return inventory.recipients[pubkey][i].ID.String() < inventory.recipients[pubkey][j].ID.String()
		})
	}
	return inventory, nil
}

func validateSetInventory(inventory setKeyInventory, recipients []Recipient, opts options, prepared map[setKeySpec]preparedAgeKey) error {
	repairIDs := make(map[restic.ID]struct{})

	for _, desired := range recipients {
		existingRecipients := inventory.recipients[desired.Pubkey]
		if len(existingRecipients) == 0 {
			recipient, err := resolveNewSetRecipient(desired, opts)
			if err != nil {
				return err
			}
			if key, ok := prepared[recipientKeySpec(recipient)]; ok {
				repairIDs[key.id] = struct{}{}
			}
			continue
		}

		for _, existing := range existingRecipients {
			recipient, changed, err := resolveUpdatedSetRecipient(desired, existing)
			if err != nil {
				return err
			}
			if !changed {
				continue
			}
			data, err := rewriteAgeKeyMetadata(existing.raw, recipient.Host, recipient.User)
			if err != nil {
				return err
			}
			repairIDs[restic.Hash(data)] = struct{}{}
		}
	}

	invalidIDs := make([]restic.ID, 0, len(inventory.invalid))
	for id := range inventory.invalid {
		invalidIDs = append(invalidIDs, id)
	}
	sort.Slice(invalidIDs, func(i, j int) bool {
		return invalidIDs[i].String() < invalidIDs[j].String()
	})
	for _, id := range invalidIDs {
		if _, repairable := repairIDs[id]; !repairable {
			return fmt.Errorf("failed to inspect key %s: %w", id.Str(), inventory.invalid[id])
		}
	}
	return nil
}

func runKeySet(ctx context.Context, opts options) error {
	if err := resolveRepo(&opts); err != nil {
		return err
	}

	if opts.recipientsFile == "" {
		return errors.Fatal("Please specify recipients file (--recipients-file)")
	}

	setRecipients, err := readRecipientsFile(opts.recipientsFile)
	if err != nil {
		return errors.Fatalf("Unable to read recipients file: %v", err)
	}

	setRecipients, desiredByPubkey, err := prepareSetRecipients(setRecipients)
	if err != nil {
		return errors.Fatalf("Invalid recipients file: %v", err)
	}

	repo, be, currentPassword, err := openRepositoryWithPasswordPreferring(ctx, opts, desiredByPubkey)
	if err != nil {
		return err
	}
	defer func() {
		_ = be.Close()
	}()
	if repo.Key() == nil {
		return errors.New("repo master key not loaded")
	}

	expectedMaster := *repo.Key()
	originalKeyID := repo.KeyID()
	prepared := make(map[setKeySpec]preparedAgeKey)
	var inventory setKeyInventory
	var operationCtx = ctx
	var unlocker *repository.Unlocker

	const maxPlanAttempts = 3
	for attempt := 0; ; attempt++ {
		snapshot, err := inspectSetKeys(ctx, repo)
		if err != nil {
			return fmt.Errorf("failed to inspect repository keys: %w", err)
		}

		for _, desired := range setRecipients {
			if len(snapshot.recipients[desired.Pubkey]) != 0 {
				continue
			}

			recipient, err := resolveNewSetRecipient(desired, opts)
			if err != nil {
				return err
			}
			spec := recipientKeySpec(recipient)
			if _, ok := prepared[spec]; ok {
				continue
			}

			password, ageData, err := ageEncryptRandomKey(ctx, opts.ageProgram, recipient.Pubkey)
			if err != nil {
				return fmt.Errorf("failed to add key %s: %w", recipient.Pubkey, err)
			}
			key, err := prepareAgeKey(recipient.Pubkey, recipient.Host, recipient.User, expectedMaster, encryptedAgePassword{password: password, data: ageData})
			if err != nil {
				return fmt.Errorf("failed to add key %s: %w", recipient.Pubkey, err)
			}
			prepared[spec] = key
		}

		if err := validateSetInventory(snapshot, setRecipients, opts, prepared); err != nil {
			return fmt.Errorf("failed to inspect repository keys: %w", err)
		}

		if opts.dryRun {
			inventory = snapshot
			break
		}

		locked, lockedCtx, err := repository.Lock(ctx, repo, true, 0, func(string) {}, backendErrorLog)
		if err != nil {
			return fmt.Errorf("failed to lock repository: %w", err)
		}

		if _, err := verifyKeyAccess(lockedCtx, be, originalKeyID, currentPassword, expectedMaster); err != nil {
			locked.Unlock()
			return fmt.Errorf("failed to verify repository key after acquiring lock: %w", err)
		}

		lockedInventory, err := inspectSetKeys(lockedCtx, repo)
		if err != nil {
			locked.Unlock()
			return fmt.Errorf("failed to inspect repository keys: %w", err)
		}

		needsPreparation := false
		for _, desired := range setRecipients {
			if len(lockedInventory.recipients[desired.Pubkey]) != 0 {
				continue
			}
			recipient, err := resolveNewSetRecipient(desired, opts)
			if err != nil {
				locked.Unlock()
				return err
			}
			if _, ok := prepared[recipientKeySpec(recipient)]; !ok {
				needsPreparation = true
				break
			}
		}

		if needsPreparation {
			locked.Unlock()
			if attempt+1 >= maxPlanAttempts {
				return errors.New("repository keys changed while preparing set; retry command")
			}
			continue
		}
		if err := validateSetInventory(lockedInventory, setRecipients, opts, prepared); err != nil {
			locked.Unlock()
			return fmt.Errorf("failed to inspect repository keys: %w", err)
		}

		inventory = lockedInventory
		operationCtx = lockedCtx
		unlocker = locked
		break
	}

	if unlocker != nil {
		defer unlocker.Unlock()
	}
	ctx = operationCtx
	repoKeys := inventory.recipients

	var keysToCreate []setKeyCreation
	var keysToRemove []Recipient

	for _, desired := range setRecipients {
		existingRecipients := repoKeys[desired.Pubkey]
		if len(existingRecipients) == 0 {
			recipient, err := resolveNewSetRecipient(desired, opts)
			if err != nil {
				return err
			}
			key, ok := prepared[recipientKeySpec(recipient)]
			if !ok {
				return errors.New("repository keys changed while preparing set; retry command")
			}
			keysToCreate = append(keysToCreate, setKeyCreation{
				recipient: recipient,
				prepared:  key,
			})
			continue
		}

		for _, existing := range existingRecipients {
			recipient, changed, err := resolveUpdatedSetRecipient(desired, existing)
			if err != nil {
				return err
			}
			if !changed {
				continue
			}

			keysToCreate = append(keysToCreate, setKeyCreation{
				recipient:       recipient,
				existing:        existing,
				updatesExisting: true,
			})
			keysToRemove = append(keysToRemove, existing.Recipient)
		}
	}

	var stalePubkeys []string
	for pubkey := range repoKeys {
		if _, desired := desiredByPubkey[pubkey]; !desired {
			stalePubkeys = append(stalePubkeys, pubkey)
		}
	}
	sort.Strings(stalePubkeys)
	for _, pubkey := range stalePubkeys {
		for _, existing := range repoKeys[pubkey] {
			keysToRemove = append(keysToRemove, existing.Recipient)
		}
	}

	removesCurrentKey := false
	hasPlannedReplacement := false
	for _, recipient := range keysToRemove {
		if recipient.ID == originalKeyID {
			removesCurrentKey = true
			break
		}
	}
	for _, creation := range keysToCreate {
		if creation.updatesExisting && creation.existing.ID == originalKeyID {
			hasPlannedReplacement = true
			break
		}
	}
	cannotRemoveCurrent := removesCurrentKey && !hasPlannedReplacement

	logPrefix := ""
	if opts.dryRun {
		logPrefix = "[DRY RUN] "
	}

	var replacementRepo *repository.Repository

	for _, creation := range keysToCreate {
		var id restic.ID
		var password string
		var created bool

		if creation.updatesExisting {
			id, created, err = saveUpdatedAgeKey(ctx, repo, be, creation.existing, creation.recipient, opts.dryRun)
			if err == nil && creation.existing.ID == originalKeyID {
				password = currentPassword
			}
		} else {
			id = creation.prepared.id
			password = creation.prepared.password
			created, err = savePreparedAgeKey(ctx, repo, be, creation.prepared, true, opts.dryRun)
		}
		if err != nil {
			return fmt.Errorf("failed to add key %s: %w", creation.recipient.Pubkey, err)
		}

		var verifiedRepo *repository.Repository
		if !opts.dryRun && password != "" {
			verifiedRepo, err = verifyKeyAccess(ctx, be, id, password, expectedMaster)
			if err != nil {
				if created {
					if cleanupErr := cleanupUnverifiedKey(ctx, repo, be, id); cleanupErr != nil {
						fmt.Fprintf(os.Stderr, "failed to remove unverified key %s: %v\n", id.Str(), cleanupErr)
					}
				}
				return fmt.Errorf("failed to verify key %s: %w", creation.recipient.Pubkey, err)
			}
		}

		fmt.Fprintf(os.Stderr, "%sAdd key %s for %s@%s\n", logPrefix, creation.recipient.Pubkey, creation.recipient.User, creation.recipient.Host)

		if verifiedRepo != nil && creation.updatesExisting && creation.existing.ID == originalKeyID {
			replacementRepo = verifiedRepo
		}
	}

	hasError := false
	repoForRemoval := repo
	blockedKeyID := restic.ID{}

	if cannotRemoveCurrent {
		fmt.Fprintln(os.Stderr, "Error: refusing to remove key currently used to access repository")
		if !opts.dryRun && len(keysToCreate) > 0 {
			fmt.Fprintln(os.Stderr, "Additions were staged. The current key was retained.")
		}
		fmt.Fprintln(os.Stderr, "Re-run set using a retained recipient's identity to verify access before removing it.")
		hasError = true
		blockedKeyID = originalKeyID
	} else if removesCurrentKey && !opts.dryRun {
		if replacementRepo == nil {
			return errors.Fatal("refusing to remove key currently used to access repository")
		}
		repoForRemoval = replacementRepo
		blockedKeyID = replacementRepo.KeyID()
	} else if !opts.dryRun {
		blockedKeyID = repo.KeyID()
	}

	for _, recipient := range keysToRemove {
		if recipient.ID == blockedKeyID {
			if !cannotRemoveCurrent {
				fmt.Fprintln(os.Stderr, "Error: refusing to remove key currently used to access repository")
			}
			hasError = true
			continue
		}

		fmt.Fprintf(os.Stderr, "%sRemove key %s for %s@%s\n", logPrefix, recipient.Pubkey, recipient.User, recipient.Host)

		if opts.dryRun {
			continue
		}

		if err := repository.RemoveKey(ctx, repoForRemoval, recipient.ID); err != nil {
			// An interrupt should stop the run and surface the cancellation
			// rather than failing every remaining removal in turn.
			if ctx.Err() != nil {
				return fmt.Errorf("failed to remove key %s: %w", recipient.Pubkey, ctx.Err())
			}
			fmt.Fprintf(os.Stderr, "failed to remove key %s: %v\n", recipient.Pubkey, err)
			hasError = true
		}
	}

	if hasError {
		return errors.New("failed to set keys")
	}
	if opts.output != "" && !opts.dryRun {
		finalInventory, err := inspectSetKeys(ctx, repo)
		if err != nil {
			return fmt.Errorf("failed to inspect reconciled repository keys: %w", err)
		}

		var finalRecipients []Recipient
		for _, recipients := range finalInventory.recipients {
			for _, recipient := range recipients {
				finalRecipients = append(finalRecipients, recipient.Recipient)
			}
		}
		ids, missing := matchingAgeKeyIDs(finalRecipients, setRecipients)
		if len(missing) > 0 {
			return fmt.Errorf("repository is missing age keys for recipients: %s", strings.Join(missing, ", "))
		}
		if err := writeRepoInitKeyIDs(opts.output, ids); err != nil {
			return err
		}
	}

	return nil
}
func readRecipientsFile(path string) ([]Recipient, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var recipients []Recipient
	err = json.Unmarshal(data, &recipients)
	if err != nil {
		return nil, fmt.Errorf("failed to parse recipients file as JSON: %w", err)
	}
	if recipients == nil {
		return nil, errors.New("recipients file must contain a JSON array")
	}

	return recipients, nil
}

type identityKeyCandidate struct {
	id      restic.ID
	pubkey  string
	ageData []byte
	data    []byte
}

func openIdentityKeyError(id restic.ID, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, crypto.ErrUnauthenticated):
		return fmt.Errorf("decrypted password does not open key %s: %w", id.Str(), err)
	default:
		return fmt.Errorf("failed to verify key %s: %w", id.Str(), err)
	}
}

// verifyIdentityKey checks that password opens key id and that the key belongs
// to this repository. A repository whose config cannot be read is left
// unverified so that restic reports the damaged config itself instead of this
// surfacing as a password failure.
func verifyIdentityKey(ctx context.Context, repo *repository.Repository, id restic.ID, password string, keysComplete bool) error {
	config, err := repo.LoadRaw(ctx, restic.ConfigFile, restic.ID{})
	if err != nil || len(config) < crypto.CiphertextLength(0) {
		_, openErr := repository.OpenKey(ctx, repo, id, password)
		return openIdentityKeyError(id, openErr)
	}

	// SearchKey scans other key files when the hinted key fails to open, and
	// OpenKey panics on a key file whose data is shorter than a nonce. Opening
	// the hinted key first keeps that scan from running.
	if !keysComplete {
		if _, openErr := repository.OpenKey(ctx, repo, id, password); openErr != nil {
			return openIdentityKeyError(id, openErr)
		}
	}

	searchErr := repo.SearchKey(ctx, password, 1, id.String())
	if errors.Is(searchErr, crypto.ErrUnauthenticated) {
		return fmt.Errorf("key %s does not open this repository: %w", id.Str(), searchErr)
	}
	if searchErr != nil {
		_, openErr := repository.OpenKey(ctx, repo, id, password)
		return openIdentityKeyError(id, openErr)
	}
	if openedID := repo.KeyID(); openedID != id {
		return fmt.Errorf("opened key %s instead of decrypted key %s", openedID.Str(), id.Str())
	}
	return nil
}

// matchesKeyHint reports whether id is the key named by --key-hint, which
// restic matches as an ID prefix.
func matchesKeyHint(keyHint string, id restic.ID) bool {
	return keyHint != "" && strings.HasPrefix(id.String(), keyHint)
}

func readPasswordViaIdentityPreferring(ctx context.Context, repo *repository.Repository, opts options, preferredPubkeys map[string]Recipient) (string, restic.ID, error) {
	closeIdentityCommand, err := readIdentityCommand(ctx, &opts)
	if err != nil {
		return "", restic.ID{}, fmt.Errorf("Resolving identity failed: %w", err) //nolint:staticcheck // matches restic's capitalized message
	}
	defer closeIdentityCommand()

	if opts.identityFile == "" {
		return "", restic.ID{}, errors.New("no identity file specified")
	}

	var candidates []identityKeyCandidate
	var keyErr error
	keysComplete := true

	listErr := repo.List(ctx, restic.KeyFile, func(id restic.ID, size int64) error {
		data, err := repo.LoadRaw(ctx, restic.KeyFile, id)
		if err != nil {
			if keyErr == nil {
				keyErr = err
			}
			keysComplete = false
			return nil
		}

		var key AgeKey
		if err := json.Unmarshal(data, &key); err != nil {
			return nil
		}
		if len(key.Data) < crypto.CiphertextLength(0) {
			keysComplete = false
		}
		if key.AgePubkey == "" {
			return nil
		}

		candidates = append(candidates, identityKeyCandidate{
			id:      id,
			pubkey:  key.AgePubkey,
			ageData: key.AgeData,
			data:    key.Data,
		})
		return nil
	})
	if listErr != nil {
		return "", restic.ID{}, listErr
	}

	sort.Slice(candidates, func(i, j int) bool {
		_, iPreferred := preferredPubkeys[candidates[i].pubkey]
		_, jPreferred := preferredPubkeys[candidates[j].pubkey]
		if iPreferred != jPreferred {
			return iPreferred
		}
		iHinted := matchesKeyHint(opts.keyHint, candidates[i].id)
		jHinted := matchesKeyHint(opts.keyHint, candidates[j].id)
		if iHinted != jHinted {
			return iHinted
		}
		return candidates[i].id.String() < candidates[j].id.String()
	})

	var verifyErr error
	for _, candidate := range candidates {
		password, err := ageDecryptKey(ctx, opts.ageProgram, opts.identityFile, candidate.ageData)
		if err == nil {
			if len(candidate.data) < crypto.CiphertextLength(0) {
				if verifyErr == nil {
					verifyErr = fmt.Errorf("age key %s is incomplete", candidate.id.Str())
				}
				continue
			}
			openErr := verifyIdentityKey(ctx, repo, candidate.id, password, keysComplete)
			if openErr == nil {
				return password, candidate.id, nil
			}
			if ctx.Err() != nil {
				return "", restic.ID{}, fmt.Errorf("failed to verify key %s: %w", candidate.id.Str(), openErr)
			}
			if verifyErr == nil {
				verifyErr = openErr
			}
			continue
		}
		// A cancelled or expired context will fail every remaining candidate,
		// so report it instead of aggregating it behind an earlier failure.
		if ctx.Err() != nil {
			return "", restic.ID{}, err
		}
		if strings.Contains(err.Error(), "no identity matched any of the recipients") {
			continue
		}
		if keyErr == nil {
			keyErr = err
		}
	}

	if verifyErr != nil {
		return "", restic.ID{}, verifyErr
	}
	if keyErr != nil {
		return "", restic.ID{}, keyErr
	}

	return "", restic.ID{}, errors.New("no password found")
}

func readPasswordViaIdentity(ctx context.Context, opts options) (string, error) {
	repo, be, err := openRepository(ctx, opts)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = be.Close()
	}()

	password, _, err := readPasswordViaIdentityPreferring(ctx, repo, opts, nil)
	return password, err
}

// helperContextErr reports why a helper command was killed, so an interrupt or
// a timeout is not masked by the process exit status the helper returns.
func helperContextErr(ctx context.Context, timeoutMsg string) error {
	switch ctx.Err() {
	case context.DeadlineExceeded:
		return errors.New(timeoutMsg)
	case context.Canceled:
		return ctx.Err()
	default:
		return nil
	}
}

func ageEncryptRandomKey(ctx context.Context, ageProgram string, pubkey string) (string, []byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	cmd := exec.CommandContext(ctx, ageProgram, "--encrypt", "--recipient", pubkey)
	cmd.Stdin = bytes.NewReader(key)

	out, err := cmd.Output()
	if err != nil {
		if cerr := helperContextErr(ctx, "timeout exceeded while encrypting key with age"); cerr != nil {
			return "", nil, cerr
		}

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return "", nil, fmt.Errorf("%s", string(exitErr.Stderr))
		}

		return "", nil, fmt.Errorf("failed to encrypt key with age: %w", err)
	}
	if len(out) == 0 {
		return "", nil, errors.New("age returned no encrypted data")
	}

	return hex.EncodeToString(key), out, nil
}

func ageDecryptKey(ctx context.Context, ageProgram string, identityFile string, key []byte) (string, error) {
	cmd := exec.CommandContext(ctx, ageProgram, "--decrypt", "--identity", identityFile)
	cmd.Stdin = bytes.NewReader(key)

	out, err := cmd.Output()
	if err != nil {
		if cerr := helperContextErr(ctx, "timeout exceeded while decrypting key with age"); cerr != nil {
			return "", cerr
		}

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return "", fmt.Errorf("%s", string(exitErr.Stderr))
		}

		return "", fmt.Errorf("failed to decrypt key with age: %w", err)
	}

	return hex.EncodeToString(out), nil
}

func readIdentityCommand(ctx context.Context, opts *options) (func(), error) {
	noop := func() {}

	if opts.identityCommand == "" {
		return noop, nil
	}

	if opts.identityFile != "" {
		fmt.Fprintf(os.Stderr, "warn: ignoring identity-command, identity-file already set\n")

		return noop, nil
	}
	if strings.TrimSpace(opts.identityCommand) == "" {
		return noop, errors.New("identity command is empty")
	}

	args, err := backend.SplitShellStrings(opts.identityCommand)
	if err != nil {
		return noop, fmt.Errorf("failed to split shell string: %w", err)
	}
	if len(args) == 0 {
		return noop, errors.New("identity command is empty")
	}

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stderr = os.Stderr

	output, err := cmd.Output()
	if err != nil {
		if cerr := helperContextErr(ctx, "timeout exceeded while executing identity command"); cerr != nil {
			return noop, cerr
		}
		return noop, err
	}

	filename, closeCallback, err := writeTempFile("identity-*", output)
	if err != nil {
		return closeCallback, err
	}

	opts.identityFile = filename

	return closeCallback, nil
}

func writeTempFile(pattern string, data []byte) (string, func(), error) {
	tmpFile, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temporary file: %w", err)
	}

	closeCallback := func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
	}

	_, err = tmpFile.Write(data)
	if err != nil {
		closeCallback()

		return "", nil, fmt.Errorf("failed to write to temporary file: %w", err)
	}

	return tmpFile.Name(), closeCallback, nil
}

// readPassword resolves the repository password. An explicit --password wins,
// then restic's own order applies: the password command beats a password file,
// which beats RESTIC_PASSWORD.
func readPassword(ctx context.Context, opts *options) (string, error) {
	if opts.insecureNoPassword {
		return "", nil
	}

	switch {
	case opts.password != "":
		return opts.password, nil
	case opts.passwordCommand != "":
		return readPasswordFromCommand(ctx, opts.passwordCommand)
	case opts.passwordFile != "":
		return readPasswordFromFile(opts.passwordFile)
	case opts.passwordEnv != "":
		return opts.passwordEnv, nil
	default:
		return "", errors.New("no password given")
	}
}

// validatePasswordSources rejects conflicting sources before a command runs,
// mirroring where restic validates them in global.Options.PreRun. Commands that
// never consult a password, such as password and from-password, skip it.
func validatePasswordSources(opts options) error {
	if opts.insecureNoPassword {
		if opts.password != "" || opts.passwordEnv != "" || opts.passwordFile != "" || opts.passwordCommand != "" {
			return errors.Fatal("--insecure-no-password must not be specified together with providing a password via a cli option or environment variable")
		}
		return nil
	}
	if opts.passwordFile != "" && opts.passwordCommand != "" {
		return errors.Fatal("Password file and command are mutually exclusive options")
	}
	return nil
}

func readPasswordFromFile(passwordFile string) (string, error) {
	s, err := textfile.Read(passwordFile)
	if err != nil {
		return "", fmt.Errorf("failed to read password file: %w", err)
	}

	password := strings.TrimSpace(string(s))
	if password == "" {
		return "", errors.New("empty password file")
	}

	return password, nil
}

func readPasswordFromCommand(ctx context.Context, passwordCommand string) (string, error) {
	if strings.TrimSpace(passwordCommand) == "" {
		return "", errors.New("password command is empty")
	}

	args, err := backend.SplitShellStrings(passwordCommand)
	if err != nil {
		return "", err
	}
	if len(args) == 0 {
		return "", errors.New("password command is empty")
	}

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stderr = os.Stderr

	output, err := cmd.Output()
	if err != nil {
		if cerr := helperContextErr(ctx, "timeout exceeded while executing password command"); cerr != nil {
			return "", cerr
		}
		return "", fmt.Errorf("failed to execute password command: %w", err)
	}

	password := strings.TrimSpace(string(output))
	if password == "" {
		return "", errors.New("empty password command output")
	}

	return password, nil
}

func openRepositoryWithPassword(ctx context.Context, opts options) (*repository.Repository, backend.Backend, string, error) {
	return openRepositoryWithPasswordPreferring(ctx, opts, nil)
}

func openRepositoryWithPasswordPreferring(ctx context.Context, opts options, preferredPubkeys map[string]Recipient) (*repository.Repository, backend.Backend, string, error) {
	repo, be, err := openRepository(ctx, opts)
	if err != nil {
		return nil, nil, "", err
	}

	var identityKeyID restic.ID
	password, err := readPassword(ctx, &opts)
	if err != nil {
		if opts.identityFile != "" || opts.identityCommand != "" {
			password, identityKeyID, err = readPasswordViaIdentityPreferring(ctx, repo, opts, preferredPubkeys)
		}

		if err != nil {
			_ = be.Close()
			return nil, nil, "", errors.Fatalf("Resolving password failed: %v", err)
		}
	}

	maxKeys := 20
	keyHint := opts.keyHint
	if identityKeyID != (restic.ID{}) {
		if repo.KeyID() == identityKeyID {
			return repo, be, password, nil
		}
		maxKeys = 1
		keyHint = identityKeyID.String()
	}

	if err := repo.SearchKey(ctx, password, maxKeys, keyHint); err != nil {
		_ = be.Close()
		return nil, nil, "", fmt.Errorf("failed to verify repository key: %w", err)
	}
	if identityKeyID != (restic.ID{}) && repo.KeyID() != identityKeyID {
		_ = be.Close()
		return nil, nil, "", fmt.Errorf("opened key %s instead of decrypted key %s", repo.KeyID().String(), identityKeyID.String())
	}

	return repo, be, password, nil
}

type repositoryState struct {
	exists  bool
	ageKeys []Recipient
}

func inspectRepository(ctx context.Context, opts options, loadAgeKeys bool) (repositoryState, error) {
	be, err := createOrOpenBackend(ctx, opts, false)
	if err != nil {
		if errors.Is(err, backend.ErrNoRepository) {
			return repositoryState{}, nil
		}
		return repositoryState{}, err
	}
	defer func() {
		_ = be.Close()
	}()

	_, err = be.Stat(ctx, backend.Handle{Type: restic.ConfigFile})
	if err != nil {
		if be.IsNotExist(err) {
			return repositoryState{}, nil
		}
		return repositoryState{}, fmt.Errorf("unable to open config file: %w", err)
	}
	if !loadAgeKeys {
		return repositoryState{exists: true}, nil
	}

	repo, err := repository.New(be, repository.Options{})
	if err != nil {
		return repositoryState{}, fmt.Errorf("failed to initialize repository: %w", err)
	}

	var ageKeys []Recipient
	err = repo.List(ctx, restic.KeyFile, func(id restic.ID, size int64) error {
		data, err := repo.LoadRaw(ctx, restic.KeyFile, id)
		if err != nil {
			if errors.Is(err, restic.ErrInvalidData) {
				return nil
			}
			return fmt.Errorf("failed to load key %s: %w", id.Str(), err)
		}

		var key AgeKey
		if err := json.Unmarshal(data, &key); err != nil {
			return fmt.Errorf("failed to parse key %s: %w", id.Str(), err)
		}
		if key.AgePubkey == "" {
			return nil
		}
		if len(key.AgeData) == 0 || len(key.Data) == 0 {
			return fmt.Errorf("age key %s is incomplete", id.Str())
		}

		ageKeys = append(ageKeys, Recipient{
			ID:     id,
			Pubkey: key.AgePubkey,
			Host:   key.Hostname,
			User:   key.Username,
		})
		return nil
	})
	if err != nil {
		return repositoryState{}, fmt.Errorf("failed to inspect repository keys: %w", err)
	}

	sort.Slice(ageKeys, func(i, j int) bool {
		return ageKeys[i].ID.String() < ageKeys[j].ID.String()
	})
	return repositoryState{exists: true, ageKeys: ageKeys}, nil
}

// resolveRepo mirrors restic's handling of -r and --repository-file, so a
// repository configured for restic works here without change.
func resolveRepo(opts *options) error {
	if opts.repoResolved {
		return nil
	}
	opts.repoResolved = true

	if opts.repo == "" && opts.repositoryFile == "" {
		return errors.Fatal("Please specify repository location (-r or --repository-file)")
	}

	if opts.repositoryFile == "" {
		return nil
	}
	if opts.repo != "" {
		return errors.Fatal("Options -r and --repository-file are mutually exclusive, please specify only one")
	}

	s, err := textfile.Read(opts.repositoryFile)
	if errors.Is(err, os.ErrNotExist) {
		return errors.Fatalf("%s does not exist", opts.repositoryFile)
	}
	if err != nil {
		return err
	}

	opts.repo = strings.TrimSpace(string(s))
	return nil
}

func openRepository(ctx context.Context, opts options) (*repository.Repository, backend.Backend, error) {
	be, err := createOrOpenBackend(ctx, opts, false)
	if err != nil {
		return nil, nil, err
	}

	r, err := repository.New(be, repository.Options{})
	if err != nil {
		_ = be.Close()
		return nil, nil, fmt.Errorf("failed to initialize repository: %w", err)
	}

	_, err = be.Stat(ctx, backend.Handle{Type: restic.ConfigFile})
	if be.IsNotExist(err) {
		_ = be.Close()
		return nil, nil, fmt.Errorf("%w: unable to open config file", errNoRepository)
	}
	if err != nil {
		_ = be.Close()
		return nil, nil, fmt.Errorf("unable to open config file: %w", err)
	}

	return r, be, nil
}

func createOrOpenBackend(ctx context.Context, opts options, create bool) (backend.Backend, error) {
	backends := all.Backends()

	loc, err := location.Parse(backends, opts.repo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repository location: %w", err)
	}

	cfg := loc.Config
	if envCfg, ok := cfg.(backend.ApplyEnvironmenter); ok {
		envCfg.ApplyEnvironment("")
	}
	if rcloneCfg, ok := cfg.(*rclone.Config); ok {
		rcloneCfg.Program = opts.rcloneProgram
	}

	extended, err := resticopts.Parse(opts.extended)
	if err != nil {
		return nil, fmt.Errorf("failed to parse extended options: %w", err)
	}
	if err := extended.Extract(loc.Scheme).Apply(loc.Scheme, cfg); err != nil {
		return nil, fmt.Errorf("failed to apply extended options: %w", err)
	}

	rt, err := backend.Transport(opts.transport)
	if err != nil {
		return nil, fmt.Errorf("failed to create backend transport: %w", err)
	}
	lim := limiter.NewStaticLimiter(opts.limits)
	rt = lim.Transport(rt)

	factory := backends.Lookup(loc.Scheme)
	if factory == nil {
		return nil, fmt.Errorf("unknown repository backend: %s", loc.Scheme)
	}

	if create {
		be, err := factory.Create(ctx, cfg, rt, lim, backendErrorLog)
		if err != nil {
			return nil, fmt.Errorf("failed to create backend: %w", err)
		}
		return wrapBackend(be), nil
	}

	be, err := factory.Open(ctx, cfg, rt, lim, backendErrorLog)
	if err != nil {
		return nil, fmt.Errorf("failed to open backend: %w", err)
	}
	return wrapBackend(be), nil
}

// wrapBackend layers the connection limiting and retry behaviour that restic
// applies to every backend, so transient failures do not abort the command.
func wrapBackend(be backend.Backend) backend.Backend {
	be = logger.New(sema.NewBackend(be))

	report := func(msg string, err error, d time.Duration) {
		if d >= 0 {
			backendErrorLog("%v returned error, retrying after %v: %v", msg, d, err)
		} else {
			backendErrorLog("%v failed: %v", msg, err)
		}
	}
	success := func(msg string, retries int) {
		backendErrorLog("%v operation successful after %d retries", msg, retries)
	}

	return retry.New(be, 15*time.Minute, report, success)
}

func repositoryDisplayLocation(repo string) string {
	return location.StripPassword(all.Backends(), repo)
}

func backendErrorLog(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
}

func printTable(headers []string, rows [][]string) {
	padding := 2
	numCols := len(headers)

	colWidths := make([]int, numCols)

	for i, h := range headers {
		if i < numCols && len(h) > colWidths[i] {
			colWidths[i] = len(h)
		}
	}

	for _, row := range rows {
		for i, cell := range row {
			if i < numCols && len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	totalWidth := 0
	for _, w := range colWidths {
		totalWidth += w
	}
	totalWidth += (numCols - 1) * padding

	printRow(headers, colWidths, padding)
	divider := strings.Repeat("-", totalWidth)
	fmt.Println(divider)

	for _, row := range rows {
		printRow(row, colWidths, padding)
	}

	divider = strings.Repeat("-", totalWidth)
	fmt.Println(divider)
}

func printRow(row []string, colWidths []int, padding int) {
	for i, cell := range row {
		if i >= len(colWidths) {
			break
		}
		fmt.Printf("%-*s", colWidths[i], cell)
		if i < len(colWidths)-1 {
			fmt.Print(strings.Repeat(" ", padding))
		}
	}
	fmt.Println()
}
