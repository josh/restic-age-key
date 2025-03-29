package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"

	"github.com/josh/restic-api/api/backend"
	"github.com/josh/restic-api/api/backend/azure"
	"github.com/josh/restic-api/api/backend/b2"
	"github.com/josh/restic-api/api/backend/gs"
	"github.com/josh/restic-api/api/backend/limiter"
	"github.com/josh/restic-api/api/backend/local"
	"github.com/josh/restic-api/api/backend/location"
	"github.com/josh/restic-api/api/backend/rclone"
	"github.com/josh/restic-api/api/backend/rest"
	"github.com/josh/restic-api/api/backend/s3"
	"github.com/josh/restic-api/api/backend/sftp"
	"github.com/josh/restic-api/api/backend/swift"
	"github.com/josh/restic-api/api/crypto"
	"github.com/josh/restic-api/api/repository"
	"github.com/josh/restic-api/api/restic"
	"github.com/josh/restic-api/api/textfile"
	"github.com/spf13/cobra"
)

// constants settable at build time.
var (
	AgeBin  = ""
	Version = "0.0.0"
)

type options struct {
	ageBin          string
	repo            string
	fromRepo        string
	password        string
	passwordFile    string
	passwordCommand string
	identityFile    string
	identityCommand string
	recipient       string
	recipientsFile  string
	host            string
	user            string
	output          string
	dryRun          bool
}

func newRootCommand() *cobra.Command {
	options := options{
		ageBin:          AgeBin,
		repo:            os.Getenv("RESTIC_REPOSITORY"),
		fromRepo:        os.Getenv("RESTIC_FROM_REPOSITORY"),
		password:        os.Getenv("RESTIC_PASSWORD"),
		passwordFile:    os.Getenv("RESTIC_PASSWORD_FILE"),
		passwordCommand: os.Getenv("RESTIC_PASSWORD_COMMAND"),
		identityFile:    os.Getenv("RESTIC_AGE_IDENTITY_FILE"),
		identityCommand: os.Getenv("RESTIC_AGE_IDENTITY_COMMAND"),
		recipient:       os.Getenv("RESTIC_AGE_RECIPIENT"),
		user:            os.Getenv("RESTIC_AGE_USER"),
		host:            os.Getenv("RESTIC_AGE_HOST"),
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

	if options.ageBin == "" {
		if path, err := exec.LookPath("age"); err == nil {
			options.ageBin = path
		}
	}

	cmd := &cobra.Command{
		Use:   "restic-age-key",
		Short: "Manage age-based encryption keys for restic repositories",
		Long: `restic-age-key allows you to manage age-based encryption keys for restic repositories.
It supports listing existing keys, adding new keys, and retrieving passwords.`,
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.PersistentFlags().StringVar(&options.ageBin, "age-bin", options.ageBin, "path to age binary")
	cmd.PersistentFlags().StringVar(&options.identityFile, "identity-file", options.identityFile, "age identity file (env: RESTIC_AGE_IDENTITY_FILE)")
	cmd.PersistentFlags().StringVar(&options.identityCommand, "identity-command", options.identityCommand, "age identity command (env: RESTIC_AGE_IDENTITY_COMMAND)")

	addDecryptRepoCommands := func(cmd *cobra.Command) {
		cmd.Flags().StringVar(&options.repo, "repo", options.repo, "restic repository location (env: RESTIC_REPOSITORY)")
		cmd.Flags().StringVar(&options.password, "password", options.password, "restic repository password (env: RESTIC_PASSWORD)")
		cmd.Flags().StringVar(&options.passwordFile, "password-file", options.passwordFile, "restic repository password file (env: RESTIC_PASSWORD_FILE)")
		cmd.Flags().StringVar(&options.passwordCommand, "password-command", options.passwordCommand, "restic repository password command (env: RESTIC_PASSWORD_COMMAND)")
	}

	listCommand := &cobra.Command{
		Use:   "list",
		Short: "List all keys in the repository",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyList(cmd.Context(), options, args)
		},
	}
	listCommand.Flags().StringVar(&options.repo, "repo", options.repo, "restic repository location (env: RESTIC_REPOSITORY)")

	addCommand := &cobra.Command{
		Use:   "add",
		Short: "Add a new key to the repository",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyAdd(cmd.Context(), options, args)
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
		Long:  "Set command adds any pubkeys from the recipients file that aren't in the repo, ignores existing pubkeys, and removes keys from the repo that aren't present in the recipients file",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeySet(cmd.Context(), options, args)
		},
	}
	addDecryptRepoCommands(setCommand)
	setCommand.Flags().StringVar(&options.recipientsFile, "recipients-file", "", "file containing age recipient public keys")
	setCommand.Flags().BoolVar(&options.dryRun, "dry-run", false, "do not add or remove keys, just show what would be done")

	passwordCommand := &cobra.Command{
		Use:   "password",
		Short: "Retrieve the password for a key",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyPassword(cmd.Context(), options, args)
		},
	}
	passwordCommand.Flags().StringVar(&options.repo, "repo", options.repo, "restic repository location (env: RESTIC_REPOSITORY)")
	passwordCommand.Flags().StringVar(&options.output, "output", "", "output file to write password to")

	fromPasswordCommand := &cobra.Command{
		Use:   "from-password",
		Short: "Retrieve the password for a key",
		RunE: func(cmd *cobra.Command, args []string) error {
			options.repo = options.fromRepo
			return runKeyPassword(cmd.Context(), options, args)
		},
	}
	fromPasswordCommand.Flags().StringVar(&options.fromRepo, "from-repo", options.fromRepo, "restic repository location (env: RESTIC_FROM_REPOSITORY)")
	fromPasswordCommand.Flags().StringVar(&options.output, "output", "", "output file to write password to")

	cmd.AddCommand(
		listCommand,
		addCommand,
		setCommand,
		passwordCommand,
		fromPasswordCommand,
	)

	return cmd
}

func main() {
	err := newRootCommand().Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	os.Exit(0)
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

func runKeyList(ctx context.Context, opts options, args []string) error {
	if opts.repo == "" {
		return errors.New("Fatal: Please specify repository location (-r or --repository-file)")
	}

	repo, _, err := openRepository(ctx, opts)
	if err != nil {
		return err
	}

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

		if k.AgePubkey == "" {
			return nil
		}

		fmt.Printf("age pubkey: %v\n", k.AgePubkey)

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to list repository files: %w", err)
	}

	return nil
}

func runKeyAdd(ctx context.Context, opts options, args []string) error {
	repo, be, err := openRepository(ctx, opts)
	if err != nil {
		return err
	}

	if opts.recipient == "" {
		return errors.New("Fatal: Please specify recipient (-r or --recipient)")
	}

	password, err := readPassword(&opts)
	if err != nil {
		if opts.identityFile != "" || opts.identityCommand != "" {
			password, err = readPasswordViaIdentity(ctx, opts)
		}

		if err != nil {
			return fmt.Errorf("Resolving password failed: %w", err)
		}
	}

	err = repo.SearchKey(ctx, password, 20, "")
	if err != nil {
		return fmt.Errorf("failed to verify repository key: %w", err)
	}

	params, err := crypto.Calibrate(500*time.Millisecond, 60)
	if err != nil {
		return fmt.Errorf("failed to calibrate crypto parameters: %w", err)
	}

	newkey := &AgeKey{
		Created: time.Now(),
		KDF:     "scrypt",

		N: params.N,
		R: params.R,
		P: params.P,
	}

	newkey.Hostname = opts.host
	if newkey.Hostname == "" {
		return errors.New("hostname is empty")
	}

	newkey.Username = opts.user
	if newkey.Username == "" {
		return errors.New("username is empty")
	}

	newkey.Salt, err = crypto.NewSalt()
	if err != nil {
		return fmt.Errorf("failed to generate new salt: %w", err)
	}

	password, ageData, err := ageEncryptRandomKey(opts.ageBin, opts.recipient)
	if err != nil {
		return err
	}

	newkey.AgePubkey = opts.recipient
	newkey.AgeData = ageData

	user, err := crypto.KDF(params, newkey.Salt, password)
	if err != nil {
		return fmt.Errorf("failed to generate key from password: %w", err)
	}

	if repo.Key() == nil {
		return errors.New("repo master key not loaded")
	}

	buf, err := json.Marshal(repo.Key())
	if err != nil {
		return fmt.Errorf("failed to marshal repository key: %w", err)
	}

	nonce := crypto.NewRandomNonce()
	ciphertext := make([]byte, 0, crypto.CiphertextLength(len(buf)))
	ciphertext = append(ciphertext, nonce...)
	ciphertext = user.Seal(ciphertext, nonce, buf, nil)
	newkey.Data = ciphertext

	buf, err = json.Marshal(newkey)
	if err != nil {
		return fmt.Errorf("failed to marshal new key: %w", err)
	}

	id := restic.Hash(buf)
	h := backend.Handle{
		Type: restic.KeyFile,
		Name: id.String(),
	}

	logPrefix := ""
	if opts.dryRun {
		logPrefix = "[DRY RUN] "
	}
	fmt.Fprintf(os.Stderr, "%sAdd key %s for %s@%s\n", logPrefix, opts.recipient, opts.user, opts.host)

	if opts.dryRun {
		return nil
	}

	err = be.Save(ctx, h, backend.NewByteReader(buf, be.Hasher()))
	if err != nil {
		return fmt.Errorf("failed to save key to backend: %w", err)
	}

	if opts.output != "" {
		file, err := os.OpenFile(opts.output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("failed to write key id to file: %w", err)
		}
		defer file.Close()

		_, err = file.WriteString(id.String()[0:8] + "\n")
		if err != nil {
			return fmt.Errorf("failed to write key id to file: %w", err)
		}
	}

	return nil
}

func runKeyPassword(ctx context.Context, opts options, args []string) error {
	if opts.repo == "" {
		return errors.New("Fatal: Please specify repository location (-r or --repository-file)")
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

		defer file.Close()

		if _, err := file.WriteString(password + "\n"); err != nil {
			return fmt.Errorf("failed to write password to file: %w", err)
		}
	} else {
		fmt.Printf("%s\n", password)
	}

	return nil
}

func runKeySet(ctx context.Context, opts options, args []string) error {
	if opts.repo == "" {
		return errors.New("Fatal: Please specify repository location (-r or --repository-file)")
	}

	if opts.recipientsFile == "" {
		return errors.New("Fatal: Please specify recipients file (--recipients-file)")
	}

	setRecipients, err := readRecipientsFile(opts.recipientsFile)
	if err != nil {
		return errors.New("Fatal: Unable to read recipients file")
	}

	repo, be, err := openRepository(ctx, opts)
	if err != nil {
		return err
	}

	password, err := readPassword(&opts)
	if err != nil {
		if opts.identityFile != "" || opts.identityCommand != "" {
			password, err = readPasswordViaIdentity(ctx, opts)
		}

		if err != nil {
			return fmt.Errorf("Resolving password failed: %w", err)
		}
	}

	err = repo.SearchKey(ctx, password, 20, "")
	if err != nil {
		return fmt.Errorf("failed to verify repository key: %w", err)
	}

	repoKeys := make(map[string]Recipient)

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

		if k.AgePubkey != "" {
			repoKeys[k.AgePubkey] = Recipient{
				ID:     id,
				Pubkey: k.AgePubkey,
				Host:   k.Hostname,
				User:   k.Username,
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to list repository files: %w", err)
	}

	var keysToAdd []Recipient
	var keysToRemove []Recipient

	for _, recipient := range setRecipients {
		if _, exists := repoKeys[recipient.Pubkey]; !exists {
			keysToAdd = append(keysToAdd, recipient)
		}
	}

	for pubkey, existingRecipient := range repoKeys {
		found := false
		for _, recipient := range setRecipients {
			if pubkey == recipient.Pubkey {
				found = true
				break
			}
		}
		if !found {
			keysToRemove = append(keysToRemove, existingRecipient)
		}
	}

	logPrefix := ""
	if opts.dryRun {
		logPrefix = "[DRY RUN] "
	}

	hasError := false

	for _, recipient := range keysToAdd {
		addOpts := opts
		addOpts.recipient = recipient.Pubkey
		addOpts.host = recipient.Host
		addOpts.user = recipient.User
		addOpts.dryRun = opts.dryRun

		err := runKeyAdd(ctx, addOpts, args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to add key %s: %v\n", recipient.Pubkey, err)
			hasError = true
		}
	}

	for _, recipient := range keysToRemove {
		if recipient.ID == repo.KeyID() {
			fmt.Fprintf(os.Stderr, "Error: refusing to remove key currently used to access repository\n")
			hasError = true
			continue
		}

		h := backend.Handle{
			Type: restic.KeyFile,
			Name: recipient.ID.String(),
		}

		fmt.Fprintf(os.Stderr, "%sRemove key %s for %s@%s\n", logPrefix, recipient.Pubkey, recipient.User, recipient.Host)

		if opts.dryRun {
			continue
		}

		err := be.Remove(ctx, h)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to remove key %s: %v\n", recipient.Pubkey, err)
			hasError = true
		}
	}

	if hasError {
		return errors.New("failed to set keys")
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

	return recipients, nil
}

func readPasswordViaIdentity(ctx context.Context, opts options) (string, error) {
	repo, _, err := openRepository(ctx, opts)
	if err != nil {
		return "", err
	}

	closeIdentityCommand, err := readIdentityCommand(&opts)
	if err != nil {
		return "", fmt.Errorf("Resolving identity failed: %w", err)
	}
	defer closeIdentityCommand()

	if opts.identityFile == "" {
		return "", errors.New("no identity file specified")
	}

	var password string

	err = repo.List(ctx, restic.KeyFile, func(id restic.ID, size int64) error {
		if password != "" {
			return nil
		}

		data, err := repo.LoadRaw(ctx, restic.KeyFile, id)
		if err != nil {
			return nil
		}

		k := &AgeKey{}

		err = json.Unmarshal(data, k)
		if err != nil {
			return nil
		}

		if k.AgePubkey == "" {
			return nil
		}

		password, err = ageDecryptKey(opts.ageBin, opts.identityFile, k.AgeData)
		if err != nil {
			if strings.Contains(err.Error(), "no identity matched any of the recipients") {
				return nil
			}

			if strings.Contains(err.Error(), "malformed secret key") {
				return err
			}

			if strings.Contains(err.Error(), "unknown identity type") {
				return err
			}

			return nil
		}

		return nil
	})
	if err != nil {
		return "", err
	}

	if password == "" {
		return "", errors.New("no password found")
	}

	return password, nil
}

func ageEncryptRandomKey(ageBin string, pubkey string) (string, []byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	cmd := exec.Command(ageBin, "--encrypt", "--recipient", pubkey)
	cmd.Stdin = bytes.NewReader(key)

	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", nil, fmt.Errorf("%s", string(exitErr.Stderr))
		}

		return "", nil, fmt.Errorf("failed to encrypt key with age: %w", err)
	}

	return hex.EncodeToString(key), out, nil
}

func ageDecryptKey(ageBin string, identityFile string, key []byte) (string, error) {
	cmd := exec.Command(ageBin, "--decrypt", "--identity", identityFile)
	cmd.Stdin = bytes.NewReader(key)

	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("%s", string(exitErr.Stderr))
		}

		return "", fmt.Errorf("failed to decrypt key with age: %w", err)
	}

	return hex.EncodeToString(out), nil
}

func readIdentityCommand(opts *options) (func(), error) {
	noop := func() {}

	if opts.identityCommand == "" {
		return noop, nil
	}

	if opts.identityFile != "" {
		fmt.Fprintf(os.Stderr, "warn: ignoring identity-command, identity-file already set\n")

		return noop, nil
	}

	args, err := backend.SplitShellStrings(opts.identityCommand)
	if err != nil {
		return noop, fmt.Errorf("failed to split shell string: %w", err)
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stderr = os.Stderr

	output, err := cmd.Output()
	if err != nil {
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
		tmpFile.Close()
		os.Remove(tmpFile.Name())
	}

	_, err = tmpFile.Write(data)
	if err != nil {
		closeCallback()

		return "", nil, fmt.Errorf("failed to write to temporary file: %w", err)
	}

	return tmpFile.Name(), closeCallback, nil
}

func readPassword(opts *options) (string, error) {
	if opts.password != "" {
		return opts.password, nil
	} else if opts.passwordFile != "" {
		s, err := textfile.Read(opts.passwordFile)
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("failed to read password file: %w", err)
		}

		password := strings.TrimSpace(string(s))
		if password == "" {
			return "", errors.New("empty password file")
		}

		return password, nil
	} else if opts.passwordCommand != "" {
		args, err := backend.SplitShellStrings(opts.passwordCommand)
		if err != nil {
			return "", err
		}

		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stderr = os.Stderr

		output, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("failed to execute password command: %w", err)
		}

		password := strings.TrimSpace(string(output))
		if password == "" {
			return "", errors.New("empty password command output")
		}

		return password, nil
	} else {
		return "", errors.New("no password given")
	}
}

func openRepository(ctx context.Context, opts options) (*repository.Repository, backend.Backend, error) {
	backends := collectBackends()

	loc, err := location.Parse(backends, opts.repo)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse repository location: %w", err)
	}

	rt, _ := backend.Transport(backend.TransportOptions{})
	lim := limiter.NewStaticLimiter(limiter.Limits{})
	factory := backends.Lookup(loc.Scheme)

	be, err := factory.Open(ctx, loc.Config, rt, lim)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open backend: %w", err)
	}

	r, err := repository.New(be, repository.Options{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize repository: %w", err)
	}

	_, err = be.Stat(ctx, backend.Handle{Type: restic.ConfigFile})
	if be.IsNotExist(err) {
		return nil, nil, errors.New("repository does not exist: unable to open config file")
	}

	return r, be, nil
}

func collectBackends() *location.Registry {
	backends := location.NewRegistry()
	backends.Register(azure.NewFactory())
	backends.Register(b2.NewFactory())
	backends.Register(gs.NewFactory())
	backends.Register(local.NewFactory())
	backends.Register(rclone.NewFactory())
	backends.Register(rest.NewFactory())
	backends.Register(s3.NewFactory())
	backends.Register(sftp.NewFactory())
	backends.Register(swift.NewFactory())
	return backends
}
