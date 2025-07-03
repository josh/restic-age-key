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
	AgeProgram    = "age"
	RcloneProgram = "rclone"
	Version       = "1.0.0"
)

type options struct {
	ageProgram      string
	rcloneProgram   string
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
	timeout         time.Duration
	dryRun          bool
}

func newRootCommand() *cobra.Command {
	options := options{
		ageProgram:      AgeProgram,
		rcloneProgram:   RcloneProgram,
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
		SilenceErrors: true,
		SilenceUsage:  true,
		Version:       Version,
	}

	cmd.PersistentFlags().StringVar(&options.ageProgram, "age-program", options.ageProgram, "path to age binary")
	cmd.PersistentFlags().StringVar(&options.rcloneProgram, "rclone-program", options.rcloneProgram, "path to rclone")
	cmd.PersistentFlags().StringVar(&options.identityFile, "identity-file", options.identityFile, "age identity file (env: RESTIC_AGE_IDENTITY_FILE)")
	cmd.PersistentFlags().StringVar(&options.identityCommand, "identity-command", options.identityCommand, "age identity command (env: RESTIC_AGE_IDENTITY_COMMAND)")
	cmd.PersistentFlags().DurationVar(&options.timeout, "timeout", options.timeout, "command timeout (env: RESTIC_AGE_TIMEOUT)")

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
			if options.timeout > 0 {
				ctx, cancel := context.WithTimeout(cmd.Context(), options.timeout)
				defer cancel()
				return runKeyList(ctx, options, args)
			} else {
				return runKeyList(cmd.Context(), options, args)
			}
		},
	}
	addDecryptRepoCommands(listCommand)

	addCommand := &cobra.Command{
		Use:   "add",
		Short: "Add a new key to the repository",
		RunE: func(cmd *cobra.Command, args []string) error {
			if options.timeout > 0 {
				ctx, cancel := context.WithTimeout(cmd.Context(), options.timeout)
				defer cancel()
				return runKeyAdd(ctx, options, args)
			} else {
				return runKeyAdd(cmd.Context(), options, args)
			}
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
			if options.timeout > 0 {
				ctx, cancel := context.WithTimeout(cmd.Context(), options.timeout)
				defer cancel()
				return runKeySet(ctx, options, args)
			} else {
				return runKeySet(cmd.Context(), options, args)
			}
		},
	}
	addDecryptRepoCommands(setCommand)
	setCommand.Flags().StringVar(&options.recipientsFile, "recipients-file", "", "file containing age recipient public keys")
	setCommand.Flags().BoolVar(&options.dryRun, "dry-run", false, "do not add or remove keys, just show what would be done")

	passwordCommand := &cobra.Command{
		Use:   "password",
		Short: "Retrieve the password for a key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if options.timeout > 0 {
				ctx, cancel := context.WithTimeout(cmd.Context(), options.timeout)
				defer cancel()
				return runKeyPassword(ctx, options, args)
			} else {
				return runKeyPassword(cmd.Context(), options, args)
			}
		},
	}
	passwordCommand.Flags().StringVar(&options.repo, "repo", options.repo, "restic repository location (env: RESTIC_REPOSITORY)")
	passwordCommand.Flags().StringVar(&options.output, "output", "", "output file to write password to")

	fromPasswordCommand := &cobra.Command{
		Use:   "from-password",
		Short: "Retrieve the password for a key",
		RunE: func(cmd *cobra.Command, args []string) error {
			options.repo = options.fromRepo
			if options.timeout > 0 {
				ctx, cancel := context.WithTimeout(cmd.Context(), options.timeout)
				defer cancel()
				return runKeyPassword(ctx, options, args)
			} else {
				return runKeyPassword(cmd.Context(), options, args)
			}
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

type ListKey struct {
	ID        string
	ShortID   string
	AgePubkey string
	IsCurrent bool
	Username  string
	Hostname  string
	Created   string
}

func runKeyList(ctx context.Context, opts options, args []string) error {
	if opts.repo == "" {
		return errors.New("Fatal: Please specify repository location (-r or --repository-file)")
	}

	repo, _, err := openRepositoryWithPassword(ctx, opts)
	if err != nil {
		return err
	}

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

		shortID := idStr
		if len(idStr) > 8 {
			shortID = idStr[:8]
		}

		keys = append(keys, ListKey{
			ID:        idStr,
			ShortID:   shortID,
			IsCurrent: isCurrent,
			AgePubkey: k.AgePubkey,
			Username:  k.Username,
			Hostname:  k.Hostname,
			Created:   k.Created.Local().Format("2006-01-02 15:04:05"),
		})

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to list repository files: %w", err)
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

func runKeyAdd(ctx context.Context, opts options, args []string) error {
	repo, be, err := openRepositoryWithPassword(ctx, opts)
	if err != nil {
		return err
	}

	if opts.recipient == "" {
		return errors.New("Fatal: Please specify recipient (-r or --recipient)")
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

	password, ageData, err := ageEncryptRandomKey(ctx, opts.ageProgram, opts.recipient)
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

	repo, be, err := openRepositoryWithPassword(ctx, opts)
	if err != nil {
		return err
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

	closeIdentityCommand, err := readIdentityCommand(ctx, &opts)
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

		password, err = ageDecryptKey(ctx, opts.ageProgram, opts.identityFile, k.AgeData)
		if err != nil {
			if strings.Contains(err.Error(), "no identity matched any of the recipients") {
				return nil
			}

			return err
		}

		return nil
	})

	if password != "" {
		return password, nil
	} else if err != nil {
		return "", err
	} else {
		return "", errors.New("no password found")
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
		if ctx.Err() == context.DeadlineExceeded {
			return "", nil, fmt.Errorf("timeout exceeded while encrypting key with age")
		}

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", nil, fmt.Errorf("%s", string(exitErr.Stderr))
		}

		return "", nil, fmt.Errorf("failed to encrypt key with age: %w", err)
	}

	return hex.EncodeToString(key), out, nil
}

func ageDecryptKey(ctx context.Context, ageProgram string, identityFile string, key []byte) (string, error) {
	cmd := exec.CommandContext(ctx, ageProgram, "--decrypt", "--identity", identityFile)
	cmd.Stdin = bytes.NewReader(key)

	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("timeout exceeded while decrypting key with age")
		}

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
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

	args, err := backend.SplitShellStrings(opts.identityCommand)
	if err != nil {
		return noop, fmt.Errorf("failed to split shell string: %w", err)
	}

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stderr = os.Stderr

	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return noop, fmt.Errorf("timeout exceeded while executing identity command")
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

func readPassword(ctx context.Context, opts *options) (string, error) {
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

		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Stderr = os.Stderr

		output, err := cmd.Output()
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return "", fmt.Errorf("timeout exceeded while executing password command")
			}
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

func openRepositoryWithPassword(ctx context.Context, opts options) (*repository.Repository, backend.Backend, error) {
	repo, be, err := openRepository(ctx, opts)
	if err != nil {
		return nil, nil, err
	}

	password, err := readPassword(ctx, &opts)
	if err != nil {
		if opts.identityFile != "" || opts.identityCommand != "" {
			password, err = readPasswordViaIdentity(ctx, opts)
		}

		if err != nil {
			return nil, nil, fmt.Errorf("Fatal: Resolving password failed: %w", err)
		}
	}

	err = repo.SearchKey(ctx, password, 20, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify repository key: %w", err)
	}

	return repo, be, nil
}

func openRepository(ctx context.Context, opts options) (*repository.Repository, backend.Backend, error) {
	backends := collectBackends()

	loc, err := location.Parse(backends, opts.repo)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse repository location: %w", err)
	}

	cfg := loc.Config
	if rcloneCfg, ok := cfg.(*rclone.Config); ok {
		rcloneCfg.Program = opts.rcloneProgram
	}

	rt, _ := backend.Transport(backend.TransportOptions{})
	lim := limiter.NewStaticLimiter(limiter.Limits{})
	factory := backends.Lookup(loc.Scheme)

	be, err := factory.Open(ctx, cfg, rt, lim)
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
