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
	"github.com/josh/restic-api/api/backend/limiter"
	"github.com/josh/restic-api/api/backend/local"
	"github.com/josh/restic-api/api/backend/location"
	"github.com/josh/restic-api/api/backend/rclone"
	"github.com/josh/restic-api/api/backend/rest"
	"github.com/josh/restic-api/api/crypto"
	"github.com/josh/restic-api/api/repository"
	"github.com/josh/restic-api/api/restic"
	"github.com/josh/restic-api/api/textfile"
	"github.com/spf13/cobra"
)

type options struct {
	repo            string
	password        string
	passwordFile    string
	passwordCommand string
	identityFile    string
	identityCommand string
	recipient       string
	host            string
	user            string
	output          string
}

func newRootCommand() *cobra.Command {
	options := options{
		repo:            os.Getenv("RESTIC_REPOSITORY"),
		password:        os.Getenv("RESTIC_PASSWORD"),
		passwordFile:    os.Getenv("RESTIC_PASSWORD_FILE"),
		passwordCommand: os.Getenv("RESTIC_PASSWORD_COMMAND"),
		identityFile:    os.Getenv("RESTIC_AGE_IDENTITY_FILE"),
		identityCommand: os.Getenv("RESTIC_AGE_IDENTITY_COMMAND"),
		recipient:       os.Getenv("RESTIC_AGE_RECIPIENT"),
	}

	cmd := &cobra.Command{
		Use:   "restic-age-key",
		Short: "Manage age-based encryption keys for restic repositories",
		Long: `restic-age-key allows you to manage age-based encryption keys for restic repositories.
It supports listing existing keys, adding new keys, and retrieving passwords.`,
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.PersistentFlags().StringVarP(&options.repo, "repo", "r", options.repo, "restic repository location (env: RESTIC_REPOSITORY)")
	cmd.PersistentFlags().StringVarP(&options.password, "password", "p", options.password, "restic repository password (env: RESTIC_PASSWORD)")
	cmd.PersistentFlags().StringVarP(&options.passwordFile, "password-file", "P", options.passwordFile, "restic repository password file (env: RESTIC_PASSWORD_FILE)")
	cmd.PersistentFlags().StringVarP(&options.passwordCommand, "password-command", "C", options.passwordCommand, "restic repository password command (env: RESTIC_PASSWORD_COMMAND)")
	cmd.PersistentFlags().StringVarP(&options.identityFile, "identity-file", "i", options.identityFile, "age identity file (env: RESTIC_AGE_IDENTITY_FILE)")
	cmd.PersistentFlags().StringVar(&options.identityCommand, "identity-command", options.identityCommand, "age identity command (env: RESTIC_AGE_IDENTITY_COMMAND)")
	cmd.PersistentFlags().StringVarP(&options.recipient, "recipient", "R", options.recipient, "age recipient public key (env: RESTIC_AGE_RECIPIENT)")

	listCommand := &cobra.Command{
		Use:   "list",
		Short: "List all keys in the repository",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyList(cmd.Context(), options, args)
		},
	}

	addCommand := &cobra.Command{
		Use:   "add",
		Short: "Add a new key to the repository",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyAdd(cmd.Context(), options, args)
		},
	}
	addCommand.Flags().StringVar(&options.host, "host", "", "the hostname for new key")
	addCommand.Flags().StringVar(&options.user, "user", "", "the username for new key")
	addCommand.Flags().StringVar(&options.output, "output", "", "output file to write key id to")

	passwordCommand := &cobra.Command{
		Use:   "password",
		Short: "Retrieve the password for a key",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyPassword(cmd.Context(), options, args)
		},
	}
	passwordCommand.Flags().StringVar(&options.output, "output", "", "output file to write password to")

	cmd.AddCommand(
		listCommand,
		addCommand,
		passwordCommand,
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

	password, err := readPassword(&opts)
	if err != nil {
		if opts.identityFile != "" || opts.identityCommand != "" {
			password, err = readPasswordViaIdentity(ctx, opts)
		}

		if err != nil {
			return fmt.Errorf("failed to unmarshal data: %w", err)
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

	if hostname, err := os.Hostname(); err == nil {
		newkey.Hostname = hostname
	}

	if opts.host != "" {
		newkey.Hostname = opts.host
	}

	if newkey.Hostname == "" {
		return errors.New("hostname is empty")
	}

	if user, err := user.Current(); err == nil {
		newkey.Username = user.Username
	}

	if opts.user != "" {
		newkey.Username = opts.user
	}

	if newkey.Username == "" {
		return errors.New("username is empty")
	}

	newkey.Salt, err = crypto.NewSalt()
	if err != nil {
		return fmt.Errorf("failed to generate new salt: %w", err)
	}

	password, ageData, err := ageEncryptRandomKey(opts.recipient)
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

	err = be.Save(ctx, h, backend.NewByteReader(buf, be.Hasher()))
	if err != nil {
		return fmt.Errorf("failed to save key to backend: %w", err)
	}

	if opts.output != "" {
		file, err := os.OpenFile(opts.output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("failed to unmarshal data: %w", err)
		}
		defer file.Close()

		_, err = file.WriteString(id.String()[0:8] + "\n")
		if err != nil {
			return fmt.Errorf("failed to unmarshal data: %w", err)
		}
	}

	return nil
}

func runKeyPassword(ctx context.Context, opts options, args []string) error {
	password, err := readPasswordViaIdentity(ctx, opts)
	if err != nil {
		return err
	}

	if opts.output != "" {
		file, err := os.OpenFile(opts.output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("failed to unmarshal data: %w", err)
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

func readPasswordViaIdentity(ctx context.Context, opts options) (string, error) {
	repo, _, err := openRepository(ctx, opts)
	if err != nil {
		return "", err
	}

	closeIdentityCommand, err := readIdentityCommand(&opts)
	if err != nil {
		return "", err
	}
	defer closeIdentityCommand()

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

		password, err = ageDecryptKey(opts.identityFile, k.AgeData)
		if err != nil {
			return nil
		}

		return nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to list repository files: %w", err)
	}

	if password == "" {
		return "", errors.New("no password found")
	}

	return password, nil
}

func ageEncryptRandomKey(pubkey string) (string, []byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	cmd := exec.Command("age", "--encrypt", "--recipient", pubkey)
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

func ageDecryptKey(identityFile string, key []byte) (string, error) {
	cmd := exec.Command("age", "--decrypt", "--identity", identityFile)
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
			return "", fmt.Errorf("failed to parse password command: %w", err)
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
	backends := location.NewRegistry()
	backends.Register(local.NewFactory())
	backends.Register(rclone.NewFactory())
	backends.Register(rest.NewFactory())

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
