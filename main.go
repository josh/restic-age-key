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
	passwordCommand := &cobra.Command{
		Use:   "password",
		Short: "Retrieve the password for a key",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyPassword(cmd.Context(), options, args)
		},
	}

	cmd.AddCommand(
		listCommand,
		addCommand,
		passwordCommand,
	)

	return cmd
}

func Main() int {
	ctx := context.Background()

	err := newRootCommand().ExecuteContext(ctx)
	if err != nil {
		return 1
	}

	return 0
}

func main() {
	ctx := context.Background()

	err := newRootCommand().ExecuteContext(ctx)
	if err != nil {
		os.Exit(1)
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

func runKeyList(ctx context.Context, opts options, args []string) error {
	if opts.repo == "" {
		fmt.Fprintf(os.Stderr, "Fatal: Please specify repository location (-r or --repository-file)\n")
		os.Exit(1)
	}

	repo, _, err := openRepository(ctx, opts)
	if err != nil {
		return err
	}

	err = repo.List(ctx, restic.KeyFile, func(id restic.ID, size int64) error {
		data, err := repo.LoadRaw(ctx, restic.KeyFile, id)
		if err != nil {
			return nil
		}

		k := &AgeKey{}

		err = json.Unmarshal(data, k)
		if err != nil {
			return err
		}

		if k.AgePubkey == "" {
			return nil
		}

		fmt.Printf("age pubkey: %v\n", k.AgePubkey)

		return nil
	})
	if err != nil {
		return err
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
		return err
	}
	err = repo.SearchKey(ctx, password, 20, "")
	if err != nil {
		return err
	}

	params, err := crypto.Calibrate(500*time.Millisecond, 60)
	if err != nil {
		return err
	}

	newkey := &AgeKey{
		Created: time.Now(),
		KDF:     "scrypt",

		N: params.N,
		R: params.R,
		P: params.P,
	}

	newkey.Hostname, _ = os.Hostname()

	usr, err := user.Current()
	if err == nil {
		newkey.Username = usr.Username
	}

	newkey.Salt, err = crypto.NewSalt()
	if err != nil {
		return err
	}

	password, ageData, err := ageEncryptRandomKey(opts.recipient)
	if err != nil {
		return err
	}

	newkey.AgePubkey = opts.recipient
	newkey.AgeData = ageData

	user, err := crypto.KDF(params, newkey.Salt, password)
	if err != nil {
		return err
	}

	if repo.Key() == nil {
		return errors.New("repo master key not loaded")
	}

	buf, err := json.Marshal(repo.Key())
	if err != nil {
		return err
	}

	nonce := crypto.NewRandomNonce()
	ciphertext := make([]byte, 0, crypto.CiphertextLength(len(buf)))
	ciphertext = append(ciphertext, nonce...)
	ciphertext = user.Seal(ciphertext, nonce, buf, nil)
	newkey.Data = ciphertext

	buf, err = json.Marshal(newkey)
	if err != nil {
		return err
	}

	id := restic.Hash(buf)
	h := backend.Handle{
		Type: restic.KeyFile,
		Name: id.String(),
	}

	err = be.Save(ctx, h, backend.NewByteReader(buf, be.Hasher()))
	if err != nil {
		return err
	}

	return nil
}

// Decrypt age-data using age identity and print out string representation as it's the password.
func runKeyPassword(ctx context.Context, opts options, args []string) error {
	repo, _, err := openRepository(ctx, opts)
	if err != nil {
		return err
	}

	closeIdentityCommand, err := readIdentityCommand(&opts)
	if err != nil {
		return err
	}
	defer closeIdentityCommand()

	err = repo.List(ctx, restic.KeyFile, func(id restic.ID, size int64) error {
		data, err := repo.LoadRaw(ctx, restic.KeyFile, id)
		if err != nil {
			return nil
		}

		k := &AgeKey{}

		err = json.Unmarshal(data, k)
		if err != nil {
			return err
		}

		if k.AgePubkey == "" {
			return nil
		}

		password, err := ageDecryptKey(opts.identityFile, k.AgeData)
		if err != nil {
			return err
		}

		fmt.Println(string(password))

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func ageEncryptRandomKey(pubkey string) (string, []byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", nil, err
	}

	cmd := exec.Command("age", "--encrypt", "--recipient", pubkey)
	cmd.Stdin = bytes.NewReader(key)

	out, err := cmd.Output()
	if err != nil {
		return "", nil, err
	}

	return hex.EncodeToString(key), out, nil
}

func ageDecryptKey(identityFile string, key []byte) (string, error) {
	cmd := exec.Command("age", "--decrypt", "--identity", identityFile)
	cmd.Stdin = bytes.NewReader(key)

	out, err := cmd.Output()
	if err != nil {
		return "", err
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
		return noop, err
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
		return "", nil, err
	}

	closeCallback := func() {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
	}

	_, err = tmpFile.Write(data)
	if err != nil {
		closeCallback()
		return "", nil, err
	}

	return tmpFile.Name(), closeCallback, nil
}

func readPassword(opts *options) (string, error) {
	if opts.password != "" {
		return opts.password, nil
	} else if opts.passwordFile != "" {
		s, err := textfile.Read(opts.passwordFile)
		if errors.Is(err, os.ErrNotExist) {
			return "", err
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
			return "", err
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
		return nil, nil, err
	}

	rt, _ := backend.Transport(backend.TransportOptions{})
	lim := limiter.NewStaticLimiter(limiter.Limits{})
	factory := backends.Lookup(loc.Scheme)

	be, err := factory.Open(ctx, loc.Config, rt, lim)
	if err != nil {
		return nil, nil, err
	}

	r, err := repository.New(be, repository.Options{})
	if err != nil {
		return nil, nil, err
	}

	_, err = be.Stat(ctx, backend.Handle{Type: restic.ConfigFile})
	if be.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Fatal: repository does not exist: unable to open config file\n")
		os.Exit(1)
	}

	return r, be, nil
}
