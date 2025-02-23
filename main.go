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
	"os/user"
	"time"

	"github.com/restic/restic/public/backend"
	"github.com/restic/restic/public/backend/limiter"
	"github.com/restic/restic/public/backend/local"
	"github.com/restic/restic/public/backend/location"
	"github.com/restic/restic/public/backend/rclone"
	"github.com/restic/restic/public/backend/rest"
	"github.com/restic/restic/public/crypto"
	"github.com/restic/restic/public/repository"
	"github.com/restic/restic/public/restic"
	"github.com/spf13/cobra"
)

type options struct {
	repo         string
	password     string
	identityFile string
	recipient    string
}

func newRootCommand() *cobra.Command {
	options := options{
		repo:         os.Getenv("RESTIC_REPOSITORY"),
		password:     os.Getenv("RESTIC_PASSWORD"),
		identityFile: os.Getenv("RESTIC_AGE_IDENTITY_FILE"),
		recipient:    os.Getenv("RESTIC_AGE_RECIPIENT"),
	}

	cmd := &cobra.Command{
		Use:   "restic-age-key",
		Short: "Manage age-based encryption keys for restic repositories",
		Long: `restic-age-key allows you to manage age-based encryption keys for restic repositories.
It supports listing existing keys, adding new keys, and retrieving passwords.`,
	}

	cmd.PersistentFlags().StringVarP(&options.repo, "repo", "r", options.repo, "restic repository location (env: RESTIC_REPOSITORY)")
	cmd.PersistentFlags().StringVarP(&options.password, "password", "p", options.password, "restic repository password (env: RESTIC_PASSWORD)")
	cmd.PersistentFlags().StringVarP(&options.identityFile, "identity-file", "i", options.identityFile, "age identity file (env: RESTIC_AGE_IDENTITY_FILE)")
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
	repo, _, err := openRepository(ctx, opts.repo)
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

		fmt.Printf("age publey: %v\n", k.AgePubkey)
		return nil
	})

	if err != nil {
		return err
	}

	return nil
}

func runKeyAdd(ctx context.Context, opts options, args []string) error {
	repo, be, err := openRepository(ctx, opts.repo)
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
	repo, _, err := openRepository(ctx, opts.repo)
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

func openRepository(ctx context.Context, repo string) (*repository.Repository, backend.Backend, error) {
	backends := location.NewRegistry()
	backends.Register(local.NewFactory())
	backends.Register(rclone.NewFactory())
	backends.Register(rest.NewFactory())

	loc, err := location.Parse(backends, repo)
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

	return r, be, nil
}
