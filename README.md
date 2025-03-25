# restic-age-key

Use asymmetric [age](https://age-encryption.org/) keys instead of a password on your [restic](https://restic.net) repository.

## Usage

### `list`

List only age keys:

```sh
restic-age-key list \
  --repo /tmp/restic-repo \
  --identity key.txt
# OUTPUT TK
```

### `add`

Add first age key using existing password:

```sh
restic-age-key add \
  --repo /tmp/restic-repo \
  --password secret \
  --pubkey age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

Add subsequent age keys using another age key:

```sh
restic-age-key add \
  --repo /tmp/restic-repo \
  --identity key.txt \
  --pubkey age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

### `remove`

```sh
restic-age-key remove \
  --repo /tmp/restic-repo \
  --pubkey age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

### `password`

This can be used as your `RESTIC_PASSWORD_COMMAND` value.

```sh
restic-age-key password \
  --repo /tmp/restic-repo \
  --identity key.txt
```

Should you need to recover your password without `restic-age-key`, you can use a few standard unix tools.

```sh
cat /tmp/restic-repo/keys/123abc | \
  jq --raw-output '."age-data"' | \
  base64 --decode | \
  age --decrypt --identity "your-age-identity.txt" | \
  xxd --plain --cols 64
```
