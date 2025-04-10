# restic-age-key

Use asymmetric [age](https://age-encryption.org/) keys instead of a password on your [restic](https://restic.net) repository.

## Usage

### `list`

List keys:

```sh
restic-age-key list \
  --repo /tmp/restic-repo \
  --identity key.txt

 ID        Age Pubkey  User  Host  Created
------------------------------------------------------
 abcd1234  age16gj...  john  foo   2025-01-01 12:00:00
 efgh5678  age13er...  john  bar   2025-01-01 12:00:00
 ijkl9012              john  baz   2025-01-01 12:00:00
------------------------------------------------------
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

### `set`

Update and replace all age keys with a given recipients file:

```sh
restic-age-key set \
  --repo /tmp/restic-repo \
  --recipients-file recipients.json
```

### `password`

This can be used as your `RESTIC_PASSWORD_COMMAND` value.

```sh
restic-age-key password \
  --repo /tmp/restic-repo \
  --identity key.txt
```

`restic-age-key` uses the same standard environment variables which allows you to configure your backup scripts using something like:

```
export RESTIC_REPOSITORY=/path/to/repo
export RESTIC_PASSWORD_COMMAND='restic-age-key password'
export RESTIC_AGE_IDENTITY_FILE=/path/to/key.txt

restic backup
```

Should you need to recover your password without `restic-age-key`, you can use a few standard unix tools.

```sh
cat /tmp/restic-repo/keys/123abc | \
  jq --raw-output '."age-data"' | \
  base64 --decode | \
  age --decrypt --identity "your-age-identity.txt" | \
  xxd --plain --cols 64
```
