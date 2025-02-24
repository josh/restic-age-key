# restic-age-key

Use asymmetric [age](https://age-encryption.org/) keys instead of a password on your [restic](https://restic.net) repository.

## Usage

List only age keys:

```sh
restic-age-key list \
  --repo /tmp/restic-repo \
  --identity key.txt
# OUTPUT TK
```

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

Remove age key:

```sh
restic-age-key remove \
  --repo /tmp/restic-repo \
  --pubkey age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

Note: You can remove your own pubkey and lock yourself out.
