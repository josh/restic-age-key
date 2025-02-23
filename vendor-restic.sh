#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

rm -rf external/
mkdir -p external/

curl -L https://github.com/restic/restic/archive/refs/tags/v0.17.3.tar.gz | tar xz -C external/
mv external/restic-* external/restic
pushd external/restic

mv internal/ public/

pattern="s|github.com/restic/restic/internal|github.com/restic/restic/public|g"
if [[ "$OSTYPE" == "darwin"* ]]; then
	find . -type f -name "*.go" -exec sed -i '' "$pattern" {} +
else
	find . -type f -name "*.go" -exec sed -i "$pattern" {} +
fi
