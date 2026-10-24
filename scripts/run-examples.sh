#!/bin/sh
# Disposable fixtures: never read or overwrite the maintainer's shares directory.
set -eu
mpc_example_tmp=$(mktemp -d)
trap 'rm -rf "$mpc_example_tmp"' EXIT HUP INT TERM
MPC_WRAPPING_KEY=$(od -An -v -N32 -tx1 /dev/urandom | tr -d ' \n')
export MPC_WRAPPING_KEY
for protocol in dkls23 frost; do
  MPC_DEMO_DIR="$mpc_example_tmp/$protocol"
  export MPC_DEMO_DIR
  go -C "example/$protocol" run .
  go -C "example/$protocol" run .
done
go -C example/cold-frost run . demo "$mpc_example_tmp/cold-frost"
go -C example/cold-dkls23 run . demo "$mpc_example_tmp/cold-dkls23"
