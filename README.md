# `go-sshsudo`

SSH with sudo.

This operates by opening a shell and feeding it commands after sudo.

It also does a preflight check to see if a password will be required
for a shell so that it may bypass the password entry portion.

## Testing

The test suite will spin up docker containers to test over a real
simulated session.  You will need to have docker installed and
configured to be able to run a container in order to run `go test`.

## License

See [LICENSE](./LICENSE) file.
