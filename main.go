package sshsudo

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/go-exafi/shq"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

func openSessionPipes(session *ssh.Session) (
	io.WriteCloser,
	io.Reader,
	io.Reader,
	error,
) {
	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, nil, nil, err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		stdin.Close()
		return nil, nil, nil, err
	}
	return stdin, stdout, stderr, nil
}

func mustWrite(w io.Writer, data []byte) error {
	_, err := io.Copy(w, bytes.NewReader(data))
	return err
}

type writeEchoer chan byte

func (re writeEchoer) Write(data []byte) (int, error) {
	for i := 0; i < len(data); i++ {
		re <- data[i]
	}
	return len(data), nil
}

func newWriteEchoer() writeEchoer {
	c := make(chan byte)
	go func() {
		for {
			b := <-c
			fmt.Printf("Read a byte: %v\n", string([]byte{b}))
		}
	}()
	return writeEchoer(c)
}

func CheckSudoNeedsPassword(client *ssh.Client) (bool, error) {
	session, err := client.NewSession()
	if err != nil {
		return false, err
	}

	if err := session.Run("sudo -n -v"); err != nil {
		if _, ok := err.(*ssh.ExitError); ok {
			return true, nil
		} else {
			return false, fmt.Errorf("Could not run sudo -n -v to check for sudo password requirement: %w", err)
		}
	}

	return false, nil
}

var ErrNoSudoPrompt = errors.New("no sudo prompt found when expected")
var ErrNoReadyFlag = errors.New("no READY flag found when expected")

type PasswordCallbackFailureError struct {
	wrapped error
}

func (e PasswordCallbackFailureError) Unwrap() error {
	return e.wrapped
}

func (e PasswordCallbackFailureError) Error() string {
	return "password callback returned an error"
}

func (e PasswordCallbackFailureError) Is(target error) bool {
	_, ok := target.(PasswordCallbackFailureError)
	return ok
}

// run a command with sudo over the ssh client
//
// passwordCallback will be called if a sudo password is needed.
//
// the command will be run in a shell with all elements quoted to
// prevent word splitting or expansion.  use eval to achieve this
// if needed.
func SudoRun(client *ssh.Client, passwordCallback SudoPasswordCallback, command ...string) (
	io.WriteCloser,
	io.Reader,
	io.Reader,
	*ssh.Session,
	error,
) {
	sudoNeedsPass, err := CheckSudoNeedsPassword(client)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		err = fmt.Errorf("could not start an ssh session %w", err)
		return nil, nil, nil, nil, err
	}
	success := false
	defer func() {
		if !success {
			session.Close()
		}
	}()

	stdin, stdout, stderr, err := openSessionPipes(session)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer func() {
		if !success {
			stdin.Close()
		}
	}()

	sudoPasswordOpt := "-n"
	randomString := ""
	if sudoNeedsPass {
		randomString = uuid.New().String()
		sudoPasswordOpt = fmt.Sprintf("-p %s", shq.Arg(randomString))
	}

	commandline := &strings.Builder{}
	spc := ""
	for i := 0; i < len(command); i++ {
		fmt.Fprintf(commandline, "%s%s", spc, shq.Arg(command[i]))
		spc = " "
	}

	err = session.Start(fmt.Sprintf("sudo -S %s /bin/sh -c 'echo READY;'%s", sudoPasswordOpt, shq.Arg(commandline.String())))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to start session: %w", err)
	}

	if sudoNeedsPass {
		match, err := expectOnly(stderr, []byte(randomString))
		if err != nil {
			err = fmt.Errorf("error while expecting sudo prompt: %w", err)
			return nil, nil, nil, nil, err
		}
		if !match {
			return nil, nil, nil, nil, ErrNoSudoPrompt
		}
		pwd, err := passwordCallback()
		if err != nil {
			return nil, nil, nil, nil, PasswordCallbackFailureError{err}
		}
		_, err = io.Copy(stdin, strings.NewReader(pwd+"\n"))
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}

	match, err := expectOnly(stdout, []byte("READY\n"))
	if err != nil {
		err = fmt.Errorf("error while expecting READY flag: %w", err)
		return nil, nil, nil, nil, err
	}
	if !match {
		return nil, nil, nil, nil, ErrNoReadyFlag
	}
	success = true // don't close the resources in defer
	return stdin, stdout, stderr, session, nil
}

// open a shell with sudo on the ssh client
//
// passwordCallback will be called if a sudo password is needed.
func SudoShell(client *ssh.Client, passwordCallback SudoPasswordCallback) (
	io.WriteCloser,
	io.Reader,
	io.Reader,
	*ssh.Session,
	error,
) {
	return SudoRun(client, passwordCallback, "sh", "-")
}

type SudoPasswordCallback func() (string, error)

func SudoStaticPasswordCallback(pwd string) SudoPasswordCallback {
	return func() (string, error) {
		return pwd, nil
	}
}

func expectOnly(r io.Reader, expected []byte) (bool, error) {
	for len(expected) > 0 {
		buf := make([]byte, 1)
		n, err := r.Read(buf)
		if err != nil {
			err = fmt.Errorf("error while reading: %w", err)
			return false, err
		}
		if n == 1 {
			if buf[0] != '\r' {
				if expected[0] != buf[0] {
					return false, nil
				}
				expected = expected[1:]
			}
		}
	}
	return true, nil
}
