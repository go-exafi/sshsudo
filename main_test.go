package sshsudo

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"sync"
	"testing"

	"github.com/go-exafi/dockertesting"
	"github.com/go-exafi/shq"
	"github.com/go-exafi/sshbuilder"
)

func TestSudoRun(t *testing.T) {
	resource := dockertesting.RunDockerfile(t, "test/Dockerfile")
	resource.Expire(300)

	sshb := sshbuilder.New().
		WithUsername("testuser").
		WithHostPort(resource.GetHostPort("22/tcp")).
		WithInsecureIgnoreHostKey().
		WithPassword("pass word")

	for i := 0; i < 128; i++ {
		t.Run("testing random chars with printf", func(t *testing.T) {
			t.Parallel()
			sshc, err := sshb.Dial()
			if err != nil {
				t.Errorf("Failed to connect to testing docker container ssh: %v", err)
				return
			}

			strs := make([]string, 32)
			for i := 0; i < len(strs); i++ {
				str := make([]byte, 128)
				if n, err := rand.Read(str); n != len(str) || err != nil {
					t.Errorf("Failed to read a random string for testing: %v", err)
					return
				}
				strs[i] = string(str)
			}
			cmds := []string{"printf", `%s\n`}
			expectedBytes := bytes.Buffer{}
			for i := 0; i < len(strs); i++ {
				cmds = append(cmds, strs[i])
				_, err := expectedBytes.WriteString(shq.Arg(strs[i]).Unescaped() + "\n")
				if err != nil {
					t.Errorf("Failed to write string to expectedBytes: %v", err)
					return
				}
			}
			stdin, stdout, stderr, session, err := SudoRun(sshc, SudoStaticPasswordCallback("pass word"), cmds...)
			if err != nil {
				t.Errorf("Failed to start printf in sudo test: %v", err)
				return
			}
			defer stdin.Close()

			var stdoutBytes []byte
			var stdoutError error
			var stderrBytes []byte
			var stderrError error
			rwg := sync.WaitGroup{}
			rwg.Add(2)
			go func() {
				defer rwg.Done()
				stdoutBytes, stdoutError = ioutil.ReadAll(stdout)
			}()
			go func() {
				defer rwg.Done()
				stderrBytes, stderrError = ioutil.ReadAll(stderr)
			}()
			rwg.Wait()

			if stdoutError != nil {
				t.Errorf("Failed to read from stdout: %v", stdoutError)
				return
			}
			if stderrError != nil {
				t.Errorf("Failed to read from stderr: %v", stderrError)
				return
			}
			if !bytes.Equal(stdoutBytes, expectedBytes.Bytes()) {
				t.Errorf("stdout did not match expected output: %#v != %#v", string(stdoutBytes), expectedBytes.String())
				return
			}

			if len(stderrBytes) > 0 {
				t.Errorf("output on stderr! %v", string(stderrBytes))
				return
			}

			if err := session.Wait(); err != nil {
				t.Errorf("Failed to run printf in sudo test: %v", err)
				return
			}
		})
	}
}
