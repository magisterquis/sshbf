/* sshtask.go implements a single ssh task. */

package main

import (
	"code.google.com/p/go.crypto/ssh"
	"github.com/kd5pbo/lockedint"
	"log"
	"time"
)

/* template contains a username and a host.  It can be used to make an
attempt. */
type template struct {
	User string
	Host string
}

type TimeoutError struct{}

func (e *TimeoutError) Error() string { return "task timeout" }

/* New makes a new attempt from a template with Pass and Config filled in, and
a version string of v. */
func (t template) New(p, v string) attempt {
	n := attempt{User: t.User, Pass: p, Host: t.Host, Err: nil}
	n.Config = &ssh.ClientConfig{
		User: n.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(n.Pass),
		},
		ClientVersion: v,
	}
	return n
}

/* attempt contains all the data needed for an attempt to guess a password */
type attempt struct {
	User    string
	Pass    string
	Host    string
	Config  *ssh.ClientConfig
	Err     error /* Set if the attempt produced an error. */
	Tasknum int   /* Task number that handled the task. */
}

/* sshTask represents one parallelizable brute-forcer. attempts come in on
attemptc, and if a match is found, the userame, password, and host are sent
back on successc.  Tasknum is a unique identifier for this task. If triesf is
true, every attempt will to be printed. wait specifies how long each attempt
will wait, with an upper bound specified opaquely by the ssh library.  If errdb
is true, ssh errors will be printed.  The task will pause for pause after each
attempt. */
func sshTask(a attempt, nRunning *lockedint.TInt, failc, successc chan attempt,
	tasknum int, triesf bool, wait, pause time.Duration) {
	/* Attempt to connect to server and authenticate. */
	if triesf {
		log.Printf("[%v] Attempting %v@%v - %v", tasknum, a.User,
			a.Host, textIfBlank(a.Pass))
	}
	/* Channels internal to this sshtask */
	sc := make(chan attempt)
	fc := make(chan attempt)
	/* Closure (yuck) goroutine to actually run the task */
	go func() {
		_, err := ssh.Dial("tcp", a.Host, a.Config)
		/* Send the attempt on the appropriate channel. */
		if err != nil {
			a.Err = err
			a.Tasknum = tasknum
			fc <- a
		} else {
			sc <- a
		}
	}()
	select {
	case a := <-fc:
		failc <- a
	case a := <-sc:
		successc <- a
	case <-time.After(wait):
		a.Err = &TimeoutError{}
		a.Tasknum = tasknum
                failc <- a
	}
	/* Decrement the counter of alive sshtasks */
	nRunning.Dec()
        /* Pause for rate-limiting. */
        if pause > 0 {
                time.Sleep(pause)
        }
}
