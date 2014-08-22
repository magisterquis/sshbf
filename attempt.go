/* attempt provides the structs for templates and attempts, and the related
functions */
package main

import (
	"code.google.com/p/go.crypto/ssh"
)

/* Template represents a username/password pair */
type Template struct {
	User string /* Username */
	Pass string /* Password */
}

/* Make an attempt from the template.  The attempt will eventually go back on
d to the hostmaster, and will be executed against h. */
func (t Template) Attempt(d chan *Attempt, h string) *Attempt {
	a := &Attempt{DoneChan: d, Host: h, Pass: t.Pass}
	a.Config = &ssh.ClientConfig{User: t.User,
		ClientVersion: *gc.Sshvs,
		Auth: []ssh.AuthMethod{
			ssh.Password(t.Pass),
		},
	}
	return a
}

/* Attempt contains the data necessary to make an attempt against a target */
type Attempt struct {
	Config   *ssh.ClientConfig
	Host     string        /* Target */
	Pass     string        /* Password */
	Err      error         /* As returned by ssh.Dial */
	DoneChan chan *Attempt /* Channel to send attempt back to hostmaster */
	Tasknum  int           /* Task serial number */
}

/* Template makes a template from the attempt */
func (a *Attempt) Template() Template {
	return Template{User: a.Config.User, Pass: a.Pass}
}

/* TimeoutError is passed when an attempt times out */
type TimeoutError struct{}

func (e *TimeoutError) Error() string { return "task timeout" }
