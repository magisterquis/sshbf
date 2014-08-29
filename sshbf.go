// sshbf is a simple SSH Brute-Forcer.

/*
 * sshbf.go
 * Simple SSH bruteforcer
 * by J. Stuart McMurray
 * created 20140717
 * last modified 20140822
 */

package main

import (
	"flag"
	"fmt"
	"github.com/kd5pbo/threadsafe/tsmap"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

///* Used for removing hosts from the queue for a reason */
//type badHost struct {
//	Host   string
//	Reason string
//}

/* Internal password list */
var IPL []string = []string{"admin", "password", "1234", "12345", "123456",
	"test", "oracle", "root"}

/* Waitgroup to signal end of execution */
var WG sync.WaitGroup

/* Global command channel map and lock */
var C2CHANS *tsmap.Map
var C2CHANL sync.RWMutex

/* Templates */
var TEMPLATES []Template

/* TODO: .sshbfrc file */

/* Default connect timeout */
var deftimeout string = "5m"

//var retrywait string = "1s"

/* Global config struct */
var gc struct {
	User  *string
	Ufile *string
	Pass  *string
	Pfile *string
	Host  *string
	Hfile *string
	Pnull *bool
	Pdefl *bool
	Puser *bool
	Pback *bool
	Sshvs *string
	Htask *int
	/* TODO: Implement queue to have only N targets in parallel at once */
	Gtask *int
	//	Ntaskf *int
	Tries *bool
	//	Stdinf *bool
	Plist *bool
	Sfile *string
	Onepw *bool
	Errdb *bool
	//	Pausef *time.Duration
	Wait *time.Duration
	//	Askipf *int
	Rteof *bool
	Userl *bool
	Helpl *bool
	Helps *bool
	Cport *string
	Cwait *bool
}

func main() {

	//	/* Slice of username/password combinations */
	//	templates := tslist.New()
	//
	//	/* Initial list of passwords to guess */
	//	initpw := []string{}
	//
	//	/* Command-line arguments */
	gc.User = flag.String("user", "", "Single SSH username.  If neither "+
		"this nor -ufile is specified, root will be used.  If both "+
		"this and -ufile are specified, this will be tried first.")
	gc.Ufile = flag.String("ufile", "", "File with a list of usernames, "+
		"one per line.  If neither this nor -user is specified, the "+
		"single username root will be used.  This list will be "+
		"read into memory, so it should be kept short on low-memory "+
		"systems.")
	gc.Pass = flag.String("pass", "", "Single SSH password.  If neither "+
		"this nor -pfile is specified, a small internal list of "+
		"passwords will be attempted.  See -plist.")
	gc.Pfile = flag.String("pfile", "", "File with a list of passwords, "+
		"one per line.  If neither this nor -pass is specified, a "+
		"small internal list of passwords will be attempted.  See "+
		"-plist.  This list will be read into memory, so it should "+
		"probably be kept short on low-memory systems.")
	gc.Host = flag.String("host", "", "Target to attack.  Examples: "+
		"foo.bar.com, foo.baaz.com:2222, 192.168.1.0/24.  Either "+
		"this or -hfile must be specified, unless hosts are listed "+
		"on the command line.")
	gc.Hfile = flag.String("hfile", "", "File with a list of targets to "+
		"attack, one per line.  Either this or -host must be "+
		"specified.  This list will be read into memory, so it "+
		"should be kept short on low-memory systems.  CIDR notation "+
		"may be used to specify multiple addresses at once.")
	gc.Pnull = flag.Bool("pnull", false, "Attempt the null (empty) "+
		"password as well as other specified passwords.")
	gc.Pdefl = flag.Bool("pdefl", false, "Attempt the internal default "+
		"password list.")
	gc.Puser = flag.Bool("puser", false, "Attempt the username as the "+
		"password as well as other specified passwords.")
	gc.Pback = flag.Bool("pback", false, "Attempt the username backwards "+
		"as the password as well as other specified passwords.  "+
		"E.g. root -> toor.")
	gc.Sshvs = flag.String("sshvs", "SSH-2.0-sshbf_0.0.2", "SSH version "+
		"string to present to the server.")
	gc.Htask = flag.Int("htask", 8, "Maximum umber of concurrent "+
		"attempts per host if different from -gtask.  0 will spawn "+
		"as many concurrent attacks as -gtask allows.")
	gc.Gtask = flag.Int("gtask", 500, "Maximum number of concurrent "+
		"attempts.  If zero, an unlimited number of attacks are "+
		"allowed.")
	//	gc.Ntaskf = flag.Int("ntask", 4, "Number of attempts (tasks) to run in "+
	//		"parallel.  Don't set this too high.")
	gc.Tries = flag.Bool("tries", false, "Print every guess.")
	//	gc.Stdinf = flag.Bool("stdin", false, "Ignore most of the above and "+
	//		"read tab-separated username<tab>password<tab>host lines from "+
	//		"stdin.  NOT CURRENTLY IMPLEMENTED.")
	gc.Plist = flag.Bool("plist", false, "Print the internal default "+
		"password list and exit.")
	gc.Sfile = flag.String("sfile", "", "Append successful "+
		"authentications to this file, which whill be flock()'d to "+
		"allow for multiple processes to write to it in parallel.")
	gc.Onepw = flag.Bool("onepw", false, "Only find one username/password "+
		"pair per host.")
	gc.Errdb = flag.Bool("errdb", false, "Print debugging information "+
		"relevant to errors made during SSH attempts.")
	//	gc.Pausef = flag.Duration("pause", 0, "Pause this long between "+
	//		"attempts.  Really only makes sense if -ntask=1 is used.")
	//	gc.Askipf = flag.Int("askip", 0, "Skip this many attacks at the "+
	//		"beginning.  Useful if -host is used and a network error "+
	//		"occurred.")
	gc.Rteof = flag.Bool("rteof", true, "Sleep 1s and Retry attempts "+
		"that have generated an EOF error or other temporary errors.")
	deftimeoutd, err := time.ParseDuration(deftimeout)
	if err != nil {
		fmt.Printf("Invalid default wait duration.\n\n.")
		fmt.Printf("This is a bad bug.\n\n")
		fmt.Printf("You should tell the developers.\n")
		os.Exit(-8)
	}
	gc.Wait = flag.Duration("wait", deftimeoutd, "Wait this long for "+
		"authentication to succeed or fail.")
	gc.Userl = flag.Bool("userl", false, "Loop over usernames (instead "+
		"of passwords).")
	gc.Helps = flag.Bool("h", false, "Print help.")
	gc.Helpl = flag.Bool("help", false, "Print help.")
	gc.Cport = flag.String("cport", "", "Port (or address) on which to "+
		"listen for commands.  Default is to not listen.  The "+
		"command h prints help.")
	gc.Cwait = flag.Bool("cwait", false, "Wait for more commands after "+
		"last target has been attacked.")
	flag.Parse()

	/* Print usage if no arguments */
	if len(os.Args) == 1 || *gc.Helps || *gc.Helpl {
		fmt.Printf("Usage: %v [flags] [target] [target...]\n", os.Args[0])
		fmt.Printf("Flags:\n")
		flag.PrintDefaults()
		os.Exit(-2)
	}

	/* If we're just printing the password list, do so and exit */
	if *gc.Plist {
		fmt.Printf("Internal password list:\n")
		for _, p := range IPL {
			fmt.Printf("\t%v\n", p)
		}
		return
	}

	/* Die if we can't run enough tasks */
	if *gc.Gtask < 0 || *gc.Htask < 0 {
		log.Printf("Only positive numbers make sense.")
		os.Exit(-5)
	}

	/* Use -user if supplied */
	iu := []string{}
	if len(*gc.User) > 0 {
		iu = append(iu, *gc.User)
	}
	/* Make the list of usernames */
	usernames := makeListFromFile(iu, *gc.Ufile, []string{"root"})
	/* If the right flags are given, prepend the default password list and
	   the null password */
	passwords := []string{}
	if len(*gc.Pass) > 0 {
		passwords = append(passwords, *gc.Pass)
	}
	if *gc.Pnull {
		passwords = append(passwords, "")
	}
	if *gc.Pdefl {
		passwords = deDupe(append(passwords, IPL...))
	}
	passwords = makeListFromFile(passwords, *gc.Pfile, IPL)

	/* Make a slice of username/password templates */
	templates := []Template{}
	ol := usernames
	il := passwords
	mt := func(p, u string) Template { return Template{User: u, Pass: p} }
	/* Switch if flagged */
	if *gc.Userl {
		ol = passwords
		il = usernames
		mt = func(u, p string) Template {
			return Template{User: u, Pass: p}
		}
		for _, u := range usernames {
			if *gc.Puser {
				templates = append(templates, mt(u, u))
			}
			if *gc.Pback {
				templates = append(templates, mt(u,
					reverse(u)))
			}
		}

	}
	/* Loop over the lists */
	for _, o := range ol {
		/* Handle puser and pback */
		if !*gc.Userl {
			if *gc.Puser {
				templates = append(templates, mt(o, o))
			}
			if *gc.Pback {
				templates = append(templates, mt(reverse(o),
					o))
			}
		}
		/* Add the rest */
		for _, i := range il {
			templates = append(templates, mt(i, o))
		}
	}
	temps := []Template{}      /* Temporary slice of templates */
	tempm := map[string]bool{} /* Temporary hash table for O(1) deduping */
	for _, t := range templates {
		/* "Hash" of template */
		s := fmt.Sprintf("%4v%v%4v%v", len(t.User), t.User,
			len(t.Pass), t.Pass)
		/* If it's not been seen, note it, add it to temporary slice */
		if _, ok := tempm[s]; !ok {
			tempm[s] = true
			temps = append(temps, t)
		}
	}
	TEMPLATES = temps

	/* Get a list of targets and CIDR ranges */
	ih := flag.Args()
	if len(*gc.Host) != 0 {
		ih = append(ih, *gc.Host)
	}
	ft := makeListFromFile(ih, *gc.Hfile, nil)
	/* Make a slice of targets */
	targets := []string{}
	/* Parse CIDR names */
	for _, t := range ft {
		/* Can't have empty hostnames */
		if 0 == len(t) {
			continue
		}
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
	/* Make sure the targets have ports */
	for i, t := range targets {
		targets[i] = addDefaultPort(t)
	}
	/* Deduplicate slice */
	targets = deDupe(targets)
	if len(targets) == 0 {
		log.Printf("Not enough target hosts specified.  " +
			"Please use -host and/or -hfile.\n")
		os.Exit(-4)
	}

	/* Don't say we will start more per-target tasks than global tasks. */
	if *gc.Gtask != 0 && *gc.Htask > *gc.Gtask {
		*gc.Htask = *gc.Gtask
	}

	/* Command channels */
	C2CHANS = tsmap.New()

	/* Waitgroup to wait for goroutine initialization */
	var init sync.WaitGroup

	/* Start taskmaster */
	init.Add(1)
	go taskmaster(&init)
	init.Wait()

	/* Start a goroutine to listen for new commands */
	if *gc.Cwait && 0 == len(*gc.Cport) {
		log.Printf("Cannot use -cwait without -cport.")
		os.Exit(-3)
	}
	if *gc.Cport != "" {
		if *gc.Cwait {
			WG.Add(1)
		}
		init.Add(1)
		go listener(&init)
		init.Wait()
	}

	/* Give the user warm fuzzies that we're starting */
	log.Printf("Attacking %v hosts with %v username/password combinations",
		len(targets), len(templates))
	as := fmt.Sprintf("Will perform %v attacks",
		len(targets)*len(templates))
	if 0 == *gc.Htask && 0 == *gc.Gtask {
		log.Printf("%v", as)
	} else if 0 == *gc.Htask {
		log.Printf("%v (max %v simultaneously)", as, *gc.Gtask)
	} else if 0 == *gc.Gtask {
		log.Printf("%v (max %v simultaneously per host)", as,
			*gc.Htask)
	} else {
		log.Printf("%v (max %v simultaneously overall, max %v "+
			"simultaneously per host)", as, *gc.Gtask, *gc.Htask)
	}

	/* TODO: Log somewere other than stderr, if requested. */
	/* Start a hostmaster for each host */
	for _, t := range targets {
		WG.Add(1)
		go hostmaster(t)
	}

	/* Wait until everything is done */
	WG.Wait()
	log.Printf("All done.")

	// /* Work out a list of passwords */
	//
	//	/* If we're to read from stdin, we can skip a lot of work */
	//	if *gc.Stdinf {
	//		/* TODO: Implement this */
	//		log.Printf("Reading from stdin not currently implemented.\n")
	//		os.Exit(-1)
	//	} else {
	//
	//		unames, err := readLines(*gc.Userf, *gc.Ufilef)
	//		if err != nil {
	//			log.Printf("Unable to read usernames from %v: %v.\n",
	//				*gc.Ufilef, err)
	//			os.Exit(-3)
	//		} else if len(unames) == 0 {
	//			/* Default to root only */
	//			unames = append(unames, "root")
	//		}
	//
	//		/* Make sure the targets have ports */
	//		for i, t := range targets {
	//			if _, _, err := net.SplitHostPort(t); err != nil {
	//				targets[i] = net.JoinHostPort(t, "22")
	//			}
	//		}
	//
	//		/* Make a list of passwordless ssh templates. */
	//		for _, u := range unames {
	//			for _, t := range targets {
	//				templates.PushBack(&template{User: u, Host: t})
	//			}
	//		}
	//
	//		/* Work out a list of initial passwords */
	//		if *gc.Passf != "" { /* Password on command line */
	//			initpw = uniqueAppend(initpw, *gc.Passf)
	//		}
	//		if *gc.Pnullf { /* Use null password */
	//			initpw = uniqueAppend(initpw, "")
	//		}
	//		if *gc.Puserf { /* Username as password */
	//			for _, u := range unames {
	//				initpw = uniqueAppend(initpw, u)
	//			}
	//		}
	//		if *gc.Pbackf { /* Backwards username as password */
	//			for _, u := range unames {
	//				initpw = uniqueAppend(initpw, reverse(u))
	//			}
	//		}
	//		if *gc.Pdeflf { /* Internal default password list */
	//			for _, p := range IPL {
	//				initpw = uniqueAppend(initpw, p)
	//			}
	//		}
	//		if len(initpw) == 0 && *gc.Pfilef == "" { /* If all else fails */
	//			initpw = IPL
	//		}
	//
	//	}
	//
	//	/* File to which to append successes */
	//	var sf *os.File = nil
	//	if *gc.Sfilef != "" {
	//		sf, err = os.OpenFile(*gc.Sfilef,
	//			os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	//		if err != nil {
	//			fmt.Printf("Error opening success file %v: %v",
	//				*gc.Sfilef, err)
	//			os.Exit(-7)
	//		}
	//	}
	//
	//	/* Message that we're starting */
	//	log.Printf("Trying %v Username/Host combinations.", templates.Len())
	//
	//	/* Generate username/password/host attempts */
	//	internalc := make(chan attempt) /* Internal list */
	//	go internalAttemptMaker(templates, initpw, *gc.Sshvsf, internalc)
	//
	//	filec := make(chan attempt) /* Password file */
	//	go fileAttemptMaker(templates, *gc.Pfilef, *gc.Sshvsf, filec)
	//
	//	/* TODO: Read username\tpassword\thost tuples from stdin */
	//	stdinc := make(chan attempt) /* Standard input */
	//	go stdinAttemptMaker(stdinc) /* TODO: Implement this */
	//
	//	/* Start broker */
	//	go broker(internalc, filec, stdinc, *gc.Ntaskf, sf, *gc.Triesf,
	//		*gc.Onepwf, *gc.Errdbf, *gc.Waitf, *gc.Pausef, templates,
	//		*gc.Askipf)
	//
	//	/* Derp derp derp */
	//	/* TODO: Make a c2 channel here */
	//	<-make(chan int)
	//
	//	/* TODO: Use RemoveTemplates to remove unnecessary hosts */

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

//
///* maxIP tests if every byte in the IP address is 0xFF */
//func maxIP(ip net.IP) bool {
//	for _, b := range ip {
//		if 0xFF != b {
//			return false
//		}
//	}
//	return true
//}
//
/* Read lines from a file into a string slice, or exits the program. */
func readLines(file string) []string {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		log.Printf("Error reading %v: %v", file, err)
		os.Exit(-1)
	}
	/* Empty file */
	if 0 == len(content) {
		return []string{}
	}
	/* Remove final newline */
	c := strings.TrimSuffix(string(content), "\n")
	return strings.Split(c, "\n")
}

/* Put v into a slice if it's not "", same with the contents of f if f
   is not "".  If the slice is empty, put d into it.  The returned
   slice will be deduplicated. */
func makeListFromFile(v []string, f string, d []string) []string {
	/* Output slice */
	o := []string{}
	/* Element from command line */
	if len(v) > 0 {
		o = append(o, v...)
	}
	/* Lines from a file */
	if len(f) > 0 {
		o = append(o, readLines(f)...)
	}
	/* Default */
	if 0 == len(o) && d != nil {
		o = append(o, d...)
	}
	return deDupe(o)
}

/* Return a deduped slice in O(n)-ish time, but with lots of memory use. */
func deDupe(o []string) []string {
	/* Deduped list */
	n := []string{}
	/* Deduping map */
	h := map[string]bool{}
	/* Iterate through input slice */
	for _, s := range o {
		/* Check and see if we've seen it before */
		if _, ok := h[s]; !ok {
			/* If not, note it and add it to the output list */
			n = append(n, s)
			h[s] = true
		}
	}
	return n
}

///* Read lines from the file named file into a deduped, in-order slice,
//optionally starting with leader if it is not nil.  It is not an error if file
//is the empty string (in which case a slice containing only leader
//will be returned), but it is an error if file cannot be read.  Windows line
//endings may do strange things. */
//func readLines(leader *string, file string) []string {
//	/* Initial collections */
//	m := map[string]bool{}
//	s := []string{}
//
//	/* Add leader if it's not empty */
//	if leader != "" {
//		m[leader] = true
//		s = append(s, leader)
//	}
//
//	/* Read from file if we have it */
//	if file != "" {
//		bytes, err := ioutil.ReadFile(file)
//		if err != nil {
//			return s, err
//		}
//		/* Remove single trailing newline (to prevent always having a
//		   blank string */
//		if bytes[len(bytes)-1] == '\n' {
//			bytes = bytes[:len(bytes)-1]
//		}
//		/* Split the contents of the file into lines, append each
//		   unique line */
//		for _, h := range strings.Split(string(bytes), "\n") {
//			/* Add the line if we don't already have it */
//			if _, in := m[h]; !in {
//				m[h] = true
//				s = append(s, h)
//			}
//		}
//	}
//	return s, nil
//}

//
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

//
///* uniqueAppend appends a string to a slice only if the slice doesn't contain
//the string.  Since it searches in O(n) time, it should only be used for
//reasonably small slices */
//func uniqueAppend(slice []string, s string) []string {
//	/* Make sure s isn't in slice */
//	for _, val := range slice {
//		if val == s {
//			return slice
//		}
//	}
//	return append(slice, s)
//}
//
///* randDuration generates a random duration less than s, which should be
//a string allowed by time.ParseDuration */
//func randDuration(s string) (time.Duration, error) {
//	/* Get the max */
//	d, err := time.ParseDuration(s)
//	if err != nil {
//		return d, err
//	}
//	/* Make a smaller duration */
//	m := rand.Int63n(int64(d))
//	/* Return it as a duration */
//	return time.Duration(m), nil
//}
