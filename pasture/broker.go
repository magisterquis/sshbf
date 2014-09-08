/* broker.go is the central broker for all attempts */
package main

import (
	"fmt"
	"github.com/kd5pbo/lockedint"
	"github.com/kd5pbo/tslist"
	"log"
	"os"
	"syscall"
	"time"
)

/*
 * stdin-------------------+         +->sshtask0-+
 * internal password lists-+->broker-+->sshtask1-+
 * passwords from files----+     A   +->sshtaskn-+
 *                               |               |
 *                               +----------------
 */

/* Broker listens on internalc, filec, stdinc, and retryc for attempts, and
sends them out on attemptc.  It internally keeps track of the number of
attempts in existence, which is incremented on every read from internalc,
filec, stdinc, and retryc, and is decremented on every send on attemptc.
Channels:
        Input Channels:
        internalc:      attempts made from the internal password list
        filec:          attempts made from passwords in a file
        stdinc:         attempts as read from stdin
        Feedback Channels:
        failc:          attempts that have failed are sent back here
        successc:       attempts that have succeeded are sent back here
        retryc:         attempts that need to be retried are sent back here
broker will spawn a new sshtask for each attempt, which sends on donec before
it terminates.  At most ntask ssh tasks will be spawned at once.
When internalc, filec, and stdinc are all closed, broker waits for all the
remaining tasks to finish with nothing to be read on retryc, at which point it
sends on bdonec.
If sf is not nil, successes will be written to it.  triesf determines whether
or not sshtasks print their attempts.  If onepw is true, only one username/
password pail will be found per host.  Errdbf will cause all errrors to be
printed.  sshtasks will timetout after wait.  skip attempts will be skipped
at the begging.  This is useful to restart after an error. */

func broker(internalc, filec, stdinc chan attempt, ntask int, sf *os.File,
	tries, onepw, errdb bool, wait, pause time.Duration, ts *tslist.List,
	skip int) {
	/* Channels for communication with spawned tasks */
	failc := make(chan attempt)
	successc := make(chan attempt)
	retryc := make(chan attempt)
	/* Number of sshtasks running */
	nRunning := lockedint.New()
	/* Number of attempts in play */
	nAttempts := lockedint.New()
	/* Number of attempts made so far */
	totalTasks := 0
	/* Closure (yuck) to die when we're out of attempts and all channels
	   are closed */
	doneNote := false
	dieIfDone := func() {
		/* Don't execute if something's still going on */
		if stdinc == nil && internalc == nil && filec == nil {
			if 0 == nRunning.Val() {
				log.Printf("All done.")
				os.Exit(0)
			} else if !doneNote {
				log.Printf("Giving %v tasks time to "+
					"finish.  This shouldn't take much "+
					"more than %v.", nRunning.Val(), wait)
				doneNote = true
			}
		}
	}
	/* startTask starts an sshtask against a. */
	startTask := func(a attempt) {
		if !(totalTasks <= skip) {
			go sshTask(a, nRunning, failc, successc, totalTasks,
				tries, wait, pause)
                        nRunning.Inc()
		}
		totalTasks++
		/* TODO: Fix wait */
	}
	/* Closures (yuck) to handle channel inputs */
	successh := func(a attempt, ok bool) {
		if !ok {
			log.Printf("Success channel closed.  This is a " +
				"really bad bug.  Please tell the developers.")
			os.Exit(-13)
		}
		/* Print a success message */
		log.Printf("SUCCESS: %v@%v %v", a.User, a.Host,
			textIfBlank(a.Pass))
		/* Log to the success file if we have one */
		if sf != nil {
			logSuccess(sf, a)
		}
		/* Remove either the host or template, as appropriate */
		if onepw {
			removeHost(ts, a, "", nAttempts)
		} else {
			/* Search list for matching template */
			for e := ts.Head(); e != nil; e = e.Next() {
				v, ok := e.Value().(*template)
				if !ok {
					printTemplateNotOk(e)
					os.Exit(-15)
				}
				/* Remove template when found */
				if v.User == a.User && v.Host == a.Host {
					e.Remove()
				}
			}
			/* One fewer attempt is in play */
			nAttempts.Dec()
		}
		_ = onepw /* DEBUG */
		dieIfDone()
	}
	failh := func(a attempt, ok bool) {
		if !ok {
			log.Printf("Fail channel closed.  This is a really " +
				"bad bug.  Please tell the developers.")
			os.Exit(-12)
		}
		/* Handle failures.*/
		parseFail(a, retryc, errdb, nAttempts, ts)
		dieIfDone()
	}
	retryh := func(a attempt, ok bool) {
		if !ok {
			log.Printf("Retry channel closed.  This is a really " +
				"bad bug.  Please tell the developers.")
			os.Exit(-11)
		}
		startTask(a)
	}

	/* Main loop */
	for {
		if nRunning.Val() < ntask {
			/* When we don't have enough running tasks, accept
			   input from all channels */
			select {
			case a, ok := <-retryc:
				retryh(a, ok)
			case a, ok := <-internalc:
				if !ok {
					internalc = nil
					dieIfDone()
					continue
				}
				startTask(a)
			case a, ok := <-filec:
				if !ok {
					filec = nil
					dieIfDone()
					continue
				}
				startTask(a)
			case a, ok := <-stdinc:
				if !ok {
					stdinc = nil
					dieIfDone()
					continue
				}
				startTask(a)
			case a, ok := <-failc:
				failh(a, ok)
			case a, ok := <-successc:
				successh(a, ok)
			}
		} else {
			/* When we have enough running tasks, only read from
			   channels that signal tasks are done. */
			select {
			case a, ok := <-failc:
				failh(a, ok)
			case a, ok := <-successc:
				successh(a, ok)
			}
		}
	}
}

/* Log success to a file asyncronously */
func logSuccess(sf *os.File, a attempt) {
	/* Try to get a lock */
	if err := syscall.Flock(int(sf.Fd()), syscall.LOCK_EX); err != nil {
		/* If not, log it */
		log.Printf("Not printing successful password guess %v for "+
			"%v@%v due to error acquiring exclusive lock on %v: "+
			"%v", a.Pass, a.User, a.Host, sf.Name(), err)
		/* That's bad indentation */
	} else {
		/* If we got the lock, log the
		   password */
		fmt.Fprintf(sf, "%v@%v %v\n", a.User, a.Host, a.Pass)
	}
	/* In either case, (try to) unlock the
	   file */
	syscall.Flock(int(sf.Fd()), syscall.LOCK_UN)
}

/* TODO: Better "out of guesses" message to handle tasks starting after the
message. */
//
//start with all
//when enough tasks, feedback only
//when not, all
//when input done, and not enough tasks, all
//when input done and enough tasks, feedback only
//
//Tasks:  enough     not enough
//input
//
//start   FB         all
//
//done    fb         all
//
//not done fb        all
