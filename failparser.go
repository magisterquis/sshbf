/* parseFail prints the appropriate sort of message when an attempt fails, and
requeues a task if the failure is temporary.  If errdb is true, debugging
output will be printed. */
package main

import (
	"github.com/kd5pbo/lockedint"
	"github.com/kd5pbo/tslist"
	"log"
	"net"
	"strings"
)

func parseFail(a attempt, rc chan attempt, errdb bool, nA *lockedint.TInt,
	ts *tslist.List) {
	if errdb {
		log.Printf("Error: %v (%T): %v", a, a.Err, a.Err)
	}
	/* Work out the type of error */
	switch e := a.Err.(type) {
	case *net.OpError:
		handleNetOpError(a, rc, nA, ts)
	case *TimeoutError:
		removeHost(ts, a, "took too long", nA)
	case error:
		handleErrorString(a, rc, nA, ts)
	default:
		_ = e /* DEBUG */
		goto Unknown
	}
	return
Unknown:
	log.Printf("[%v] %v@%v - %v PLEASE REPORT UNHANDLED ERROR (%T): %v",
		a.Tasknum, a.User, a.Host, a.Pass, a.Err, a.Err)
}

/* Handle *net.OpError errors */
func handleNetOpError(a attempt, rc chan attempt, nA *lockedint.TInt,
	ts *tslist.List) {
	/* Error string */
	s := a.Err.Error()
	switch {
	case strings.HasSuffix(s, "connection refused"):
		/* RST */
		removeHost(ts, a, "connection refused", nA)
	case strings.HasSuffix(s, "connection timed out"):
		/* No SYNACK */
		removeHost(ts, a, "connection timed out", nA)
	}
}

/* Handle generic error strings */
func handleErrorString(a attempt, rc chan attempt, nA *lockedint.TInt,
	ts *tslist.List) {
	s := a.Err.Error()
	switch {
	case strings.HasPrefix(s, "ssh: unable to authenticate") &&
		strings.HasSuffix(s, "no supported methods remain"):
		/* Auth failed, Decrement the number of attempts in the wild */
		nA.Dec()
	}

}

func xx() {

	/* TODO: Decrement nAttempt if it fails, or requeue in retry if needed */
	/* TODO: Work out how to remove from the list of templates. */
	//		/* Take action depending on the type of the error */
	//		/* Too many open files -> requeue attempt, sleep */
	//		if e, ok := err.(*net.OpError); ok &&
	//			strings.HasSuffix(e.Error(),
	//				"too many open files") {
	//			w, err := randDuration(retrywait)
	//			if err != nil {
	//				log.Printf("Unable to parse \"%v\" "+
	//					"as a time duration.  "+
	//					"Please report as a bug.",
	//					retrywait)
	//				os.Exit(-5)
	//			}
	//			log.Printf("[%v] Too many files (or network "+
	//				"connections) open, when trying %v "+
	//				"for %v@%v.  Sleeping %v and "+
	//				"requeuing.", tasknum, a.Pass, a.User,
	//				a.Host, w)
	//			time.Sleep(w)
	//			incA()
	//			//log.Printf("[%v] addN - too many files - %v",
	//			//	tasknum, nA()) /* DEBUG */
	//			attemptc <- a
	//			//log.Printf("[%v] Requeued %v", tasknum,
	//			//	a) /* DEBUG */
	//		} else if e, ok := err.(*net.OpError); ok &&
	//			(strings.HasSuffix(e.Error(), "operation "+
	//				"timed out") || /* Host down */
	//				strings.HasSuffix(e.Error(),
	//					"host is down") ||
	//				strings.HasSuffix(e.Error(),
	//					"no route to host") ||
	//				strings.HasSuffix(e.Error(),
	//					"network is unreachable")) {
	//			badhostc <- badHost{Host: a.Host,
	//				Reason: "Target is down."}
	//			/* TODO: Work out segfault */
	//			/* TODO: "connection timed out" -> host doesn't exist (*net.OpError) */
	//		} else if e, ok := err.(*net.OpError); ok &&
	//			strings.HasSuffix(e.Error(),
	//				"connection refused") {
	//			badhostc <- badHost{Host: a.Host,
	//				Reason: "Connection refused."}
	//			/* TODO: Multicore enable */
	//		} else if e, ok := err.(*net.OpError); ok &&
	//			(strings.HasSuffix(e.Error(),
	//				"no such host") ||
	//				strings.HasSuffix(e.Error(),
	//					"invalid domain name") ||
	//				strings.HasSuffix(e.Error(),
	//					"connection timed out") ||
	//				strings.HasSuffix(e.Error(),
	//					"invalid argument")) {
	//			/* DNS Fail */
	//			badhostc <- badHost{Host: a.Host,
	//				Reason: "Does not exist (DNS Error?)."}
	//		} else if e, ok := err.(*net.OpError); ok &&
	//			strings.HasSuffix(e.Error(),
	//				"permission denied") {
	//			badhostc <- badHost{Host: a.Host,
	//				Reason: "Permission denied."}
	//		} else if e, ok := err.(error); ok &&
	//			(strings.HasSuffix(e.Error(), "ssh: no "+
	//				"common algorithms") ||
	//				strings.HasSuffix(e.Error(),
	//					"ssh: invalid packet length, "+
	//						"packet too large")) {
	//			badhostc <- badHost{Host: a.Host,
	//				Reason: "SSH Error"}
	//		} else if e, ok := err.(error); ok &&
	//			strings.HasPrefix(e.Error(), "ssh: "+
	//				"handshake failed: ssh: unable to "+
	//				"authenticate") {
	//			/* Auth failed */
	//		} else if e, ok := err.(error); ok &&
	//			(strings.HasSuffix(e.Error(), "connection "+
	//				"reset by peer") ||
	//				strings.HasPrefix(e.Error(), "ssh: "+
	//					"handshake failed: EOF")) {
	//			w, err := randDuration(retrywait)
	//			if err != nil {
	//				log.Printf("Unable to parse \"%v\" "+
	//					"as a time duration.  "+
	//					"Please report as a bug.",
	//					retrywait)
	//				os.Exit(-9)
	//			}
	//			log.Printf("[%v] Too many connection "+
	//				"attempts, too fast to %v, sleeping "+
	//				"%v and retrying last attempt.",
	//				tasknum, a.Host, w)
	//			time.Sleep(w)
	//			incA()
	//			//log.Printf("[%v] incA too many connection "+
	//			//	"- %v", tasknum, nA()) /* DEBUG */
	//			attemptc <- a
	//		} else { /* Who knows... */
	//		}
	//
	//			log.Printf("[%v] DEBUG %v@%v - %v (%T): %v",
	//				tasknum, a.User, a.Host, a.Pass, err,
	//				err)
	//		/* Print the attempt if requested */
	//                ```
}
