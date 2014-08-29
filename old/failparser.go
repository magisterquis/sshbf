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
	"time"
)

func parseFail(a attempt, rc chan attempt, errdb bool, nA *lockedint.TInt,
	ts *tslist.List) {
	if errdb {
		log.Printf("Error: %v (%T): %v", a, a.Err, a.Err)
	}
	/* Work out the type of error */
	switch e := a.Err.(type) {
	case *net.OpError:
		if !handleNetOpError(a, rc, nA, ts) {
			goto Unknown
		}
	case *TimeoutError:
		removeHost(ts, a, "took too long", nA)
	case error:
		if !handleErrorString(a, rc, nA, ts) {
			goto Unknown
		}
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
	ts *tslist.List) bool {
	/* Error string */
	s := a.Err.Error()
	switch {
	case strings.HasSuffix(s, "connection refused"):
		/* RST */
		removeHost(ts, a, "connection refused", nA)
	case strings.HasSuffix(s, "connection timed out"):
		/* No SYNACK */
		removeHost(ts, a, "connection timed out", nA)
	case strings.HasSuffix(s, "invalid argument"):
		removeHost(ts, a, "invalid host", nA)
	case strings.HasSuffix(s, "no route to host"):
		removeHost(ts, a, "no route to host", nA)
	default:
		return false
	}
	return true
}

/* Handle generic error strings */
func handleErrorString(a attempt, rc chan attempt, nA *lockedint.TInt,
	ts *tslist.List) bool {
	s := a.Err.Error()
	switch {
	case strings.HasPrefix(s, "ssh: handshake failed: ssh: unable "+
		"to authenticate") && strings.HasSuffix(s, "no supported "+
		"methods remain"):
		/* Auth failed, Decrement the number of attempts in the wild */
		nA.Dec()
	case strings.HasSuffix(s, "ssh: handshake failed: ssh: no common "+
		"algorithms"):
		removeHost(ts, a, "no common algorithms", nA)
	case strings.HasSuffix(s, "ssh: handshake failed: ssh: invalid "+
		"packet length, packet too large"):
		removeHost(ts, a, "packet to large", nA)
	case strings.HasSuffix(s, "ssh: handshake failed: EOF"):
		/* Sometimes EOFs aren't the host's fault. */
		if *gc.Rteoff {
			log.Printf("[%v] Retrying %v@%v - %v in 1 second "+
				"due to EOF", a.Tasknum, a.User, a.Host,
				a.Pass)
			/* This causes all new attempts to halt for a second */
			time.Sleep(time.Second)
		} else {
			removeHost(ts, a, "unexpected EOF", nA)
		}
	case strings.HasPrefix(s, "ssh: handshake failed: read tcp") &&
		strings.HasSuffix(s, "connection reset by peer"):
		removeHost(ts, a, "connection reset by target", nA)
	default:
		return false
	}
	return true

}
