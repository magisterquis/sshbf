/* util provides small functions used in multiple files */
package main

import (
	"github.com/kd5pbo/lockedint"
	"github.com/kd5pbo/tslist"
	"log"
	"os"
)

/* textIfBlank returs <blank> if s is "", and s otherwise. */
func textIfBlank(s string) string {
	if len(s) > 0 {
		return s
	}
	return "<blank>"
}

/* Remove a host from the template list, give the reason as r and decrement
nA.  If r is the empty string, no message will be printed. */
func removeHost(ts *tslist.List, a attempt, r string, nA *lockedint.TInt) {
	/* Tell the user what's going on */
	if r != "" {
		log.Printf("[%v] Removing %v from attack queue: %v", a.Tasknum,
			a.Host, r)
	}
	/* Mark a bunch of hosts for removal */
	for e := ts.Head(); e != nil; e = e.Next() {
		if c, ok := e.Value().(*template); !ok {
			printTemplateNotOk(e)
			os.Exit(-10)
		} else if ok && c.Host == a.Host {
			e.RemoveMark()
		}
	}
	/* Remove the marked hosts */
	ts.RemoveMarked()
	/* Decrement the number of attempts in the wild */
	nA.Dec()
}

/* Prints an error that the Value stored by e (a *tslist.Element) is not a
template.  */
func printTemplateNotOk(e *tslist.Element) {
	log.Printf("Corruption in template list.  This is a bad bug.  "+
		"Please report the following to the developers (sanatized "+
		"as appropriate): [e: %#v][t: (%T): %#v]", e, e.Value(),
		e.Value())
}
