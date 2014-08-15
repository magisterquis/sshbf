/* AttemptMakers spew out attempts on their output channel. */
package main

import (
	"bufio"
	"github.com/kd5pbo/tslist"
	"log"
	"os"
)

/* internalAttemptMaker generates attempts based on the list of templates and
some combination of the internal list and command-line options.   The version
string will be set to v. */
func internalAttemptMaker(templates *tslist.List, passwords []string, v string,
	internalc chan attempt) {
	passwordc := make(chan string)
	defer close(passwordc)
	/* Start the attemptmaker itself */
	go channelAttemptMaker(templates, passwordc, v, internalc)
	for _, p := range passwords {
		passwordc <- p
	}
}

/* fileAttemptMaker reads passwords from a file and generates attempts based on
the passwords found in the file named pwfile.  The version string will be set
to v. */
func fileAttemptMaker(templates *tslist.List, pwfile string, v string,
	filec chan attempt) {
	passwordc := make(chan string)
	defer close(passwordc)
	go channelAttemptMaker(templates, passwordc, v, filec)
	/* Last password read */
	lastpass := ""
	/* Open pwfile */
	if pwfile != "" {
		pf, err := os.Open(pwfile)
		/* Make pwfile iterable */
		if err != nil {
			log.Printf("Unable to open password file %v: %v",
				pwfile, err)
			return
		}
		scanner := bufio.NewScanner(pf)
		/* For each password in pwfile */
		for scanner.Scan() {
			lastpass = scanner.Text()
			passwordc <- lastpass
		}
		/* Let the user know if there was an error reading pwfile */
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading password file %v (last "+
				"password read: %v): %v", pwfile, lastpass,
				err)
		}
	}
}

/* TODO: Implement this */
func stdinAttemptMaker(stdinc chan attempt) {
	/* TODO: Finish this */
	close(stdinc)
}

/* channelAttemptMaker reads passwords from passwordc and sends attempts out on
attemptc based on the templates in templates.  When passwordc is closed (i.e.
all its passwords have been read), attemptc will be closed and the attempt
maker will terminate.  The attempts will have a version string of version. */
func channelAttemptMaker(templates *tslist.List, passwordc chan string,
	version string, attemptc chan attempt) {
	defer close(attemptc)
	for {
		select {
		case p, ok := <-passwordc:
			if !ok {
				return
			}
			/* New attempt for each combination. */
			for e := templates.Head(); nil != e; e = e.Next() {
				a, ok := e.Value().(*template)
				if !ok {
					printTemplateNotOk(e)
					es.Exit(-14)
				}
				attemptc <- a.New(p, version)
			}
		}

	}
}
