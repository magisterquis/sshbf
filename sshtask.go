/* sshtask represents one try */
package main

import (
	"code.google.com/p/go.crypto/ssh"
	"log"
	"time"
)

func sshTask(a *Attempt, tasknum int) {
	/* Note the serial number */
	a.Tasknum = tasknum
	/* Channel on which to return the results of the attempt, locally */
	dc := make(chan error)
	/* Log the try, if flagged */
	if *gc.Tries {
		log.Printf("[%v] Attempting %v@%v - %v", tasknum,
			a.Config.User, a.Host, textIfBlank(a.Pass))
	}
	/* Start asynchronously (along with a timer, later) */
	go func() {
		c, err := ssh.Dial("tcp", a.Host, a.Config)
		if c != nil {
			c.Close()
		}
		dc <- err
	}()
	/* Wait for a timeout or a response from ssh */
	select {
	case <-time.After(*gc.Wait):
		a.Err = &TimeoutError{}
	case e := <-dc:
		a.Err = e
	}
	/* Send the attempt back */
	TMDONE <- a
}
