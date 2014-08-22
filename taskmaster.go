/* Starts tasks and limits how many there are */
package main

import (
        "log"
)

var TMNEW chan *Attempt
var TMDONE chan *Attempt

func taskmaster() {
	/* C2 channel */
	c2 := make(chan string)
	C2CHANS.Put("taskmaster", c2)

	/* Input channel */
	TMNEW = make(chan *Attempt)
	/* Finished attempts */
	TMDONE = make(chan *Attempt)

	/* Number of tasks running, globally */
	nRunning := 0
	/* Max number of tasks */
	nMax := *gc.Gtask

        /* Total number of tasks so far */
        nTot := 0

	/* Main taskmaster loop */
	for {
		/* Only listen on the input channel if there's not enough
		   running tasks. */
		in := TMNEW
		if nRunning >= nMax && nMax > 0 {
			in = nil
		}
		/* Wait for something to happen */
		select {
                case a := <-in:
			/* New task to start */
			go sshTask(a, nTot)
			nRunning++
                        nTot++
		case a := <-TMDONE:
			/* Task finished */
			nRunning--
			a.DoneChan <- a
		case c := <-c2:
			log.Printf("Taskmaster command received: %v", c) /* DEBUG */
			/* Command */
			break
		}
	}
}
