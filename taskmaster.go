/* Starts tasks and limits how many there are */
package main

import (
	"log"
	"sync"
)

var TMNEW chan *Attempt
var TMDONE chan *Attempt

func taskmaster(init *sync.WaitGroup) {
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

        /* Signal end of initialization */
        init.Done()

	/* Main taskmaster loop */
	for {
		//log.Printf("[T] Loop: nR: %v", nRunning) /* DEBUG */
		/* Only listen on the input channel if there's not enough
		   running tasks. */
		in := TMNEW
		if nRunning >= nMax && nMax > 0 {
			in = nil
		}
                //log.Printf("[T] Select: nR: %v in: %v", nRunning, in) /* DEBUG */
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
			//log.Printf("[T] Sending %v (%v)", a.Tasknum, a.Host) /* DEBUG */
			a.DoneChan <- a
                        //log.Printf("[T] Got %v (%v)", a.Tasknum, a.Host) /* DEBUG */
			//log.Printf("[T] Sent %v (%v)", a.Tasknum, a.Host) /* DEBUG */
		case c := <-c2:
			log.Printf("Taskmaster command received: %v", c) /* DEBUG */
			/* Command */
			break
		//case <-time.After(20 * time.Second): /* DEBUG */
			//log.Printf("[T] STill waiting") /* DEBUG */
		}
	}
}
