/* Listen for commands, act appropriately */
package main

import (
	"log"
	"net"
	"os"
	"strconv"
	"sync"
)

/* Listen for a connection on *gc.Cwait, handle it with handler */
func listener() {
	/* If someone's waiting on us... */
	if *gc.Cwait {
		defer WG.Done()
	}
	/* Make sure the listen address isn't just a port. */
	if _, err := strconv.Atoi(*gc.Cport); nil == err {
		*gc.Cport = ":" + *gc.Cport
	}
	/* Get tcp4 and tcp6 addresses, maybe */
	a4, e4 := net.ResolveTCPAddr("tcp4", *gc.Cport)
	a6, e6 := net.ResolveTCPAddr("tcp6", *gc.Cport)

	/* Die if neither work */
	if e4 != nil && e6 != nil {
		log.Printf("Unable to resolve %v as an IPv4 address: %v",
			*gc.Cport, e4)
		log.Printf("Unable to resolve %v as an IPv6 address: %v",
			*gc.Cport, e6)
		os.Exit(-6)
	}

	/* Waitgroup for listeners */
	wg := sync.WaitGroup{}

	/* Start listeners */
	var l4 *net.TCPListener
	var l6 *net.TCPListener
	if nil == e4 {
		l4, e4 = net.ListenTCP("tcp4", a4)
		if nil == e4 {
			log.Printf("Command listener started on %v", l4.Addr())
			wg.Add(1)
			go accept(l4, wg)
			defer l4.Close()
		}
	} else {
		e4 = nil
	}
	if nil == e6 {
		l6, e6 = net.ListenTCP("tcp6", a6)
		if nil == e6 {
			log.Printf("Command listener started on %v", l6.Addr())
			wg.Add(1)
			go accept(l6, wg)
			defer l6.Close()
		}
	} else {
		e6 = nil
	}
	if e4 != nil && e6 != nil {
		log.Printf("Cannot start IPv4 listener on %v: %v", a4, e4)
		log.Printf("Cannot start IPv6 listener on %v: %v", a6, e6)
		os.Exit(-7)
	}

	/* Wait for accepters to die. */
	wg.Wait()

	return

}

/* Wait for and accept a client.  wg.Done() will be called when l is closed or
an error occurs (and the goroutine terminates). */
func accept(l *net.TCPListener, wg sync.WaitGroup) {
	defer wg.Done()
	for {
		/* Get a connection */
		c, err := l.AcceptTCP()
		/* Notify listener and die on error */
		if err != nil {
			log.Printf("Ceasing to listen on %v: %v", l.Addr(),
				err)
			return
		}
		/* Handle client */
		go handle(c)
	}
}

/* Handle an incoming command connection */
func handle(c *net.TCPConn) {
        defer c.Close()
        log.Printf("New command connection from %v", c.RemoteAddr())
        /* TOOD: Implement commands */
}
