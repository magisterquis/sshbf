/* Listen for commands, act appropriately */
package main

import (
	"bufio"
	"fmt"
	"github.com/kd5pbo/ipsorter"
	"log"
	"net"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"sync"
)

/* Listen for a connection on *gc.Cwait, handle it with handler */
func listener(init *sync.WaitGroup) {
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

	/* Signal end of initialization */
	init.Done()

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
	defer log.Printf("%v ended command connection", c.RemoteAddr())
	defer wl(c, "Good bye.")
	log.Printf("New command connection from %v", c.RemoteAddr())
	/* Easy readers and writers */
	r := textproto.NewReader(bufio.NewReader(c))
	/* TOOD: Implement more commands */
	/* Send the list of commands */
	handleH(c, []string{})
	/* Main loop */
	for {
		/* Send the prompt */
		wf(c, "sshbf> ")
		/* Get a line from the client */
		l, err := r.ReadLine()
		/* Handle disconnect */
		if err != nil && err.Error() == "EOF" {
			return
		}
		/* Handle errors */
		if err != nil {
			/* TODO: Handle errors better */
			log.Printf("[c:%v] Error (%T): %v", c.RemoteAddr(), err, err)
			return
		}
		/* Split the line on whitespace */
		cmd := strings.Fields(strings.TrimSpace(l))
		/* Empty lines don't do much */
		if 0 == len(cmd) {
			continue
		}
		/* TODO: Work out readline */

		/* Function handler */
		var f func(*net.TCPConn, []string)
		/* Handle commands */
		switch cmd[0] {
		case "a": /* Attack */
			f = handleA
		case "m": /* Max attacks */
			f = handleM
		case "s": /* Stop */
			f = handleS
                case "l": /* List */
f = handleL
		case "k":
			log.Printf("Killed by %v", c.RemoteAddr())
			os.Exit(0)
		case "q":
			return
		default:
			wf(c, "Unknown command %v\n", cmd[0])
			fallthrough
		case "h": /* Help */
			f = handleH
		}
		f(c, cmd)
	}
}

/* Print help message */
func handleH(c *net.TCPConn, cmd []string) {
	wl(c, "Commands:")
	wl(c, "\ta - Attack a host or hosts")
	wl(c, "\tm - Get or set the maximum number of concurrant attacks "+
		"against a host")
	wl(c, "\ts - Stop an attack on a host or hosts")
	wl(c, "\tl - List attacks in progress")
	wl(c, "\tk - Kill sshbf")
	wl(c, "\tq - Exit (quit) this command session")
	wl(c, "\th - This help")
	wl(c, "Enter a command by itself for more information.")
}

/* Handle a request for attack(s) */
func handleA(c *net.TCPConn, cmd []string) {
	/* Usage */
	if 1 == len(cmd) {
		wl(c, "Attack Usage:")
		wl(c, "\ta host [host [host...]]")
		wl(c, "Attacks a host or hosts.")
	}
	/* Spawn hostmasters for each host on the list */
	for _, h := range cmd[1:] {
		h = addDefaultPort(h)
		log.Printf("[%v] Attacking %v", c.RemoteAddr(), h)
		wf(c, "Attacking %v\n", h)
		WG.Add(1)
		go hostmaster(h)
	}
}

/* Set the maximum number of concurrent attacks */
func handleM(c *net.TCPConn, cmd []string) {
	/* Usage */
	switch len(cmd) {
	case 2: /* Get */
		n := wc(c, cmd[1], "m", true)
		wf(c, "%v\n", n)
	case 3: /* Set */
		n, err := strconv.Atoi(cmd[2])
		if err != nil {
			wf(c, "Unable to parse %v: %v", cmd[2], err)
			break
		}
		wc(c, cmd[1], fmt.Sprintf("m %v", n), false)

	default:
		wl(c, "Max Usage:")
		wl(c, "\tm host")
		wl(c, "Gets the number of concurrent attacks against a host.")
		wl(c, "\tm host max")
		wl(c, "Sets the number of concurrent attacks against a host.")
	}
}

/* Send the list of running attacks */
func handleL(c *net.TCPConn, cmd []string) {
        /* Get the list of keys */
        tasks := C2CHANS.Keys()
        /* Sort */
        i, s := ipsorter.Sort(tasks, true)
        stasks := append(i, s...)
        /* Header */
        wf(c, "%v attacks:\n", len(stasks))
        wf(c, "%4v %32v %4v\n", "#", "Target", "m")
        /* Print each target */
        for i, t := range stasks {
                m := wc(c, t, "m", true)
                wf(c, "%4v %32v %4v\n", i, t, m)
        }
}

/* Stop an attack in progress */
func handleS(c *net.TCPConn, cmd []string) {
	/* Usage */
	if 1 == len(cmd) {
		wl(c, "Stop Usage:")
		wl(c, "\ta host [host [host...]]")
		wl(c, "stops an attack on a host or hosts.")
	}
	/* Spawn hostmasters for each host on the list */
	for _, h := range cmd[1:] {
		h = addDefaultPort(h)
		wc(c, h, "s", false)
	}
}

/* Write a string to a tcp connection, printf-style */
func wf(c *net.TCPConn, f string, a ...interface{}) {
	/* Make a string */
	s := fmt.Sprintf(f, a...)
	/* Send it on the conn */
	c.Write([]byte(s))
}

/* Write a newline-terminated string to a tcp connection */
func wl(c *net.TCPConn, s string) {
	wf(c, "%v\n", s)
}

/* Write a command to a channel and, if res is true, get a response */
func wc(c *net.TCPConn, cname string, s string, res bool) string {
	/* Lock the C2CHAN for reading */
	C2CHANL.RLock()
	defer C2CHANL.RUnlock()
	/* Add a port, if needed */
	cname = addDefaultPort(cname)
	/* Try to get the channel */
	ch, ok := C2CHANS.Get(cname)
	/* If we failed, tell the user and give up */
	if !ok {
		wf(c, "%v does not seem to be a valid attack in progress.\n",
			cname)
		return ""
	}
	/* Send the message */
	ch.(chan string) <- s
	if res {
		if r, ok := <-ch.(chan string); ok {
			return r
		}
		log.Printf("Please report the following bug: C2 channel closed " +
			"before read.")
	}
	return ""
}
