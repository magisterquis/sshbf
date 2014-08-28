/* util provides small functions used in multiple files */
package main

import (
	"net"
)

/* textIfBlank returs <blank> if s is "", and s otherwise. */
func textIfBlank(s string) string {
	if len(s) > 0 {
		return s
	}
	return "<blank>"
}

/* addPort adds a :22 to the end of an address if it's not there */
func addDefaultPort(a string) string {
	if _, _, err := net.SplitHostPort(a); err != nil {
		return net.JoinHostPort(a, "22")
	}
        return a
}
