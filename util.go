/* util provides small functions used in multiple files */
package main

/* textIfBlank returs <blank> if s is "", and s otherwise. */
func textIfBlank(s string) string {
        if len(s) > 0 {
                return s
        }
        return "<blank>"
}

