package tree

import "github.com/miekg/dns"

// AuthWalk performs fn on all authoritative values stored in the tree in
// pre-order depth first. If a non-nil error is returned the AuthWalk was interrupted
// by an fn returning that error. If fn alters stored values' sort
// relationships, future tree operation behaviors are undefined.
func (t *Tree) AuthWalk(fn func(e *Elem, rrs map[uint16][]dns.RR) error) error {
	if t.Root == nil {
		return nil
	}
	_, err := t.Root.authwalk(make(map[string]struct{}), fn)
	return err
}

type status int

const (
	gotoNext status = iota
	skipChildren
	terminate
)

func (n *Node) authwalk(delegated map[string]struct{}, fn func(e *Elem, rrs map[uint16][]dns.RR) error) (status, error) {
	if n.Elem.Type(dns.TypeNS) != nil {
		return skipChildren, nil
	}

	if err := fn(n.Elem, n.Elem.m); err != nil {
		return terminate, err
	}

	if n.Left != nil {
		stat, err := n.Left.authwalk(delegated, fn)
		if err != nil {
			return terminate, err
		}
		if stat == skipChildren {
			return gotoNext, nil
		}
	}

	if n.Right != nil {
		stat, err := n.Right.authwalk(delegated, fn)
		if err != nil {
			return terminate, err
		}
		if stat == skipChildren {
			return gotoNext, nil
		}
	}
	return gotoNext, nil
}
