package ticket

type Ticket struct {
	VerifiablyRandomIdentifier [32]byte // y
	EntryIndex                 uint8    // r
}

// ReorderTicketsOutsideIn takes a slice of tickets and reorders them using the outside-in algorithm.
// The outside-in algorithm takes elements alternating from the start and end of the array,
// working toward the middle. For example, given tickets [0,1,2,3,4,5], the reordering would be [0,5,1,4,2,3].
func ReorderTicketsOutsideIn(tickets []Ticket) []Ticket {
	if len(tickets) == 0 {
		return []Ticket{}
	}

	reorderedTickets := make([]Ticket, len(tickets))
	index := 0

	// outside-in sequencing
	for i, j := 0, len(tickets)-1; i <= j; i, j = i+1, j-1 {
		if i == j {
			// When both indices meet, assign the middle element only once.
			reorderedTickets[index] = tickets[i]
			index++
		} else {
			// Assign first the element from the start then from the end.
			reorderedTickets[index] = tickets[i]
			index++
			reorderedTickets[index] = tickets[j]
			index++
		}
	}

	return reorderedTickets
}
