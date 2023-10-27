package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	spec, err := ebpf.LoadCollectionSpec("bpf/xdp.elf")
	if err != nil {
		panic(err)
	}

	coll, err := ebpf.NewCollection(spec)
	// panic: Failed to create new collection: map xdp_stats_map: map create: operation not permitted (MEMLOCK may be too low, consider rlimit.RemoveMemlock)
	if err != nil {
		panic(fmt.Sprintf("Failed to create new collection: %v\n", err))
	}
	defer coll.Close()

	prog := coll.Programs["xdp_prog_func"]
	if prog == nil {
		panic("No program named 'xdp_prog_func' found in collection")
	}

	ifaceName := os.Getenv("INTERFACE")
	if ifaceName == "" {
		panic("No interface specified. Please set the INTERFACE environment variable to the name of the interface to be use")
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		panic(fmt.Sprintf("Failed to get interface %s: %v\n", ifaceName, err))
	}
	opts := link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		// Flags is one of XDPAttachFlags (optional).
	}
	lnk, err := link.AttachXDP(opts)
	if err != nil {
		panic(err)
	}
	defer lnk.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")
	// handle perf events
	outputMap, ok := coll.Maps["xdp_stats_map"]
	if !ok {
		panic("No map named 'xdp_stats_map' found in collection")
	}
	// Print the contents of the BPF hash map (source IP address -> packet count).
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatMapContents(outputMap)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Map contents:\n%s", s)
	}

}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key netip.Addr
		val uint32
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		sourceIP := key // IPv4 source address in network byte order.
		packetCount := val
		sb.WriteString(fmt.Sprintf("\t%s => %d\n", sourceIP, packetCount))
	}
	return sb.String(), iter.Err()
}
