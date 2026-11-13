package collector

import (
	"context"
	"encoding/binary"
	"errors"
	"syscall"
	"time"
)

// Linux process connector (linux/connector.h, linux/cn_proc.h): a netlink socket on which
// the kernel announces fork/exec/exit of every process. Needs CAP_NET_ADMIN (root).
const (
	netlinkConnector = 11 // NETLINK_CONNECTOR
	cnIdxProc        = 1
	cnValProc        = 1
	procCnMcastOn    = 1
	procEventExec    = 0x00000002

	nlmsgHdrLen = 16
	cnMsgLen    = 20 // idx, val, seq, ack (u32 each), len, flags (u16 each)
)

// watchExecs calls onExec(pid) for every exec on the host until ctx ends. It returns an
// error when the connector cannot be opened (no privilege, kernel without it, container).
func watchExecs(ctx context.Context, onExec func(pid int)) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, netlinkConnector)
	if err != nil {
		return err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: cnIdxProc}); err != nil { // Pid 0: the kernel assigns the port
		syscall.Close(fd)
		return err
	}
	if err := syscall.Sendto(fd, listenMessage(), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return err
	}
	// Bounded reads let the goroutine notice ctx without closing the fd under a Recvfrom.
	tv := syscall.NsecToTimeval(int64(time.Second))
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20)

	go func() {
		defer syscall.Close(fd)
		buf := make([]byte, 64<<10)
		for ctx.Err() == nil {
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.ENOBUFS) {
					continue // timeout, signal, or the kernel dropped messages under load
				}
				return
			}
			for _, pid := range ParseExecEvents(buf[:n]) {
				onExec(pid)
			}
		}
	}()
	return nil
}

// listenMessage is nlmsghdr + cn_msg + PROC_CN_MCAST_LISTEN.
func listenMessage() []byte {
	b := make([]byte, nlmsgHdrLen+cnMsgLen+4)
	le := binary.LittleEndian               // netlink uses host byte order; every Linux target we build is little endian
	le.PutUint32(b[0:], uint32(len(b)))     // nlmsg_len
	le.PutUint16(b[4:], syscall.NLMSG_DONE) // nlmsg_type
	le.PutUint32(b[16:], cnIdxProc)         // cn_msg.id.idx
	le.PutUint32(b[20:], cnValProc)         // cn_msg.id.val
	le.PutUint16(b[32:], 4)                 // cn_msg.len
	le.PutUint32(b[nlmsgHdrLen+cnMsgLen:], procCnMcastOn)
	return b
}

// ParseExecEvents returns the tgid of every PROC_EVENT_EXEC in a netlink datagram.
func ParseExecEvents(b []byte) []int {
	le := binary.LittleEndian
	var pids []int
	for len(b) >= nlmsgHdrLen {
		msgLen := int(le.Uint32(b[0:]))
		if msgLen < nlmsgHdrLen || msgLen > len(b) {
			break
		}
		msg := b[nlmsgHdrLen:msgLen]
		// cn_msg header, then struct proc_event: what u32, cpu u32, timestamp u64, union.
		if len(msg) >= cnMsgLen+24 && le.Uint32(msg[0:]) == cnIdxProc {
			ev := msg[cnMsgLen:]
			if le.Uint32(ev[0:]) == procEventExec {
				pids = append(pids, int(le.Uint32(ev[20:]))) // exec: process_pid u32, process_tgid u32
			}
		}
		aligned := (msgLen + 3) &^ 3
		if aligned >= len(b) {
			break
		}
		b = b[aligned:]
	}
	return pids
}
