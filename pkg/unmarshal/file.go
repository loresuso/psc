package unmarshal

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	FilePathLen = 256
)

// File descriptor types
const (
	FdTypeOther  uint8 = 0
	FdTypeFile   uint8 = 1
	FdTypeSocket uint8 = 2
)

// Socket families
const (
	AfUnix  uint8 = 1
	AfInet  uint8 = 2
	AfInet6 uint8 = 10
)

// Socket types
const (
	SockStream uint8 = 1 // TCP
	SockDgram  uint8 = 2 // UDP
)

// TCP states
const (
	TcpEstablished uint8 = 1
	TcpSynSent     uint8 = 2
	TcpSynRecv     uint8 = 3
	TcpFinWait1    uint8 = 4
	TcpFinWait2    uint8 = 5
	TcpTimeWait    uint8 = 6
	TcpClose       uint8 = 7
	TcpCloseWait   uint8 = 8
	TcpLastAck     uint8 = 9
	TcpListen      uint8 = 10
	TcpClosing     uint8 = 11
)

type FileDescriptor struct {
	Pid  int32 `cel:"pid"`
	Tid  int32 `cel:"tid"`
	Ppid int32 `cel:"ppid"`
	Fd   int32 `cel:"fd"`

	// Type information
	FdType     uint8 `cel:"fdType"`
	SockFamily uint8 `cel:"family"`
	SockType   uint8 `cel:"type"`
	SockState  uint8 `cel:"state"`

	// For regular files
	Path string `cel:"path"`

	// For inet sockets
	SrcAddr net.IP `cel:"srcAddr"`
	DstAddr net.IP `cel:"dstAddr"`
	SrcPort int32  `cel:"srcPort"`
	DstPort int32  `cel:"dstPort"`

	// For unix sockets
	UnixPath string `cel:"unixPath"`
}

// EmptyFileDescriptor is used when no file context is available.
// This allows CEL expressions to safely access socket/file fields without nil checks.
var EmptyFileDescriptor = &FileDescriptor{}

func (f *FileDescriptor) String() string {
	switch f.FdType {
	case FdTypeSocket:
		return f.socketString()
	default:
		return fmt.Sprintf("PID: %d, FD: %d, Path: %s", f.Pid, f.Fd, f.Path)
	}
}

func (f *FileDescriptor) socketString() string {
	proto := f.ProtocolString()
	switch f.SockFamily {
	case AfInet, AfInet6:
		return fmt.Sprintf("PID: %d, FD: %d, %s %s:%d -> %s:%d (%s)",
			f.Pid, f.Fd, proto,
			f.SrcAddr, f.SrcPort,
			f.DstAddr, f.DstPort,
			f.StateString())
	case AfUnix:
		return fmt.Sprintf("PID: %d, FD: %d, UNIX %s", f.Pid, f.Fd, f.UnixPath)
	default:
		return fmt.Sprintf("PID: %d, FD: %d, Socket (family=%d)", f.Pid, f.Fd, f.SockFamily)
	}
}

// ProtocolString returns a human-readable protocol name
func (f *FileDescriptor) ProtocolString() string {
	family := ""
	switch f.SockFamily {
	case AfInet:
		family = "4"
	case AfInet6:
		family = "6"
	}

	switch f.SockType {
	case SockStream:
		return "TCP" + family
	case SockDgram:
		return "UDP" + family
	default:
		return fmt.Sprintf("SOCK%s", family)
	}
}

// StateString returns a human-readable socket state (ss-style output)
// For UDP sockets, only UNCONN (unconnected) or ESTAB (connected) are meaningful
func (f *FileDescriptor) StateString() string {
	// UDP sockets: only UNCONN or ESTAB are meaningful
	if f.SockType == SockDgram {
		switch f.SockState {
		case TcpEstablished:
			return "ESTAB"
		default:
			return "UNCONN"
		}
	}

	// TCP sockets: use ss-style state names
	switch f.SockState {
	case TcpEstablished:
		return "ESTAB"
	case TcpSynSent:
		return "SYN-SENT"
	case TcpSynRecv:
		return "SYN-RECV"
	case TcpFinWait1:
		return "FIN-WAIT-1"
	case TcpFinWait2:
		return "FIN-WAIT-2"
	case TcpTimeWait:
		return "TIME-WAIT"
	case TcpClose:
		return "CLOSE"
	case TcpCloseWait:
		return "CLOSE-WAIT"
	case TcpLastAck:
		return "LAST-ACK"
	case TcpListen:
		return "LISTEN"
	case TcpClosing:
		return "CLOSING"
	default:
		return fmt.Sprintf("STATE_%d", f.SockState)
	}
}

// IsSocket returns true if this is a socket file descriptor
func (f *FileDescriptor) IsSocket() bool {
	return f.FdType == FdTypeSocket
}

// IsTCP returns true if this is a TCP socket
func (f *FileDescriptor) IsTCP() bool {
	return f.FdType == FdTypeSocket && f.SockType == SockStream
}

// IsUDP returns true if this is a UDP socket
func (f *FileDescriptor) IsUDP() bool {
	return f.FdType == FdTypeSocket && f.SockType == SockDgram
}

// IsUnix returns true if this is a Unix socket
func (f *FileDescriptor) IsUnix() bool {
	return f.FdType == FdTypeSocket && f.SockFamily == AfUnix
}

// IsRegularFile returns true if this is a regular file (not a socket)
func (f *FileDescriptor) IsRegularFile() bool {
	return f.FdType == FdTypeFile
}

// CEL-friendly helper methods for filtering

// SrcAddrStr returns the source address as a string (for CEL filtering)
func (f *FileDescriptor) SrcAddrStr() string {
	if f.SrcAddr == nil {
		return ""
	}
	return f.SrcAddr.String()
}

// DstAddrStr returns the destination address as a string (for CEL filtering)
func (f *FileDescriptor) DstAddrStr() string {
	if f.DstAddr == nil {
		return ""
	}
	return f.DstAddr.String()
}

// Protocol returns the protocol as a string ("tcp", "udp", "unix", or "other")
func (f *FileDescriptor) Protocol() string {
	if f.FdType != FdTypeSocket {
		return "file"
	}
	switch f.SockFamily {
	case AfUnix:
		return "unix"
	case AfInet, AfInet6:
		switch f.SockType {
		case SockStream:
			return "tcp"
		case SockDgram:
			return "udp"
		}
	}
	return "other"
}

// State returns the socket state as a string (for CEL filtering)
func (f *FileDescriptor) State() string {
	return f.StateString()
}

// IsListening returns true if this is a listening socket
func (f *FileDescriptor) IsListening() bool {
	return f.FdType == FdTypeSocket && f.SockState == TcpListen
}

// IsEstablished returns true if this is an established TCP connection
func (f *FileDescriptor) IsEstablished() bool {
	return f.FdType == FdTypeSocket && f.SockState == TcpEstablished
}

// Port returns the local port (srcPort) for convenience
func (f *FileDescriptor) Port() int32 {
	return f.SrcPort
}

// rawFileDescriptor matches the C struct layout exactly
// C struct layout:
//
//	int pid;                    // offset 0, 4 bytes
//	int tid;                    // offset 4, 4 bytes
//	int ppid;                   // offset 8, 4 bytes
//	int fd;                     // offset 12, 4 bytes
//	__u8 fd_type;               // offset 16, 1 byte
//	__u8 sock_family;           // offset 17, 1 byte
//	__u8 sock_type;             // offset 18, 1 byte
//	__u8 sock_state;            // offset 19, 1 byte
//	union data[256];            // offset 20, 256 bytes
//
// Total: 276 bytes
type rawFileDescriptor struct {
	Pid        int32
	Tid        int32
	Ppid       int32
	Fd         int32
	FdType     uint8
	SockFamily uint8
	SockType   uint8
	SockState  uint8
	Data       [FilePathLen]byte // Union data
}

// rawInetSockInfo matches the inet socket portion of the union
type rawInetSockInfo struct {
	SrcAddr [16]byte
	DstAddr [16]byte
	SrcPort uint16
	DstPort uint16
}

func (f *FileDescriptor) Unmarshal(data []byte) error {
	if len(data) < binary.Size(rawFileDescriptor{}) {
		return fmt.Errorf("data too short: got %d bytes, need %d", len(data), binary.Size(rawFileDescriptor{}))
	}

	var raw rawFileDescriptor
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &raw); err != nil {
		return fmt.Errorf("failed to unmarshal file descriptor: %w", err)
	}

	f.Pid = raw.Pid
	f.Tid = raw.Tid
	f.Ppid = raw.Ppid
	f.Fd = raw.Fd
	f.FdType = raw.FdType
	f.SockFamily = raw.SockFamily
	f.SockType = raw.SockType
	f.SockState = raw.SockState

	// Parse the union data based on type
	switch {
	case raw.FdType == FdTypeFile:
		// Regular file - data is path
		if idx := bytes.IndexByte(raw.Data[:], 0); idx >= 0 {
			f.Path = string(raw.Data[:idx])
		} else {
			f.Path = string(raw.Data[:])
		}

	case raw.FdType == FdTypeSocket && (raw.SockFamily == AfInet || raw.SockFamily == AfInet6):
		// Inet socket - parse addresses and ports
		var inet rawInetSockInfo
		inetReader := bytes.NewReader(raw.Data[:])
		if err := binary.Read(inetReader, binary.LittleEndian, &inet); err == nil {
			f.SrcPort = int32(inet.SrcPort)
			f.DstPort = int32(inet.DstPort)

			if raw.SockFamily == AfInet {
				f.SrcAddr = net.IP(inet.SrcAddr[:4])
				f.DstAddr = net.IP(inet.DstAddr[:4])
			} else {
				f.SrcAddr = net.IP(inet.SrcAddr[:])
				f.DstAddr = net.IP(inet.DstAddr[:])
			}
		}

	case raw.FdType == FdTypeSocket && raw.SockFamily == AfUnix:
		// Unix socket - data is unix path
		if idx := bytes.IndexByte(raw.Data[:], 0); idx >= 0 {
			f.UnixPath = string(raw.Data[:idx])
		} else {
			f.UnixPath = string(raw.Data[:])
		}
	}

	return nil
}

// Size returns the size of the raw file descriptor in bytes
func (FileDescriptor) Size() int {
	return binary.Size(rawFileDescriptor{})
}
