package libcore

import (
	"context"
	"libcore/comm"
	"libcore/device"
	"libcore/protect"
	"libcore/tun"
	"libcore/tun/tuns"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/errors"
	v2rayNet "github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/transport"
)

var _ tun.Handler = (*Tun2ray)(nil)

type Tun2ray struct {
	access   sync.Mutex
	dev      tun.Tun
	v2ray    *V2RayInstance
	udpTable *natTable
	udpQueue chan *tun.UDPPacket

	fakedns  bool
	sniffing bool
	debug    bool

	dumpUid      bool
	trafficStats bool
	appStats     map[uint16]*appStats

	fdProtector Protector
}

type TunConfig struct {
	FileDescriptor int32
	MTU            int32
	V2Ray          *V2RayInstance
	IPv6Mode       int32
	Implementation int32
	Sniffing       bool
	FakeDNS        bool
	Debug          bool
	DumpUID        bool
	TrafficStats   bool
	ErrorHandler   ErrorHandler
	LocalResolver  LocalResolver
	FdProtector    Protector
}

type Protector interface {
	Protect(fd int32) bool
}

type ErrorHandler interface {
	HandleError(err string)
}

func NewTun2ray(config *TunConfig) (*Tun2ray, error) {
	t := &Tun2ray{
		v2ray:        config.V2Ray,
		udpTable:     &natTable{},
		udpQueue:     make(chan *tun.UDPPacket, 200),
		sniffing:     config.Sniffing,
		fakedns:      config.FakeDNS,
		debug:        config.Debug,
		dumpUid:      config.DumpUID,
		trafficStats: config.TrafficStats,
		fdProtector:  config.FdProtector,
	}

	for i := 0; i < device.NumUDPWorkers(); i++ {
		go t.udpHandleUplink()
	}

	// setup resolver first
	underlyingResolver.sekaiResolver = config.LocalResolver
	ipv6Mode = config.IPv6Mode
	if t.fdProtector != nil {
		protect.FdProtector = t.fdProtector
	}

	if config.TrafficStats {
		t.appStats = map[uint16]*appStats{}
	}
	var err error
	if config.Implementation == 0 { // gvisor
		t.dev, err = tuns.NewGvisor(config.FileDescriptor, config.MTU, t, 0x01, config.IPv6Mode)
	} else if config.Implementation == 1 { // SYSTEM
		t.dev, err = tuns.NewSystem(config.FileDescriptor, config.MTU, t, config.IPv6Mode, config.ErrorHandler.HandleError)
	} else if config.Implementation == 2 { // Tun2Socket
		t.dev, err = tuns.NewTun2Socket(config.FileDescriptor, t)
	} else {
		err = newError("Not supported")
	}
	if err != nil {
		return nil, err
	}

	return t, nil
}

func (t *Tun2ray) Close() {
	t.access.Lock()
	defer t.access.Unlock()
	defer close(t.udpQueue)

	underlyingResolver.sekaiResolver = nil
	if t.fdProtector != nil {
		protect.FdProtector = nil
	}

	t.dev.Stop()
}

func (t *Tun2ray) SetV2ray(i *V2RayInstance) {
	t.access.Lock()
	defer t.access.Unlock()
	t.v2ray = i
	if i != nil {
		t.udpTable = &natTable{}
	}
}

// TCP
func (t *Tun2ray) NewConnection(source v2rayNet.Destination, destination v2rayNet.Destination, conn net.Conn) {
	t.access.Lock()
	if t.v2ray == nil {
		conn.Close()
		t.access.Unlock()
		return
	}
	v2ray := t.v2ray
	t.access.Unlock()

	inbound := &session.Inbound{
		Source: source,
		Tag:    "socks",
	}

	// [TCP] dns to router
	isDns := destination.Address.String() == tun.PRIVATE_VLAN4_ROUTER && destination.Port.Value() == 53
	if isDns {
		inbound.Tag = "dns-in"
	}

	var uid uint16
	var self bool

	if t.dumpUid || t.trafficStats {
		u, err := dumpUid(source, destination)
		if err == nil {
			uid = uint16(u)
			var info *UidInfo
			self = uid > 0 && int(uid) == os.Getuid()
			if t.debug && !self && uid >= 10000 {
				if err == nil {
					info, _ = uidDumper.GetUidInfo(int32(uid))
				}
				if info == nil {
					logrus.Infof("[TCP] %s ==> %s", source.NetAddr(), destination.NetAddr())
				} else {
					logrus.Infof("[TCP][%s (%d/%s)] %s ==> %s", info.Label, uid, info.PackageName, source.NetAddr(), destination.NetAddr())
				}
			}

			if uid < 10000 {
				uid = 1000
			}

			inbound.Uid = uint32(uid)
		}
	}

	ctx := core.WithContext(context.Background(), v2ray.Core)
	ctx = session.ContextWithInbound(ctx, inbound)

	// [tun-in] [TCP] sniffing
	if !isDns && (t.sniffing || t.fakedns) {
		req := session.SniffingRequest{
			Enabled:      true,
			MetadataOnly: t.fakedns && !t.sniffing,
			RouteOnly:    true,
		}
		if t.sniffing && t.fakedns {
			req.OverrideDestinationForProtocol = []string{"fakedns", "http", "tls"}
		}
		if t.sniffing && !t.fakedns {
			req.OverrideDestinationForProtocol = []string{"http", "tls"}
		}
		if !t.sniffing && t.fakedns {
			req.OverrideDestinationForProtocol = []string{"fakedns"}
		}
		ctx = session.ContextWithContent(ctx, &session.Content{
			SniffingRequest: req,
		})
	}

	if t.trafficStats && !self && !isDns {
		stats := t.appStats[uid]
		if stats == nil {
			t.access.Lock()
			stats = t.appStats[uid]
			if stats == nil {
				stats = &appStats{}
				t.appStats[uid] = stats
			}
			t.access.Unlock()
		}
		atomic.AddInt32(&stats.tcpConn, 1)
		atomic.AddUint32(&stats.tcpConnTotal, 1)
		atomic.StoreInt64(&stats.deactivateAt, 0)
		defer func() {
			if atomic.AddInt32(&stats.tcpConn, -1)+atomic.LoadInt32(&stats.udpConn) == 0 {
				atomic.StoreInt64(&stats.deactivateAt, time.Now().Unix())
			}
		}()
		conn = &statsConn{conn, &stats.uplink, &stats.downlink}
	}

	//这个 DispatchLink 是 outbound, link reader 是上行流量
	rw := &connReaderWriter{conn, buf.NewReader(conn), buf.NewWriter(conn), 0}
	link := &transport.Link{
		Reader: rw,
		Writer: rw,
	}
	err := v2ray.Dispatcher.DispatchLink(ctx, destination, link)

	if err != nil {
		logrus.Errorf("[TCP] dispatchLink failed: %s", err.Error())
		comm.CloseIgnore(link.Reader, link.Writer)
		comm.CloseIgnore(conn)
		return
	}

	// connection ends (in core), let core close it
	// fuck v2ray pipe
}

type connReaderWriter struct {
	net.Conn
	buf.Reader
	buf.Writer
	closed uint32
}

func (r *connReaderWriter) ReadMultiBufferTimeout(t time.Duration) (buf.MultiBuffer, error) {
	r.SetReadDeadline(time.Now().Add(t))
	defer r.SetReadDeadline(time.Time{})
	mb, err := r.ReadMultiBuffer()
	if err != nil {
		if nerr, ok := errors.Cause(err).(net.Error); ok && nerr.Timeout() {
			return nil, buf.ErrReadTimeout
		}
		return nil, err
	}
	return mb, nil
}

func (r *connReaderWriter) Interrupt() {
	r.Close()
}

func (r *connReaderWriter) Close() (err error) {
	cnt := atomic.AddUint32(&r.closed, 1)
	if cnt > 1 {
		return nil
	}
	return r.Conn.Close()
}

// UDP

func (t *Tun2ray) HandlePacket(p *tun.UDPPacket) {
	t.udpQueue <- p
}

func (t *Tun2ray) udpHandleUplink() {
	for p := range t.udpQueue {
		t.udpHandleUplinkInternal(p)
	}
}

func (t *Tun2ray) udpHandleUplinkInternal(p *tun.UDPPacket) {
	natKey := p.Src.String()

	sendTo := func() bool {
		conn := t.udpTable.Get(natKey)
		if conn == nil {
			return false
		}
		_, err := conn.WriteTo(p.Data, p.Dst)
		if p.Put != nil {
			p.Put()
		}
		if err != nil {
			_ = conn.Close()
		}
		return true
	}

	// cached udp conn
	if sendTo() {
		return
	}

	// new udp conn
	lockKey := natKey + "-lock"
	cond, loaded := t.udpTable.GetOrCreateLock(lockKey)

	// cached udp conn (waiting)
	if loaded {
		cond.L.Lock()
		cond.Wait()
		sendTo()
		cond.L.Unlock()
		return
	}

	// new udp conn
	source := v2rayNet.DestinationFromAddr(p.Src)
	destination := v2rayNet.DestinationFromAddr(p.Dst)
	inbound := &session.Inbound{
		Source: source,
		Tag:    "socks",
	}

	// change destination
	destination2 := destination

	// [UDP] dns to router
	isDns := destination.Address.String() == tun.PRIVATE_VLAN4_ROUTER

	// [UDP] dns to all
	dnsMsg := dns.Msg{}
	err := dnsMsg.Unpack(p.Data)
	if err == nil && !dnsMsg.Response && len(dnsMsg.Question) > 0 {
		// v2ray only support A and AAAA
		switch dnsMsg.Question[0].Qtype {
		case dns.TypeA:
			isDns = true
		case dns.TypeAAAA:
			isDns = true
		default:
			if isDns {
				// unknown dns traffic send as UDP to 8.8.8.8
				destination2.Address = v2rayNet.ParseAddress("8.8.8.8")
			}
			isDns = false
		}
	}

	if isDns {
		inbound.Tag = "dns-in"
	}

	var uid uint16
	var self bool

	if t.dumpUid || t.trafficStats {

		u, err := dumpUid(source, destination)
		if err == nil {
			uid = uint16(u)
			var info *UidInfo
			self = uid > 0 && int(uid) == os.Getuid()

			if t.debug && !self && uid >= 1000 {
				if err == nil {
					info, _ = uidDumper.GetUidInfo(int32(uid))
				}
				var tag string
				if !isDns {
					tag = "UDP"
				} else {
					tag = "DNS"
				}

				if info == nil {
					logrus.Infof("[%s] [uid:%d] %s ==> %s", tag, uid, source.NetAddr(), destination.NetAddr())
				} else {
					logrus.Infof("[%s][%s (%d/%s)] %s ==> %s", tag, info.Label, uid, info.PackageName, source.NetAddr(), destination.NetAddr())
				}
			}

			if uid < 10000 {
				uid = 1000
			}

			inbound.Uid = uint32(uid)
		}

	}

	ctx := session.ContextWithInbound(context.Background(), inbound)

	// [tun-in] [UDP] sniffing
	if !isDns {
		override := []string{}
		if t.fakedns {
			override = append(override, "fakedns")
		}
		if t.sniffing {
			override = append(override, "quic")
		}
		if len(override) != 0 {
			ctx = session.ContextWithContent(ctx, &session.Content{
				SniffingRequest: session.SniffingRequest{
					Enabled:                        true,
					MetadataOnly:                   t.fakedns && !t.sniffing,
					OverrideDestinationForProtocol: override,
					RouteOnly:                      true,
				},
			})
		}
	}

	workerN := 1
	timeout := time.Minute
	if !isDns {
		workerN = device.NumUDPWorkers()
	} else {
		timeout = time.Second * 30
	}

	if t.v2ray == nil {
		return
	}

	conn, err := t.v2ray.newDispatcherConn(ctx, destination, destination2, p.WriteBack, timeout, workerN)

	if err != nil {
		logrus.Errorf("[UDP] dial failed: %s", err.Error())
		return
	}

	if t.trafficStats && !self && !isDns {
		stats := t.appStats[uid]
		if stats == nil {
			t.access.Lock()
			stats = t.appStats[uid]
			if stats == nil {
				stats = &appStats{}
				t.appStats[uid] = stats
			}
			t.access.Unlock()
		}
		atomic.AddInt32(&stats.udpConn, 1)
		atomic.AddUint32(&stats.udpConnTotal, 1)
		atomic.StoreInt64(&stats.deactivateAt, 0)
		defer func() {
			if atomic.AddInt32(&stats.udpConn, -1)+atomic.LoadInt32(&stats.tcpConn) == 0 {
				atomic.StoreInt64(&stats.deactivateAt, time.Now().Unix())
			}
		}()
		conn.stats = &myStats{
			uplink:   &stats.uplink,
			downlink: &stats.downlink,
		}
	}

	// [FakeDNS] [UDP] must fake ip & no endpoint change
	if tun.FAKEDNS_VLAN4_CLIENT_IPNET.Contains(destination.Address.IP()) {
		conn.fake = true
	}

	// udp conn ok
	t.udpTable.Set(natKey, conn)
	t.udpTable.Delete(lockKey)
	cond.Broadcast()

	// uplink
	sendTo()

	// wait for connection ends
	go func() {
		// downlink (moved to handleDownlink)
		<-conn.ctx.Done()

		// close
		comm.CloseIgnore(conn)
		t.udpTable.Delete(natKey)
	}()
}

type natTable struct {
	mapping sync.Map
}

func (t *natTable) Set(key string, pc *dispatcherConn) {
	t.mapping.Store(key, pc)
}

func (t *natTable) Get(key string) *dispatcherConn {
	item, exist := t.mapping.Load(key)
	if !exist {
		return nil
	}
	return item.(*dispatcherConn)
}

func (t *natTable) GetOrCreateLock(key string) (*sync.Cond, bool) {
	item, loaded := t.mapping.LoadOrStore(key, sync.NewCond(&sync.Mutex{}))
	return item.(*sync.Cond), loaded
}

func (t *natTable) Delete(key string) {
	t.mapping.Delete(key)
}
