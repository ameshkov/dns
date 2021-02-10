package dns

// Tests that solve that an specific issue.

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestNSEC3MissingSalt(t *testing.T) {
	rr := testRR("ji6neoaepv8b5o6k4ev33abha8ht9fgc.example. NSEC3 1 1 12 aabbccdd K8UDEMVP1J2F7EG6JEBPS17VP3N8I58H")
	m := new(Msg)
	m.Answer = []RR{rr}
	mb, err := m.Pack()
	if err != nil {
		t.Fatalf("expected to pack message. err: %s", err)
	}
	if err := m.Unpack(mb); err != nil {
		t.Fatalf("expected to unpack message. missing salt? err: %s", err)
	}
	in := rr.(*NSEC3).Salt
	out := m.Answer[0].(*NSEC3).Salt
	if in != out {
		t.Fatalf("expected salts to match. packed: `%s`. returned: `%s`", in, out)
	}
}

func TestNSEC3MixedNextDomain(t *testing.T) {
	rr := testRR("ji6neoaepv8b5o6k4ev33abha8ht9fgc.example. NSEC3 1 1 12 - k8udemvp1j2f7eg6jebps17vp3n8i58h")
	m := new(Msg)
	m.Answer = []RR{rr}
	mb, err := m.Pack()
	if err != nil {
		t.Fatalf("expected to pack message. err: %s", err)
	}
	if err := m.Unpack(mb); err != nil {
		t.Fatalf("expected to unpack message. err: %s", err)
	}
	in := strings.ToUpper(rr.(*NSEC3).NextDomain)
	out := m.Answer[0].(*NSEC3).NextDomain
	if in != out {
		t.Fatalf("expected round trip to produce NextDomain `%s`, instead `%s`", in, out)
	}
}

func BenchmarkNetBuffers(b *testing.B) {
	HandleFunc("example.org.", HelloServer)
	defer HandleRemove("example.org.")
	s, addrstr, _, err := RunLocalTCPServer(":0")
	if err != nil {
		b.Fatal(err)
	}
	defer s.Shutdown()

	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		b.StartTimer()
		m := new(Msg)
		m.SetQuestion("example.org.", TypeA)

		buf, err := m.Pack()
		if err != nil {
			b.Fatal(err)
		}

		conn, err := net.Dial("tcp", addrstr)
		if err != nil {
			b.Fatal(err)
		}
		defer conn.Close()

		l := make([]byte, 2)
		binary.BigEndian.PutUint16(l, uint16(len(buf)))
		_, err = (&net.Buffers{l, buf}).WriteTo(conn)
		if err != nil {
			b.Fatal(err)
		}

		b.StopTimer()
	}
}
