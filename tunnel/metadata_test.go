package tunnel

import (
	"bytes"
	"testing"
)

func TestAddressReadWriteIPv4(t *testing.T) {
	// Create IPv4 address
	addr := &Address{
		IP:          []byte{127, 0, 0, 1},
		Port:        443,
		AddressType: IPv4,
		NetworkType: "tcp",
	}

	var buf bytes.Buffer
	_, err := addr.WriteTo(&buf)
	if err != nil {
		t.Fatal("WriteTo failed:", err)
	}

	// Read back
	decoded := new(Address)
	_, err = decoded.ReadFrom(&buf)
	if err != nil {
		t.Fatal("ReadFrom failed:", err)
	}

	if decoded.Port != 443 {
		t.Errorf("port = %d, want 443", decoded.Port)
	}
	if decoded.AddressType != IPv4 {
		t.Errorf("ATYP = %d, want IPv4(1)", decoded.AddressType)
	}
	if !bytes.Equal(decoded.IP.To4(), []byte{127, 0, 0, 1}) {
		t.Errorf("IP = %v, want 127.0.0.1", decoded.IP)
	}
	if decoded.String() != "127.0.0.1:443" {
		t.Errorf("String() = %q, want 127.0.0.1:443", decoded.String())
	}
}

func TestAddressReadWriteDomainName(t *testing.T) {
	addr := &Address{
		DomainName:  "example.com",
		Port:        8080,
		AddressType: DomainName,
		NetworkType: "tcp",
	}

	var buf bytes.Buffer
	_, err := addr.WriteTo(&buf)
	if err != nil {
		t.Fatal("WriteTo failed:", err)
	}

	decoded := new(Address)
	_, err = decoded.ReadFrom(&buf)
	if err != nil {
		t.Fatal("ReadFrom failed:", err)
	}

	if decoded.DomainName != "example.com" {
		t.Errorf("DomainName = %q, want example.com", decoded.DomainName)
	}
	if decoded.Port != 8080 {
		t.Errorf("port = %d, want 8080", decoded.Port)
	}
	if decoded.AddressType != DomainName {
		t.Errorf("ATYP = %d, want DomainName(3)", decoded.AddressType)
	}
	if decoded.String() != "example.com:8080" {
		t.Errorf("String() = %q", decoded.String())
	}
}

func TestAddressReadWriteIPv6(t *testing.T) {
	addr := &Address{
		IP:          []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		Port:        3128,
		AddressType: IPv6,
		NetworkType: "tcp",
	}

	var buf bytes.Buffer
	_, err := addr.WriteTo(&buf)
	if err != nil {
		t.Fatal("WriteTo failed:", err)
	}

	decoded := new(Address)
	_, err = decoded.ReadFrom(&buf)
	if err != nil {
		t.Fatal("ReadFrom failed:", err)
	}

	if decoded.Port != 3128 {
		t.Errorf("port = %d, want 3128", decoded.Port)
	}
	if decoded.AddressType != IPv6 {
		t.Errorf("ATYP = %d, want IPv6(4)", decoded.AddressType)
	}
	if decoded.String() != "[::1]:3128" {
		t.Errorf("String() = %q", decoded.String())
	}
}

func TestAddressDomainNameWithEmbeddedIP(t *testing.T) {
	// "the fucking browser uses IP as a domain name sometimes"
	// Test that when domain name bytes look like an IP, they are parsed as IP
	addr := &Address{
		DomainName:  "1.2.3.4",
		Port:        80,
		AddressType: DomainName,
	}

	var buf bytes.Buffer
	if _, err := addr.WriteTo(&buf); err != nil {
		t.Fatal("WriteTo:", err)
	}

	decoded := new(Address)
	if _, err := decoded.ReadFrom(&buf); err != nil {
		t.Fatal("ReadFrom:", err)
	}

	// The address should have been reclassified as IPv4
	if decoded.AddressType != IPv4 {
		t.Errorf("embedded IP should be reclassified as IPv4, got %d", decoded.AddressType)
	}
	if decoded.Port != 80 {
		t.Errorf("port = %d", decoded.Port)
	}
}

func TestAddressNewFromHostPort(t *testing.T) {
	// IPv4
	a4 := NewAddressFromHostPort("tcp", "192.168.1.1", 80)
	if a4.AddressType != IPv4 || a4.Port != 80 {
		t.Fatal("IPv4 parse failed")
	}

	// Domain
	aDom := NewAddressFromHostPort("tcp", "google.com", 443)
	if aDom.AddressType != DomainName || aDom.DomainName != "google.com" {
		t.Fatal("Domain parse failed")
	}

	// IPv6
	a6 := NewAddressFromHostPort("tcp", "::1", 3128)
	if a6.AddressType != IPv6 {
		t.Fatal("IPv6 parse failed")
	}
}

func TestAddressNewFromAddr(t *testing.T) {
	a, err := NewAddressFromAddr("tcp", "127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if a.Port != 1080 || a.AddressType != IPv4 {
		t.Fatal("parse failed")
	}

	a2, err := NewAddressFromAddr("udp", "example.com:53")
	if err != nil {
		t.Fatal(err)
	}
	if a2.DomainName != "example.com" || a2.Port != 53 {
		t.Fatal("domain parse failed")
	}
}

func TestAddressResolveIP(t *testing.T) {
	// IPv4 address should resolve without DNS lookup
	a4 := NewAddressFromHostPort("tcp", "127.0.0.1", 80)
	ip, err := a4.ResolveIP()
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(a4.IP) {
		t.Error("IP mismatch")
	}
}

func TestAddressNetwork(t *testing.T) {
	a := NewAddressFromHostPort("udp", "127.0.0.1", 80)
	if a.Network() != "udp" {
		t.Errorf("Network() = %q, want udp", a.Network())
	}
}

func TestAddressInvalidATYP(t *testing.T) {
	data := []byte{99} // invalid ATYP
	decoded := new(Address)
	_, err := decoded.ReadFrom(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for invalid ATYP")
	}
}

func TestMetadataReadWrite(t *testing.T) {
	addr := NewAddressFromHostPort("tcp", "example.com", 8443)
	meta := &Metadata{
		Command: 1, // TCP CONNECT
		Address: addr,
	}

	var buf bytes.Buffer
	_, err := meta.WriteTo(&buf)
	if err != nil {
		t.Fatal("WriteTo:", err)
	}

	decoded := new(Metadata)
	_, err = decoded.ReadFrom(&buf)
	if err != nil {
		t.Fatal("ReadFrom:", err)
	}

	if decoded.Command != 1 {
		t.Errorf("Command = %d, want 1", decoded.Command)
	}
	if decoded.Address.DomainName != "example.com" {
		t.Errorf("DomainName = %q", decoded.Address.DomainName)
	}
	if decoded.Address.Port != 8443 {
		t.Errorf("Port = %d", decoded.Address.Port)
	}
	if decoded.Network() != "" {
		t.Logf("Network() after ReadFrom = %q (expected empty - NetworkType not serialized)", decoded.Network())
	}
}

func TestMetadataString(t *testing.T) {
	meta := &Metadata{
		Command: 1,
		Address: NewAddressFromHostPort("tcp", "1.2.3.4", 443),
	}
	if meta.String() != "1.2.3.4:443" {
		t.Errorf("String() = %q", meta.String())
	}
}

func TestMetadataNetwork(t *testing.T) {
	meta := &Metadata{
		Command: 1,
		Address: NewAddressFromHostPort("udp", "8.8.8.8", 53),
	}
	if meta.Network() != "udp" {
		t.Errorf("Network() = %q, want udp", meta.Network())
	}
}

func TestAddressRoundTripOneBytePortEdge(t *testing.T) {
	// Port values at byte boundaries
	for _, port := range []int{0, 1, 255, 256, 65535} {
		addr := NewAddressFromHostPort("tcp", "10.0.0.1", port)
		var buf bytes.Buffer
		if _, err := addr.WriteTo(&buf); err != nil {
			t.Fatalf("WriteTo port=%d: %v", port, err)
		}
		decoded := new(Address)
		if _, err := decoded.ReadFrom(&buf); err != nil {
			t.Fatalf("ReadFrom port=%d: %v", port, err)
		}
		if decoded.Port != port {
			t.Errorf("port round-trip: got %d, want %d", decoded.Port, port)
		}
	}
}
