package main

import (
	"container/list"
	"net"
	"testing"
	"time"
)

func TestComputeObscuredAddr(t *testing.T) {
	want := net.ParseIP("fe80::e64c:f59b:fbcf:3c57")
	ip, ipnet, _ := net.ParseCIDR("fe80::1/64")
	got := computeObscuredAddr(IP{IP: ip, IPNet: ipnet}, []byte(""), 0)
	if !want.Equal(got) {
		t.Fatalf("Got %v, want: %v", got, want)
	}

	want = net.ParseIP("fe80::fc32:4e9a:71a5:2615")
	got = computeObscuredAddr(IP{IP: ip, IPNet: ipnet}, []byte("secret"), 424242)
	if !want.Equal(got) {
		t.Fatalf("Got %v, want: %v", got, want)
	}
}

func TestMoveExpiredRoutes(t *testing.T) {
	r := &Routes{
		Expired: list.New(),
		Head:    list.New(),
	}
	for i := uint64(0); i < 10; i++ {
		r.Head.PushFront(&Route{
			ExpirationTime: time.Time{},
			NftRuleHandle:  i,
		})
	}

	r.MoveExpiredRoutes()

	if r.Head.Len() != 0 {
		t.Fatalf("list should be empty")
	}
	if r.Expired.Len() != 10 {
		t.Fatalf("all elements should be here")
	}
	want := uint64(9)
	for e := r.Expired.Front(); e != nil; e = e.Next() {
		got := e.Value.(*Route)
		if got.NftRuleHandle != want {
			t.Fatalf("wrong list ordering, got %d, want: %d", got.NftRuleHandle, want)
		}
		want--
	}

	// clean
	r.Expired = list.New()
	r.Head = list.New()

	for i := uint64(0); i < 10; i++ {
		t := time.Time{}
		if i%2 == 0 {
			t = time.Now().UTC().Add(1 * time.Minute)
		}
		r.Head.PushFront(&Route{
			ExpirationTime: t,
			NftRuleHandle:  i,
		})
	}

	r.MoveExpiredRoutes()

	if r.Head.Len() != 5 {
		t.Fatalf("list should be of len 5")
	}
	if r.Expired.Len() != 5 {
		t.Fatalf("list should be of len 5")
	}

	want = uint64(8)
	for e := r.Head.Front(); e != nil; e = e.Next() {
		got := e.Value.(*Route)
		if got.NftRuleHandle != want {
			t.Fatalf("wrong list ordering, got %d, want: %d", got.NftRuleHandle, want)
		}
		want -= 2
	}
	want = uint64(9)
	for e := r.Expired.Front(); e != nil; e = e.Next() {
		got := e.Value.(*Route)
		if got.NftRuleHandle != want {
			t.Fatalf("wrong list ordering, got %d, want: %d", got.NftRuleHandle, want)
		}
		want -= 2
	}
}

func TestActive(t *testing.T) {
	r := &Routes{
		Expired: list.New(),
		Head:    list.New(),
	}

	got := r.Active()

	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}

	r.Head.PushFront(&Route{
		NftRuleHandle: 42,
	})

	got = r.Active()

	if got.NftRuleHandle != 42 {
		t.Fatalf("want 42, got %d", got.NftRuleHandle)
	}

	r.Head = list.New()

	for i := uint64(0); i < 10; i++ {
		r.Head.PushFront(&Route{
			NftRuleHandle: i,
		})
	}

	got = r.Active()

	if got.NftRuleHandle != 8 {
		t.Fatalf("want 8, got %d", got.NftRuleHandle)
	}
}

func TestIsExpired(t *testing.T) {
	r := Route{
		ExpirationTime: time.Time{},
	}

	if !r.IsExpired() {
		t.Fatalf("should be expired")
	}

	r.ExpirationTime = time.Now().UTC().Add(10 * time.Second)

	if r.IsExpired() {
		t.Fatalf("should not be expired")
	}

}
