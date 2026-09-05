package collaborator

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPayloadAndPathHit(t *testing.T) {
	s := NewServer("http://oob.test")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	token, _ := s.Payload()
	if s.Hit(token) {
		t.Fatal("no interaction yet")
	}
	// simulate a target fetching the path-form payload
	resp, err := http.Get(srv.URL + "/" + token)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if !s.Hit(token) {
		t.Fatal("path interaction not recorded")
	}
	got := s.Interactions(token)
	if len(got) != 1 || got[0].Path != "/"+token {
		t.Fatalf("interaction wrong: %+v", got)
	}
}

func TestNoTokenNoRecord(t *testing.T) {
	s := NewServer("http://oob.test")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	http.Get(srv.URL + "/favicon.ico")
	if len(s.Interactions("favicon")) != 0 {
		t.Fatal("non-token path should not record")
	}
}
