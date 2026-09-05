package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSend(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	if err := Send(context.Background(), srv.URL, "2 new findings"); err != nil {
		t.Fatal(err)
	}
	if got["text"] != "2 new findings" || got["content"] != "2 new findings" {
		t.Fatalf("payload wrong: %+v", got)
	}
}

func TestSendBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	if err := Send(context.Background(), srv.URL, "x"); err == nil {
		t.Fatal("expected error on 500")
	}
}
