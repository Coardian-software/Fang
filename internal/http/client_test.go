package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientLimitsResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer server.Close()

	client := NewClient(WithMaxResponseBytes(4))
	response, err := client.GetContext(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("GetContext() error = %v", err)
	}
	if got := response.Body; got != "0123" {
		t.Fatalf("Body = %q, want truncated body", got)
	}
	if !response.BodyTruncated {
		t.Fatal("BodyTruncated = false, want true")
	}
}

func TestClientPropagatesCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewClient().GetContext(ctx, server.URL)
	if err == nil {
		t.Fatal("GetContext() error = nil, want cancellation error")
	}
}
