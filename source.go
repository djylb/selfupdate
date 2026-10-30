package selfupdate

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Source finds the signed manifest of a product. Implement it to discover
// releases any way you like (an API, a database, a peer); the manifest it
// returns is verified by the [Updater], so a Source need not be trusted.
type Source interface {
	// Fetch returns the signed manifest document. Base, when non-nil, is
	// the URL relative artifact URLs are resolved against.
	Fetch(ctx context.Context) (Fetched, error)
}

// Fetched is what a [Source] returns.
type Fetched struct {
	// Base resolves relative artifact URLs; nil leaves them unresolved.
	Base *url.URL
	// Data is the signed manifest as produced by [SignManifest].
	Data []byte
}

// HTTPSource fetches a manifest from a fixed URL, such as a manifest.json
// placed in a static directory next to the artifacts it lists by relative
// URL.
type HTTPSource struct {
	// Client sends the request; nil means [http.DefaultClient].
	Client *http.Client
	// URL locates the manifest.
	URL string
	// MaxSize bounds the manifest size. Zero means 1 MiB.
	MaxSize int64
}

// Fetch implements [Source]. The final URL after redirects is the base.
func (s *HTTPSource) Fetch(ctx context.Context) (Fetched, error) {
	limit := s.MaxSize
	if limit <= 0 {
		limit = 1 << 20
	}
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return Fetched{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return Fetched{}, err
	}
	defer closeQuietly(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return Fetched{}, fmt.Errorf("%w: %s from %s", ErrHTTPStatus, resp.Status, req.URL.Redacted())
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return Fetched{}, err
	}
	if int64(len(data)) > limit {
		return Fetched{}, fmt.Errorf("%w: manifest larger than %d bytes", ErrTooLarge, limit)
	}
	return Fetched{Base: resp.Request.URL, Data: data}, nil
}
