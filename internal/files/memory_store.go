package files

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"sync"
	"time"
)

type MemoryObjectStore struct {
	mu      sync.RWMutex
	objects map[string][]byte
}

func NewMemoryObjectStore() *MemoryObjectStore {
	return &MemoryObjectStore{objects: map[string][]byte{}}
}

func (m *MemoryObjectStore) PutObject(_ context.Context, bucket, key string, body io.Reader, _ int64, _ string) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("read object body: %w", err)
	}
	m.mu.Lock()
	m.objects[bucket+"/"+key] = data
	m.mu.Unlock()
	return nil
}

func (m *MemoryObjectStore) DeleteObject(_ context.Context, bucket, key string) error {
	m.mu.Lock()
	delete(m.objects, bucket+"/"+key)
	m.mu.Unlock()
	return nil
}

func (m *MemoryObjectStore) SignGetURL(_ context.Context, bucket, objectKey, downloadFilename string, ttl time.Duration) (string, error) {
	q := url.Values{}
	q.Set("ttl", ttl.String())
	if downloadFilename != "" {
		q.Set("filename", downloadFilename)
	}
	return "https://example.invalid/" + url.PathEscape(bucket) + "/" + url.PathEscape(objectKey) + "?" + q.Encode(), nil
}
