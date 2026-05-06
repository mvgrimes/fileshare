package files

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"

	"fileshare/internal/auth"
)

var ErrBucketRequired = errors.New("bucket is required")

type ObjectStore interface {
	PutObject(ctx context.Context, bucket, key string, body io.Reader, size int64, contentType string) error
}

type ObjectDeleteStore interface {
	DeleteObject(ctx context.Context, bucket, key string) error
}

type UploadService struct {
	bucket   string
	store    ObjectStore
	metadata *MetadataService
	now      func() time.Time
}

type UploadInput struct {
	Uploader         auth.Principal
	OriginalFilename string
	ContentType      string
	SizeBytes        int64
	ExpiresAt        *time.Time
	Body             io.Reader
}

func NewUploadService(bucket string, store ObjectStore, metadata *MetadataService) (*UploadService, error) {
	if strings.TrimSpace(bucket) == "" {
		return nil, ErrBucketRequired
	}
	return &UploadService{
		bucket:   strings.TrimSpace(bucket),
		store:    store,
		metadata: metadata,
		now:      time.Now,
	}, nil
}

func (s *UploadService) Upload(ctx context.Context, input UploadInput) (string, string, error) {
	if input.Body == nil {
		return "", "", errors.New("upload body is required")
	}
	objectKey := s.buildObjectKey(input.Uploader, input.OriginalFilename)

	if err := s.store.PutObject(ctx, s.bucket, objectKey, input.Body, input.SizeBytes, input.ContentType); err != nil {
		return "", "", fmt.Errorf("put object: %w", err)
	}

	fileID, err := s.metadata.CreateFileMetadata(ctx, CreateMetadataInput{
		Uploader:         input.Uploader,
		OriginalFilename: input.OriginalFilename,
		StorageKey:       objectKey,
		ContentType:      input.ContentType,
		SizeBytes:        input.SizeBytes,
		ExpiresAt:        input.ExpiresAt,
	})
	if err != nil {
		if deleteStore, ok := s.store.(ObjectDeleteStore); ok {
			_ = deleteStore.DeleteObject(ctx, s.bucket, objectKey)
		}
		return "", "", fmt.Errorf("persist metadata: %w", err)
	}

	return fileID, objectKey, nil
}

func (s *UploadService) buildObjectKey(uploader auth.Principal, filename string) string {
	ext := path.Ext(strings.TrimSpace(filename))
	date := s.now().UTC().Format("20060102")
	return fmt.Sprintf("uploads/%s/%s/%s%s", uploader.ActorType, uploader.ActorID, date+"-"+uuid.NewString(), ext)
}
