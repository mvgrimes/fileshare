package files

import (
	"context"
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type s3ClientStub struct {
	putInput    *s3.PutObjectInput
	deleteInput *s3.DeleteObjectInput
	putErr      error
	deleteErr   error
}

func (s *s3ClientStub) PutObject(
	_ context.Context,
	params *s3.PutObjectInput,
	_ ...func(*s3.Options),
) (*s3.PutObjectOutput, error) {
	s.putInput = params
	if s.putErr != nil {
		return nil, s.putErr
	}
	return &s3.PutObjectOutput{}, nil
}

func (s *s3ClientStub) DeleteObject(
	_ context.Context,
	params *s3.DeleteObjectInput,
	_ ...func(*s3.Options),
) (*s3.DeleteObjectOutput, error) {
	s.deleteInput = params
	if s.deleteErr != nil {
		return nil, s.deleteErr
	}
	return &s3.DeleteObjectOutput{}, nil
}

type s3PresignStub struct {
	url      string
	err      error
	ttl      time.Duration
	getInput *s3.GetObjectInput
}

func (s *s3PresignStub) PresignGetObject(
	_ context.Context,
	input *s3.GetObjectInput,
	optFns ...func(*s3.PresignOptions),
) (*v4.PresignedHTTPRequest, error) {
	s.getInput = input
	for _, fn := range optFns {
		opts := &s3.PresignOptions{}
		fn(opts)
		s.ttl = opts.Expires
	}
	if s.err != nil {
		return nil, s.err
	}
	return &v4.PresignedHTTPRequest{URL: s.url}, nil
}

func TestNewS3ObjectStoreRequiresRegion(t *testing.T) {
	_, err := NewS3ObjectStore(context.Background(), S3BackendConfig{})
	if !errors.Is(err, ErrS3RegionRequired) {
		t.Fatalf("error = %v, want %v", err, ErrS3RegionRequired)
	}
}

func TestS3ObjectStorePutDeleteAndSign(t *testing.T) {
	client := &s3ClientStub{}
	presign := &s3PresignStub{url: "https://example.test/signed"}
	store := &S3ObjectStore{client: client, presign: presign}

	err := store.PutObject(
		context.Background(),
		"bucket-1",
		"uploads/user/u-1/file.pdf",
		strings.NewReader("bytes"),
		5,
		"application/pdf",
	)
	if err != nil {
		t.Fatalf("PutObject() error = %v", err)
	}
	if client.putInput == nil {
		t.Fatal("expected put input")
	}
	if *client.putInput.Bucket != "bucket-1" ||
		*client.putInput.Key != "uploads/user/u-1/file.pdf" {
		t.Fatalf("put bucket/key = (%q,%q)", *client.putInput.Bucket, *client.putInput.Key)
	}
	body, _ := io.ReadAll(client.putInput.Body)
	if string(body) != "bytes" {
		t.Fatalf("put body = %q, want bytes", string(body))
	}

	err = store.DeleteObject(context.Background(), "bucket-1", "uploads/user/u-1/file.pdf")
	if err != nil {
		t.Fatalf("DeleteObject() error = %v", err)
	}
	if client.deleteInput == nil {
		t.Fatal("expected delete input")
	}

	signed, err := store.SignGetURL(
		context.Background(),
		"bucket-1",
		"uploads/user/u-1/file.pdf",
		"Quarterly Report.pdf",
		3*time.Minute,
	)
	if err != nil {
		t.Fatalf("SignGetURL() error = %v", err)
	}
	if signed != "https://example.test/signed" {
		t.Fatalf("signed = %q", signed)
	}
	if presign.ttl != 3*time.Minute {
		t.Fatalf("ttl = %s, want 3m", presign.ttl)
	}
	if presign.getInput == nil || presign.getInput.ResponseContentDisposition == nil {
		t.Fatal("expected response content disposition")
	}
	if !strings.Contains(*presign.getInput.ResponseContentDisposition, "filename=") {
		t.Fatalf(
			"content disposition = %q, want filename parameter",
			*presign.getInput.ResponseContentDisposition,
		)
	}
}

func TestS3ObjectStoreErrors(t *testing.T) {
	putErr := errors.New("put failed")
	deleteErr := errors.New("delete failed")
	signErr := errors.New("sign failed")
	store := &S3ObjectStore{
		client:  &s3ClientStub{putErr: putErr, deleteErr: deleteErr},
		presign: &s3PresignStub{err: signErr},
	}

	if err := store.PutObject(
		context.Background(),
		"b",
		"k",
		strings.NewReader("x"),
		1,
		"text/plain",
	); err == nil ||
		!strings.Contains(err.Error(), "s3 put object") {
		t.Fatalf("PutObject error = %v", err)
	}
	if err := store.DeleteObject(
		context.Background(),
		"b",
		"k",
	); err == nil ||
		!strings.Contains(err.Error(), "s3 delete object") {
		t.Fatalf("DeleteObject error = %v", err)
	}
	if _, err := store.SignGetURL(
		context.Background(),
		"b",
		"k",
		"k.txt",
		time.Minute,
	); err == nil ||
		!strings.Contains(err.Error(), "s3 sign get url") {
		t.Fatalf("SignGetURL error = %v", err)
	}

	badURLStore := &S3ObjectStore{
		client:  &s3ClientStub{},
		presign: &s3PresignStub{url: "://bad url"},
	}
	if _, err := badURLStore.SignGetURL(
		context.Background(),
		"b",
		"k",
		"k.txt",
		time.Minute,
	); err == nil {
		t.Fatal("expected invalid signed url error")
	}
	if _, err := url.Parse("://bad url"); err == nil {
		t.Fatal("test URL should be invalid")
	}
}
