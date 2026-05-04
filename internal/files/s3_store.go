package files

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/url"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

var ErrS3RegionRequired = errors.New("s3 region is required")

type S3BackendConfig struct {
	Region          string
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	UsePathStyle    bool
}

type s3PutDeleteClient interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

type s3PresignClient interface {
	PresignGetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}

type S3ObjectStore struct {
	client      s3PutDeleteClient
	presign     s3PresignClient
	contentType string
}

func NewS3ObjectStore(ctx context.Context, cfg S3BackendConfig) (*S3ObjectStore, error) {
	if strings.TrimSpace(cfg.Region) == "" {
		return nil, ErrS3RegionRequired
	}

	loadOpts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(strings.TrimSpace(cfg.Region))}
	if strings.TrimSpace(cfg.AccessKeyID) != "" || strings.TrimSpace(cfg.SecretAccessKey) != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(strings.TrimSpace(cfg.AccessKeyID), strings.TrimSpace(cfg.SecretAccessKey), strings.TrimSpace(cfg.SessionToken))))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(options *s3.Options) {
		options.UsePathStyle = cfg.UsePathStyle
		endpoint := strings.TrimSpace(cfg.Endpoint)
		if endpoint == "" {
			return
		}
		options.BaseEndpoint = &endpoint
	})

	return &S3ObjectStore{client: client, presign: s3.NewPresignClient(client)}, nil
}

func (s *S3ObjectStore) PutObject(ctx context.Context, bucket, key string, body io.Reader, size int64, contentType string) error {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        &bucket,
		Key:           &key,
		Body:          body,
		ContentLength: &size,
		ContentType:   &contentType,
	})
	if err != nil {
		return fmt.Errorf("s3 put object: %w", err)
	}
	return nil
}

func (s *S3ObjectStore) DeleteObject(ctx context.Context, bucket, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		return fmt.Errorf("s3 delete object: %w", err)
	}
	return nil
}

func (s *S3ObjectStore) SignGetURL(ctx context.Context, bucket, objectKey, downloadFilename string, ttl time.Duration) (string, error) {
	input := &s3.GetObjectInput{Bucket: &bucket, Key: &objectKey}
	if strings.TrimSpace(downloadFilename) != "" {
		disposition := mime.FormatMediaType("attachment", map[string]string{"filename": strings.TrimSpace(downloadFilename)})
		input.ResponseContentDisposition = &disposition
	}
	out, err := s.presign.PresignGetObject(ctx, input, func(options *s3.PresignOptions) {
		options.Expires = ttl
	})
	if err != nil {
		return "", fmt.Errorf("s3 sign get url: %w", err)
	}
	if _, parseErr := url.Parse(out.URL); parseErr != nil {
		return "", fmt.Errorf("invalid signed url: %w", parseErr)
	}
	return out.URL, nil
}
