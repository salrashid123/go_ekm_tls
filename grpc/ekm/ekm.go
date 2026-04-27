package ekmcredential

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"
)

const ()

type EKMCallback interface {
	EKM(ekm []byte) map[string]string
}

var (
	logger = grpclog.Component("credentials")
)

type Options struct {
	EKMLabel   string
	EKMContext []byte
	EKMLength  int
	Secret     []byte
}

func (o Options) String() string {
	return fmt.Sprintf("%s:%s:%d", o.EKMLabel, o.EKMContext, o.EKMLength)
}

// NewCredentials returns a new PerRPCCredentials implementation, configured
// using opts, which performs token exchange using STS.
func NewCredentials(opts Options) (credentials.PerRPCCredentials, error) {
	if err := validateOptions(opts); err != nil {
		return nil, err
	}

	return &callCreds{
		opts: opts,
	}, nil
}

// callCreds provides the implementation of call credentials based on an STS
// token exchange.
type callCreds struct {
	opts          Options
	tokenMetadata map[string]string
}

// GetRequestMetadata returns the cached accessToken, if available and valid, or
// fetches a new one by performing an STS token exchange.
func (c *callCreds) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	ri, ok := credentials.RequestInfoFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("error getting RequestInfoFromContext")
	}
	if err := credentials.CheckSecurityLevel(ri.AuthInfo, credentials.PrivacyAndIntegrity); err != nil {
		return nil, fmt.Errorf("error validating securitylevel: %v", err)
	}

	tlsInfo, ok := ri.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, fmt.Errorf("error getting TLSInfo")
	}

	ekm, err := tlsInfo.State.ExportKeyingMaterial(c.opts.EKMLabel, c.opts.EKMContext, c.opts.EKMLength)
	if err != nil {
		return nil, fmt.Errorf("unable to get EKM: %v", err)
	}
	logger.Infof("EKM: %s, %s %s\n", c.opts.EKMLabel, c.opts.EKMContext, hex.EncodeToString(ekm))

	//c.opts.EKMCallback <- hex.EncodeToString(ekm)

	mac := hmac.New(sha256.New, c.opts.Secret)
	mac.Write(ekm)
	h := mac.Sum(nil)
	c.tokenMetadata = map[string]string{"Authorization": fmt.Sprintf("Bearer %s", hex.EncodeToString(h))}

	// derive the ekm an apply a new bearer token like
	// https://github.com/salrashid123/tls_tpm_one_time_password
	// for now, i'm just using it as is in the header
	//c.tokenMetadata = map[string]string{"Authorization": fmt.Sprintf("Bearer %s", hex.EncodeToString(ekm))}
	return c.tokenMetadata, nil
}

// RequireTransportSecurity indicates whether the credentials requires
// transport security.
func (c *callCreds) RequireTransportSecurity() bool {
	return true
}

// validateOptions performs the following validation checks on opts:

func validateOptions(opts Options) error {
	return nil
}
