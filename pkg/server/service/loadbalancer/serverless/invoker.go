package serverless

import (
	"errors"
	"net/http"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
)

// NewInvoker creates a http handler object based on given serverless configuration.
func NewInvoker(config *dynamic.Serverless) (http.Handler, error) {
	if config.AWSLambdaFunctionArn != "" {
		sess := session.Must(session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
		}))

		var region *string
		if config.AWSRegion != "" {
			region = aws.String(config.AWSRegion)
		}

		var endpoint *string
		if config.AWSEndpoint != "" {
			endpoint = aws.String(config.AWSEndpoint)
		}

		var creds *credentials.Credentials
		if config.AWSAccessKey != "" && config.AWSSecretKey != "" {
			creds = credentials.NewStaticCredentials(config.AWSAccessKey, config.AWSSecretKey, "")
		}

		client := lambda.New(sess, &aws.Config{
			Region:      region,
			Endpoint:    endpoint,
			Credentials: creds,
		})

		return AWSLambdaInvoker{
			Client:      client,
			FunctionArn: config.AWSLambdaFunctionArn,
		}, nil
	}

	return nil, errors.New("unknown or invalid serverless configuration")
}
