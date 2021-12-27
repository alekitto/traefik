package serverless

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
)

func TestInvoke(t *testing.T) {
	mockserver := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "POST", req.Method)
		assert.Equal(t, "/2015-03-31/functions/arn%3Aaws%3Alambda%3Aeu-west-1%3A000000000000%3Afunction%3Axxx%3A1/invocations", req.URL.RawPath)

		var buf bytes.Buffer
		_, err := io.Copy(&buf, req.Body)
		if err != nil {
			t.Fatal(err)
		}

		var lReq LambdaRequest
		err = json.Unmarshal(buf.Bytes(), &lReq)
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, "POST", lReq.HTTPMethod)
		assert.Equal(t, "/this/path/is/not/empty", lReq.Path)
		assert.Equal(t, map[string]string{"a": "1", "b": "2"}, lReq.QueryStringParameters)
		assert.Equal(t, map[string][]string{"a": {"1"}, "b": {"2"}, "c": {"3", "4"}, "d[]": {"5", "6"}}, lReq.MultiValueQueryStringParameters)
		assert.Equal(t, map[string]string{"Content-Type": "text/plain"}, lReq.Headers)
		assert.Equal(t, map[string][]string{"Content-Type": {"text/plain"}, "X-Test": {"foo", "foobar"}}, lReq.MultiValueHeaders)

		res.WriteHeader(200)
		_, err = res.Write([]byte("{\"statusCode\": 500}"))
		if err != nil {
			t.Fatal(err)
		}
	}))
	defer func() { mockserver.Close() }()

	ctx := context.Background()

	handler, err := NewInvoker(&dynamic.Serverless{
		AWSRegion:            "eu-west-1",
		AWSAccessKey:         "aws-key",
		AWSSecretKey:         "@@not-a-key",
		AWSEndpoint:          mockserver.URL,
		AWSLambdaFunctionArn: "arn:aws:lambda:eu-west-1:000000000000:function:xxx:1",
	})
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	var buf bytes.Buffer
	buf.WriteString("This is the body")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/this/path/is/not/empty?a=1&b=2&c=3&c=4&d[]=5&d[]=6", &buf)
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Add("X-Test", "foo")
	req.Header.Add("X-Test", "foobar")
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)
}
