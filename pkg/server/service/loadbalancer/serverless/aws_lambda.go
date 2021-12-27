package serverless

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
)

// AWSLambdaInvoker will invoke associated lambda function to handle http request.
type AWSLambdaInvoker struct {
	http.Handler

	Client      *lambda.Lambda
	FunctionArn string
}

// LambdaContextIdentity holds the request source ip.
type LambdaContextIdentity struct {
	SourceIP string `json:"sourceIp"`
}

// LambdaRequestContext holds context information for the current request.
type LambdaRequestContext struct {
	RequestTimeEpoch int64                 `json:"requestTimeEpoch"`
	Identity         LambdaContextIdentity `json:"identity"`
}

// LambdaRequest represents a request to send to lambda.
type LambdaRequest struct {
	RequestContext                  LambdaRequestContext `json:"requestContext"`
	HTTPMethod                      string               `json:"httpMethod"`
	Path                            string               `json:"path"`
	QueryStringParameters           map[string]string    `json:"queryStringParameters"`
	MultiValueQueryStringParameters map[string][]string  `json:"multiValueQueryStringParameters"`
	MultiValueHeaders               map[string][]string  `json:"multiValueHeaders"`
	Headers                         map[string]string    `json:"headers"`
	Body                            string               `json:"body"`
	IsBase64Encoded                 bool                 `json:"isBase64Encoded"`
}

// LambdaResponse represents a response to a lambda HTTP request from LB.
type LambdaResponse struct {
	StatusCode        int                 `json:"statusCode"`
	StatusDescription string              `json:"statusDescription"`
	IsBase64Encoded   bool                `json:"isBase64Encoded"`
	Headers           map[string]string   `json:"headers"`
	MultiValueHeaders map[string][]string `json:"multiValueHeaders"`
	Body              string              `json:"body"`
	ErrorType         string              `json:"errorType"`
	ErrorMessage      string              `json:"errorMessage"`
}

func (i AWSLambdaInvoker) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	trace := httptrace.ContextClientTrace(req.Context())
	base64Encoded, body, err := bodyToBase64(req)
	if err != nil {
		http.Error(rw, fmt.Sprintf("%s: error while reading request body %v", http.StatusText(http.StatusInternalServerError), err), http.StatusInternalServerError)
		return
	}

	resp, err := i.invokeFunction(LambdaRequest{
		RequestContext: LambdaRequestContext{
			RequestTimeEpoch: time.Now().Unix(),
			Identity: LambdaContextIdentity{
				SourceIP: strings.Split(req.RemoteAddr, ":")[0],
			},
		},
		HTTPMethod:                      req.Method,
		Path:                            req.URL.Path,
		QueryStringParameters:           valuesToMap(req.URL.Query()),
		MultiValueQueryStringParameters: valuesToMultiMap(req.URL.Query()),
		Headers:                         headersToMap(req.Header),
		MultiValueHeaders:               headersToMultiMap(req.Header),
		Body:                            body,
		IsBase64Encoded:                 base64Encoded,
	})

	if trace != nil {
		trace.WroteHeaders()
		trace.WroteRequest(httptrace.WroteRequestInfo{Err: err})
	}

	if err != nil {
		http.Error(rw, fmt.Sprintf("%s: error invoking lambda function %v", http.StatusText(http.StatusInternalServerError), err), http.StatusInternalServerError)
		return
	}

	body = resp.Body
	var bodyBytes []byte
	if resp.IsBase64Encoded {
		buf, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			http.Error(rw, fmt.Sprintf("%s: error decoding lambda response %v", http.StatusText(http.StatusInternalServerError), err), http.StatusInternalServerError)
			return
		}

		bodyBytes = buf
	} else {
		bodyBytes = []byte(body)
	}

	for key, value := range resp.Headers {
		rw.Header().Set(key, value)
	}

	for key, values := range resp.MultiValueHeaders {
		for _, value := range values {
			rw.Header().Add(key, value)
		}
	}

	rw.WriteHeader(resp.StatusCode)
	_, err = rw.Write(bodyBytes)
	if err != nil {
		http.Error(rw, fmt.Sprintf("%s: error writing response %v", http.StatusText(http.StatusInternalServerError), err), http.StatusInternalServerError)
	}
}

func bodyToBase64(req *http.Request) (bool, string, error) {
	base64Encoded := false
	body := ""
	if req.ContentLength != 0 {
		var buf bytes.Buffer
		encoder := base64.NewEncoder(base64.StdEncoding, &buf)

		_, err := io.Copy(encoder, req.Body)
		if err != nil {
			return false, "", err
		}

		err = encoder.Close()
		if err != nil {
			return false, "", err
		}

		body = buf.String()
		base64Encoded = true
	}

	return base64Encoded, body, nil
}

func (i *AWSLambdaInvoker) invokeFunction(request LambdaRequest) (*LambdaResponse, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	result, err := i.Client.Invoke(&lambda.InvokeInput{
		FunctionName: aws.String(i.FunctionArn),
		Payload:      payload,
	})
	if err != nil {
		return nil, err
	}

	if *result.StatusCode != 200 {
		return nil, errors.New("call to lambda failed")
	}

	var resp LambdaResponse
	err = json.Unmarshal(result.Payload, &resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 0 {
		return nil, errors.New("invalid response from lambda: status code is missing or 0")
	}

	if resp.ErrorType != "" {
		return nil, fmt.Errorf("%s: %s", resp.ErrorType, resp.ErrorMessage)
	}

	return &resp, nil
}

func headersToMap(h http.Header) map[string]string {
	values := map[string]string{}
	for name, headers := range h {
		if len(headers) != 1 {
			continue
		}

		values[name] = headers[0]
	}

	return values
}

func headersToMultiMap(h http.Header) map[string][]string {
	values := map[string][]string{}
	for name, headers := range h {
		if len(headers) == 0 {
			continue
		}

		values[name] = headers
	}

	return values
}

func valueToString(f interface{}) (string, bool) {
	var v string
	typeof := reflect.TypeOf(f)
	s := reflect.ValueOf(f)

	switch typeof.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v = strconv.FormatInt(s.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v = strconv.FormatUint(s.Uint(), 10)
	case reflect.Float32:
		v = strconv.FormatFloat(s.Float(), 'f', 4, 32)
	case reflect.Float64:
		v = strconv.FormatFloat(s.Float(), 'f', 4, 64)
	case reflect.String:
		v = s.String()
	case reflect.Slice:
		t, valid := valuesToStrings(f)
		if !valid || len(t) != 1 {
			return "", false
		}

		v = t[0]
	default:
		return "", false
	}

	return v, true
}

func valuesToStrings(f interface{}) ([]string, bool) {
	typeof := reflect.TypeOf(f)
	if typeof.Kind() != reflect.Slice {
		return []string{}, false
	}

	var v []string
	switch typeof.Elem().Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32,
		reflect.Float32, reflect.Float64, reflect.String:
		s := reflect.ValueOf(f)

		for i := 0; i < s.Len(); i++ {
			conv, valid := valueToString(s.Index(i).Interface())
			if !valid {
				continue
			}

			v = append(v, conv)
		}
	default:
		return []string{}, false
	}

	return v, true
}

func valuesToMap(i url.Values) map[string]string {
	values := map[string]string{}
	for name, val := range i {
		value, valid := valueToString(val)
		if !valid {
			continue
		}

		values[name] = value
	}

	return values
}

func valuesToMultiMap(i url.Values) map[string][]string {
	values := map[string][]string{}
	for name, val := range i {
		value, valid := valuesToStrings(val)
		if !valid {
			continue
		}

		values[name] = value
	}

	return values
}
