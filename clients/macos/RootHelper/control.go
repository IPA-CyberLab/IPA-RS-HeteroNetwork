package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"
)

const controlSocketPath = "/var/run/heteronetwork-client/control.sock"

type controlRequest struct {
	Action        string               `json:"action"`
	Configuration *tunnelConfiguration `json:"configuration,omitempty"`
}

type controlResponse struct {
	OK        bool   `json:"ok"`
	Status    string `json:"status"`
	Interface string `json:"interface,omitempty"`
	Gateway   string `json:"gateway,omitempty"`
	PID       int    `json:"pid,omitempty"`
	Error     string `json:"error,omitempty"`
}

func requestControl(request controlRequest) (controlResponse, error) {
	var response controlResponse
	connection, err := net.DialTimeout("unix", controlSocketPath, 2*time.Second)
	if err != nil {
		return response, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	encoder := json.NewEncoder(connection)
	if err := encoder.Encode(request); err != nil {
		return response, fmt.Errorf("send control request: %w", err)
	}
	decoder := json.NewDecoder(io.LimitReader(connection, maximumConfigurationBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return response, fmt.Errorf("read control response: %w", err)
	}
	if !response.OK {
		if response.Error == "" {
			response.Error = "root helper rejected the request"
		}
		return response, errors.New(response.Error)
	}
	return response, nil
}

func disconnectedResponseFor(err error) (controlResponse, bool) {
	if err == nil {
		return controlResponse{}, false
	}
	if os.IsNotExist(err) || errors.Is(err, syscall.ECONNREFUSED) {
		return controlResponse{OK: true, Status: "disconnected"}, true
	}
	var operationError *net.OpError
	if errors.As(err, &operationError) &&
		(os.IsNotExist(operationError.Err) || errors.Is(operationError.Err, syscall.ECONNREFUSED)) {
		return controlResponse{OK: true, Status: "disconnected"}, true
	}
	return controlResponse{}, false
}

func encodeResponse(response controlResponse) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(response)
}

func decodeControlRequest(connection net.Conn) (controlRequest, error) {
	var request controlRequest
	reader := bufio.NewReader(io.LimitReader(connection, maximumConfigurationBytes+1))
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return request, err
	}
	if len(line) > maximumConfigurationBytes {
		return request, errors.New("control request is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, err
	}
	return request, nil
}
