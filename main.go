// Copyright (c) 2025 Edoardo Spadolini
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	defer context.AfterFunc(ctx, cancel)()

	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	var destination string
	flag.StringVar(&destination, "destination", "https://console.aws.amazon.com", "destination URL after login")
	var sessionDuration time.Duration
	flag.DurationVar(&sessionDuration, "session-duration", 12*time.Hour, "session duration")
	flag.Parse()

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("loading default AWS config: %w", err)
	}

	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("retrieving credentials: %w", err)
	}

	hc := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer hc.CloseIdleConnections()

	req := &http.Request{
		Method: http.MethodPost,
		URL:    buildGetSigninTokenURL(creds, sessionDuration),
	}
	resp, err := hc.Do(req.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("getSigninToken: %w", err)
	}
	resp.Body = http.MaxBytesReader(nil, resp.Body, 128*1024)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("getSigninToken status %v: %q", resp.Status, msg)
	}
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading getSigninToken response: %w", err)
	}

	var getSigninTokenResponse struct {
		SigninToken string `json:"SigninToken"`
	}
	if err := json.Unmarshal(respData, &getSigninTokenResponse); err != nil {
		return fmt.Errorf("unmarshaling getSigninToken response: %w", err)
	}

	loginURL := buildLoginURL(destination, getSigninTokenResponse.SigninToken)

	switch runtime.GOOS {
	case "darwin":
		//#nosec G204 -- there's no possible command injection here
		err = syscall.Exec("/usr/bin/open", []string{"/usr/bin/open", "-u", loginURL.String()}, os.Environ())
		fmt.Println(loginURL.String())
		return fmt.Errorf("opening browser: %w", err)
	case "linux":
		xdgOpen, err := exec.LookPath("xdg-open")
		if err == nil {
			err = syscall.Exec(xdgOpen, []string{xdgOpen, loginURL.String()}, os.Environ())
		}
		fmt.Println(loginURL.String())
		return fmt.Errorf("opening browser: %w", err)
	default:
		fmt.Println(loginURL.String())
		return nil
	}
}

func buildGetSigninTokenURL(creds aws.Credentials, sessionDuration time.Duration) *url.URL {
	type getSigninTokenSession struct {
		SessionID    string `json:"sessionId"`
		SessionKey   string `json:"sessionKey"`
		SessionToken string `json:"sessionToken,omitempty"`
	}
	session, err := json.Marshal(getSigninTokenSession{
		SessionID:    creds.AccessKeyID,
		SessionKey:   creds.SecretAccessKey,
		SessionToken: creds.SessionToken,
	})
	if err != nil {
		panic(err)
	}

	q := make(url.Values)
	q.Set("Action", "getSigninToken")
	q.Set("Session", string(session))
	q.Set("SessionDuration", strconv.FormatInt(int64(sessionDuration/time.Second), 10))
	return &url.URL{
		Scheme:   "https",
		Host:     "signin.aws.amazon.com",
		Path:     "/federation",
		RawQuery: q.Encode(),
	}
}

func buildLoginURL(destination string, signinToken string) *url.URL {
	q := make(url.Values)
	q.Set("Action", "login")
	q.Set("Destination", destination)
	q.Set("SigninToken", signinToken)
	return &url.URL{
		Scheme:   "https",
		Host:     "signin.aws.amazon.com",
		Path:     "/federation",
		RawQuery: q.Encode(),
	}
}
