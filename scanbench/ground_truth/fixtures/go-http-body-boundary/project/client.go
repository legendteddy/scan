package client

import (
    "context"
    "fmt"
    "io"
    "net/http"
)

func Fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil {
        return nil, err
    }
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    if resp.StatusCode >= 400 {
        return nil, fmt.Errorf("remote status: %s", resp.Status)
    }
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    return body, nil
}
