// Package notify pushes a short message to a Slack/Discord-style incoming webhook.
// The webhook is a third-party service, not the target, so it is not scope-gated.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Send posts text to webhook. The payload carries both "text" (Slack) and
// "content" (Discord) so one call fits either.
func Send(ctx context.Context, webhook, text string) error {
	body, _ := json.Marshal(map[string]string{"text": text, "content": text})
	req, err := http.NewRequestWithContext(ctx, "POST", webhook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}
