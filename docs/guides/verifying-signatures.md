# Verifying Webhook Signatures

Learn how to verify that webhooks are actually from Relae and haven't been tampered with.

## Why Verify Signatures?

Webhook signature verification protects against:

- **Spoofed requests**: Attackers pretending to be Relae
- **Replay attacks**: Old webhooks being resent
- **Man-in-the-middle attacks**: Modified webhook payloads
- **Unauthorized access**: Requests from unknown sources

:::danger Always Verify Signatures
Never process webhooks without verifying signatures in production. This is a critical security measure.
:::

## Understanding Relae's Signature

Every webhook forwarded by Relae includes these headers:

```http
Content-Type: application/json
User-Agent: Relae-Webhook-Forwarder/1.0
X-Relae-Event-ID: evt_abc123...
X-Relae-Source: stripe
X-Relae-Timestamp: 1701234567
X-Relae-Signature: t=1701234567,v1=a1b2c3d4e5f6...
```

### Signature Format

The `X-Relae-Signature` header contains:

```
t=<timestamp>,v1=<signature>
```

Where:

- `t`: Unix timestamp when the webhook was forwarded
- `v1`: HMAC-SHA256 signature (hex-encoded)

### How It's Generated

1. Relae creates the signed payload: `{timestamp}.{raw_body}`
2. Computes HMAC-SHA256 using your webhook secret
3. Formats as: `t={timestamp},v1={signature}`

## Getting Your Webhook Secret

1. Go to [Dashboard](https://relaehook.com/dashboard)
2. Click **Account** in the navigation
3. Select the **Webhooks** tab
4. Copy your **Relae Webhook Secret** (starts with `whsec_`)
5. Store it securely in your environment variables:

```bash
export RELAE_WEBHOOK_SECRET="whsec_abc123..."
```

:::warning Keep It Secret
Never commit your webhook secret to version control. Always use environment variables.
:::

## Verification Steps

1. **Extract** the signature and timestamp from `X-Relae-Signature`
2. **Parse** the values: `t` and `v1`
3. **Reconstruct** the signed payload: `{timestamp}.{raw_body}`
4. **Compute** HMAC-SHA256 using your secret
5. **Compare** computed signature with `v1` (constant-time comparison)
6. **Check** timestamp tolerance (optional but recommended)

## Code Examples by Language

### Node.js / Express

#### Relae Node SDK

Relae offers a comprehensive Node SDK that includes signature verification.

- [SDK Documentation →](/api/nodesdk)

#### `Utils.verifyRelaeSignature(body, signature, secret)`

Verify the authenticity of an incoming Relae webhook using HMAC signature verification.

```typescript
import { Utils } from "relae";

const isValid = Utils.verifyRelaeSignature(
  body: string,      // Raw request body as string
  signature: string, // X-Relae-Signature header value
  secret: string     // Your webhook secret
  toleranceSec?: number // Optional: max age in seconds (default 300)
): boolean;
```

**Example with Express:**

```typescript
import express from "express";
import { Utils } from "relae";

const app = express();

app.post(
  "/webhooks/relae",
  express.raw({ type: "application/json" }),
  (req, res) => {
    const signature = req.headers["x-relae-signature"] as string;
    const secret = process.env.RELAE_WEBHOOK_SECRET!;
    const body = req.body.toString();

    if (!Utils.verifyRelaeSignature(body, signature, secret)) {
      return res.status(401).send("Invalid signature");
    }

    const payload = JSON.parse(body);
    console.log("Valid webhook received:", payload);

    res.status(200).send("OK");
  },
);
```

### Python / Flask

```python
import hmac
import hashlib
import time
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

def verify_relae_webhook(payload: str, signature: str, secret: str) -> bool:
    """Verify webhook signature from Relae"""
    # Parse signature: t=timestamp,v1=signature
    parts = signature.split(',')
    sig_dict = dict(part.split('=') for part in parts)

    timestamp = sig_dict.get('t')
    received_sig = sig_dict.get('v1')

    if not timestamp or not received_sig:
        return False

    # Create signed payload
    signed_payload = f"{timestamp}.{payload}"

    # Compute HMAC
    expected_sig = hmac.new(
        secret.encode('utf-8'),
        signed_payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    # Constant-time comparison
    return hmac.compare_digest(expected_sig, received_sig)

@app.route('/webhook', methods=['POST'])
def webhook():
    signature = request.headers.get('X-Relae-Signature')
    payload = request.get_data(as_text=True)
    secret = os.environ['RELAE_WEBHOOK_SECRET']

    # Verify signature
    if not verify_relae_webhook(payload, signature, secret):
        return jsonify({'error': 'Invalid signature'}), 401

    # Optional: Check timestamp tolerance
    timestamp = int(signature.split(',')[0].split('=')[1])
    now = int(time.time())
    tolerance = 300  # 5 minutes

    if abs(now - timestamp) > tolerance:
        return jsonify({'error': 'Timestamp too old'}), 401

    # Access Relae headers
    event_id = request.headers.get('X-Relae-Event-ID')
    source = request.headers.get('X-Relae-Source')

    # Process webhook
    event = request.get_json()
    print(f"Event ID: {event_id}")
    print(f"Source: {source}")
    print(f"Verified webhook: {event}")

    return jsonify({'received': True})

if __name__ == '__main__':
    app.run(port=3000)
```

### Go

```go
package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "strconv"
    "strings"
    "time"
)

func verifyRelaeWebhook(payload, signature, secret string) bool {
    // Parse signature: t=timestamp,v1=signature
    parts := strings.Split(signature, ",")
    var timestamp, sig string

    for _, part := range parts {
        kv := strings.SplitN(part, "=", 2)
        if len(kv) != 2 {
            continue
        }
        if kv[0] == "t" {
            timestamp = kv[1]
        } else if kv[0] == "v1" {
            sig = kv[1]
        }
    }

    if timestamp == "" || sig == "" {
        return false
    }

    // Create signed payload
    signedPayload := fmt.Sprintf("%s.%s", timestamp, payload)

    // Compute HMAC
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write([]byte(signedPayload))
    expectedSig := hex.EncodeToString(mac.Sum(nil))

    // Constant-time comparison
    return subtle.ConstantTimeCompare(
        []byte(sig),
        []byte(expectedSig)
    ) == 1
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
    signature := r.Header.Get("X-Relae-Signature")

    payload, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Failed to read body", 400)
        return
    }

    secret := os.Getenv("RELAE_WEBHOOK_SECRET")

    // Verify signature
    if !verifyRelaeWebhook(string(payload), signature, secret) {
        http.Error(w, "Invalid signature", 401)
        return
    }

    // Optional: Check timestamp tolerance
    parts := strings.Split(signature, ",")
    timestampStr := strings.TrimPrefix(parts[0], "t=")
    timestamp, _ := strconv.ParseInt(timestampStr, 10, 64)
    now := time.Now().Unix()
    tolerance := int64(300) // 5 minutes

    if abs(now-timestamp) > tolerance {
        http.Error(w, "Timestamp too old", 401)
        return
    }

    // Access Relae headers
    eventID := r.Header.Get("X-Relae-Event-ID")
    source := r.Header.Get("X-Relae-Source")

    // Process webhook
    var event map[string]interface{}
    json.Unmarshal(payload, &event)

    fmt.Printf("Event ID: %s\n", eventID)
    fmt.Printf("Source: %s\n", source)
    fmt.Printf("Verified webhook: %v\n", event)

    w.WriteHeader(200)
    json.NewEncoder(w).Encode(map[string]bool{"received": true})
}

func abs(n int64) int64 {
    if n < 0 {
        return -n
    }
    return n
}

func main() {
    http.HandleFunc("/webhook", webhookHandler)
    http.ListenAndServe(":3000", nil)
}
```

### Ruby / Sinatra

```ruby
require 'sinatra'
require 'openssl'
require 'json'

def verify_relae_webhook(payload, signature, secret)
  # Parse signature: t=timestamp,v1=signature
  sig_parts = signature.split(',').map { |p| p.split('=') }.to_h
  timestamp = sig_parts['t']
  received_sig = sig_parts['v1']

  return false if timestamp.nil? || received_sig.nil?

  # Create signed payload
  signed_payload = "#{timestamp}.#{payload}"

  # Compute HMAC
  expected_sig = OpenSSL::HMAC.hexdigest(
    OpenSSL::Digest.new('sha256'),
    secret,
    signed_payload
  )

  # Constant-time comparison
  Rack::Utils.secure_compare(expected_sig, received_sig)
end

post '/webhook' do
  request.body.rewind
  payload = request.body.read
  signature = request.env['HTTP_X_RELAE_SIGNATURE']
  secret = ENV['RELAE_WEBHOOK_SECRET']

  # Verify signature
  unless verify_relae_webhook(payload, signature, secret)
    halt 401, { error: 'Invalid signature' }.to_json
  end

  # Optional: Check timestamp tolerance
  timestamp = signature.split(',')[0].split('=')[1].to_i
  now = Time.now.to_i
  tolerance = 300 # 5 minutes

  if (now - timestamp).abs > tolerance
    halt 401, { error: 'Timestamp too old' }.to_json
  end

  # Access Relae headers
  event_id = request.env['HTTP_X_RELAE_EVENT_ID']
  source = request.env['HTTP_X_RELAE_SOURCE']

  # Process webhook
  event = JSON.parse(payload)
  puts "Event ID: #{event_id}"
  puts "Source: #{source}"
  puts "Verified webhook: #{event}"

  { received: true }.to_json
end
```

### PHP

```php
<?php
function verifyRelaeWebhook($payload, $signature, $secret) {
    // Parse signature: t=timestamp,v1=signature
    $parts = explode(',', $signature);
    $timestamp = null;
    $sig = null;

    foreach ($parts as $part) {
        list($key, $value) = explode('=', $part, 2);
        if ($key === 't') {
            $timestamp = $value;
        } elseif ($key === 'v1') {
            $sig = $value;
        }
    }

    if (!$timestamp || !$sig) {
        return false;
    }

    // Create signed payload
    $signedPayload = $timestamp . '.' . $payload;

    // Compute HMAC
    $expectedSig = hash_hmac('sha256', $signedPayload, $secret);

    // Constant-time comparison
    return hash_equals($expectedSig, $sig);
}

// Get request data
$payload = file_get_contents('php://input');
$signature = $_SERVER['HTTP_X_RELAE_SIGNATURE'] ?? '';
$secret = getenv('RELAE_WEBHOOK_SECRET');

// Verify signature
if (!verifyRelaeWebhook($payload, $signature, $secret)) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid signature']);
    exit;
}

// Optional: Check timestamp tolerance
$parts = explode(',', $signature);
$timestamp = (int)explode('=', $parts[0])[1];
$now = time();
$tolerance = 300; // 5 minutes

if (abs($now - $timestamp) > $tolerance) {
    http_response_code(401);
    echo json_encode(['error' => 'Timestamp too old']);
    exit;
}

// Access Relae headers
$eventId = $_SERVER['HTTP_X_RELAE_EVENT_ID'] ?? '';
$source = $_SERVER['HTTP_X_RELAE_SOURCE'] ?? '';

// Process webhook
$event = json_decode($payload, true);
error_log("Event ID: $eventId");
error_log("Source: $source");
error_log('Verified webhook: ' . print_r($event, true));

http_response_code(200);
echo json_encode(['received' => true]);
?>
```

## Additional Security Measures

### 1. Timestamp Tolerance

Always check that the timestamp is recent to prevent replay attacks:

```javascript
const TOLERANCE_SECONDS = 300; // 5 minutes
const timestamp = parseInt(signature.split(",")[0].split("=")[1]);
const now = Math.floor(Date.now() / 1000);

if (Math.abs(now - timestamp) > TOLERANCE_SECONDS) {
  return res.status(401).send("Timestamp too old");
}
```

### 2. Idempotency

Store processed event IDs to prevent duplicate processing:

```javascript
const eventId = req.headers["x-relae-event-id"];

// Check if already processed
if (await isEventProcessed(eventId)) {
  return res.status(200).send("Already processed");
}

// Process event
await processWebhook(event);

// Mark as processed
await markEventProcessed(eventId);
```

### 3. IP Allowlisting (Optional)

For additional security, you can allowlist Relae's IP addresses. Contact support for the current IP ranges.

## Testing Signature Verification

### Using cURL

```bash
# Get your webhook secret from dashboard
SECRET="whsec_abc123..."

# Current timestamp
TIMESTAMP=$(date +%s)

# Payload
PAYLOAD='{"test": true, "event": "payment.succeeded"}'

# Compute signature
SIGNATURE=$(echo -n "${TIMESTAMP}.${PAYLOAD}" | \
  openssl dgst -sha256 -hmac "${SECRET}" | \
  sed 's/^.* //')

# Send test webhook
curl -X POST http://localhost:3000/webhook \
  -H "Content-Type: application/json" \
  -H "X-Relae-Signature: t=${TIMESTAMP},v1=${SIGNATURE}" \
  -H "X-Relae-Event-ID: evt_test_123" \
  -H "X-Relae-Source: test" \
  -H "X-Relae-Timestamp: ${TIMESTAMP}" \
  -H "User-Agent: Relae-Webhook-Forwarder/1.0" \
  -d "${PAYLOAD}"
```

### Unit Test Example (Node.js)

```javascript
const assert = require("assert");
const crypto = require("crypto");

function createTestSignature(payload, secret) {
  const timestamp = Math.floor(Date.now() / 1000);
  const signedPayload = `${timestamp}.${payload}`;
  const signature = crypto
    .createHmac("sha256", secret)
    .update(signedPayload)
    .digest("hex");
  return `t=${timestamp},v1=${signature}`;
}

// Test valid signature
const secret = "whsec_test_secret";
const payload = JSON.stringify({ test: true });
const signature = createTestSignature(payload, secret);

assert.strictEqual(
  verifyRelaeWebhook(payload, signature, secret),
  true,
  "Valid signature should pass",
);

// Test invalid signature
assert.strictEqual(
  verifyRelaeWebhook(payload, "t=123,v1=invalid", secret),
  false,
  "Invalid signature should fail",
);

console.log("All tests passed!");
```

## Troubleshooting

### Signature Verification Failing

**Check these common issues:**

1. **Wrong secret**: Make sure you're using the Relae webhook secret (starts with `whsec_`), not the vendor's secret
2. **Body modification**: Don't parse or modify the body before verification
3. **Wrong encoding**: Use the raw body as a string, not parsed JSON
4. **Incorrect format**: Signature is `t=timestamp,v1=signature`, not `sha256=...`
5. **Timing issues**: Timestamp might be outside your tolerance window

**Debug steps:**

```javascript
// Log everything for debugging
console.log("Received signature:", signature);
console.log("Raw payload:", payload);
console.log("Secret (first 10 chars):", secret.substring(0, 10));

// Parse signature
const parts = signature.split(",");
const timestamp = parts[0].split("=")[1];
const receivedSig = parts[1].split("=")[1];

console.log("Timestamp:", timestamp);
console.log("Received sig:", receivedSig);

// Compute expected
const signedPayload = `${timestamp}.${payload}`;
const expectedSig = crypto
  .createHmac("sha256", secret)
  .update(signedPayload)
  .digest("hex");

console.log("Signed payload:", signedPayload);
console.log("Expected sig:", expectedSig);
console.log("Match:", receivedSig === expectedSig);
```

### Getting "Timestamp too old" Error

This happens when:

- Your server's clock is out of sync
- The webhook was delayed in transit
- Your tolerance window is too strict

**Solutions:**

- Increase tolerance to 10-15 minutes for development
- Sync your server clock with NTP
- Check for network delays

## Best Practices

1. ✅ **Always verify signatures in production**
2. ✅ **Use environment variables for secrets**
3. ✅ **Implement timestamp tolerance checks**
4. ✅ **Use constant-time comparison functions**
5. ✅ **Log verification failures for monitoring**
6. ✅ **Store the Relae webhook secret separately from vendor secrets**
7. ✅ **Implement idempotency using X-Relae-Event-ID**
8. ✅ **Return 200 OK only after successful verification**

## Next Steps

- [Managing Webhooks →](/guides/managing-webhooks)
- [Dead Letter Queue →](/guides/dead-letter-queue)
- [SDK Documentation →](/api/nodesdk)

## Need Help?

- 📧 Email: [support@relaehook.com](mailto:support@relaehook.com)
- 💬 Check signature verification in your language
- 🐛 Report issues on [GitHub](https://github.com/WillBallentine/relae-docs/issues)
