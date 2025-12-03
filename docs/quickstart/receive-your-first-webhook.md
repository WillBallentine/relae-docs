# Receive Your First Webhook

Now that your account and destination are configured, let's send your first webhook through Relae!

## Overview

In this guide, you'll:

1. Configure your vendor to send webhooks to Relae
2. Trigger a test webhook event
3. View the event in your Relae dashboard
4. Verify the webhook was forwarded to your application
5. Validate the HMAC signature (recommended)

## Step 1: Configure Your Vendor

You need to tell your vendor (Stripe, Shopify, GitHub, etc.) to send webhooks to your Relae endpoint URL instead of directly to your application.

### General Steps (All Vendors)

1. Log in to your vendor's dashboard
2. Navigate to webhook or API settings
3. Create a new webhook endpoint
4. Paste your Relae endpoint URL: `https://api.relaehook.com/webhook/{your-unique-id}`
5. Select the events you want to receive
6. Save the webhook configuration

### Vendor-Specific Guides

<details>
<summary><b>Stripe</b></summary>

1. Go to [Stripe Dashboard](https://dashboard.stripe.com)
2. Navigate to **Developers** → **Webhooks**
3. Click **"Add endpoint"**
4. Enter your Relae URL: `https://api.relaehook.com/webhook/{your-id}`
5. Select events to listen to (e.g., `payment_intent.succeeded`)
6. Click **"Add endpoint"**
7. Copy the **Signing secret** (starts with `whsec_`)
8. Go back to Relae → Destinations → Edit your Stripe destination
9. Paste the signing secret in **"Vendor Webhook Secret"**
10. Save

</details>

<details>
<summary><b>Shopify</b></summary>

1. Go to your Shopify Admin
2. Navigate to **Settings** → **Notifications**
3. Scroll to **Webhooks** section
4. Click **"Create webhook"**
5. Select an event (e.g., `Order creation`)
6. Set Format to **JSON**
7. Enter your Relae URL: `https://api.relaehook.com/webhook/{your-id}`
8. Click **"Save webhook"**
9. Note: Shopify doesn't show the signing secret directly - it's in the `X-Shopify-Hmac-Sha256` header

</details>

<details>
<summary><b>GitHub</b></summary>

1. Go to your GitHub repository
2. Navigate to **Settings** → **Webhooks**
3. Click **"Add webhook"**
4. Payload URL: `https://api.relaehook.com/webhook/{your-id}`
5. Content type: `application/json`
6. Secret: Enter a random string (you'll add this to Relae)
7. Select events to trigger webhook
8. Click **"Add webhook"**
9. Copy the secret you entered
10. Add it to your Relae destination as **"Vendor Webhook Secret"**

</details>

[See more vendor guides →](/guides/common-vendors)

## Step 2: Trigger a Test Event

Most vendors let you send a test webhook. Here's how:

### Stripe

1. In the Webhooks dashboard
2. Click on your webhook endpoint
3. Click **"Send test webhook"**
4. Select an event type
5. Click **"Send test webhook"**

### Shopify

1. Create a test order in your development store
2. Or use Shopify's "Test notification" button

### GitHub

1. Go to your webhook settings
2. Click **"Edit"**
3. Scroll down and click **"Redeliver"** on a past event
4. Or push a commit to trigger a `push` event

:::tip Manual Testing
You can also test with cURL:

```bash
curl -X POST https://api.relaehook.com/webhook/{your-id} \
  -H "Content-Type: application/json" \
  -d '{"event": "test", "message": "Hello from manual test"}'
```

:::

## Step 3: View the Event in Relae

1. Go to your Relae dashboard
2. Click the **"Webhooks"** tab
3. You should see your test event!

The event will show:

- **Source**: The vendor name (e.g., `stripe`)
- **Payload**: Preview of the webhook data
- **Timestamp**: When it was received
- **Status**: `delivered` (if successful)

### Click to View Details

Click on any event row to see the full details:

- Complete payload (JSON)
- All headers received
- Response from your application

![Webhook Details Modal](/img/webhook-modal.png)

## Step 4: Verify It Reached Your Application

Now check that the webhook was forwarded to your destination URL:

### If using webhook.site or RequestBin

- Refresh the page
- You should see the webhook appear with Relae's forwarded headers

### If using your own endpoint

- Check your application logs
- Look for a POST request to your webhook endpoint
- Verify the payload matches what you see in Relae

### What Gets Forwarded?

Relae forwards the webhook with these headers:

```json
{
  "headers": {
    "Content-Type": "application/json",
    "User-Agent": "Relae-Webhook-Forwarder/1.0",
    "X-Relae-Event-ID": "evt_abc123...",
    "X-Relae-Source": "stripe",
    "X-Relae-Timestamp": "1701234567",
    "X-Relae-Signature": "t=1701234567,v1=abc123..."
    // ... plus any custom headers you configured
  },
  "body": {
    // Original webhook payload from vendor
  }
}
```

#### Header Descriptions

| Header              | Description                       | Example                       |
| ------------------- | --------------------------------- | ----------------------------- |
| `Content-Type`      | Always `application/json`         | `application/json`            |
| `User-Agent`        | Identifies Relae as the forwarder | `Relae-Webhook-Forwarder/1.0` |
| `X-Relae-Event-ID`  | Unique ID for this webhook event  | `evt_abc123...`               |
| `X-Relae-Source`    | The vendor that sent the webhook  | `stripe`, `shopify`, `github` |
| `X-Relae-Timestamp` | Unix timestamp when forwarded     | `1701234567`                  |
| `X-Relae-Signature` | HMAC signature for verification   | `t=1701234567,v1=abc123...`   |

Plus any **custom headers** you configured for this destination.

## Step 5: Verify the HMAC Signature (Recommended)

For security, you should verify that the webhook actually came from Relae and wasn't tampered with.

### Understanding the Signature

Every forwarded webhook includes:

- `X-Relae-Signature`: Signature in format `t=timestamp,v1=signature`
- The timestamp and HMAC-SHA256 signature combined

### Get Your Webhook Secret

1. Go to your Relae dashboard
2. Click **Account** → **Webhooks** tab
3. Copy your **Relae Webhook Secret** (starts with `whsec_`)
4. Store it securely in your environment variables

### Verification Process

1. Extract the signature and timestamp from the `X-Relae-Signature` header
2. Compute HMAC-SHA256 of: `{timestamp}.{raw_body}`
3. Compare with the signature from the header

### Code Examples

#### Node.js / Express

```javascript
const crypto = require("crypto");

function verifyRelaeWebhook(payload, signature, secret) {
  // signature format: t=timestamp,v1=signature
  const [t, v1] = signature.split(",").map((s) => s.split("=")[1]);

  const signedPayload = `${t}.${payload}`;

  const hmac = crypto
    .createHmac("sha256", secret)
    .update(signedPayload)
    .digest("hex");

  return crypto.timingSafeEqual(Buffer.from(v1), Buffer.from(hmac));
}

// Usage in Express
app.post("/webhook", express.raw({ type: "application/json" }), (req, res) => {
  const signature = req.headers["x-relae-signature"];
  const payload = req.body.toString();

  const isValid = verifyRelaeWebhook(
    payload,
    signature,
    process.env.RELAE_WEBHOOK_SECRET,
  );

  if (!isValid) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  // Process webhook
  const event = JSON.parse(payload);
  console.log("Verified webhook:", event);

  res.json({ received: true });
});
```

#### Python / Flask

```python
import hmac
import hashlib

def verify_relae_webhook(payload: str, signature: str, secret: str) -> bool:
    """Verify webhook signature from Relae"""
    # Parse signature: t=timestamp,v1=signature
    sig_parts = dict(item.split('=') for item in signature.split(','))
    timestamp = sig_parts.get('t')
    received_sig = sig_parts.get('v1')

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

# Usage in Flask
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
def webhook():
    signature = request.headers.get('X-Relae-Signature')
    payload = request.get_data(as_text=True)
    secret = os.environ['RELAE_WEBHOOK_SECRET']

    if not verify_relae_webhook(payload, signature, secret):
        return jsonify({'error': 'Invalid signature'}), 401

    # Process webhook
    event = request.get_json()
    print(f"Verified webhook: {event}")

    return jsonify({'received': True})
```

#### Go

```go
package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "io"
    "net/http"
    "os"
    "strings"
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
        switch kv[0] {
        case "t":
            timestamp = kv[1]
        case "v1":
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
    return hmac.Equal([]byte(sig), []byte(expectedSig))
}

// Usage in HTTP handler
func webhookHandler(w http.ResponseWriter, r *http.Request) {
    signature := r.Header.Get("X-Relae-Signature")

    payload, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Failed to read body", 400)
        return
    }

    secret := os.Getenv("RELAE_WEBHOOK_SECRET")

    if !verifyRelaeWebhook(string(payload), signature, secret) {
        http.Error(w, "Invalid signature", 401)
        return
    }

    // Process webhook
    var event map[string]interface{}
    json.Unmarshal(payload, &event)
    fmt.Printf("Verified webhook: %v\n", event)

    w.WriteHeader(200)
    json.NewEncoder(w).Encode(map[string]bool{"received": true})
}
```

#### Ruby / Sinatra

```ruby
require 'openssl'

def verify_relae_webhook(payload, signature, secret)
  # Parse signature: t=timestamp,v1=signature
  sig_parts = signature.split(',').map { |part| part.split('=') }.to_h
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

# Usage in Sinatra
post '/webhook' do
  request.body.rewind
  payload = request.body.read
  signature = request.env['HTTP_X_RELAE_SIGNATURE']
  secret = ENV['RELAE_WEBHOOK_SECRET']

  unless verify_relae_webhook(payload, signature, secret)
    halt 401, { error: 'Invalid signature' }.to_json
  end

  # Process webhook
  event = JSON.parse(payload)
  puts "Verified webhook: #{event}"

  { received: true }.to_json
end
```

#### PHP

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

// Usage
$payload = file_get_contents('php://input');
$signature = $_SERVER['HTTP_X_RELAE_SIGNATURE'] ?? '';
$secret = getenv('RELAE_WEBHOOK_SECRET');

if (!verifyRelaeWebhook($payload, $signature, $secret)) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid signature']);
    exit;
}

// Process webhook
$event = json_decode($payload, true);
error_log('Verified webhook: ' . print_r($event, true));

http_response_code(200);
echo json_encode(['received' => true]);
?>
```

:::tip Timestamp Tolerance
Include a tolerance check to prevent replay attacks:

```javascript
const TOLERANCE_SECONDS = 300; // 5 minutes
const now = Math.floor(Date.now() / 1000);

if (Math.abs(now - parseInt(timestamp)) > TOLERANCE_SECONDS) {
  return res.status(401).send("Timestamp too old");
}
```

:::

:::info Where to Find Your Secret
Get your Relae webhook secret from:

1. Dashboard → Account → Webhooks tab
2. Look for "Relae Webhook Secret"
3. Copy the value (starts with `whsec_`)
4. Store in environment variable: `RELAE_WEBHOOK_SECRET`
   :::

## Step 6: Test Failure Scenarios

Let's test what happens when your application is down or returns an error:

### Simulate a Failure

1. Temporarily shut down your application (or change the destination URL to something invalid)
2. Trigger another test webhook from your vendor
3. Watch what happens in Relae

### What You'll See

1. **Webhooks tab**: Event appears with status `pending` or `failed`
2. **Automatic retries**: Relae retries up to 5 times with exponential backoff
   - 1st retry: Immediate
   - 2nd retry: After 5 seconds
   - 3rd retry: After 25 seconds
   - 4th retry: After 125 seconds
   - 5th retry: After 625 seconds
3. **Dead Letter Queue**: After 5 failures, event moves to the DLQ tab

### Manual Retry from DLQ

1. Go to the **"Dead Letter Queue"** tab
2. Find your failed event
3. Click **"Retry"** button
4. Event is reprocessed and forwarded again

![Dead Letter Queue](/img/bulk-retry.png)

## Success! 🎉

Congratulations! You've successfully:

- ✅ Created a Relae account
- ✅ Configured a destination
- ✅ Set up your vendor to send webhooks to Relae
- ✅ Received and forwarded your first webhook
- ✅ Verified the HMAC signature
- ✅ Tested the failure/retry mechanism

<!--
## Next Steps

Now that you're set up, explore more features:

- [Learn about Events →](/core-concepts/events)
- [Understand the Retry Logic →](/core-concepts/retries)
- [View Analytics →](/guides/analytics) (Scale tier)
- [Set up Multiple Vendors →](/guides/common-vendors)
-->

## Need Help?

If something isn't working:

1. Check the [Troubleshooting](#troubleshooting) section below
2. Review the [Verifying Signatures Guide](/guides/verifying-signatures)
3. Email us at [support@relaehook.com](mailto:support@relaehook.com)

## Troubleshooting

<details>
<summary><b>Event not showing in Relae dashboard</b></summary>

**Possible causes:**

1. Vendor sent webhook to wrong URL
2. Webhook signature verification failed (invalid secret)
3. Vendor didn't trigger the webhook

**Solutions:**

- Double-check the endpoint URL in vendor settings
- Verify the webhook secret is correct in both places
- Check vendor's webhook logs for delivery attempts
- Try sending a test webhook from vendor dashboard

</details>

<details>
<summary><b>Event in Relae but not reaching my application</b></summary>

**Possible causes:**

1. Incorrect destination URL
2. Your application is down or returning errors
3. Firewall blocking Relae's IP addresses

**Solutions:**

- Verify destination URL is correct and accessible
- Check your application logs for errors
- Test destination URL with curl:

  ```bash
  curl -X POST https://your-destination-url.com/webhook \
    -H "Content-Type: application/json" \
    -d '{"test": true}'
  ```

- Whitelist Relae's IP ranges (contact support for list)

</details>

<details>
<summary><b>Signature verification failing</b></summary>

**Possible causes:**

1. Using wrong endpoint token
2. Body being modified before verification
3. Timestamp tolerance too strict

**Solutions:**

- Copy endpoint token from Relae destination settings
- Verify raw body before any parsing or modifications
- Add timestamp tolerance (5-10 minutes)
- Check that signature format is `sha256={hash}`
- Enable debug logging to see computed vs. expected signatures

</details>

<details>
<summary><b>Events going to DLQ immediately</b></summary>

**Possible causes:**

1. Destination URL returning 4xx/5xx errors
2. Destination URL unreachable
3. SSL/TLS certificate issues

**Solutions:**

- Check destination URL returns 2xx status codes
- Verify SSL certificate is valid
- Test with curl to see exact error
- Check application logs for errors
- Try a test destination URL (webhook.site) first

</details>
