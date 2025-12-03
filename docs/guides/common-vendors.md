# Common Vendor Setup

Step-by-step guides for configuring webhooks from Relae's supported vendors.

## Overview

Relae currently supports signature verification for these vendors:

- [Stripe](#stripe) (Payments)
- [Shopify](#shopify) (E-commerce)
- [GitHub](#github) (Code & CI/CD)
- [GitLab](#gitlab) (Code & CI/CD)
- [Slack](#slack) (Team Communication)
- [SendGrid](#sendgrid) (Email Delivery)

:::tip Other Vendors
You can use Relae with any webhook provider! These vendors have built-in signature verification. For other vendors, Relae will still forward webhooks reliably - you just won't have incoming signature verification.
:::

## Before You Begin

For all vendors, you'll need:

1. ✅ Your Relae webhook endpoint URL
   - Get from: Dashboard → Destinations → Your destination
   - Format: `https://api.relaehook.com/webhook/{unique-id}`

2. ✅ Vendor webhook secret (optional but recommended)
   - Used by Relae to verify incoming webhooks
   - Each vendor stores this differently (covered below)

3. ✅ Your application destination URL
   - Where Relae forwards the webhooks
   - Must be HTTPS

---

## Stripe

Configure Stripe to send payment webhooks to Relae.

### 1. Create Relae Destination

```
Dashboard → Destinations → Add New Destination

Source: stripe
Destination URL: https://api.yourdomain.com/webhooks/stripe
Vendor Webhook Secret: (wait for Step 3)
```

Click **Save** and copy your Relae endpoint URL.

### 2. Add Webhook in Stripe

1. Go to [Stripe Dashboard](https://dashboard.stripe.com)
2. Navigate to **Developers** → **Webhooks**
3. Click **Add endpoint**

   **Endpoint URL:** `https://api.relaehook.com/webhook/{your-id}`

4. **Select events to listen to:**
   - `payment_intent.succeeded`
   - `payment_intent.payment_failed`
   - `charge.succeeded`
   - `charge.failed`
   - `customer.created`
   - `customer.subscription.created`
   - `customer.subscription.deleted`
   - Or select **all events** for comprehensive coverage

5. Click **Add endpoint**

### 3. Get Signing Secret

1. Click on your newly created webhook endpoint
2. Under **Signing secret**, click **Reveal**
3. Copy the secret (starts with `whsec_`)

### 4. Add Secret to Relae

```
Dashboard → Destinations → Edit Stripe destination

Vendor Webhook Secret: whsec_abc123...
```

Click **Save Changes**

### 5. Test the Integration

1. In Stripe webhook settings, click **Send test webhook**
2. Select an event type (e.g., `payment_intent.succeeded`)
3. Click **Send test webhook**
4. Check Relae Dashboard → Webhooks tab
5. Verify event appears and was forwarded

### Stripe-Specific Notes

**Event Types:**

- Payment events: `payment_intent.*`, `charge.*`
- Customer events: `customer.*`
- Subscription events: `customer.subscription.*`
- Dispute events: `charge.dispute.*`

**Best Practices:**

- Only subscribe to events you need
- Use different destinations for test vs live webhooks
- Test mode webhooks use `whsec_test_...` secrets
- Live mode webhooks use `whsec_...` secrets

**Common Issues:**

- Wrong secret for test vs live mode
- Forgetting to enable webhook endpoint
- Not handling `payment_intent.processing` state

---

## Shopify

Set up Shopify webhooks for order and inventory updates.

### 1. Create Relae Destination

```
Dashboard → Destinations → Add New Destination

Source: shopify
Destination URL: https://api.yourdomain.com/webhooks/shopify
```

Click **Save** and copy your Relae endpoint URL.

### 2. Add Webhook in Shopify

1. Go to your **Shopify Admin**
2. Navigate to **Settings** → **Notifications**
3. Scroll down to **Webhooks** section
4. Click **Create webhook**

   **Event:** Select the event to subscribe to:
   - `Order creation`
   - `Order updated`
   - `Order payment`
   - `Product creation`
   - `Product update`
   - `Customer creation`
   - `Fulfillment created`

   **Format:** JSON

   **URL:** `https://api.relaehook.com/webhook/{your-id}`

5. Click **Save webhook**

### 3. Get API Key (for signature verification)

Shopify signs webhooks with your API Secret Key:

1. Go to **Settings** → **Apps and sales channels**
2. Click **Develop apps**
3. Click on your app or **Create an app**
4. Go to **API credentials** tab
5. Copy the **API secret key**

### 4. Add Secret to Relae

```
Dashboard → Destinations → Edit Shopify destination

Vendor Webhook Secret: {your-api-secret-key}
```

Click **Save Changes**

### 5. Test the Integration

1. Create a test order in your Shopify store
2. Check Relae Dashboard → Webhooks tab
3. Verify the order webhook appears

### Shopify-Specific Notes

**Authentication:**

- Shopify sends signature in `X-Shopify-Hmac-Sha256` header
- Uses HMAC-SHA256 (base64 encoded, not hex)
- Relae handles the verification automatically

**Event Types:**

- Orders: `orders/create`, `orders/updated`, `orders/paid`
- Products: `products/create`, `products/update`, `products/delete`
- Customers: `customers/create`, `customers/update`
- Inventory: `inventory_levels/update`

**Rate Limits:**

- Maximum 15 webhooks per store at a time
- If you need more, contact Shopify support

**Common Issues:**

- Wrong API secret key (app vs shop secret)
- Webhook format set to XML instead of JSON
- Test orders not triggering webhooks (use real orders or dev store)

---

## GitHub

Configure GitHub webhooks for repository events.

### 1. Create Relae Destination

```
Dashboard → Destinations → Add New Destination

Source: github
Destination URL: https://api.yourdomain.com/webhooks/github
```

Click **Save** and copy your Relae endpoint URL.

### 2. Create Secret

Generate a random secret for GitHub:

```bash
openssl rand -hex 32
```

Copy this secret - you'll need it for both GitHub and Relae.

### 3. Add Webhook in GitHub

#### Repository-level Webhook

1. Go to your GitHub repository
2. Navigate to **Settings** → **Webhooks**
3. Click **Add webhook**

   **Payload URL:** `https://api.relaehook.com/webhook/{your-id}`

   **Content type:** `application/json`

   **Secret:** Paste your generated secret

   **SSL verification:** Enable SSL verification

   **Which events would you like to trigger this webhook?**
   - **Just the push event** (default)
   - **Send me everything** (for comprehensive coverage)
   - **Let me select individual events:**
     - Push
     - Pull request
     - Issues
     - Release
     - Deployment
     - Workflow run

4. **Active:** ✅ Checked
5. Click **Add webhook**

#### Organization-level Webhook

1. Go to your GitHub organization
2. Navigate to **Settings** → **Webhooks**
3. Follow same steps as repository webhook

### 4. Add Secret to Relae

```
Dashboard → Destinations → Edit GitHub destination

Vendor Webhook Secret: {your-generated-secret}
```

Click **Save Changes**

### 5. Test the Integration

1. In GitHub webhook settings, click **Edit**
2. Scroll down to **Recent Deliveries**
3. Click **Redeliver** on any past event
4. Or push a commit to trigger a new webhook
5. Check Relae Dashboard → Webhooks tab

### GitHub-Specific Notes

**Authentication:**

- GitHub sends signature in `X-Hub-Signature-256` header
- Format: `sha256=<hash>`
- Uses HMAC-SHA256

**Event Types:**

- Code: `push`, `pull_request`, `fork`
- Issues: `issues`, `issue_comment`
- Releases: `release`, `workflow_run`
- Security: `security_advisory`, `dependabot_alert`

**Delivery Info:**

- GitHub shows delivery status and response
- Can redeliver any past webhook
- Keeps 30 days of delivery history

**Common Issues:**

- Secret mismatch between GitHub and Relae
- SSL verification failing (check certificate)
- Event type not selected in webhook settings

---

## GitLab

Configure GitLab webhooks for repository and CI/CD events.

### 1. Create Relae Destination

```
Dashboard → Destinations → Add New Destination

Source: gitlab
Destination URL: https://api.yourdomain.com/webhooks/gitlab
```

Click **Save** and copy your Relae endpoint URL.

### 2. Create Secret Token

Generate a random secret for GitLab:

```bash
openssl rand -hex 32
```

Copy this secret - you'll need it for both GitLab and Relae.

### 3. Add Webhook in GitLab

#### Project-level Webhook

1. Go to your GitLab project
2. Navigate to **Settings** → **Webhooks**
3. Fill in the webhook details:

   **URL:** `https://api.relaehook.com/webhook/{your-id}`

   **Secret token:** Paste your generated secret

   **Trigger:**
   - ☑️ Push events
   - ☑️ Tag push events
   - ☑️ Comments
   - ☑️ Issues events
   - ☑️ Merge request events
   - ☑️ Job events
   - ☑️ Pipeline events
   - ☑️ Wiki page events
   - ☑️ Deployment events
   - ☑️ Release events

   **SSL verification:** ✅ Enable SSL verification

4. Click **Add webhook**

#### Group-level Webhook

1. Go to your GitLab group
2. Navigate to **Settings** → **Webhooks**
3. Follow same steps as project webhook

### 4. Add Secret to Relae

```
Dashboard → Destinations → Edit GitLab destination

Vendor Webhook Secret: {your-generated-secret}
```

Click **Save Changes**

### 5. Test the Integration

1. In GitLab webhook settings, scroll down to your webhook
2. Click **Test** dropdown
3. Select **Push events** or another event type
4. Click the test option
5. Check Relae Dashboard → Webhooks tab
6. Verify event appears

### GitLab-Specific Notes

**Authentication:**

- GitLab sends token in `X-Gitlab-Token` header
- Simple token comparison (not HMAC)
- Relae verifies automatically

**Event Types:**

- Code: `Push Hook`, `Tag Push Hook`, `Merge Request Hook`
- Issues: `Issue Hook`, `Note Hook`, `Confidential Issue Hook`
- CI/CD: `Pipeline Hook`, `Job Hook`, `Deployment Hook`
- Wiki: `Wiki Page Hook`
- Releases: `Release Hook`

**Event Format:**

- All events include `object_kind` field
- Rich event data with user, project, and commit info
- Consistent JSON structure across event types

**Common Event Kinds:**

```json
{
  "object_kind": "push",
  "object_kind": "merge_request",
  "object_kind": "pipeline",
  "object_kind": "issue"
}
```

**Common Issues:**

- Secret token mismatch between GitLab and Relae
- SSL verification failing (check certificate)
- Trigger not enabled for desired event
- Rate limiting on high-traffic repos

**Best Practices:**

- Use project webhooks for specific repos
- Use group webhooks for organization-wide events
- Filter events at webhook level to reduce noise
- Test with push event first before enabling all

---

## Slack

Set up Slack webhooks to receive events from your workspace.

### 1. Create Relae Destination

```
Dashboard → Destinations → Add New Destination

Source: slack
Destination URL: https://api.yourdomain.com/webhooks/slack
```

Click **Save** and copy your Relae endpoint URL.

### 2. Create Slack App

1. Go to [Slack API](https://api.slack.com/apps)
2. Click **Create New App**
3. Choose **From scratch**
4. Enter **App Name** and select your **Workspace**
5. Click **Create App**

### 3. Enable Event Subscriptions

1. In your app settings, go to **Event Subscriptions**
2. Toggle **Enable Events** to **On**

   **Request URL:** `https://api.relaehook.com/webhook/{your-id}`

   :::warning Verification Challenge
   Slack will send a verification challenge immediately. Relae handles this automatically. Wait for the "Verified" checkmark.
   :::

3. **Subscribe to bot events:**
   - `message.channels` - Messages in public channels
   - `message.groups` - Messages in private channels
   - `message.im` - Direct messages
   - `app_mention` - When someone mentions your app
   - `reaction_added` - Emoji reactions
   - `team_join` - New members
4. **Subscribe to events on behalf of users** (optional):
   - Similar events but require user OAuth

5. Click **Save Changes**

### 4. Get Signing Secret

1. Go to **Basic Information** in your app settings
2. Under **App Credentials**, find **Signing Secret**
3. Click **Show** and copy the secret

### 5. Add Secret to Relae

```
Dashboard → Destinations → Edit Slack destination

Vendor Webhook Secret: {signing-secret}
```

Click **Save Changes**

### 6. Install App to Workspace

1. Go to **Install App** in sidebar
2. Click **Install to Workspace**
3. Review permissions and click **Allow**
4. Your app is now installed

### 7. Test the Integration

1. Send a message in a channel where your app is added
2. Check Relae Dashboard → Webhooks tab
3. Verify event appears

### Slack-Specific Notes

**Authentication:**

- Slack sends signature in `X-Slack-Signature` header
- Also sends timestamp in `X-Slack-Request-Timestamp` header
- Uses HMAC-SHA256 with format: `v0=<hash>`
- Relae verifies automatically

**Verification Format:**

```
v0 + ':' + timestamp + ':' + body
```

**Event Types:**

- **Message events:** `message.channels`, `message.im`, `message.groups`
- **User events:** `team_join`, `user_change`
- **Reaction events:** `reaction_added`, `reaction_removed`
- **App events:** `app_mention`, `app_home_opened`

**Event Structure:**

```json
{
  "token": "...",
  "team_id": "T1234567",
  "api_app_id": "A1234567",
  "event": {
    "type": "message",
    "channel": "C1234567",
    "user": "U1234567",
    "text": "Hello world",
    "ts": "1234567890.123456"
  },
  "type": "event_callback",
  "event_time": 1234567890
}
```

**URL Verification:**
When you first add the Request URL, Slack sends:

```json
{
  "type": "url_verification",
  "challenge": "3eZbrw1aBm2rZgRNFdxV2595E9CY3gmdALWMmHkvFXO7tYXAYM8P"
}
```

Relae automatically responds with the challenge value.

**Rate Limiting:**

- Slack has rate limits on event deliveries
- High-traffic channels may experience delays
- Consider filtering events to reduce volume

**Common Issues:**

- URL verification failing (Relae should handle automatically)
- Events not appearing (check bot is in channel)
- Signing secret mismatch
- Timestamp too old (check server clock sync)

**Best Practices:**

- Only subscribe to events you need
- Use bot events instead of user events when possible
- Handle `retry-after` headers for rate limits
- Acknowledge events immediately (return 200)
- Process messages asynchronously

**Responding to Messages:**
To send messages back to Slack from your application:

```javascript
// Your application endpoint
app.post("/webhooks/slack", async (req, res) => {
  // Acknowledge immediately
  res.status(200).send();

  // Process asynchronously
  const event = req.body.event;

  if (event.type === "app_mention") {
    // Respond using Slack Web API
    await fetch("https://slack.com/api/chat.postMessage", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.SLACK_BOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        channel: event.channel,
        text: "Hello! You mentioned me.",
      }),
    });
  }
});
```

---

## SendGrid

Configure SendGrid event webhooks for email delivery tracking.

### 1. Create Relae Destination

```
Dashboard → Destinations → Add New Destination

Source: sendgrid
Destination URL: https://api.yourdomain.com/webhooks/sendgrid
```

Click **Save** and copy your Relae endpoint URL.

### 2. Enable Event Webhook

1. Go to [SendGrid Dashboard](https://app.sendgrid.com)
2. Navigate to **Settings** → **Mail Settings** → **Event Webhook**
3. Click **Edit** (or **Enable** if disabled)

   **HTTP Post URL:** `https://api.relaehook.com/webhook/{your-id}`

   **Select events to post:**
   - ✅ Delivered
   - ✅ Opened
   - ✅ Clicked
   - ✅ Bounced
   - ✅ Spam Report
   - ✅ Unsubscribe
   - ✅ Dropped
   - ✅ Deferred

4. **Status:** Enabled
5. Click **Save**

### 3. Test Event Webhook

1. In Event Webhook settings, click **Test Your Integration**
2. SendGrid will send test events
3. Check Relae Dashboard → Webhooks tab

### SendGrid-Specific Notes

**Event Types:**

- Delivery: `delivered`, `bounce`, `dropped`, `deferred`
- Engagement: `open`, `click`
- Feedback: `spamreport`, `unsubscribe`

**Batch Delivery:**

- SendGrid can batch multiple events in one webhook
- Your endpoint receives array of events
- Handle as JSON array

**No Built-in Signature:**

- SendGrid doesn't provide webhook signatures by default
- Consider using IP allowlisting
- Or implement your own verification token

**No Built-in Signature:**

- SendGrid doesn't provide HMAC webhook signatures
- Relae still forwards reliably without incoming verification
- Consider adding custom authentication headers in Relae destination
- Or use IP allowlisting on your destination endpoint

**Common Issues:**

- Event webhook disabled after testing
- Not handling batched events (arrays)
- IP not allowlisted (if using IP filtering)

---

## Using Other Vendors

Relae works with **any webhook provider**, not just the six listed above!

### Vendors Without Signature Support

For vendors not listed (e.g., Twilio, Mailgun, WooCommerce, etc.):

**Setup is still simple:**

1. Create destination in Relae:

   ```
   Source: vendor-name
   Destination URL: https://api.yourdomain.com/webhooks/vendor
   Vendor Webhook Secret: (leave empty)
   ```

2. Configure vendor to send to your Relae endpoint

3. Relae will:
   - ✅ Receive and store webhooks
   - ✅ Forward reliably to your destination
   - ✅ Provide automatic retries
   - ✅ Move failures to Dead Letter Queue
   - ✅ Sign outgoing webhooks with Relae signature
   - ⚠️ Cannot verify incoming vendor signature

**You still get:**

- Guaranteed delivery
- Automatic retries
- Dead Letter Queue
- Analytics (on Scale+)
- Relae signature on forwarded webhooks

**Additional Security:**
You can add custom authentication headers in your Relae destination:

```
Custom Headers:
  X-Auth-Token: your-secret-token
  X-API-Key: your-api-key
```

Your destination endpoint can verify these headers.

### Need Signature Support for Your Vendor?

Contact us at [support@relaehook.com](mailto:support@relaehook.com) with:

- Vendor name
- Link to webhook documentation
- Signature verification details

We're constantly adding support for more vendors!

---

## General Troubleshooting

### Webhook Not Appearing in Relae

**Check:**

1. ✅ Vendor webhook URL is correct Relae endpoint
2. ✅ Webhook is enabled/active in vendor settings
3. ✅ Event actually occurred (trigger test event)
4. ✅ Vendor's webhook delivery logs show success

**Debug:**

- Check vendor's webhook delivery logs
- Verify SSL certificate is valid
- Test with webhook.site first
- Contact Relae support with vendor logs

### Signature Verification Failing

**Check:**

1. ✅ Correct secret added to Relae destination
2. ✅ Secret matches vendor's webhook secret
3. ✅ Using correct secret for test vs live mode
4. ✅ Vendor webhook URL points to Relae, not direct

**Debug:**

- Remove secret temporarily to isolate issue
- Regenerate secret in vendor and update Relae
- Check vendor documentation for signature format
- Enable debug logging

### Webhook Delivered But Not Forwarded

**Check:**

1. ✅ Destination URL in Relae is correct
2. ✅ Your endpoint is accessible (not down)
3. ✅ Your endpoint returns 2xx status
4. ✅ No firewall blocking Relae IPs

**Debug:**

- Test destination URL with curl
- Check Dead Letter Queue for failures
- Review failure reasons in DLQ
- Verify SSL certificate on destination

## Best Practices

1. ✅ **Use separate destinations per vendor**
   - Easier to manage and debug
   - Can rotate endpoints individually
   - Better organization

2. ✅ **Always provide webhook secrets**
   - Critical for security
   - Prevents spoofed webhooks
   - Relae verifies before forwarding

3. ✅ **Subscribe only to needed events**
   - Reduces noise
   - Lowers costs
   - Easier to process

4. ✅ **Test in sandbox/development first**
   - Use test mode webhooks
   - Verify integration works
   - Then enable production

5. ✅ **Monitor webhook health**
   - Check analytics regularly
   - Review Dead Letter Queue
   - Set up alerts for failures

6. ✅ **Document your webhooks**
   - Which events you subscribe to
   - What your app does with each
   - Expected payload format

## Need Help?

**Don't see your vendor?** Relae works with any webhook provider!

**For vendors with signature support:**

- Email: [support@relaehook.com](mailto:support@relaehook.com)
- Include: vendor name and webhook documentation link
- We'll add verification support

**For other vendors:**

- Use Relae without incoming signature verification
- Still get reliable delivery, retries, and DLQ
- Add custom authentication headers for security

## Next Steps

- [Verifying Signatures →](/guides/verifying-signatures)
- [Managing Webhooks →](/guides/managing-webhooks)
- [Dead Letter Queue →](/guides/dead-letter-queue)
- [Analytics →](/guides/analytics)

## Vendor Documentation Links

- [Stripe Webhooks](https://stripe.com/docs/webhooks)
- [Shopify Webhooks](https://shopify.dev/docs/api/admin-rest/webhooks)
- [GitHub Webhooks](https://docs.github.com/en/webhooks)
- [GitLab Webhooks](https://docs.gitlab.com/ee/user/project/integrations/webhooks.html)
- [Slack Events API](https://api.slack.com/apis/connections/events-api)
- [SendGrid Event Webhook](https://docs.sendgrid.com/for-developers/tracking-events/event)
