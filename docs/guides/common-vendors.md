---
title: Common Vendors
description: How to get webhook secrets for the vendors Relae currently supports
---

# Common Vendors

Relae currently supports the following vendors:

- **Stripe**
- **Shopify**
- **GitHub**
- **GitLab**
- **Slack**
- **SendGrid**

For each vendor, you’ll need a **webhook secret** to enable Relae to verify incoming webhooks.

---

## 🔹 Stripe

Relae uses Stripe’s webhook signing secret to verify requests.

**How to get your Stripe webhook secret:**

1. Log in to your [Stripe Dashboard](https://dashboard.stripe.com/).
2. Go to **Developers → Webhooks**.
3. Click on your webhook endpoint or create a new one.
4. Copy the **Signing secret** (starts with `whsec_...`) and save it in Relae.

Relae expects the header:

Stripe-Signature

---

## 🔹 Shopify

Shopify uses HMAC-SHA256 signatures to verify webhooks.

**How to get your Shopify webhook secret:**

1. Log in to your Shopify Admin panel.
2. Go to **Settings → Notifications → Webhooks**.
3. Click **Create webhook** or view an existing webhook.
4. Copy the **Webhook secret key** and save it in Relae.

Relae expects the header:

X-Shopify-Hmac-Sha256

---

## 🔹 GitHub

GitHub uses HMAC-SHA256 signatures for webhook verification.

**How to get your GitHub webhook secret:**

1. Go to your GitHub repository.
2. Navigate to **Settings → Webhooks → Add webhook**.
3. Enter your payload URL and choose a secret.
4. Copy this secret and save it in Relae.

Relae expects the header:

X-Hub-Signature-256

---

## 🔹 GitLab

GitLab verifies webhooks using a token.

**How to get your GitLab webhook token:**

1. Go to your GitLab repository.
2. Navigate to **Settings → Webhooks → Add webhook**.
3. Set a **Secret Token**.
4. Copy this token and save it in Relae.

Relae expects the header:

X-Gitlab-Token

---

## 🔹 Slack

Slack signs requests with a timestamped HMAC signature.

**How to get your Slack signing secret:**

1. Go to your Slack App [Dashboard](https://api.slack.com/apps).
2. Click **Basic Information → App Credentials**.
3. Copy the **Signing Secret** and save it in Relae.

Relae expects the headers:

X-Slack-Signature
X-Slack-Request-Timestamp

---

## 🔹 SendGrid

SendGrid signs events with a timestamp + payload HMAC signature.

**How to get your SendGrid webhook secret:**

1. Log in to [SendGrid](https://app.sendgrid.com/).
2. Navigate to **Settings → Mail Settings → Event Webhook**.
3. Enable the webhook and copy the **Signed Event Webhook Key**.
4. Save this key in Relae.

Relae expects the headers:

X-Twilio-Email-Event-Webhook-Signature
X-Twilio-Email-Event-Webhook-Timestamp
