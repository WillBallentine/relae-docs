# Relae Node SDK

[![npm version](https://img.shields.io/npm/v/relae.svg)](https://www.npmjs.com/package/relae)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Official Node.js SDK for [Relae](https://relaehook.com) - A reliable webhook delivery platform with automatic retries, observability, and dead letter queue management.

## Features

- 🚀 **Simple API** - Clean, intuitive interface for webhook operations
- 🔄 **Dead Letter Queue** - Manage and replay failed webhook deliveries
- 📊 **Delivery Tracking** - Monitor webhook delivery attempts and status
- 🔒 **Type Safe** - Full TypeScript support with complete type definitions
- ✅ **Webhook Verification** - Built-in signature verification utilities
- ⚡ **Pagination Support** - Async generators and helper methods for handling large datasets
- 🛡️ **Error Handling** - Specific error classes for different failure scenarios

## Installation

```bash
npm install @relae/node
```

or with yarn:

```bash
yarn add @relae/node
```

## Quick Start

```typescript
import { Relae } from "relae";

// Initialize the client with your API key
const relae = new Relae("your-api-key");

// List all destinations
const { destinations } = await relae.destinations.list();
console.log(destinations);

// Create a new destination
await relae.destinations.create({
  source: "stripe",
  destination_url: "https://myapp.com/webhooks/stripe",
  headers: [{ key: "X-Custom-Header", value: "value" }],
});

// List webhook events with pagination
const webhooksPage = await relae.webhooks.list();
console.log(webhooksPage.events);

// Or iterate through all events using async generator
for await (const event of relae.webhooks.all()) {
  console.log(event);
}
```

## API Reference

### Client Initialization

```typescript
import { Relae } from "relae";

const relae = new Relae(apiKey: string);
```

The client provides access to four main resources:

- `destinations` - Manage webhook destinations
- `webhooks` - View webhook delivery events
- `deadLetter` - Manage failed webhook events
- `utils` - Utility methods for webhook verification

---

### Destinations API

Manage webhook destinations where your events are delivered.

#### `destinations.list()`

List all webhook destinations in your account.

```typescript
const response = await relae.destinations.list();

// Returns:
interface DestinationListResponse {
  destinations: Destination[];
}

interface Destination {
  id: string;
  account_id: string;
  source: string;
  destination_url: string;
  headers: { key: string; value: string }[];
  vendor_webhook_secret?: string;
  endpoint_token: string;
  webhook_url: string;
  is_active: boolean;
  last_used_at?: string | null;
  created_at: string;
  updated_at: string;
}
```

**Example:**

```typescript
const { destinations } = await relae.destinations.list();
destinations.forEach((dest) => {
  console.log(`${dest.source}: ${dest.destination_url}`);
});
```

#### `destinations.create(input)`

Create a new webhook destination.

```typescript
await relae.destinations.create({
  source: string,                           // e.g., "stripe", "github"
  destination_url: string,                  // Your webhook endpoint URL
  headers?: Record<string, string>[],       // Optional custom headers
  vendor_webhook_secret?: string,           // Optional vendor secret
});
```

**Example:**

```typescript
await relae.destinations.create({
  source: "stripe",
  destination_url: "https://api.myapp.com/webhooks/stripe",
  headers: [{ key: "X-Custom-Auth", value: "secret-token" }],
  vendor_webhook_secret: "whsec_...",
});
```

#### `destinations.update(id, input)`

Update an existing destination.

```typescript
await relae.destinations.update(
  id: string,
  input: Partial<DestinationInput>
);
```

**Example:**

```typescript
await relae.destinations.update("dest_123", {
  destination_url: "https://api.myapp.com/webhooks/stripe-v2",
  headers: [{ key: "X-API-Version", value: "2024-01" }],
});
```

#### `destinations.delete(id)`

Delete a destination.

```typescript
await relae.destinations.delete(id: string);
```

**Example:**

```typescript
await relae.destinations.delete("dest_123");
```

---

### Webhooks API

View and monitor webhook delivery events.

#### `webhooks.list(cursor?)`

List webhook events with pagination support.

```typescript
const page = await relae.webhooks.list(cursor?: string);

// Returns:
interface PaginatedWebhookEvents {
  events: WebhookEvent[];
  next_cursor?: string;
}

interface WebhookEvent {
  id: string;
  account_id: string;
  source: string;
  payload: Record<string, any>;
  headers: Record<string, any>;
  status: string;
  retry_count: number;
  created_at: string;
  updated_at: string;
  duration: number;  // Delivery duration in ms
}
```

**Example:**

```typescript
// Get first page
const firstPage = await relae.webhooks.list();
console.log(firstPage.events);

// Get next page if available
if (firstPage.next_cursor) {
  const nextPage = await relae.webhooks.list(firstPage.next_cursor);
  console.log(nextPage.events);
}
```

#### `webhooks.all()`

Async generator to iterate through all webhook events across all pages.

```typescript
for await (const event of relae.webhooks.all()) {
  console.log(`Event ${event.id}: ${event.status}`);
  console.log(`Duration: ${event.duration}ms, Retries: ${event.retry_count}`);
}
```

#### `webhooks.listAllPages()`

Fetch all pages at once and return as an array of pages.

```typescript
const allPages: WebhookEvent[][] = await relae.webhooks.listAllPages();

// Flatten if needed
const allEvents = allPages.flat();
console.log(`Total events: ${allEvents.length}`);
```

---

### Dead Letter Queue API

Manage and replay failed webhook deliveries.

#### `deadLetter.list(cursor?)`

List failed webhook events in the dead letter queue.

```typescript
const page = await relae.deadLetter.list(cursor?: string);

// Returns:
interface PaginatedDeadLetterEvents {
  events: DeadLetterEvent[];
  next_cursor?: string;
}

interface DeadLetterEvent {
  id: string;
  orig_id: string;          // Original webhook event ID
  account_id: string;
  source: string;
  payload: Record<string, any>;
  headers: Record<string, any>;
  retry_count: number;
  failed_reason: string;    // Reason for failure
  created_at: string;
}
```

**Example:**

```typescript
const { events } = await relae.deadLetter.list();
events.forEach((event) => {
  console.log(`Failed: ${event.source} - ${event.failed_reason}`);
});
```

#### `deadLetter.replay(eventId)`

Retry a single failed webhook event.

```typescript
await relae.deadLetter.replay(eventId: string);
```

**Example:**

```typescript
// Replay a specific failed event
await relae.deadLetter.replay("dlq_abc123");
```

#### `deadLetter.replayMulti(input)`

Retry multiple failed webhook events at once.

```typescript
await relae.deadLetter.replayMulti({
  events: string[]  // Array of event IDs
});
```

**Example:**

```typescript
// Replay multiple failed events
await relae.deadLetter.replayMulti({
  events: ["dlq_abc123", "dlq_def456", "dlq_ghi789"],
});
```

#### `deadLetter.all()`

Async generator to iterate through all dead letter events.

```typescript
for await (const event of relae.deadLetter.all()) {
  console.log(`Failed event: ${event.id}`);
  console.log(`Reason: ${event.failed_reason}`);

  // Optionally replay
  if (event.retry_count < 3) {
    await relae.deadLetter.replay(event.id);
  }
}
```

#### `deadLetter.listAllPages()`

Fetch all dead letter queue pages at once.

```typescript
const allPages: DeadLetterEvent[][] = await relae.deadLetter.listAllPages();
const allFailedEvents = allPages.flat();

console.log(`Total failed events: ${allFailedEvents.length}`);
```

---

### Utils API

Utility methods for webhook handling.

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

**Signature Format:**

The `X-Relae-Signature` header has the format: `t=<timestamp>,v1=<signature>`

---

## Error Handling

The SDK provides specific error classes for different failure scenarios:

```typescript
import {
  RelaeError, // Base error class
  UnauthorizedError, // 401 - Invalid API key
  ForbiddenError, // 403 - Insufficient permissions
  NotFoundError, // 404 - Resource not found
  RateLimitError, // 429 - Rate limit exceeded
  InternalServerError, // 500 - Server error
} from "relae";
```

**Example:**

```typescript
try {
  await relae.destinations.create({
    source: "stripe",
    destination_url: "https://api.myapp.com/webhooks",
  });
} catch (error) {
  if (error instanceof UnauthorizedError) {
    console.error("Invalid API key");
  } else if (error instanceof RateLimitError) {
    console.error("Rate limit exceeded, please retry later");
  } else if (error instanceof RelaeError) {
    console.error(`API error: ${error.message} (${error.status})`);
    console.error("Raw response:", error.raw);
  } else {
    console.error("Unexpected error:", error);
  }
}
```

All `RelaeError` instances include:

- `message` - Error description
- `status` - HTTP status code (if applicable)
- `raw` - Raw error response from the API

---

## TypeScript Support

The SDK is fully written in TypeScript with complete type definitions.

```typescript
import {
  Relae,
  Destination,
  DestinationInput,
  WebhookEvent,
  DeadLetterEvent,
  PaginatedWebhookEvents,
  PaginatedDeadLetterEvents,
} from "relae";

const relae = new Relae("your-api-key");

// All responses are fully typed
const response: PaginatedWebhookEvents = await relae.webhooks.list();
const events: WebhookEvent[] = response.events;
```

---

## Advanced Examples

### Monitoring Failed Webhooks

```typescript
// Check dead letter queue and replay recent failures
const { events } = await relae.deadLetter.list();

const recentFailures = events.filter((event) => {
  const hourAgo = Date.now() - 60 * 60 * 1000;
  return new Date(event.created_at).getTime() > hourAgo;
});

if (recentFailures.length > 0) {
  console.log(`Found ${recentFailures.length} recent failures`);

  await relae.deadLetter.replayMulti({
    events: recentFailures.map((e) => e.id),
  });

  console.log("Replayed all recent failures");
}
```

### Processing All Events in Batches

```typescript
// Process all webhook events in batches of 100
const batchSize = 100;
let batch: WebhookEvent[] = [];

for await (const event of relae.webhooks.all()) {
  batch.push(event);

  if (batch.length >= batchSize) {
    await processBatch(batch);
    batch = [];
  }
}

// Process remaining events
if (batch.length > 0) {
  await processBatch(batch);
}

async function processBatch(events: WebhookEvent[]) {
  console.log(`Processing ${events.length} events...`);
  // Your batch processing logic
}
```

### Creating Multiple Destinations

```typescript
const sources = [
  { name: "stripe", url: "https://api.myapp.com/webhooks/stripe" },
  { name: "github", url: "https://api.myapp.com/webhooks/github" },
  { name: "slack", url: "https://api.myapp.com/webhooks/slack" },
];

for (const source of sources) {
  await relae.destinations.create({
    source: source.name,
    destination_url: source.url,
  });
  console.log(`Created destination for ${source.name}`);
}
```

---

## Authentication

All API requests use Bearer token authentication:

```
Authorization: Bearer <your-api-key>
```

Get your API key from the [Relae dashboard](https://relaehook.com/dashboard).

⚠️ **Security:** Never commit API keys to version control. Use environment variables:

```typescript
const relae = new Relae(process.env.RELAE_API_KEY!);
```

---

## Request IDs

Every request automatically includes a unique `X-Request-Id` header for tracking and debugging purposes. This can be useful when contacting support about specific API calls.

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Support

- **Documentation:** [https://docs.relaehook.com](https://docs.relaehook.com)
- **Email:** <support@relaehook.com>
- **Issues:** [GitHub Issues](https://github.com/WillBallentine/relae-node/issues)

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
