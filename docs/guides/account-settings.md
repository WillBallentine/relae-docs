# Account Settings

Manage your profile, team members, billing, and webhook security settings.

## Accessing Account Settings

1. Log in to your [dashboard](https://relaehook.com/dashboard)
2. Click **Account** in the top navigation
3. Select a section from the sidebar

![Account Settings](/img/account-settings.png)

## Sections Overview

Your account settings are organized into four main sections:

- **Profile**: Personal information and account details
- **Team**: Manage team members and roles (Launch tier and above)
- **Webhooks**: Security settings and signature verification
- **Billing**: Subscription and payment management (Owner only)

---

## Profile Settings

Manage your personal information and account details.

### Personal Information

#### Name

Your display name shown in the dashboard and team member list.

**To update:**

1. Go to Account → Profile
2. Enter your name in the **Name** field
3. Click **Save Changes**

#### Email

Your email address for login and notifications.

**To update:**

1. Enter new email in the **Email** field
2. Click **Save Changes**
3. Verify the new email address

**Email Verification:**

- ✅ **Verified**: Green checkmark indicates email is verified
- ⚠️ **Not Verified**: Yellow warning - check your inbox for verification email

:::warning Email Changes
Changing your email requires re-verification. You'll receive a verification email at the new address.
:::

### Account Information

#### Account ID

Your unique account identifier.

```
acc_1234567890abcdef
```

**Uses:**

- API authentication
- Support requests
- Webhook tracking
- Billing references

**To copy:** Click the text to select, then copy to clipboard.

### Alert Email (Admin/Owner Only)

Configure where account-level alerts are sent.

**Alert types:**

- High failure rates
- Billing issues
- Security notifications
- System updates

**To configure:**

1. Enter email in **Account Alert Email** field
2. Click **Save Changes**

:::tip Multiple Recipients
Want alerts sent to multiple people? Use an email distribution list (e.g., `alerts@company.com`) or set up forwarding rules.
:::

---

## Team Management

Collaborate with your team by inviting members and managing roles.

:::info Availability
Team features are available on **Launch**, **Scale**, and **Enterprise** tiers.
[Upgrade to enable team collaboration →](https://relaehook.com/dashboard)
:::

### Team Roles

Relae has four team roles with different permissions:

#### Owner 👑

**Permissions:**

- ✅ Full account access
- ✅ Manage billing and subscription
- ✅ Invite and remove all team members
- ✅ Assign admin role
- ✅ View and manage webhooks
- ✅ Configure destinations
- ✅ View analytics

**Limitations:**

- Only one owner per account
- Cannot be removed (transfer ownership first)

#### Admin 🛡️

**Permissions:**

- ✅ Invite and remove members
- ✅ View and manage webhooks
- ✅ Configure destinations
- ✅ View analytics
- ✅ Update account alert email

**Limitations:**

- ❌ Cannot manage billing
- ❌ Cannot remove owner
- ❌ Cannot assign admin role (owner only)

#### Member ⚙️

**Permissions:**

- ✅ View webhooks
- ✅ Manage Dead Letter Queue
- ✅ Retry failed webhooks
- ✅ Configure destinations
- ✅ View analytics

**Limitations:**

- ❌ Cannot invite users
- ❌ Cannot remove team members
- ❌ Cannot manage billing

#### Read-Only 👁️ (Scale & Enterprise)

**Permissions:**

- ✅ View webhooks
- ✅ View destinations
- ✅ View analytics

**Limitations:**

- ❌ Cannot modify anything
- ❌ Cannot retry webhooks
- ❌ Cannot invite users
- ❌ Perfect for stakeholders and auditors

:::tip Role Selection

- **Developers**: Member role
- **DevOps/SRE**: Admin role
- **Managers/Stakeholders**: Read-only role
- **Finance/Billing**: Keep as owner or admin
  :::

### Inviting Team Members

**Prerequisites:**

- Admin or Owner role
- Launch tier or above

**Steps:**

1. Go to **Account** → **Team**
2. Click **+ Invite User**
3. Enter the user's email address
4. Select their role:
   - Admin (Owner only)
   - Member
   - Read-Only (Scale/Enterprise)
5. Click **Send Invitation**

![Invite User Modal](/img/invite-user.png)

**What happens next:**

1. User receives invitation email
2. They click the verification link
3. Create a password (if new to Relae)
4. Gain access to your account

:::info Invitation Expiration
Invitations expire after 7 days. If needed, remove and re-invite the user.
:::

### Managing Team Members

View all team members with their:

- Name and email
- Current role
- Last seen timestamp
- Verification status

![Team Members List](/img/team-members.png)

#### Removing Team Members

**Prerequisites:**

- Admin or Owner role
- Cannot remove yourself
- Cannot remove owner (unless you are owner)

**Steps:**

1. Find the team member
2. Click the **Trash** icon (🗑️)
3. Confirm removal

**What happens:**

- User loses access immediately
- Cannot log in to the account
- Any active sessions are invalidated
- Can be re-invited later

:::warning Removing Members
Removed members lose access immediately. Make sure to remove them from any shared credentials or documentation.
:::

### Role Indicators

Each team member has a visual role badge:

- 👑 **Owner**: Yellow badge
- 🛡️ **Admin**: Blue badge
- ⚙️ **Member**: Green badge
- 👁️ **Read-Only**: Gray badge

---

## Webhook Security

Configure security settings for webhooks forwarded from Relae to your endpoints.

### Relae Webhook Secret

Your unique secret for verifying webhooks from Relae.

**Format:** `whsec_` followed by 48 random characters

**Example:**

```
whsec_abc123def456ghi789jkl012mno345pqr678stu901vwx234yz
```

### Viewing Your Secret

1. Go to **Account** → **Webhooks**
2. Find **Relae Webhook Secret** section
3. Click the **Eye** icon (👁️) to reveal
4. Click again to hide

![Webhook Secret](/img/webhook-secret.png)

:::danger Keep It Secret
Never commit your webhook secret to version control or share it publicly. Always use environment variables.
:::

### Copying Your Secret

**Option 1: Copy Button**

1. Click the **Copy** button
2. Secret is copied to clipboard
3. Paste into your environment variables

**Option 2: Manual Copy**

1. Click the **Eye** icon to reveal
2. Select and copy the text
3. Click **Eye** again to hide

### Using Your Secret

Store as an environment variable:

**Linux/Mac:**

```bash
export RELAE_WEBHOOK_SECRET="whsec_abc123..."
```

**Windows (PowerShell):**

```powershell
$env:RELAE_WEBHOOK_SECRET="whsec_abc123..."
```

**Docker:**

```yaml
environment:
  - RELAE_WEBHOOK_SECRET=whsec_abc123...
```

**Node.js (.env file):**

```
RELAE_WEBHOOK_SECRET=whsec_abc123...
```

Then verify webhooks in your application:

```javascript
const signature = req.headers["x-relae-signature"];
const secret = process.env.RELAE_WEBHOOK_SECRET;

if (!verifyRelaeWebhook(payload, signature, secret)) {
  return res.status(401).json({ error: "Invalid signature" });
}
```

[See complete verification examples →](/guides/verifying-signatures)

### Regenerating Your Secret

**When to regenerate:**

- 🔐 Secret was exposed or committed to Git
- 🔄 Regular security rotation (every 90 days)
- 👤 Team member with access leaves
- 🚨 Suspected security breach

**Steps:**

1. Go to **Account** → **Webhooks**
2. Click **Regenerate Secret**
3. Confirm the action

:::warning Breaking Change
Regenerating immediately invalidates the old secret. Update all your endpoints before regenerating!
:::

**Recommended process:**

1. Deploy new secret to staging environment
2. Test webhook verification works
3. Deploy to production
4. Wait for all instances to update
5. Then regenerate secret in Relae
6. Monitor for verification failures

### Code Examples by Language

The Account → Webhooks page includes copy-paste verification code in:

- **Node.js** (Express)
- **Python** (Flask)
- **Go**
- **Ruby** (Sinatra)
- **PHP**
- **Java** (Spring Boot)
- **C#** (ASP.NET Core)

**To use:**

1. Select your language from dropdown
2. Review the code
3. Click **Copy** button
4. Paste into your application
5. Update the secret in environment variables

---

## Billing & Subscription

Manage your subscription, payment methods, and billing information.

:::info Owner Only
Only account owners can access billing settings. Other team members see a restricted view.
:::

### Current Plan

View your active subscription tier and status:

![Current Plan](/img/current-plan.png)

**Information shown:**

- **Tier**: Free, Launch, Scale, or Enterprise
- **Status**: Active, Trialing, or Inactive
- **Trial end date** (if applicable)
- **Cancellation date** (if subscription is ending)

**Status badges:**

- 🟢 **Active**: Subscription is active and billing normally
- 🔵 **Trialing**: In trial period, no charges yet
- ⚠️ **Canceling**: Will end at period close
- ⚫ **Inactive**: No active subscription

### Managing Billing

Click **Manage Billing & Payment** to access Stripe's secure billing portal.

**What you can do:**

- Update credit card
- View payment history
- Download invoices
- Update billing address
- Add tax ID/VAT number

**Security:**

- Managed by Stripe (PCI compliant)
- Relae never sees your card details
- All data encrypted in transit

### Upgrading Your Plan

**From Free to Launch/Scale:**

1. Click **Upgrade to Launch →** button
2. Redirected to Stripe checkout
3. Enter payment details
4. Complete checkout
5. Instant access to new features

**From Launch to Scale:**

1. Click **Upgrade to Scale →** button
2. Prorated charge for remainder of billing period
3. Immediate upgrade

**Plan comparison:**

| Feature         | Free   | Launch  | Scale   |
| --------------- | ------ | ------- | ------- |
| Events/month    | 10K    | 100K    | 500K    |
| Retention       | 7 days | 14 days | 30 days |
| Team members    | ❌     | ✅      | ✅      |
| Analytics       | ❌     | ❌      | ✅      |
| Read-only users | ❌     | ❌      | ✅      |

[See full pricing details →](https://relaehook.com/#pricing)

### Canceling Subscription

**Steps:**

1. Go to **Account** → **Billing**
2. Click **Cancel Subscription**
3. Confirm cancellation

**What happens:**

- ✅ Keep access until end of billing period
- ✅ No future charges
- ⚠️ Data retention follows tier limits
- ⚠️ Downgraded to Free at period end

**Example:**

```
Today: December 1
Billing period ends: December 31
Cancel today → Keep access until Dec 31
Jan 1 → Downgrade to Free tier
```

:::tip Changed Your Mind?
You can reactivate before the period ends. Click **Reactivate Subscription** in billing settings.
:::

### Reactivating Subscription

If you canceled but want to continue:

1. Go to **Account** → **Billing**
2. Click **Reactivate Subscription**
3. Subscription continues normally
4. Next billing cycle proceeds as scheduled

**Must reactivate before:** End of current billing period

### Trial Period

**New paid subscriptions include:**

- 14-day free trial
- Full access to tier features
- No credit card required upfront (some tiers)
- Cancel anytime during trial

**Trial status shown in billing:**

```
Trial active until January 15, 2024
```

**After trial ends:**

- Automatic billing starts
- Subscription becomes active
- Keep same tier and features

### Billing Cycle

**When you're charged:**

- Monthly subscriptions: Same day each month
- First charge: After trial or immediately (if no trial)
- Upgrades: Prorated for current period

**Example monthly cycle:**

```
Dec 1: Subscribe to Launch ($35/mo)
Dec 15: Upgrade to Scale ($65/mo)
Dec 15: Charged $25 prorated (half of $50 difference)
Jan 1: Charged $65 (full Scale tier price)
```

### Payment Failed

If payment fails:

1. You'll receive email notification
2. Stripe retries automatically (3 times)
3. Update payment method in billing portal
4. Subscription suspends if all retries fail

**To prevent:**

- Keep card details updated
- Set up backup payment method
- Monitor billing email alerts

### Invoices & Receipts

**Accessing invoices:**

1. Click **Manage Billing & Payment**
2. View **Billing history** in Stripe portal
3. Download PDF invoices
4. Email receipts

**What's included:**

- Invoice number
- Date and amount charged
- Payment method used
- Billing address
- Line items (subscription, overage)

### Overage Charges

If you exceed your plan's event limit:

**Launch tier:**

- Base: 100,000 events/month
- Overage: $0.00015 per additional event
- Example: 120,000 events = $35 + (20,000 × $0.00015) = $38

**Scale tier:**

- Base: 500,000 events/month
- Overage: $0.0001 per additional event
- Example: 550,000 events = $65 + (50,000 × $0.0001) = $70

**Viewing usage:**
Check current usage in [Analytics dashboard →](/guides/analytics)

---

## Best Practices

### Security

1. ✅ **Enable 2FA** on your email account
2. ✅ **Use strong, unique password** for Relae
3. ✅ **Rotate webhook secret** every 90 days
4. ✅ **Limit team members** to those who need access
5. ✅ **Use read-only role** for stakeholders
6. ✅ **Remove ex-employees** immediately

### Team Management

1. ✅ **Document who has access** and why
2. ✅ **Review team members** quarterly
3. ✅ **Use appropriate roles** (don't over-permission)
4. ✅ **Set up alert email** to distribution list
5. ✅ **Train team** on webhook management

### Billing

1. ✅ **Monitor usage** regularly in analytics
2. ✅ **Set calendar reminder** for trial end
3. ✅ **Keep payment method** updated
4. ✅ **Download invoices** for accounting
5. ✅ **Plan upgrades** before hitting limits

---

## Troubleshooting

### Can't Access Account Settings

**Issue:** Account button not showing

**Solutions:**

1. Make sure you're logged in
2. Check you're not on landing page
3. Refresh the page
4. Try different browser
5. Clear cache and cookies

### Can't Invite Team Members

**Issue:** No "Invite User" button

**Possible causes:**

1. ❌ On Free tier (upgrade required)
2. ❌ Not admin or owner role
3. ❌ Account not verified

**Solution:** Upgrade to Launch tier or contact owner for role change

### Webhook Secret Not Working

**Issue:** Signature verification failing

**Check:**

1. ✅ Using correct secret (not vendor secret)
2. ✅ Secret stored as environment variable
3. ✅ Application restarted after updating secret
4. ✅ Using correct verification code
5. ✅ Headers being read correctly

[See signature verification guide →](/guides/verifying-signatures)

### Payment Issues

**Issue:** Payment declined or failing

**Steps:**

1. Check card hasn't expired
2. Verify sufficient funds
3. Update payment method in billing portal
4. Contact your bank if card is being blocked
5. Try different payment method

**Still having issues?**
Email [support@relaehook.com](mailto:support@relaehook.com) with:

- Account ID
- Error message
- Last 4 digits of card (if applicable)

### Can't Cancel Subscription

**Issue:** No cancel button or error when canceling

**Possible causes:**

1. ❌ Not the account owner
2. ❌ Already canceled
3. ❌ No active subscription

**Solution:**

- Ask owner to cancel
- Or check billing status in Stripe portal

---

## Frequently Asked Questions

### Can I change the account owner?

Not currently. If you need to transfer ownership:

1. Invite new owner as admin
2. They should subscribe on new account
3. Migrate destinations
4. Cancel original account

Contact [support@relaehook.com](mailto:support@relaehook.com) for assistance.

### How many team members can I have?

**Launch & Scale:** Unlimited team members

**Role limits:**

- Owner: 1
- Admin: Unlimited
- Member: Unlimited
- Read-only: Unlimited (Scale/Enterprise only)

### What happens if I downgrade?

**Immediate effects:**

- Keep current features until period end
- No new charges for lower tier yet

**At period end:**

- Features restricted to new tier
- Data retention reduced (older events deleted)
- Team access may be limited (Free tier)

### Can I get a refund?

Refunds are handled case-by-case:

- Trial cancellations: No charge, no refund needed
- Service issues: Contact support
- Change of mind: Generally no refunds, but ask

Email [support@relaehook.com](mailto:support@relaehook.com)

### Do you offer discounts?

**Startup/nonprofit discounts:**
Contact [support@relaehook.com](mailto:support@relaehook.com) with:

- Company details
- Current traction/usage
- How you heard about Relae

**Annual billing:**
Email for annual pricing (20% discount typical)

### Is my payment information secure?

Yes!

- Payments processed by Stripe
- Relae never sees card numbers
- Industry-standard encryption

---

## Next Steps

- [Configure Destinations →](/guides/managing-webhooks)
- [Verify Webhook Signatures →](/guides/verifying-signatures)
- [View Analytics →](/guides/analytics)
- [Set Up Common Vendors →](/guides/common-vendors)

## Need Help?

- 📧 Email: [support@relaehook.com](mailto:support@relaehook.com)
- 💬 Questions about account settings
- 🔐 Security concerns
- 💳 Billing inquiries
