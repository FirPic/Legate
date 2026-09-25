# How-To: Create a Scoped Cloudflare API Token

This guide walks you through creating a restricted, least-privilege Cloudflare API token strictly permitted to manage DNS records for a single zone.

---

## Why Use a Scoped Token Instead of Global API Key?

- **Global API Key**: Grants full administrative access to your entire Cloudflare account (billing, zone deletion, account-level settings, all domains). If compromised, an attacker has total control.
- **Scoped API Token**: Strictly limited to `Zone.DNS:Edit` for a single specified domain. Cannot access billing, cannot modify other zones, and can be revoked instantly.

---

## Step-by-Step Creation Guide

### 1. Access the API Tokens Section
1. Log in to the [Cloudflare Dashboard](https://dash.cloudflare.com/).
2. In the top right corner, click on your profile icon and select **My Profile**.
3. In the left navigation menu, click **API Tokens**.
4. Click the blue **Create Token** button.

### 2. Configure a Custom Token
Scroll to the bottom of the templates page and select **Create Custom Token** by clicking **Get started**.

### 3. Fill in Permissions and Scope

Configure the token parameters as follows:

| Field | Configuration | Notes |
| :--- | :--- | :--- |
| **Token name** | `acme-dns-httpreq-proxy` | Descriptive identifier |
| **Permissions** | `Zone` | Resource type |
| | `DNS` | Sub-resource |
| | `Edit` | Required to create and delete TXT records |
| **Zone Resources** | `Include` | |
| | `Specific zone` | Do **not** select "All zones" |
| | Select your domain (e.g. `example.com`) | Target zone |
| **Client IP Address Filtering** *(Optional)* | `Is in` -> `Your proxy public/egress IP` | Restricts API use to proxy server IP |
| **TTL** | Set expiration or keep active | Align with rotation policies |

### 4. Review and Create
1. Click **Continue to summary**.
2. Verify that the scope shows only `Zone.DNS:Edit` for your specific zone.
3. Click **Create Token**.
4. **Copy the generated token immediately.** Cloudflare will not display this token again.

---

## Testing Your Token

Verify the token using `curl` before configuring `acme-dns-httpreq-proxy`:

### 1. Verify Token Validity
```bash
curl -s -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
  -H "Authorization: Bearer <YOUR_API_TOKEN>" | jq .
```

**Expected output:**
```json
{
  "result": {
    "id": "...",
    "status": "active"
  },
  "success": true,
  "errors": [],
  "messages": [
    {
      "code": 10000,
      "message": "This API Token is valid and active"
    }
  ]
}
```

### 2. Test Zone Access and Retrieve Zone ID
```bash
curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=example.com" \
  -H "Authorization: Bearer <YOUR_API_TOKEN>" | jq '.result[0] | {id: .id, name: .name, status: .status}'
```

**Expected output:**
```json
{
  "id": "023e105f4ecef8ad9ca31a8372d0c353",
  "name": "example.com",
  "status": "active"
}
```

---

## Configuring the Proxy

Assign the token to the `CLOUDFLARE_API_TOKEN` environment variable:

```bash
export CLOUDFLARE_API_TOKEN="<YOUR_API_TOKEN>"
export ALLOWED_DOMAIN="example.com"

# Optional optimization: pre-seed zone ID to skip zone lookup call
export CLOUDFLARE_ZONE_ID="023e105f4ecef8ad9ca31a8372d0c353"
```
