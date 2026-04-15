# API Specification: Fortgate ID SDK

## ⚙️ Global Configuration (FortgateConfig)
| Parameter | Type | Description |
| :--- | :--- | :--- |
| `minTier` | `SecurityTier` | Minimum hardware tier accepted (Maximum, High, Medium). |
| `locationTolerance` | `number` | Tolerance radius in meters from fiscal address. |

## 🌐 TypeScript Usage
```typescript
const fortgate = new FortgateID({ 
  minTier: SecurityTier.Maximum,
  locationTolerance: 2000 
});

const result = await fortgate.verifyIdentity(certBuffer);
```

## 📊 IdentityResult
```json
{
  "status": "Verified",
  "nullifier": "0x12a...",
  "actualTier": "High",
  "locationStatus": "InsideRange",
  "attestationId": "att_..."
}
```
