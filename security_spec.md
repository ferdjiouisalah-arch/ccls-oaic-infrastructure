# Security Specification — CCLS / OAIC Storage Infrastructure App

## 1. Data Invariants
1. **Owner Scoping**: Every `Facility`, `FacilityPhoto`, and `UserProfile` document is strictly owned by `request.auth.uid` (`ownerId == request.auth.uid` or `userId == request.auth.uid`).
2. **Email Verification**: Every read and write requires `request.auth != null && request.auth.token.email_verified == true`.
3. **Referential Integrity**: A `FacilityPhoto` cannot be created unless its referenced `facilityId` exists in `/facilities/{facilityId}` and belongs to `request.auth.uid`.
4. **Immutable Ownership & Timestamps**: `ownerId`, `id`, `facilityId` (on photos), and `createdAt` cannot be modified after creation. `createdAt` and `updatedAt` must equal `request.time`.
5. **Strict Volumetric Limits**: Every string and bounded array (`cellGroups` max 20 items, `dataUrl` max 600,000 chars, `name` max 200 chars, IDs matching `^[a-zA-Z0-9_\-]+$` max 128 chars) is enforced in rules.
6. **Zero Blanket List Queries**: `allow list` rules strictly evaluate `resource.data.ownerId == request.auth.uid`.

## 2. The "Dirty Dozen" Adversarial Payloads
1. **Unauthenticated Create**: Creating `/facilities/site-01` with `auth == null` -> `PERMISSION_DENIED`.
2. **Unverified Email Spoof**: Creating `/facilities/site-01` with `email_verified: false` -> `PERMISSION_DENIED`.
3. **Identity Spoofing**: Creating `/facilities/site-01` with `ownerId: "victim_uid"` while signed in as `"attacker_uid"` -> `PERMISSION_DENIED`.
4. **Shadow / Ghost Field Injection**: Creating `/facilities/site-01` with an extra undeclared field `isAdmin: true` -> `PERMISSION_DENIED`.
5. **ID Poisoning**: Creating `/facilities/bad$id..with..slash` or a 200-char ID -> `PERMISSION_DENIED`.
6. **Timestamp Forgery**: Creating `/facilities/site-01` with a backdated `createdAt` not equal to `request.time` -> `PERMISSION_DENIED`.
7. **Owner Mutation on Update**: Updating `/facilities/site-01` to change `ownerId` -> `PERMISSION_DENIED`.
8. **Type Poisoning on Update**: Updating `/facilities/site-01` setting `length: "not-a-number"` or `name: 12345` -> `PERMISSION_DENIED`.
9. **Unbounded Array Attack**: Creating `/facilities/site-01` with 25 items in `cellGroups` (> 20 limit) -> `PERMISSION_DENIED`.
10. **Orphan Photo Write**: Creating `/facility_photos/p1` referencing a non-existent `facilityId` or a facility owned by another user -> `PERMISSION_DENIED`.
11. **PII Cross-User Read**: Reading `/users/other_uid` while signed in as `attacker_uid` -> `PERMISSION_DENIED`.
12. **Blanket List Scraping**: Listing `/facilities` without filtering `where("ownerId", "==", request.auth.uid)` -> `PERMISSION_DENIED`.
