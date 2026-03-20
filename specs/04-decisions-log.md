# Decisions Log (Locked)

## Confirmed

1. Priority order for v1:
   - reliability and memory safety on constrained hardware
   - operational simplicity
   - query flexibility/performance tuning
2. v1 interface scope:
   - in: CLI and Telegram
   - out: web app
3. Sensitive data handling:
   - default output is masked for `password`, `password_hash`, `email`, `phone`, `address`
   - explicit reveal flag is available for authorized local usage
4. Storage lifecycle:
   - keep raw dumps forever in v1
   - keep normalized artifacts forever in v1

## Non-Blocking Future Choices

- If/when AWS S3 migration starts, revisit lifecycle policy and storage class transitions.
- If web app is introduced post-v1, re-apply masking/reveal policy in UI layer.
