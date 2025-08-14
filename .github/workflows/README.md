# Daily OTS Timestamping for Rule 16 Compliance

This GitHub Action automatically creates daily OpenTimestamps proofs of the complete commit history to ensure continuous Rule 16 compliance.

## What it does

1. **Daily execution** at 12:00 UTC (configurable)
2. **Generates commit list** - All commit hashes in chronological order
3. **Creates SHA256 hash** - Hash of the newline-separated commit list
4. **OpenTimestamps proof** - Anchors the hash to Bitcoin blockchain
5. **Stores evidence** - Organized by date in `.timestamps/` directory
6. **Creates releases** - Public releases with timestamp proofs
7. **Uploads artifacts** - GitHub artifacts for backup

## Files generated

- `commits.txt` - Complete commit history (newline-separated hashes)
- `commits.sha256` - SHA256 hash of commit list
- `commits.sha256.ots` - OpenTimestamps proof file
- `latest-commits.sha256.ots` - Always points to most recent proof

## Verification

```bash
# Verify the latest timestamp
ots verify latest-commits.sha256.ots

# Verify a specific date
ots verify .timestamps/2025-08-14/commits.sha256.ots
```

## Manual triggering

The workflow can be manually triggered from the GitHub Actions tab using the "workflow_dispatch" trigger.

## Rule 16 Compliance

This automation ensures:
- **Continuous timestamping** of development progress
- **Immutable blockchain proofs** that cannot be retroactively falsified
- **Public verification** through GitHub releases and artifacts
- **Organized historical record** of all timestamp proofs

Going forward, this provides perfect Rule 16 compliance for all JAM milestone submissions.
