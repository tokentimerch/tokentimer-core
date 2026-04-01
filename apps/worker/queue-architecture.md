# Queue-Based Alert Architecture

## Overview

The alert system uses a queue-based architecture with clear separation of concerns:

1. **Queue Discovery Job** - Finds due alerts and queues them
2. **Delivery Worker Job** - Processes queued alerts and sends notifications

## Design principles

**Separation of concerns**
- Discovery: pure logic for finding due alerts
- Delivery: pure logic for sending notifications
- State management: clear queue status tracking

**Scalability**
- Discovery and delivery run on independent schedules
- Each job can be scaled independently via CronJob replicas

**Reliability**
- Failed alerts stay in queue for retry with backoff
- Successful alerts are marked as sent
- Full audit trail of all attempts via delivery log

## Database Schema

### Alert Queue Table

```sql
CREATE TABLE alert_queue (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL,
  token_id INTEGER NOT NULL,
  alert_key TEXT NOT NULL UNIQUE,
  threshold_days INTEGER NOT NULL,
  due_date DATE NOT NULL,
  channels JSONB NOT NULL DEFAULT '[]'::jsonb,
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  last_attempt TIMESTAMP NULL,
  error_message TEXT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
```

**Status values:**

- `pending` - Alert queued, ready to send
- `sent` - Alert successfully delivered to all channels
- `failed` - Alert failed to deliver, will retry
- `limit_exceeded` - User hit plan limit, won't retry

### Delivery Log Table

```sql
CREATE TABLE alert_delivery_log (
  id SERIAL PRIMARY KEY,
  alert_queue_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  token_id INTEGER NOT NULL,
  channel VARCHAR(16) NOT NULL,
  status VARCHAR(20) NOT NULL,
  sent_at TIMESTAMP NOT NULL DEFAULT NOW(),
  error_message TEXT NULL,
  metadata JSONB DEFAULT '{}'::jsonb
);
```

## Default Schedules

Schedules are configurable via Helm values (`worker.cronjobs.*`) or Docker Compose environment.

| Job | Default schedule | Helm value |
|-----|-----------------|------------|
| Alert Discovery | `*/5 * * * *` | `worker.cronjobs.discovery.schedule` |
| Alert Delivery | `*/5 * * * *` | `worker.cronjobs.delivery.schedule` |
| Weekly Digest | `0 9 * * 1` | `worker.cronjobs.weeklyDigest.schedule` |
| Endpoint Check | `*/1 * * * *` | `worker.cronjobs.endpointCheck.schedule` |
| Auto Sync | `0 * * * *` | `worker.cronjobs.autoSync.schedule` |

## Workflow Examples

### Normal Alert Flow

```
Day 1 - Token expires in 30 days:
  Discovery Job runs
  Finds token due for 30-day alert
  Queues alert: status='pending', channels=['email','slack']
  Audit: ALERT_QUEUED

5 minutes later:
  Delivery Job runs
  Finds pending alert
  Sends email: success
  Sends Slack: success
  Updates queue: status='sent'
  Logs delivery: 2 success records
  Audit: ALERT_SENT
```

### Failure Recovery Flow

```
Day 1 - SMTP down:
  Delivery Job runs
  Email fails: connection timeout
  Slack succeeds
  Updates queue: status='failed' (not all channels succeeded)
  Logs delivery: 1 failed, 1 success
  Audit: ALERT_SEND_FAILED

Day 1 - 5 minutes later (SMTP restored):
  Delivery Job runs
  Finds failed alert (status='failed')
  Retries email: success
  Skips Slack (already succeeded)
  Updates queue: status='sent'
  Audit: ALERT_SENT
```

## Monitoring Queries

### Queue Status Overview

```sql
SELECT
  status,
  COUNT(*) as count,
  MIN(due_date) as oldest_due,
  MAX(due_date) as newest_due
FROM alert_queue
GROUP BY status;
```

### Delivery Success Rates

```sql
SELECT
  channel,
  COUNT(*) as attempts,
  SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) as successes,
  ROUND(100.0 * SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) / COUNT(*), 2) as success_rate
FROM alert_delivery_log
WHERE sent_at >= NOW() - INTERVAL '7 days'
GROUP BY channel;
```

### Failed Alerts Needing Attention

```sql
SELECT
  aq.id,
  aq.user_id,
  aq.token_id,
  aq.threshold_days,
  aq.attempts,
  aq.error_message,
  aq.last_attempt
FROM alert_queue aq
WHERE aq.status = 'failed'
  AND aq.attempts >= 3
ORDER BY aq.last_attempt DESC;
```
