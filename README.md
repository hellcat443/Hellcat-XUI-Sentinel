# Hellcat XUI Sentinel

Hellcat XUI Sentinel is a traffic enforcement daemon for 3X-UI, built by hellcat443.

Written in Go, this script monitors user traffic and automatically disables users who exceed a specified limit. It’s ideal for protecting public panels, stress servers, or enforcing fair usage policies.

## Features

- Monitors uplink and downlink traffic via the 3X-UI API
- Automatically disables users who exceed traffic threshold
- Stores banned users in ban.json to avoid re-disabling them
- Triggers a panel restart to immediately drop all active connections
- Automatically re-enables the user after 1 hour
- Supports multiple servers via config.json
- Logs all activity to monitor.log

## Files

- config.json – list of panel credentials and inbound IDs
- prev_usage.json – stores previous usage for delta calculation
- ban.json – stores banned clients to avoid reprocessing
- monitor.log – logs all monitoring actions and errors

## Why?

Built for precision control over 3X-UI deployments, especially in scenarios where traffic abuse can’t be tolerated. Lightweight, fast, and fully autonomous.
