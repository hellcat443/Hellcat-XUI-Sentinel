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

## Usage

This tool is designed for use with [3X-UI](https://github.com/MHSanaei/3x-ui), a powerful Xray panel.

To run:

1. Build the binary using Go:

   go build -o hellcat443 main.go

2. Create a config.json file with your 3X-UI server details:

   {
     "MyServer": {
       "baseUrl": "https://your-server:port/your-panel-path",
       "username": "admin",
       "password": "yourpassword",
       "inboundId": 3
     }
   }

3. Run the binary with desired parameters:

   ./hellcat443-sentinel -threshold=100 -interval=60

This example sets a 100MB limit and checks usage every 60 seconds.

## Why?

Built for precision control over 3X-UI deployments, especially in scenarios where traffic abuse can’t be tolerated. Lightweight, fast, and fully autonomous.
