# Residence Management System — C++ Edition

Zero external dependencies. Pure C++17 + POSIX sockets.

## Build

```bash
g++ -std=c++17 -O2 -o residence main.cpp -lpthread
```

## Run

```bash
./residence
# Open http://localhost:3000
```

Custom port or DB file:
```bash
./residence 8080 mydb.json
```

## Default credentials

| Role     | Username | Password  |
|----------|----------|-----------|
| Admin    | admin    | admin123  |
| Resident | *(self-register)* | — |

## Features

- **Login system** — residents self-register with name, room number, username & password
- **News** — admin posts announcements by category (Kitchen, Laundry, Maintenance, General)
- **Events** — create events, residents register with their name/room auto-filled
- **Laundry booking** — visual time-slot picker per machine, prevents overlaps
- **Equipment booking** — 1hr/day limit per resident per item
- **Admin panel** — full management of users, news, events, bookings, notices
- **Real-time updates** — Server-Sent Events push changes to all connected browsers
- **Persistent storage** — JSON file database, auto-saves on every change

## Architecture

- Single `main.cpp` file (~2000 lines)
- Embedded frontend (complete SPA in a raw string literal)
- POSIX sockets HTTP server, one thread per connection
- SHA-256 password hashing (10,000 iterations, custom salt per user)
- In-memory session tokens (Bearer auth, 7-day TTL)
- JSON parser/serializer (no external libs)
