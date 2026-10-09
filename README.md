# npm-dns

A tiny DNS server that answers for the `server_name`s configured in
[Nginx Proxy Manager](https://nginxproxymanager.com/) and forwards everything
else to a public resolver.

It reads `proxy_host/*.conf` from the NPM data directory **on every query**, so
hosts added or removed in NPM are visible immediately with no restart.

## How a query is answered

For a query name `Q`, in order:

1. **`A_<Q>` rule** (exact name only): answer with that address. Subdomains of
   `Q` are *not* covered.
2. **`Q` is an NPM server_name** (exact, or under an nginx `*.` wildcard) and a
   `CNAME_<domain>` rule exists for `Q` or one of its parent domains: answer
   with a CNAME to that target. The most specific (longest) domain wins.
   The CNAME is chased, so the target's A record (local rule or fallback) is
   included in the same reply.
3. Otherwise forward the query unchanged to `FALLBACK`.

Names that are not in NPM are always forwarded, even if a `CNAME_` rule covers
their domain.

## Configuration

Everything is an environment variable. In rule names `_` means `.` and `__`
means `-`.

| Variable | Default | Meaning |
|---|---|---|
| `CNAME_<domain>=<target>` | | CNAME for `<domain>` and every NPM host under it |
| `A_<host>=<ipv4>[,<ipv4>]` | | A record(s) for exactly `<host>` |
| `FALLBACK` | *(none → REFUSED)* | Upstream resolver(s), comma separated, `host[:port]` |
| `LISTEN` | `:53` | Listen address (UDP and TCP) |
| `NPM_DATA` | `./data/nginx` | NPM nginx dir containing `proxy_host/` |
| `TTL` | `60` | TTL for locally generated records |
| `LOG_QUERIES` | | Set to `1` to log each query and its answer |

Example:

```sh
CNAME_myserver_com=servera.myserver.com          # *.myserver.com and the apex
CNAME_chat_myserver_com=serverb.myserver.com # overrides for chat.* and below
A_servera_myserver_com=192.168.0.69
A_rest__backend_myserver_com=192.168.0.5      # rest-backend.myserver.com
FALLBACK=1.1.1.1
```

## Running

```sh
go build -o npm-dns .
LISTEN=:5533 FALLBACK=1.1.1.1 CNAME_myserver_com=servera.myserver.com \
  A_servera_myserver_com=192.168.0.69 ./npm-dns

dig @127.0.0.1 -p 5533 git.myserver.com
```

With Docker, mount NPM's data volume read-only:

```sh
docker build -t npm-dns .
docker run -p 53:53/udp -p 53:53/tcp -v /path/to/npm/data/nginx:/data/nginx:ro \
  -e FALLBACK=1.1.1.1 -e CNAME_myserver_com=servera.myserver.com \
  -e A_servera_myserver_com=192.168.0.69 npm-dns
```

## Tests

```sh
go test ./...
```
