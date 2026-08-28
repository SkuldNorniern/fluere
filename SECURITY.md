# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.8.x | yes |
| 0.7.x | security fixes only |
| < 0.7 | no |

There has never been a 1.x release. The table used to say otherwise.

## Reporting a vulnerability

Do not open a public issue for a vulnerability. Use GitHub's
[private vulnerability reporting](https://github.com/SkuldNorniern/fluere/security/advisories/new)
instead, which keeps the report between you and the maintainers until there is
a fix.

What happens after that:

- acknowledged within 4 working days
- you get updates as it is looked at, fixed, or declined
- if it is declined you get the reason
- credit in the release notes when it is fixed, unless you would rather not

## Plugins are not sandboxed

Plugins run inside the fluere process with the permissions of that process. A
Lua plugin can read and write files and do everything else the standard library
allows, and all Lua plugins share one interpreter state.

Installing a plugin is running its code. Treat a plugin config entry the way
you would treat a script you are about to run as root, because under `sudo`
that is what it is.

## Capturing needs privileges

Reading packets off an interface needs `CAP_NET_RAW` and `CAP_NET_ADMIN` on
Linux, or root. Rather than running the whole thing under `sudo`:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip ./fluere
```

Converting a pcap file needs no privileges at all.
