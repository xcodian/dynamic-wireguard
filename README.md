# ♾️ dynamic-wireguard
Make WireGuard connections with servers without any pre-configuration. You can use this as a general-purpose VPN connection
system, using something like a username & password to connect. No static addressing required!

## Motive
WireGuard is inflexible.
- It uses static IP addresses everywhere
- It requires exchanging the public keys of peers out-of-band
- It needs complex settings on the peer's end for it to work

Now, don't get me wrong, **this isn't necessarily a bad thing**, in fact, it's actually really good to be rigorous for network design!
Furthermore, **WireGuard gets its job done well - it's a secure & fast tunnel** you can use to connect point-to-point or use as a VPN proxy.

However, sometimes, you need to have flexibility with your connections. One example is **a VPN server hosted for a large number of people**, with
**peers coming & going** & authentication systems determining whether they are allowed to connect.

This is where Dynamic Wireguard can help you. It allows:
- Dynamic addresses assigned to clients as they connect
- Exchanging all WireGuard configuration dynamically on the wire
- Pretty much no configurationn required to get up & running

## How It Works
(todo)

## How To Use It
(todo)

On the server:
```bash
$ dynwg-server -c server.conf
```

On the client:
```bash
$ dynwg join wg.example.net
Connecting to wg.example.net...
You are now connected!
```