# Victim container

The victim uses the stock `nginx:1.27-alpine` image with no custom build. Three files are mounted read-only:

- `nginx.conf`: serves a static page at `/` and protects `/admin/` with HTTP basic authentication.
- `htpasswd`: one lab-only account (`admin`), used as the login target for the brute-force demo.
- `html/index.html`: the static page.

A stock image was chosen so the protected server is ordinary, well-known software, and so the lab has nothing custom to maintain on the victim side. The NIDS container shares this container's network namespace (`network_mode: service:victim`), so it sees every packet the victim sends and receives, and its iptables rules apply to the victim's traffic.
