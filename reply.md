Great piece, Martin. From the CISO seat, the root cause behind every one of these stories is the same: the firmware is closed. You can't verify what your router is doing, who it's talking to, or what's listening — you just have to trust the vendor. And "trust us" never survives an incident review.

That's why I built AiFw: an open-source firewall for FreeBSD (pf + Rust, MIT). Every line is public — no hidden telemetry, no secret ports, nowhere to hide a backdoor. The only firewall I'd put in front of my own family is one I'm allowed to read.

Happy to share the repo for anyone who wants to audit it themselves.
