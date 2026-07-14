The family in the video below did everything they were told to do.

They still got hacked — through the one device they trusted most. Don't be like them. 👇

I've spent most of my career as a business owner, and a good part of it in the CISO chair — the person who's accountable when something goes wrong. Security has never been a side interest for me; it's the lens I see everything through. And one rule never changes: you cannot secure what you cannot inspect.

So here's what actually keeps me up at night — the home router. That one box sees every packet your family sends. Banking. Your work VPN. Your kid's homework. And it runs firmware you're not allowed to read, built by a vendor whose only answer is "trust us."

In my world, "trust us" isn't a security model. It's an incident waiting for a timestamp.

And these incidents are real:

🔓 Sercomm "port 32764" (2014) — a hidden service that handed full admin to anyone who knew the secret port. The same firmware shipped under Netgear, Linksys, and Cisco. One backdoor, a dozen logos.

🔓 Netgear's "telnetenable" magic packet — for years, models shipped with a hidden remote-login service you could wake up with a single crafted packet. Undocumented. By design.

🔓 CVE-2025-4978 (CVSS 9.3, this year) — on a Netgear router, one unauthenticated web request flips an internal flag that turns authentication completely off. One request, instant admin.

In plain English: imagine your front door has a second lock only the manufacturer knows about — and the key got copied. You can't see it. You can't change it. You find out when someone's already inside.

Malicious, lazy, or a "debug feature someone forgot to remove" — it doesn't matter to an attacker. The door is open either way.

This is structural. When firmware is closed, you can't audit it, can't see what it phones home to, can't know what's listening. You're handing a black box your entire network.

So I built the opposite.

AiFw is an open-source firewall for FreeBSD — built on pf, written in Rust, MIT licensed. Every line is public.

✅ No backdoors. And you don't take my word for it — read the code, diff it, compile it yourself.
✅ No secret ports, no magic packets, no hidden accounts. If one existed, the source would show it.
✅ Auditable by anyone — a security team or a curious teenager.
✅ Free. The AI threat detection is optional; it's a serious firewall with or without it.

A backdoor can't survive in the open. That's the whole point.

The only firewall I'd put in front of my own family is one I'm allowed to read.

👉 Go look at the code. That's a sentence the big vendors will never write.

#CISO #CyberSecurity #OpenSource #Firewall #NetworkSecurity #InfoSec #FreeBSD #Rust
