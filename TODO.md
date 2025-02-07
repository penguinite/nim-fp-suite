
* Implement async re-scanning... As in, we scan 2-6 versions at the same time...

Note: It's way easier to issue the max number of rescans we can in a minute, and instruct the user to wait an hour or two before running `nimble run fetch`
Also, in a way, this has been mitigated by the `rescan.yml` workflow which issues rescans every night.

* Implement auto upload of new nim versions.

It'll be a pain to implement multipart handling but I might be able to borrow code from nim-fp-data for this.

* Add support for Linux and other platforms

It'll require a small rewrite but nothing too major.
(Also PS: Make sure to migrate the archive data to the new format.)

* Distribute archive data on [ftp.penguinite.dev](https://ftp.penguinite.dev)

As a way for people to get data without connecting to github.
Altho, that domain is secured with cloudflare, so the benefits are unclear.