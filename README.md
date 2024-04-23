# Nim false positive reduction suite

A suite of Nim programs and datasets that I use to create emails which I then send to antivirus companies in order to get them to stop flagging Nim as malware.

*note:* This code is not up to my standards as I made it only for myself as a quick hackjob, be warned, the code blinds its readers.

## How to use

1. Get a VirusTotal API key and make a file named `.vt_key` containing it.
2. Run `nimble fetch` to fetch VirusTotal data
3. Adjust the `start`, `end` and `detection` template files to your hearts content.
4. And then run `nimble generate` to generate the emails!
5. Voila! You should be able to find the emails in the `emails/` folder. Good luck!

## How does it work?

Well, there is one part that is not automated and that should be.
That is the submission of new Nim versions and the re-submission of old ones (in order to see if they have changed)
So you do need to manually submit every new nim release to virustotal, and to record it in the `virustotal links` file so that this program can work with it.

Please follow the format very strictly, I should probably re-write any code that uses `virustotal links` to use a more flexible JSON-based format but I dont want to re-write anything anymore, so whatever.

Also, no other architecture other than x64 and x32 is supported in the `virustotal_links` file, so don't bother scanning Nim Windows ARM releases (if there are any in the future.)