# Antivirus False Positive Reduction Suite. (nim-fp-suite)

A set of programs and files to generate emails which will be sent to antivirus companies to (hopefully) reduce false positives in the long run. 

## *2025 Update*

This code has been updated, and it should be way cleaner now. Although there are still a couple of pain spots.

## How to use

This single repository includes a suite of programs each designed for a specific task. Each one can be ran with `nimble run PROGRAM` where `PROGRAM` is one of the following:

* `rescan`: This issues "re-analyze" requests to VirusTotal
* `fetch`: This fetches the VirusTotal data for nim binaries
* `generate`: This uses the previously fetched data to generate a bunch of emails/messages to be sent to antivirus companies.
* `all`: This program just runs all the above three in a sensible order.

So in order to use this suite of tools, you should do the following:

1. Get a VirusTotal API key and create a file named `.vt_key` containing it.
2. Execute `nimble run rescan` to re-scan every nim binary. (The command finishes immediately but waiting for the rescans to finish takes a while.)
2. Execute `nimble run fetch` to fetch VirusTotal data
3. Adjust the `start` and `end` templates to your hearts content. (Maybe add your own contact info instead of mine lol)
4. And then run `nimble run generate` to generate the emails!
5. Voila! You should be able to find the emails in the `emails/` folder. Good luck!

You now have to manually find each antivirus company's email and forward the results to them. `nim-fp-suite` might in the future make this process easier, but I have decided not to implement it for now.

Here is a [github repo that should help](https://github.com/yaronelh/False-Positive-Center)
