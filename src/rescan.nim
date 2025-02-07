{.define: ssl.}

import fp/[utils], std/[os, tables]

# Try fetching VT key before doing anything
# More of a UX change than a practical one.
discard fetchVirustotalKey()

var versionData = parseNimData(getNimDataFile())

# This is the max number of commands we will run per minute
# I just chose 8 arbitrarily but you can set it to anything with -d:limit=NUMBER
const limit{.intdefine.} = 5
var num = 0 # Number of *current* tasks running.
for hash in versionData[0].keys:
  inc num
  if num >= limit:
    sleep(60000)
    num = 0
  rescanVersion(hash, versionData)