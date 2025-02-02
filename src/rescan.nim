{.define: ssl.}

import fp/[utils], std/[os, tables]

var versionData = parseNimData(getNimDataFile())

when compileOption("threads"):
  if not fileExists("bin/rescan_cmd"):
    discard execShellCmd("nimble build rescan_cmd")

# The easiest way to do multi-threading is to just utilize commands
# Anyway this is the max number of commands we will run per minute
# I just chose 8 arbitrarily but you can set it to anything with -d:limit=NUMBER
const limit{.intdefine.} = 8
var num = 0 # Number of *current* tasks running.
for hash in versionData[0].keys:
  when compileOption("threads"):
    echo "Threads enabled! Running ", limit, " rescans at a time!"
    if num >= 4:
      sleep(60000)
      num = 0
    inc num
    discard execShellCmd("bin/rescan_cmd " & hash)
  else:
    echo "Threads disabled... This will be way slower than usual."
    echo "Consider compilling with --threads:off to get a significant performance boost."
    rescanVersion(hash, versionData)