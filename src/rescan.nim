{.define: ssl.}

import fp/[utils], std/[os, tables, options]

var versionData = parseNimData(getNimDataFile())

for hash in versionData[0].keys:
  echo "Issuing rescan for ", prettifyVersion(tupleVerToString(versionData[0][hash][0]), versionData[0][hash][1])
  let rescanData = issueVTRescan(hash, fetchVirustotalKey())
  if isSome(rescanData):
    echo "Rescan issue succeeded!"
    echo "Waiting patiently now for VT to finish scanning..."
    var count = 0
    while not isVTRescanDone(get(rescanData), fetchVirustotalKey()):
      inc count
      echo "Rescan nr.", count
      sleep(60000)
    echo "Moving on now!"
  else:
    echo "Rescan issue failed..."