{.define: ssl.}

import fp/[utils], std/[os, tables, options, json]

var versionData = parseNimData(getNimDataFile())

if dirExists("json"):
  removeDir("json")
  createDir("json")

for hash, version in versionData[0].pairs:
  echo "Fetching VT scan data for ", hash
  let
    data = getVTScanData(hash, fetchVirustotalKey())
    fn  = versionToFilename(tupleVerToString(version[0]), version[1])
  if isSome(data):
    writeFile("json/" & fn, $(get(data)))
    echo "Writing to ", $("json/" & fn)
    echo "Moving on!"
  else:
    echo "Fetch failed... Moving on"