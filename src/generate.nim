{.define: ssl.}

import fp/utils, std/[tables, strutils, os]

var
  versionData = parseNimData(getNimDataFile())
  startT = readFromTemp("start")
  endT = readFromTemp("end")

# A var with the type Table[string, string] gets created
#                            ^ Antivirus Engine name
#                                      ^ Intermediate list of detections
var intermediateEmails: Table[string, string]
# The process of generating emails is done like so:
# 1. We loop over every detection
# 2. We generate a human-readable summary of the detection and
#    append it to the appropriate key in the intermediateEmails table
#
# As we go on, our final list of emails will be one where each key in a
# table corresponds to a single AV company, so we only have to send a single email
# This is kinda memory and computationally intensive tho
for jsonFile in walkDir("json", true):
  echo "Reading JSON data file ", jsonFile[1]
  for detection in parseVTData(readFile(jsonFile[1]), versionData):
    let tmp = """

  Version: $#
  Detection: $#
  AV Engine Version: $#
  AV Engine Update: $#
  VirusTotal link: https://www.virustotal.com/gui/file/$#
  Download link: $#

  """ % [
      prettifyVersion(tupleVerToString(detection.version), detection.architecture),
      detection.detection, detection.engine_version, detection.engine_update,
      detection.virustotal, detection.download
    ]
    if intermediateEmails.hasKey(detection.antivirus_name):
      intermediateEmails[detection.antivirus_name] = intermediateEmails[detection.antivirus_name] & tmp
    else:
      intermediateEmails[detection.antivirus_name] = tmp

for av, email in intermediateEmails.pairs:
  echo "Writing down email for ", av
  writeEmail(
    av,
    $(startT % [av]) & email & endT
  )