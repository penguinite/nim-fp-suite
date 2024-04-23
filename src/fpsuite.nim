{.define: ssl.}

import std/[os, httpclient, parsecsv, tables, strutils, streams, json, times]

const
  virusTotalKey{.strdefine.}: string = ""
  email_dir = "email"
  temp_dir = "templates"
  json_dir = "json"

# table[antivirus] = Table[version, (detection, engine_version)]
var
  hashes: seq[string]
  detections: Table[(string, string), (string, string)]
  links: Table[string, string] # links[version] = virustotal_link

var p: CsvParser
p.open("virustotal links")
while p.readRow():
  let hashArray = p.row[1].split("/")
  hashes.add(hashArray[high(hashArray)])
  links[p.row[0]] = p.row[1]
p.close()

when not defined(useFetchedData):
  proc downloadJson(hash: string): string = 
    return newHttpClient("Nim-Lang False Positive Reduction Efforts <3").request("https://www.virustotal.com/api/v3/files/" & hash, HttpGet, "", newHttpHeaders({ "x-apikey": virusTotalKey }))[].bodyStream.readAll()

{.warning[UnreachableCode]: off.}
when defined(fetchAndLeave):
  # Keep old JSON files. And timestamp the new ones.

  const f = initTimeFormat("yyyy-mm-dd-hh-mm-ss")
  if dirExists(json_dir):
    # 2024-04-23T09:38:48+02:00
    let date = readFile(json_dir & "/date")
    moveDir(json_dir, json_dir & "-" & date)
  createDir(json_dir)

  for hash in hashes:
    writeFile(json_dir & "/" & hash & ".json", downloadJson(hash))
  writeFile(json_dir & "/date", now().utc().format(f))

  quit(0)
{.warning[UnreachableCode]: on.}


for hash in hashes:
  echo hash
  when defined(useFetchedData):
    let jason = readFile(json_dir & "/" & hash & ".json").parseJson()
  else:
    let jason = downloadJson(hash).parseJson()

  let version = jason["data"]["attributes"]["meaningful_name"].getStr()[4..^5]
  # table[(antivirus, nim_version) = (detection, engine_version)]

  for antivirus, node in jason["data"]["attributes"]["last_analysis_results"].pairs:
    if node["category"].getStr() == "malicious":
      detections[(antivirus, version)] = (node["result"].getStr(), node["engine_version"].getStr())


# Generate email
proc prettifyVersion(s: string): string =
  return "Nim " & s.split("_")[0] & " (" & s.split("_")[1][1..^1] & " bits)"

proc readFromTemp(fn: string): string =
  if fileExists(fn):
    return readFile(fn)
  if fileExists(temp_dir & "/" & fn):
    return readFile(temp_dir & "/" & fn)


let
  start = readFromTemp("start")
  ending = readFromTemp("end")

if dirExists(email_dir):
  removeDir(email_dir)
createDir(email_dir)

# table[(antivirus, nim_version) = (detection, engine_version)]
var bigTmp: Table[string, string] # table[antivirus] = complete list
for stuff_one, stuff_two in detections.pairs:
  let
    antivirus = stuff_one[0]
    version = stuff_one[1]
    detection = stuff_two[0]
    engine_version = stuff_two[1]
  echo "($#: $# + $# = $#)" % [antivirus, version, engine_version, detection]

  if not bigTmp.hasKey(antivirus):
    bigTmp[antivirus] = ""
  bigTmp[antivirus].add("""

$#
Virustotal link: $#
Download link: $#
Engine version: $#
Virustotal Detection: $#
""" % [prettifyVersion(version), links[version], "https://nim-lang.org/download/nim-" & version & ".zip", engine_version, detection])

for antivirus,stuff in bigTmp.pairs:
  writeFile(
    email_dir & "/" & antivirus,
    $(start & stuff & ending) % [antivirus]
  )