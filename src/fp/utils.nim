{.define: ssl.}
import std/[strutils, os, json, httpclient, times, streams, tables, options]

proc getBody*(obj: Response): string =
  ## Returns the body of a response object
  return readAll(obj[].bodyStream)

func getCode*(obj: Response): int =
  ## Returns the HTTP Status Code of a response object (as int)
  return parseInt(split(obj[].status, " ")[0])

proc prettifyVersion*(ver, arch: string, os = "Windows"): string =
  ## Returns a prettified Nim version string along with architecture and platform details.
  ## 
  ## Used for generating the emails to be sent out to antivirus companies.
  return "Nim version $1 ($2; $3)" % [ver, arch, os]

proc versionToFilename*(ver: string, arch: string): string =
  return "nim_" & ver & "_" & arch & "_data.json"

proc tupleVerToString*(ver: (int, int, int)): string =
  return "$1.$2.$3" % [$(ver[0]),$(ver[1]),$(ver[2])]

const tempDir*{.strdefine.} = "templates"
proc readFromTemp*(file: string): string =
  ## Reads a file from the templates directory
  if not dirExists(tempDir):
    createDir(tempDir)
  return readFile(tempDir & "/" & file)

const virusTotalKey: string = ""
proc fetchVirustotalKey*(): string =
  ## Returns the virustotal API key using a variety of methods.
  # Order of priority:
  # 1. VIRUSTOTAL_KEY envvar
  # 2. "vt_key" file
  # 4. 
  # 4. virusTotalKey compile-time constant
  # 5. Fail and crash the program
  
  if existsEnv("VIRUSTOTAL_KEY"):
    result = getEnv("VIRUSTOTAL_KEY")
  
  proc getKeyFromParams(): string =
    return commandLineParams()[high(commandLineParams())]
  if paramCount() > 0 and getKeyFromParams() != "fetch":
    result = getKeyFromParams()
  

  if existsEnv("VIRUSTOTAL_KEY"):
    return getEnv("VIRUSTOTAL_KEY")
  
  if fileExists("vt_key"):
    return readFile("vt_key")

  if fileExists(".vt_key"):
    return readFile(".vt_key")

  # Check if a key was provided at build-time
  if virusTotalKey != "":
    return virusTotalKey

  # If all else fails, then we also fail.
  raise newException(ValueError, "Missing virustotal key!")

type
  Version* = (int, int, int)
  VersionPair* = (Version, string)
  HashToVersion* = OrderedTable[string, VersionPair]
  HashToDownload* = OrderedTable[string, string]

func parseNimVersion*(s: string): (int, int, int) =
  ## Parses a nim version
  let arr = s.split(".")
  return (arr[0].parseInt(), arr[1].parseInt(), arr[2].parseInt())

proc createHttpClient*(): HttpClient =
  ## Creates an httpclient with the ideal user agent we want!
  return newHttpClient("Nim-Lang False Positive Reduction Efforts <3") 

template log*(msg: varargs[string,`$`]): untyped =
  ## Simple logging func.
  echo "[$1 $2]($3:$4): $5" % [getDateStr(), getClockStr(), instantiationInfo().filename, $(instantiationInfo().line), msg.join]

proc getNimDataFile*(fn = "data.json", client = createHttpClient()): string =
  ## This proc attempts to get nimdata BY ANY MEANS NECCESSARY!
  ## 
  ## It will attempt to look for 
  if fileExists("data.json"):
    log "Returning data.json"
    return readFile("data.json")

  when defined(release):
    const nimDataUrl{.strdefine.} = "https://ftp.penguinite.dev/nim-fp/versions.json"
    log "Downloading data.json from the net"
    log "nimDataUrl is ", nimDataUrl
    try:
      return client.getContent(nimDataUrl)
    except CatchableError as err:
      log "Couldn't fetch nimdata from the net: ", err.msg

proc parseNimData*(input: string): (HashToVersion, HashToDownload) =  
  ## Parses the `data.json` file into a proper NimData object.
  ## 
  ## Basically, this proc returns a bunch of amazing data.
  
  # TODO: For now, since we only scan Windows binaries, we can just
  # skip scanning anything else. But a less hacky implement would be nice.
  for version, archNode in parseJson(input)["windows"].pairs:
    for arch in archNode.keys:
      echo "Found data for version: ", prettifyVersion(version, arch)
      result[0][archNode[arch]["virustotal"].getStr()] = (parseNimVersion(version), arch)
      result[1][archNode[arch]["virustotal"].getStr()] = archNode[arch]["download"].getStr()
  return result

const outputDir*{.strdefine.} = "output"
proc createOutputDir*() =
  ## Removes the email output directory if it exists and creates it again.
  ## 
  ## Used to ensure a "clean slate" inbetween runs and generations.
  if dirExists(outputDir):
    removeDir(outputDir)
  createDir(outputDir)

type
  VTDetection = object of RootObj
    architecture*: string
    antivirus_name*: string
    version*: (int, int, int)
    engine_version*: string
    engine_update*: string # From VT API
    detection*: string
    virustotal*: string
    download*: string

  VTData = seq[VTDetection]

proc getVTScanData*(hash, apikey: string, client = createHttpClient()): Option[JsonNode] =
  ## https://docs.virustotal.com/reference/file-info
  ## Retrieves plain old file info from virustotal with no processing.
  ## You might want to pass this onto parseVTData

  let response = client.request(
    "https://www.virustotal.com/api/v3/files/" & hash,
    headers = newHttpHeaders(
      { "x-apikey": apikey, "accept": "application/json" }
    ),
    httpMethod = HttpGet
  )

  case getCode(response):
  of 200:
    return some(parseJson(getBody(response)))
  else:
    log "Failed to retrieve virustotal data for ", hash
    log "Response code:", getCode(response)
    log "Response body:", getBody(response)
    return none(JsonNode)

proc issueVTRescan*(hash, apikey: string, client = createHttpClient()): Option[string] =
  ## https://docs.virustotal.com/reference/files-analyse
  ## Issues a rescan for a file
  ## This only issues a rescan, it doesn't check if a rescan is done.
  ## You can check with checkVTRescan()
  let response = client.request(
    "https://www.virustotal.com/api/v3/files/" & hash & "/analyse",
    headers = newHttpHeaders(
      { "x-apikey": apikey, "accept": "application/json" }
    ),
    httpMethod = HttpPost
  )

  case getCode(response):
  of 200:
    result = some(parseJson(getBody(response))["data"]["id"].getStr())
    echo "Rescan ID: ", get(result)
    return result
  else:
    log "Failed to issue rescan for ", hash
    log "Response code:", getCode(response)
    log "Response body:", getBody(response)
    return none(string)

proc isVTRescanDone*(id,apikey: string, client = createHttpClient()): bool =
  ## https://docs.virustotal.com/reference/analysis
  ## Checks whether a virustotal rescan is done or not.
  ## The `id` given should be a string from issueVTRescan()
  echo "Sending rescan request"
  let response = client.request(
    "https://www.virustotal.com/api/v3/analyses/" & id,
    headers = newHttpHeaders(
      { "x-apikey": apikey, "accept": "application/json" }
    ),
    httpMethod = HttpGet
  )
  echo "VT Rescan HTTP code:", getCode(response)
  case getCode(response):
  of 200:
    let json = parseJson(getBody(response))
    # VirusTotal's API is utterly deranged.
    # Sometimes it will return 200 but then proceed to NOT return the proper JSON!!!
    # Fuck you virustotal! Honestly you're such a dickhead service!

    if not json.hasKey("data"):
      return false
    
    if not json["data"].hasKey("attributes"):
      return false

    if not json["data"]["attributes"].hasKey("status"):
      return false

    let status = json["data"]["attributes"]["status"].getStr()
    echo "VT Rescan reported as:", status
    return status == "completed"
  else:
    return false

proc rescanVersion*(hash: string, versionData: (HashToVersion, HashToDownload)) =
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

proc parseVTData*(input: JsonNode, nimdata: (HashToVersion, HashToDownload)): VTData =
  ## When given data from getVTScanData(), it parses into a VTData object.
  let hash = input["meta"]["file_info"]["sha256"].getStr()
  for key,node in input["data"]["attributes"]["results"].pairs:
    case input["data"]["attributes"]["results"][key]["category"].getStr():
    of "malicious":
      log "Found malicious detection for ", hash, " from ", node["engine_name"].getStr()
      result.add(
        VTDetection(
          # TODO: This has to be better... wtf?
          architecture: nimdata[0][hash][1],
          version: nimdata[0][hash][0],
          antivirus_name: node["engine_name"].getStr(),
          engine_version: node["engine_version"].getStr(),
          engine_update: node["engine_update"].getStr(),
          detection: node["result"].getStr(),
          virustotal: hash,
          download: nimdata[1][hash]
        )
      )
    else: continue
  return result

proc parseVTData*(input: string, nimdata: (HashToVersion, HashToDownload)): VTData =
  ## When given data from getVTScanData(), it parses into a VTData object. (String input version)
  return parseVTData(parseJson(input), nimdata)

const emailDir*{.strdefine.} = "emails"
if dirExists(emailDir):
  removeDir(emailDir)
proc writeEmail*(fn: string, contents: string) =
  if not dirExists(emailDir):
    createDir(emailDir)
  writeFile(emailDir & "/" & fn, contents)