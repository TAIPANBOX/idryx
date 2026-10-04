Feature: An event is ingested as the source it claims only when its file may carry that source

  The shared event bus is one directory with one file per writer, and every
  writer can append to every file. Nothing checked that the `source` inside a
  line is the source the file belongs to, and idryx verified the chain and then
  ingested the line anyway, so a line claiming `source: wardryx` inside
  tokenfuse.ndjson put an identity and an event about wardryx into the graph.
  The owner chose that each writer writes only its own stream and everyone else
  reads, plus a verifier. This is the reader half for idryx: a line whose source
  is not allowed for the file it was read from is not ingested into the graph,
  it is counted beside the malformed lines and named on stderr, and it never
  stops the load. A file that legitimately carries more than one source, or a
  different name, is declared, so no legitimate event is dropped; a file
  nothing declares is ingested when its lines claim its own name, and named.

  Scenario: a line claiming another plane's name is not ingested as that plane
    Given tokenfuse.ndjson holds a tokenfuse line and a line claiming wardryx
    When idryx loads the file
    Then the graph holds the tokenfuse line's agent and no agent or event for the wardryx claim, and stderr names the file and the claim
  # @test:TestALineClaimingAnotherSourceIsNotIngestedAsThatSource

  Scenario: a refusal is reported and never fatal
    Given tokenfuse.ndjson holds a line claiming wardryx
    When idryx runs detect over it
    Then the run succeeds and stderr says the event was not ingested
  # @test:TestARefusalIsReportedAndNeverFatal

  Scenario: a glob judges each file by its own name
    Given tokenfuse.ndjson holds a line claiming wardryx and wardryx.ndjson holds a wardryx line
    When idryx loads the glob over both
    Then the claim in tokenfuse.ndjson is refused and the line in wardryx.ndjson is kept
  # @test:TestAGlobAppliesTheRuleFileByFile

  Scenario: a file nobody declared cannot carry several sources, even one named demo
    Given a co-tenant creates demo.ndjson holding a line claiming wardryx
    When idryx loads it with no declaration
    Then the claim is not ingested as wardryx and stderr names demo.ndjson
  # @test:TestACoTenantsDemoFileIsRefusedByDefault

  Scenario: a file the operator declared to carry several sources is ingested whole
    Given IDRYX_STREAMS declares demo=tokenfuse|wardryx|mockryx and demo.ndjson holds lines from those three
    When idryx loads it
    Then all three agents are in the graph and nothing is reported as refused
  # @test:TestADeclaredMultiSourceFileIsIngestedWhole

  Scenario: agent-conform's own stream is a known stream
    Given agent-conform.ndjson holds a line claiming agent-conform
    When the stream rule decides it
    Then it is allowed as a known single-source stream and not counted as an unknown stream
  # @test:TestAgentConformIsAKnownSingleSourceStream

  Scenario: the control plane's and the broker's own files carry the tokenfuse source
    Given tokenfuse-cloud.ndjson and tokenfuse-mcp.ndjson each hold a tokenfuse line
    When idryx loads the glob
    Then both agents are in the graph and nothing is reported as refused
  # @test:TestRenamedFilesOfTheSameProducerAreIngested

  Scenario: a stream nothing declares is ingested and named, and a forged claim in it is refused
    Given newplane.ndjson holds a line claiming newplane and a line claiming tokenfuse
    When idryx loads it
    Then the newplane agent is in the graph, the tokenfuse claim is not, and stderr says the stream is not one this build knows
  # @test:TestAnUnknownStreamIsIngestedAndNamedNotTrustedInSilence

  Scenario: an operator declares what a file of their own may carry
    Given events.ndjson holds tokenfuse and wardryx lines
    When it is undeclared the lines are refused, and when IDRYX_STREAMS declares events=tokenfuse|wardryx they are ingested with nothing reported
    Then the declaration is the only thing that changes the outcome
  # @test:TestAFileNamedEventsIsRefusedUntilItsSourcesAreDeclared

  Scenario: a malformed declaration refuses the load and names the variable
    Given IDRYX_STREAMS holds an entry with no sources
    When idryx loads any bus file
    Then the load fails with an error naming IDRYX_STREAMS
  # @test:TestAMalformedStreamDeclarationRefusesTheLoadNamingTheVariable

  Scenario: hostile lines are unchanged and a hostile claim stays on one line of stderr
    Given tokenfuse.ndjson holds garbage, a truncated envelope, a claimed source with a header injection, and one legitimate line
    When idryx loads it
    Then the two broken lines still count as malformed, the legitimate agent is in the graph, the hostile claim is not, and no claimed text leaves its line
  # @test:TestHostileLinesAreUnchangedAndAHostileClaimStaysOnOneLine

  Scenario: a refused line still takes part in the chain verdict
    Given a chained stream whose second line was edited to claim wardryx
    When idryx loads it
    Then the chain is reported broken at the next line and the edited line is also refused
  # @test:TestARefusedLineStillTakesPartInTheChainVerdict
