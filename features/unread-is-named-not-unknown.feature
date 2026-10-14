Feature: An ingest names the event types and sources no detector reads, and does not call a registered type unknown

  The shared event bus registry names event types that no idryx detector reads
  yet. The stderr line used to count every such type as unknown, which is false
  for a type the registry names. Those events are still ingested as they are,
  carried through and counted, never dropped. The line now says exactly that:
  it names the types and the sources no detector reads, in a bounded list, and
  it stays silent when every type and source is one a detector reads.

  Scenario: a registered type no detector reads is named as ingested as it is
    Given tokenfuse.ndjson holds a spend event and events of four registered types that no detector reads
    When idryx loads the file
    Then stderr names the four types as event types no detector reads, ingested as they are, and calls none of them unknown
  # @test:TestARegisteredTypeNoDetectorReadsIsNotCalledUnknown

  Scenario: a source none of whose events a detector reads is named, across every file of a load
    Given typryx.ndjson holds events of a type no detector reads, and tokenfuse is read in one file of the load and not in the other
    When idryx loads the glob over both
    Then stderr names typryx as a source no detector reads, and does not name tokenfuse
  # @test:TestAnUnreadSourceIsJudgedAcrossEveryFileOfALoad

  Scenario: a long or hostile name stays on one bounded line
    Given a load carries more than eight unread type names, one of them over sixty-four bytes and one holding a line break
    When the stderr summary of the load is written
    Then it is one line, the hostile name is escaped, the long name is cut, eight names are listed and the rest are counted
  # @test:TestStderrSummaryBoundsAndEscapesEveryName

  Scenario: an ingest that a detector reads in full says nothing
    Given a load holds only types and sources that a detector reads
    When the stderr summary of the load is written
    Then the summary is empty
  # @test:TestStderrSummaryIsEmptyWhenEveryTypeAndSourceIsRead
