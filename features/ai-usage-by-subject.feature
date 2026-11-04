Feature: The AI inventory says, for each agent or service, what was declared, what was seen and what the code can reach, and names every disagreement

  The inventory used to compare three sources provider by provider. A reader
  still could not say which agent or service a disagreement belonged to, and a
  source that was never loaded looked the same as a source that found nothing.
  The report now has one row per subject and provider, a row for each of the
  sources it was built from, and a name for each disagreement. It judges
  nothing: scoring one subject stays with the detectors, and the code scan has
  no subject, so its column is per provider for the whole estate.

  Scenario: a provider an agent declares and no source saw is named declared, not seen
    Given an agent whose Passport declares a provider and models, and no egress, no bus event and no capture for it
    When the inventory is built
    Then the row for that agent and provider is named declared but not seen, and lists the declared models
  # @test:TestADeclaredProviderNoSourceSawIsNamedDeclaredNotSeen

  Scenario: a provider an agent reached and never declared is named seen, not declared
    Given an agent that declares one provider and is seen reaching another
    When the inventory is built
    Then the row for the second provider is named seen but not declared, and the first is not called seen
  # @test:TestAProviderAnAgentReachedAndNeverDeclaredIsNamedSeenNotDeclared

  Scenario: a process seen only by name reaching a provider is named seen with no declaration and attributed by name
    Given a captured process with no Passport that reaches a provider, and a process that named itself an agent by its own claim
    When the inventory is built
    Then both rows are named seen with no declaration, one says it is attributed by process name and the other says the attribution is self-declared
  # @test:TestAProcessSeenReachingAProviderIsNamedSeenWithNoDeclarationAndAttributedByName

  Scenario: an agent active on the bus is not called unseen, and the report says the bus names no provider
    Given an agent that declares a provider, has events on the bus from an enforcement point and has no egress of its own
    When the inventory is built
    Then the row is named declared and active on the bus only, it lists the bus source and event count, and it is not named declared but not seen
  # @test:TestAnAgentActiveOnTheBusIsNotCalledUnseenAndTheBusNamesNoProvider

  Scenario: a provider in the code that no subject was seen reaching is named in code, not seen in operation
    Given a code scan that finds a provider and a graph in which nobody reaches it
    When the inventory is built
    Then the provider row carries the gap in code but not seen in operation, and says the code column is estate-wide
  # @test:TestAProviderInCodeThatNobodyWasSeenReachingIsNamedInCodeNotSeen

  Scenario: a source that was not supplied is a row of its own and never a zero
    Given a graph with no Passport, no bus event, no egress and no capture, and no code scan, and then a graph in which an agent reaches a provider while no code scan was supplied
    When the inventory is built
    Then there is one source row each for declared, bus, egress, ebpf and code, every one absent with a sentence saying what it means, supplying a source turns only its own row to present, and the agent's code cell reads not scanned and never not found
  # @test:TestAnAbsentSourceIsARowAndNotAZero

  Scenario: an agent that declares no model is told apart from an agent with no declaration at all
    Given one agent whose Passport declares no model and one agent known only from the bus
    When the inventory is built
    Then the first is named declares no models and the second is named no declaration, and neither is called declared but not seen
  # @test:TestAnAgentThatDeclaresNoModelIsNotAnAgentWithNoDeclaration

  Scenario: a code scan that is hostile is refused or neutralised
    Given qryx documents that are oversized, of the wrong shape, full of control bytes, with provider names that are not ids, with thousands of labels and limits, and truncated at every offset
    When idryx reads each as a code scan
    Then each is refused or read within fixed bounds, no accepted string holds a control character, and nothing panics
  # @test:TestAHostileCodeScanIsRefusedOrReadWithinBounds

  Scenario: hostile names never reach the terminal raw
    Given an agent id, a model name, a host and a code scan label that hold escape and line-break bytes
    When the inventory is written for a person
    Then no output line holds a raw escape or control byte, and the names are shown escaped and cut to a bounded length
  # @test:TestHostileNamesNeverReachTheTerminalRaw

  Scenario: the report states the limits of agent monitoring and ranks nothing
    Given any graph, with or without a code scan
    When the inventory is written for a person and as JSON
    Then both carry the limits that attribution is self-declared, that the sensor is Linux-only and that a process can always open a socket, and the human form holds no severity word
  # @test:TestTheReportStatesTheMonitoringLimitsAndRanksNothing

  Scenario: the same input gives the same report
    Given one estate loaded in two different orders
    When the inventory is written as JSON twice
    Then the two documents are byte for byte equal
  # @test:TestTheSameEstateInAnyOrderGivesTheSameReport

  Scenario: the report agrees with the detectors on the cases they both judge
    Given a governed agent that declares one provider and reaches another, and an unattributed process that reaches a provider
    When the detectors run and the inventory is built
    Then undeclared_llm fires for exactly the agent the report names seen but not declared, and unmanaged_egress fires for exactly the process the report names seen with no declaration
  # @test:TestTheReportAgreesWithUndeclaredLLMAndUnmanagedEgress

  Scenario: the command wires the real vocabulary and the bus into the per-subject rows
    Given a bus file of a governed agent, an egress capture of a process and a Passport, loaded through the same door the command uses
    When the inventory is built with the real host vocabulary
    Then the process reaching a real provider host is a seen row, the governed agent shows its bus source, and the source rows say which inputs were present
  # @test:TestAIInventoryPerSubjectRowsAreWiredToTheRealVocabularyAndTheBus
