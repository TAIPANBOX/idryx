Feature: A webhook credential can come from a file that other users cannot read

  A header typed after --webhook-header sits in the process list, where any local
  user can read it. The operator can keep the header in a file instead, and name
  the file on the command line or in an environment variable. A file that group or
  other users can read is refused before anything is sent. A credential-looking
  header still given on the command line is sent as before, and is named with a
  warning that never prints its value.

  Scenario: a header file that only its owner can read is sent with the alerts
    Given a file holding an Authorization header, readable by its owner only
    When idryx detect runs with --webhook pointing at an endpoint and --webhook-header-file naming the file
    Then the endpoint receives the Authorization header from the file
  # @test:TestWebhookHeaderFileIsSentWithTheAlerts

  Scenario: a header file that other users can read is refused before any request is sent
    Given a file holding an Authorization header, readable by its owner and by other users
    When idryx detect runs with --webhook-header-file naming the file
    Then the run fails naming the file and its mode, the endpoint receives no request, and the error does not print the header value
  # @test:TestHeaderFileReadableByOthersIsRefusedBeforeAnySend

  Scenario: a line that is not "Name: Value" is refused by its line number, without echoing it
    Given a header file whose second line has no colon and holds a secret
    When idryx reads the header file
    Then the read fails naming line 2, and the error does not print that line
  # @test:TestHeaderFileRefusesAMalformedLineWithoutEchoingIt

  Scenario: an environment variable names the header file when no flag does
    Given IDRYX_WEBHOOK_HEADER_FILE names a file readable by its owner only, and no header file flag is given
    When idryx detect runs with --webhook pointing at an endpoint
    Then the endpoint receives the header from that file
  # @test:TestEnvironmentNamesTheHeaderFile

  Scenario: a header on the command line overrides the file's header of the same name
    Given a header file sets X-Origin, and --webhook-header sets X-Origin to another value
    When idryx detect runs with both
    Then the endpoint receives the value from the command line
  # @test:TestCommandLineHeaderOverridesTheFile

  Scenario: a credential-looking header on the command line is still sent, and named with a warning
    Given --webhook-header "Authorization: Bearer <value>" on the command line
    When idryx detect runs with --webhook pointing at an endpoint
    Then the endpoint receives the header, and stderr has one line naming Authorization that does not print the value
  # @test:TestCredentialHeaderOnTheCommandLineIsNamedWithAWarning

  Scenario: a header with a name that is not credential-looking gets no warning
    Given --webhook-header "X-Origin: https://idryx.internal:8443/detect" on the command line
    When the command line headers are checked for credential-looking names
    Then nothing is written to stderr
  # @test:TestOrdinaryHeaderOnTheCommandLineIsNotWarned

  Scenario: the credential-looking test is by name, case-insensitive, and covers the named families
    Given header names Authorization, Proxy-Authorization, cookie, X-Api-Key, X-Auth-Token, and X-Client-Secret
    When each name is checked for credential-looking
    Then each one is credential-looking, and Accept and X-Origin are not
  # @test:TestCredentialLookingNamesAreRecognised
