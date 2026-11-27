Feature: CloudTrail activity is credited only to a role the session actually names

  An assumed-role session ARN is matched to the IAM role it assumed. A session
  ARN with nothing after "assumed-role/", or with no account, names no role, so
  its activity is refused instead of being credited to a role with an empty
  name that no inventory entry can match.

  Scenario: a session ARN with no role name or no account is refused
    Given CloudTrail records whose session ARNs name no role, or no account, and one that names a role
    When usage is read from them
    Then only the record that names a role is credited, to that role
  # @test:TestCloudTrailUsageRefusesASessionARNThatNamesNoRole

  Scenario: the ARN normaliser refuses a session that names no role or account
    Given a session ARN with an empty role name or an empty account
    When it is normalised
    Then it is refused rather than turned into a role ARN
  # @test:TestNormalizeARNRefusesASessionThatNamesNoRoleOrAccount
