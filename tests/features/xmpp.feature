@xmpp
Feature: Authentication with a xmpp server

  Background:
    Given Connection to xmpp server

  @plain
  Scenario: Authenticate with xmpp server through plain text authentication
    Given xmpp server supports authentication method "PLAIN"
    When authenticate with method PLAIN
    Then should be authenticated at xmpp server

  @digestmd5
  Scenario: Authenticate with xmpp server through digest-md5 authentication
    Given xmpp server supports authentication method "DIGEST-MD5"
    When authenticate with method DIGEST-MD5
    And response to challenge received for DIGEST-MD5
    And response to rspauth challenge
    Then should be authenticated at xmpp server

  @scramsha1
  Scenario: Authenticate with xmpp server through scram-sha-1 authentication
    Given xmpp server supports authentication method "SCRAM-SHA-1"
    When authenticate with method SCRAM-SHA-1
    And response to challenge for SCRAM-SHA-1
    Then should be authenticated at xmpp server with verification

  @scramsha256
  Scenario: Authenticate with xmpp server through scram-sha-256 authentication
    Given xmpp server supports authentication method "SCRAM-SHA-256"
    When authenticate with method SCRAM-SHA-256
    And response to challenge for SCRAM-SHA-256
    Then should be authenticated at xmpp server with verification

  @scramsha512
  Scenario: Authenticate with xmpp server through scram-sha-512 authentication
    Given xmpp server supports authentication method "SCRAM-SHA-512"
    When authenticate with method SCRAM-SHA-512
    And response to challenge for SCRAM-SHA-512
    Then should be authenticated at xmpp server with verification
