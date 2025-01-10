@xmpp @downgradeProtection
Feature: Authentication with a XMPP server

  Background:
    Given Connection to XMPP server
    And Connection is encrypted by STARTTLS

  @scramsha1
  Scenario: Authenticate with xmpp server through scram-sha-1 authentication with downgrade protection
    Given xmpp server supports authentication method "SCRAM-SHA-1"
    And Downgrade protection is properly set up
    When authenticate with method SCRAM-SHA-1
    And response to challenge for SCRAM-SHA-1
    Then should be authenticated at xmpp server with verification

  @scramsha256
  Scenario: Authenticate with xmpp server through scram-sha-256 authentication with downgrade protection
    Given xmpp server supports authentication method "SCRAM-SHA-256"
    And Downgrade protection is properly set up
    When authenticate with method SCRAM-SHA-256
    And response to challenge for SCRAM-SHA-256
    Then should be authenticated at xmpp server with verification

  @scramsha1
  Scenario: Authenticate with xmpp server through scram-sha-1 authentication with downgrade protection with invalid mechanism
    Given xmpp server supports authentication method "SCRAM-SHA-1"
    And Downgrade protection is properly set up
    And We simulate downgrade protection error by adding an auth mechanism
    When authenticate with method SCRAM-SHA-1
    And response to challenge for SCRAM-SHA-1 was invalid
    Then Server connection should be closed

  @scramsha1
  Scenario: Authenticate with xmpp server through scram-sha-1 authentication with downgrade protection with invalid channel-binding
    Given xmpp server supports authentication method "SCRAM-SHA-1"
    And Downgrade protection is properly set up
    And We simulate downgrade protection error by adding an unsupported channel-binding
    When authenticate with method SCRAM-SHA-1
    And response to challenge for SCRAM-SHA-1 was invalid
    Then Server connection should be closed

  @scramsha1
  Scenario: Authenticate with xmpp server through scram-sha-1 authentication with downgrade protection is disabled
    Given xmpp server supports authentication method "SCRAM-SHA-1"
    When authenticate with method SCRAM-SHA-1
    And response to challenge for SCRAM-SHA-1
    Then should be authenticated at xmpp server with verification
