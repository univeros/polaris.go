// Package mfa holds what a plugin needs of multi-factor authentication: the [FactorType] a plugin
// implements to add a factor (wiring.MFAFactorTypeProvider), the challenge purposes, the values
// the MFA service returns ([LoginChallenge], [ConfirmResult], [FactorView]), the errors its
// refusals match, and E.164 validation and destination masking.
//
// The service itself is internal to Polaris; a plugin uses wiring.Graph.MFA.
package mfa
