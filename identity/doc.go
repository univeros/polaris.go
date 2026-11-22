// Package identity holds what the account service hands its callers: the outcome of a password
// login ([LoginResult]), the errors its refusals match ([ErrInvalidCredentials], …, [Error],
// [PasswordError]), the password policy ([PasswordPolicy]) and the stored form of an email
// ([NormalizeEmail]).
//
// The service itself is internal to Polaris. A host uses polaris.Users and polaris.Sessions; a
// plugin uses wiring.Graph.Identity.
package identity
