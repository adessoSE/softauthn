# jafido

jafido provides an implementation of the [WebAuthn](https://www.w3.org/TR/2021/REC-webauthn-2-20210408/) API and a software authenticator in Java, 
using the [`java-webauthn-server`](https://developers.yubico.com/java-webauthn-server/) library for data models. This makes it especially well-suited 
to interface with code that uses that same library.

## Purpose
The primary purpose of this library is to enable developers to test their WebAuthn server implementations.
E.g. you might have a web app that allows users to authenticate via WebAuthn and you want to unit test your 
backend authentication process. This library gives you an API to create arbitrary authenticators that behave
like "real" ones in pure software.

## Installation

## Usage

```java
// Create an authenticator that will implement the functionality of a WebAuthn authenticator in pure software
// This one mimics a traditional USB key: it is external (attachment), does not have proper storage for keys and can verify users (e.g. via a pin code)
var authenticator = new Authenticator(AuthenticatorAttachment.CROSS_PLATFORM, false, true);
// Create a credentials environment (mimics the browser navigator.credentials API)
// It will pretend its origin is https://example.com
var credentials = new Credentials("https://example.com", List.of(authenticator));
// Get the options for credential creation from your backend
PublicKeyCredentialCreationOptions opts = callYourBackend();

credentials.create(opts);
```

## Completeness

While this library does aim to come close to the WebAuthn specification, it does not implement all of its features.
These aspects are currently unsupported:
- Enterprise attestation
- Token Binding
- Client Extensions