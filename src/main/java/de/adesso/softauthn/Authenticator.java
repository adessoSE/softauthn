package de.adesso.softauthn;

import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import de.adesso.softauthn.authenticator.WebAuthnAuthenticator;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;

/**
 * The Authenticator interface represents the API provided by WebAuthn authenticators as specified by the WebAuthn
 * spec (see below).
 *
 * @apiNote Not every authenticator operation is implemented. Specifically,
 * <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-cancel">authenticatorCancel</a> is
 * missing because it serves no purpose in a non-concurrent software environment.
 *
 * @implNote The intention behind this interface is to allow the definition of WebAuthn authenticators in software
 * (like the main implementation of this library {@link WebAuthnAuthenticator}), but it can of course be implemented
 * in other ways to achieve different purposes. For instance, there are several "broken" implementations provided by
 * this library that emulate authenticators that behave incorrectly because of e.g. some hardware defect or even because
 * of malicious intent.<br>
 * In theory, this interface can also be implemented for <em>actual</em> WebAuthn hardware authenticators
 * by communicating with their respective drivers or similar.
 *
 * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-model">
 *     WebAuthn Authenticator Model</a>
 * @see Authenticators
 */
public interface Authenticator {

    /**
     * Method that will be called by a client platform to create a new credential on this authenticator.
     *
     * @param hash The hash of the <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#collectedclientdata-hash-of-the-serialized-client-data">serialized client data</a>, provided by the client.
     * @param rpEntity The Relying Party entity
     * @param userEntity The user account's entity, containing the user handle given by the Relying Party.
     * @param requireResidentKey The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#effective-resident-key-requirement-for-credential-creation">effective resident key requirement for credential creation</a>, a Boolean value determined by the client.
     * @param requireUserVerification The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#effective-user-verification-requirement-for-credential-creation">effective user verification requirement for credential creation</a>, a Boolean value determined by the client.
     * @param credTypesAndPubKeyAlgs A sequence of credential types and algorithms requested by the Relying Party. This sequence is ordered from most preferred to least preferred.
     *                               The authenticator makes a best-effort to create the most preferred credential that it can.
     * @param excludeCredentials A nullable list of PublicKeyCredentialDescriptor objects provided by the Relying Party with the intention that,
     *                           if any of these are known to the authenticator, it SHOULD NOT create a new credential.
     *                           excludeCredentials contains a list of known credentials.
     * @param enterpriseAttestationPossible A Boolean value that indicates that individually-identifying attestation MAY be returned by the authenticator.
     * @param extensions A CBOR map from extension identifiers to their authenticator extension inputs, created by the client based on the extensions requested by the Relying Party, if any.
     * @return An <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#attestation-object">Attestation object</a> created by the authenticator for the request.
     * @throws IllegalArgumentException If the parameters are malformed in any way.
     * @throws UnsupportedOperationException If some requirement was requested that this authenticator does not support.
     * @throws IllegalStateException If the current state of this authenticator prevents it from fulfilling the request.
     *
     * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-make-cred">The authenticatorMakeCredential Operation</a>
     */
    CBORObject makeCredential(
            byte[] hash, RelyingPartyIdentity rpEntity, UserIdentity userEntity, boolean requireResidentKey,
            boolean requireUserVerification, List<PublicKeyCredentialParameters> credTypesAndPubKeyAlgs,
            Set<PublicKeyCredentialDescriptor> excludeCredentials, boolean enterpriseAttestationPossible, byte[] extensions
    ) throws IllegalArgumentException, UnsupportedOperationException, IllegalStateException;

    /**
     * Method that will be called by a client platform to create an assertion for an existing credential.
     *
     * @param rpId The caller’s <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#rp-id">RP ID</a>, as determined by the user agent and the client.
     * @param hash The hash of the <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#collectedclientdata-hash-of-the-serialized-client-data">serialized client data</a>, provided by the client.
     * @param allowedCredentialDescriptorList A nullable list of PublicKeyCredentialDescriptors describing credentials acceptable to the Relying Party (possibly filtered by the client), if any.
     * @param requireUserVerification The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#effective-user-verification-requirement-for-assertion">effective user verification requirement for assertion</a>, a Boolean value provided by the client.
     * @param extensions A CBOR map from extension identifiers to their authenticator extension inputs, created by the client based on the extensions requested by the Relying Party, if any.
     * @return The result data of the assertion.
     * @throws IllegalArgumentException If the parameters are malformed in any way.
     * @throws NoSuchElementException If this authenticator cannot find any matching credential.
     *
     * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-get-assertion">The authenticatorGetAssertion Operation</a>
     */
    AuthenticatorAssertionData getAssertion(
            String rpId, byte[] hash,
            List<PublicKeyCredentialDescriptor> allowedCredentialDescriptorList,
            boolean requireUserVerification, byte[] extensions
    ) throws IllegalArgumentException, NoSuchElementException;

    /**
     * Returns this authenticator's <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-attachment-modality">attachment</a>.
     *
     * @return the attachment.
     */
    AuthenticatorAttachment getAttachment();

    /**
     * Returns whether this authenticator supports the creation of <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-public-key-credential-source">client-side discoverable credentials</a>,
     * also known as resident keys.
     *
     * @return Whether this authenticator can store credentials itself.
     * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-credential-storage-modality">Credential Storage Modality</a>
     */
    boolean supportsClientSideDiscoverablePublicKeyCredentialSources();

    /**
     * Returns whether this authenticator can perform <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-verification">user verification</a>.
     *
     * @return Whether user verification is supported.
     * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authentication-factor-capability">Authentication Factor Capability</a>
     */
    boolean supportsUserVerification();
}
