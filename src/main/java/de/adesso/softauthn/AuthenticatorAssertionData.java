package de.adesso.softauthn;

import com.yubico.webauthn.data.ByteArray;

/**
 * Data returned by an authenticator upon performing an assertion.
 */
public class AuthenticatorAssertionData {

    private ByteArray credentialId;
    private final ByteArray authenticatorData;
    private final ByteArray signature;
    private final ByteArray userHandle;

    /**
     * Public constructor of this data class.
     *
     * @param credentialId The id of the credential that was used to create the assertion.
     * @param authenticatorData The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authenticator-data">authenticator data</a> created in the process.
     * @param signature The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#assertion-signature">assertion signature</a> produced in the process.
     * @param userHandle The user handle of the user this credential belongs to.
     */
    public AuthenticatorAssertionData(ByteArray credentialId, ByteArray authenticatorData, ByteArray signature, ByteArray userHandle) {
        this.credentialId = credentialId;
        this.authenticatorData = authenticatorData;
        this.signature = signature;
        this.userHandle = userHandle;
    }

    /**
     * See {@link #AuthenticatorAssertionData(ByteArray, ByteArray, ByteArray, ByteArray) constructor} for a description of this field.
     *
     * @return The credential id.
     */
    public ByteArray getCredentialId() {
        return credentialId;
    }

    /**
     * Set the credential id to some new value.
     * This can be done <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authenticatorGetAssertion-return-values">in the case that the authenticator does not return the credential id that was used</a>.
     *
     * @param credentialId The credential id used for this asseriton.
     */
    public void setCredentialId(ByteArray credentialId) {
        this.credentialId = credentialId;
    }

    /**
     * See {@link #AuthenticatorAssertionData(ByteArray, ByteArray, ByteArray, ByteArray) constructor} for a description of this field.
     *
     * @return The authenticator data bytes.
     */
    public ByteArray getAuthenticatorData() {
        return authenticatorData;
    }

    /**
     * See {@link #AuthenticatorAssertionData(ByteArray, ByteArray, ByteArray, ByteArray) constructor} for a description of this field.
     *
     * @return The assertion signature.
     */
    public ByteArray getSignature() {
        return signature;
    }

    /**
     * See {@link #AuthenticatorAssertionData(ByteArray, ByteArray, ByteArray, ByteArray) constructor} for a description of this field.
     *
     * @return The user handle.
     */
    public ByteArray getUserHandle() {
        return userHandle;
    }
}
