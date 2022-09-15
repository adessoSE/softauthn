package de.adesso.softauthn;

import COSE.CoseException;
import COSE.OneKey;
import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialType;

import java.util.Optional;

/**
 * A data class that stores information associated with a credential. This data is required to create assertions,
 * as it contains the private key of the credential.
 *
 * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#public-key-credential-source">Public Key Credential Source</a>
 */
public class PublicKeyCredentialSource {

  private final PublicKeyCredentialType type;
  private final OneKey key;
  private final String rpId;
  private final ByteArray userHandle;

  private ByteArray id;

  /**
   * Public constructor of this data class.
   * <p>Note that the credential id must be {@link #setId(ByteArray) set} after creation.
   *
   * @param type Type of credential.
   * @param privateKey The private key wrapped as a COSE {@link OneKey}.
   * @param rpId The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#relying-party-identifier">relying party identifier</a>
   * @param userHandle The user handle of the user this credential belongs to.
   */
  public PublicKeyCredentialSource(PublicKeyCredentialType type, OneKey privateKey, String rpId, ByteArray userHandle) {
    this.type = type;
    this.key = privateKey;
    this.rpId = rpId;
    this.userHandle = userHandle;
  }

  /**
   * See {@link this#PublicKeyCredentialSource(PublicKeyCredentialType, OneKey, String, ByteArray) constructor} for a description of this field.
   *
   * @return credential type.
   */
  public PublicKeyCredentialType getType() {
    return type;
  }

  /**
   * See {@link this#PublicKeyCredentialSource(PublicKeyCredentialType, OneKey, String, ByteArray) constructor} for a description of this field.
   *
   * @return the (private) key.
   */
  public OneKey getKey() {
    return key;
  }

  /**
   * See {@link this#PublicKeyCredentialSource(PublicKeyCredentialType, OneKey, String, ByteArray) constructor} for a description of this field.
   *
   * @return relying party id.
   */
  public String getRpId() {
    return rpId;
  }

  /**
   * See {@link this#PublicKeyCredentialSource(PublicKeyCredentialType, OneKey, String, ByteArray) constructor} for a description of this field.
   *
   * @return user handle.
   */
  public ByteArray getUserHandle() {
    return userHandle;
  }

  /**
   * Encodes this credential source to a byte array so it can be encrypted and used as the credential id for
   * <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#server-side-public-key-credential-source">server-side credential storage</a>
   *
   * @return this credential source serialized as a CBOR map. It can be deserialized again via {@link #deserialize(ByteArray)}.
   * @see #deserialize(ByteArray)
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#credential-id">Credential ID</a>
   */
  public byte[] serialize() {
    CBORObject map = CBORObject.NewMap()
            .Set("type", type.ordinal())
            .Set("key", key.EncodeToBytes())
            .Set("rpId", rpId);
    if (userHandle != null) {
      map.Set("user", userHandle.getBytes());
    }
    return map.EncodeToBytes();
  }

  /**
   * Deserialize the given byte array to reconstruct the credential source it represents.
   *
   * @param credentialId The byte array used as a credential id that encodes the credential source data.
   * @return An optional containing the resulting credential source if the byte array is indeed a serialized credential
   * source, or the empty optional if no credential source can be constructed from the information in the byte array.
   */
  public static Optional<PublicKeyCredentialSource> deserialize(ByteArray credentialId) {
    try {
      CBORObject map = CBORObject.DecodeFromBytes(credentialId.getBytes());
      PublicKeyCredentialType type = PublicKeyCredentialType.values()[map.get("type").AsInt32()];
      OneKey key = new OneKey(map.get("key"));
      String rpId = map.get("rpId").AsString();
      CBORObject encodedUserHandle = map.get("user");
      ByteArray userHandle = null;
      if (encodedUserHandle != null) {
        userHandle = new ByteArray(encodedUserHandle.GetByteString());
      }
      PublicKeyCredentialSource source = new PublicKeyCredentialSource(type, key, rpId, userHandle);
      source.setId(credentialId);
      return Optional.of(source);
    } catch (CBORException | CoseException e) {
      return Optional.empty();
    }
  }

  @Override
  public String toString() {
    return "PublicKeyCredentialSource{" +
            "type=" + type +
            ", privateKey=" + key +
            ", rpId='" + rpId + '\'' +
            ", userHandle=" + userHandle +
            '}';
  }

  /**
   * Returns the credential id if set, otherwise null.
   *
   * @return the credential ID of this credential source.
   */
  public ByteArray getId() {
    return id;
  }

  /**
   * Set the credential ID, for example to the {@link #serialize() serialized version of this credential source itself}
   * for server-side credentials or a randomly generated byte array for client-side discoverable credentials.
   *
   * @param id The id to set.
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#credential-id">Credential ID</a>
   */
  public void setId(ByteArray id) {
    this.id = id;
  }
}
