package de.adesso.softauthn;

import COSE.CoseException;
import COSE.OneKey;
import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialType;

import java.util.Optional;

public class PublicKeyCredentialSource {

  private final PublicKeyCredentialType type;
  private final OneKey key;
  private final String rpId;
  private final ByteArray userHandle;

  private ByteArray id;

  public PublicKeyCredentialSource(PublicKeyCredentialType type, OneKey privateKey, String rpId, ByteArray userHandle) {
    this.type = type;
    this.key = privateKey;
    this.rpId = rpId;
    this.userHandle = userHandle;
  }

  public PublicKeyCredentialType getType() {
    return type;
  }

  public OneKey getKey() {
    return key;
  }

  public String getRpId() {
    return rpId;
  }

  public ByteArray getUserHandle() {
    return userHandle;
  }

  public byte[] encrypt() {
    CBORObject map = CBORObject.NewMap()
            .Set("type", type.ordinal())
            .Set("key", key.EncodeToBytes())
            .Set("rpId", rpId);
    if (userHandle != null) {
      map.Set("user", userHandle.getBytes());
    }
    return map.EncodeToBytes();
  }

  public static Optional<PublicKeyCredentialSource> decrypt(ByteArray credentialId) {
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

  public ByteArray getId() {
    return id;
  }

  public void setId(ByteArray id) {
    this.id = id;
  }
}
