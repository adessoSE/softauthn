package com.github.johnnyjayjay.jafido;

import COSE.CoseException;
import COSE.OneKey;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.yubico.internal.util.JacksonCodecs;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialType;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import java.util.Optional;

public class PublicKeyCredentialSource {

  private static final ObjectMapper mapper = new ObjectMapper();

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

  public OneKey getPrivateKey() {
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
      return Optional.of(new PublicKeyCredentialSource(type, key, rpId, userHandle));
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
