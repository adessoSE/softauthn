package com.github.johnnyjayjay.jafido;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.EdDSAParameterSpec;
import java.util.Optional;

public class PublicKeyCredentialSource {

  private static final ObjectMapper mapper = new ObjectMapper();

  private final PublicKeyCredentialType type;
  private final PrivateKey privateKey;
  private final String rpId;
  private final ByteArray userHandle;

  public PublicKeyCredentialSource(PublicKeyCredentialType type, PrivateKey privateKey, String rpId, ByteArray userHandle) {
    this.type = type;
    this.privateKey = privateKey;
    this.rpId = rpId;
    this.userHandle = userHandle;
  }

  public PublicKeyCredentialType getType() {
    return type;
  }

  public PrivateKey getPrivateKey() {
    return privateKey;
  }

  public String getRpId() {
    return rpId;
  }

  public ByteArray getUserHandle() {
    return userHandle;
  }

  public ByteArray encrypt() {
    ObjectNode object = mapper.createObjectNode()
        .put("type", type.getId())
        .put("privateKey", new ByteArray(privateKey.getEncoded()).getBase64Url())
        .put("rpId", rpId);
    if (userHandle != null) {
      object.put("userHandle", userHandle.getBase64Url());
    }
    byte[] serialized;
    try {
      serialized = mapper.writeValueAsBytes(object);
    } catch (JsonProcessingException e) {
      throw new AssertionError(e);
    }
    return new ByteArray(serialized);
  }

  public static Optional<PublicKeyCredentialSource> decrypt(ByteArray credentialId) {
    try {
      JsonNode node = mapper.readTree(credentialId.getBytes());
      if (!node.isObject()) {
        return Optional.empty();
      }
      ObjectNode object = (ObjectNode) node;
      // TODO: 26/08/2022 implement
      return Optional.empty();
    } catch(StreamReadException e) {
      return Optional.empty();
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }
}
