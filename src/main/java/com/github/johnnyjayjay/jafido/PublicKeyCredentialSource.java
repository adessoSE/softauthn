package com.github.johnnyjayjay.jafido;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.internal.util.JacksonCodecs;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import com.yubico.webauthn.data.exception.Base64UrlException;

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
  private final PrivateKey privateKey;
  private final String rpId;
  private final ByteArray userHandle;

  private ByteArray id;

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
    ByteArrayOutputStream privateKeyBytes = new ByteArrayOutputStream();
    try (ObjectOutputStream oos = new ObjectOutputStream(privateKeyBytes)) {
      oos.writeObject(privateKey);
    } catch (IOException e) {
      throw new AssertionError(e);
    }

    ObjectNode object = JacksonCodecs.cbor().createObjectNode()
        .put("type", type.ordinal())
        .put("privateKey", privateKeyBytes.toByteArray())
        .put("rpId", rpId);

    if (userHandle != null) {
      object.put("userHandle", userHandle.getBytes());
    }
    byte[] serialized;
    try {
      serialized = JacksonCodecs.cbor().writeValueAsBytes(object);
    } catch (JsonProcessingException e) {
      throw new AssertionError(e);
    }
    return new ByteArray(serialized);
  }

  public static Optional<PublicKeyCredentialSource> decrypt(ByteArray credentialId) {
    try {
      JsonNode node = JacksonCodecs.cbor().readTree(credentialId.getBytes());
      if (!node.isObject()) {
        return Optional.empty();
      }
      ObjectNode object = (ObjectNode) node;
      PublicKeyCredentialType type = PublicKeyCredentialType.values()[object.get("type").asInt()];
      ByteArrayInputStream privateKeyBytes = new ByteArrayInputStream(object.get("privateKey").binaryValue());
      PrivateKey privateKey;
      try (ObjectInputStream ois = new ObjectInputStream(privateKeyBytes)) {
        privateKey = (PrivateKey) ois.readObject();
      }
      String rpId = object.get("rpId").asText();
      JsonNode encodedUserHandle = object.get("userHandle");
      ByteArray userHandle = null;
      if (encodedUserHandle != null) {
        userHandle = new ByteArray(encodedUserHandle.binaryValue());
      }
      return Optional.of(new PublicKeyCredentialSource(type, privateKey, rpId, userHandle));
    } catch(StreamReadException | ClassNotFoundException e) {
      return Optional.empty();
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  public String toString() {
    return "PublicKeyCredentialSource{" +
            "type=" + type +
            ", privateKey=" + privateKey +
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
