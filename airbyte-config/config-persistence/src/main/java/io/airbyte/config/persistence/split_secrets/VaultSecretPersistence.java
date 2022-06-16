/*
 * Copyright (c) 2022 Airbyte, Inc., all rights reserved.
 */

package io.airbyte.config.persistence.split_secrets;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.response.AuthResponse;
import io.airbyte.commons.lang.Exceptions;
import java.util.HashMap;
import java.util.Optional;

import io.airbyte.config.Configs;
import lombok.extern.slf4j.Slf4j;

import static io.airbyte.config.Configs.VaultAuthMethod.AWS_IAM;

@Slf4j
final public class VaultSecretPersistence implements SecretPersistence {

  private final String SECRET_KEY = "value";
  private final Vault vault;
  private final String pathPrefix;
  private final VaultConfig config;

  public VaultSecretPersistence(final String address, final String prefix, final Configs.VaultAuthMethod authMethod, final String vaultAWSRole, final String vaultAWSIdentity, final String vaultAWSSignature) {
    this.vault = Exceptions.toRuntime(() -> getVaultClient(address));
    this.pathPrefix = prefix;
    this.config = getVaultConfig(authMethod);
  }

  /**
   * Constructor for testing
   */
  protected VaultSecretPersistence(final String address, final String prefix, final String token, final Configs.VaultAuthMethod authMethod, final String vaultAWSRole, final String vaultAWSIdentity, final String vaultAWSSignature) {
    this.vault = Exceptions.toRuntime(() -> getVaultClient(address, token));
    this.pathPrefix = prefix;
    this.config = getVaultConfig(authMethod);
  }

  private VaultConfig getVaultConfig(final Configs.VaultAuthMethod vaultAuthMethod) {

    if (vaultAuthMethod == AWS_IAM) {
      final VaultConfig config = new VaultConfig().engineVersion(2)
              .address(url)
              .sslConfig(new SslConfig().build());
      final Vault authVault = new Vault(config);
      final AuthResponse authResponse = authVault.auth()
              .loginByAwsIam(
                      role,
                      AwsIamLogin.INSTANCE.getBase64EncodedRequestUrl(),
                      AwsIamLogin.INSTANCE.getBase64EncodedRequestBody(),
                      AwsIamLogin.INSTANCE.getBase64EncodedRequestHeaders(url),
                      AwsIamLogin.INSTANCE.getAuthMount()
              );
      final String token = authResponse.getAuthClientToken();

    }

  }

  @Override
  public Optional<String> read(final SecretCoordinate coordinate) {
    try {
      final var response = vault.logical().read(pathPrefix + coordinate.getFullCoordinate());
      final var restResponse = response.getRestResponse();
      final var responseCode = restResponse.getStatus();
      if (responseCode != 200) {
        log.error("failed on read. Response code: " + responseCode);
        return Optional.empty();
      }
      final var data = response.getData();
      return Optional.of(data.get(SECRET_KEY));
    } catch (final VaultException e) {
      return Optional.empty();
    }
  }

  @Override
  public void write(final SecretCoordinate coordinate, final String payload) {
    try {
      final var newSecret = new HashMap<String, Object>();
      newSecret.put(SECRET_KEY, payload);
      vault.logical().write(pathPrefix + coordinate.getFullCoordinate(), newSecret);
    } catch (final VaultException e) {
      log.error("failed on write", e);
    }
  }

  /**
   * This creates a vault client using a vault agent which uses AWS IAM for auth using engine version 2.
   */
  private Vault getVaultClient(final String address) throws VaultException {
    final var config = this.config
        .address(address)
        .engineVersion(2)
        .build();
    return new Vault(config);
  }

  /**
   * Vault client for testing
   */
  private Vault getVaultClient(final String address, final String token) throws VaultException {
    final var config = this.config
        .address(address)
        .token(token)
        .engineVersion(2)
        .build();
    return new Vault(config);
  }
}
