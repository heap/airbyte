/*
 * Copyright (c) 2022 Airbyte, Inc., all rights reserved.
 */

package io.airbyte.integrations.source.postgres;

import static io.airbyte.integrations.source.postgres.utils.PostgresUnitTestsUtil.createRecord;
import static io.airbyte.integrations.source.postgres.utils.PostgresUnitTestsUtil.map;
import static io.airbyte.integrations.source.postgres.utils.PostgresUnitTestsUtil.setEmittedAtToNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import io.airbyte.commons.io.IOs;
import io.airbyte.commons.json.Jsons;
import io.airbyte.commons.string.Strings;
import io.airbyte.commons.util.MoreIterators;
import io.airbyte.db.Database;
import io.airbyte.db.factory.DSLContextFactory;
import io.airbyte.db.factory.DatabaseDriver;
import io.airbyte.protocol.models.AirbyteCatalog;
import io.airbyte.protocol.models.AirbyteMessage;
import io.airbyte.protocol.models.AirbyteStream;
import io.airbyte.protocol.models.CatalogHelpers;
import io.airbyte.protocol.models.ConfiguredAirbyteCatalog;
import io.airbyte.protocol.models.Field;
import io.airbyte.protocol.models.JsonSchemaType;
import io.airbyte.protocol.models.SyncMode;
import io.airbyte.test.utils.PostgreSQLContainerHelper;
import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.jooq.DSLContext;
import org.jooq.SQLDialect;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.MountableFile;

class PostgresSourceTest {

  private static final String SCHEMA_NAME = "public";
  private static final String STREAM_NAME = "id_and_name";
  private static final String STREAM_NAME_PRIVILEGES_TEST_CASE = "id_and_name_3";
  private static final String STREAM_NAME_PRIVILEGES_TEST_CASE_VIEW = "id_and_name_3_view";
  private static final AirbyteCatalog CATALOG = new AirbyteCatalog().withStreams(List.of(
      CatalogHelpers.createAirbyteStream(
          STREAM_NAME,
          SCHEMA_NAME,
          Field.of("id", JsonSchemaType.NUMBER),
          Field.of("name", JsonSchemaType.STRING),
          Field.of("power", JsonSchemaType.NUMBER))
          .withSupportedSyncModes(Lists.newArrayList(SyncMode.FULL_REFRESH, SyncMode.INCREMENTAL))
          .withSourceDefinedPrimaryKey(List.of(List.of("id"))),
      CatalogHelpers.createAirbyteStream(
          STREAM_NAME + "2",
          SCHEMA_NAME,
          Field.of("id", JsonSchemaType.NUMBER),
          Field.of("name", JsonSchemaType.STRING),
          Field.of("power", JsonSchemaType.NUMBER))
          .withSupportedSyncModes(Lists.newArrayList(SyncMode.FULL_REFRESH, SyncMode.INCREMENTAL)),
      CatalogHelpers.createAirbyteStream(
          "names",
          SCHEMA_NAME,
          Field.of("first_name", JsonSchemaType.STRING),
          Field.of("last_name", JsonSchemaType.STRING),
          Field.of("power", JsonSchemaType.NUMBER))
          .withSupportedSyncModes(Lists.newArrayList(SyncMode.FULL_REFRESH, SyncMode.INCREMENTAL))
          .withSourceDefinedPrimaryKey(List.of(List.of("first_name"), List.of("last_name"))),
      CatalogHelpers.createAirbyteStream(
          STREAM_NAME_PRIVILEGES_TEST_CASE,
          SCHEMA_NAME,
          Field.of("id", JsonSchemaType.NUMBER),
          Field.of("name", JsonSchemaType.STRING))
          .withSupportedSyncModes(Lists.newArrayList(SyncMode.FULL_REFRESH, SyncMode.INCREMENTAL))
          .withSourceDefinedPrimaryKey(List.of(List.of("id"))),
      CatalogHelpers.createAirbyteStream(
          STREAM_NAME_PRIVILEGES_TEST_CASE_VIEW,
          SCHEMA_NAME,
          Field.of("id", JsonSchemaType.NUMBER),
          Field.of("name", JsonSchemaType.STRING))
          .withSupportedSyncModes(Lists.newArrayList(SyncMode.FULL_REFRESH, SyncMode.INCREMENTAL))
          .withSourceDefinedPrimaryKey(List.of(List.of("id")))));
  private static final ConfiguredAirbyteCatalog CONFIGURED_CATALOG = CatalogHelpers.toDefaultConfiguredCatalog(CATALOG);
  private static final Set<AirbyteMessage> ASCII_MESSAGES = Sets.newHashSet(
      createRecord(STREAM_NAME, SCHEMA_NAME, map("id", new BigDecimal("1.0"), "name", "goku", "power", null)),
      createRecord(STREAM_NAME, SCHEMA_NAME, map("id", new BigDecimal("2.0"), "name", "vegeta", "power", 9000.1)),
      createRecord(STREAM_NAME, SCHEMA_NAME, map("id", null, "name", "piccolo", "power", null)));

  private static final Set<AirbyteMessage> UTF8_MESSAGES = Sets.newHashSet(
      createRecord(STREAM_NAME, SCHEMA_NAME, ImmutableMap.of("id", 1, "name", "\u2013 someutfstring")),
      createRecord(STREAM_NAME, SCHEMA_NAME, ImmutableMap.of("id", 2, "name", "\u2215")));

  private static final Set<AirbyteMessage> PRIVILEGE_TEST_CASE_EXPECTED_MESSAGES = Sets.newHashSet(
      createRecord(STREAM_NAME_PRIVILEGES_TEST_CASE, SCHEMA_NAME, ImmutableMap.of("id", 1, "name", "Zed")),
      createRecord(STREAM_NAME_PRIVILEGES_TEST_CASE, SCHEMA_NAME, ImmutableMap.of("id", 2, "name", "Jack")),
      createRecord(STREAM_NAME_PRIVILEGES_TEST_CASE, SCHEMA_NAME, ImmutableMap.of("id", 3, "name", "Antuan")),
      createRecord(STREAM_NAME_PRIVILEGES_TEST_CASE_VIEW, SCHEMA_NAME, ImmutableMap.of("id", 1, "name", "Zed")),
      createRecord(STREAM_NAME_PRIVILEGES_TEST_CASE_VIEW, SCHEMA_NAME, ImmutableMap.of("id", 2, "name", "Jack")),
      createRecord(STREAM_NAME_PRIVILEGES_TEST_CASE_VIEW, SCHEMA_NAME, ImmutableMap.of("id", 3, "name", "Antuan")));

  private static PostgreSQLContainer<?> PSQL_DB;

  private String dbName;

  @BeforeAll
  static void init() {
    PSQL_DB = new PostgreSQLContainer<>("postgres:13-alpine");
    PSQL_DB.start();
  }

  @BeforeEach
  void setup() throws Exception {
    dbName = Strings.addRandomSuffix("db", "_", 10).toLowerCase();

    final String initScriptName = "init_" + dbName.concat(".sql");
    final String tmpFilePath = IOs.writeFileToRandomTmpDir(initScriptName, "CREATE DATABASE " + dbName + ";");
    PostgreSQLContainerHelper.runSqlScript(MountableFile.forHostPath(tmpFilePath), PSQL_DB);

    final JsonNode config = getConfig(PSQL_DB, dbName);

    try (final DSLContext dslContext = getDslContext(config)) {
      final Database database = getDatabase(dslContext);
      database.query(ctx -> {
        ctx.fetch("CREATE TABLE id_and_name(id NUMERIC(20, 10), name VARCHAR(200), power double precision, PRIMARY KEY (id));");
        ctx.fetch("CREATE INDEX i1 ON id_and_name (id);");
        ctx.fetch(
            "INSERT INTO id_and_name (id, name, power) VALUES (1,'goku', 'Infinity'),  (2, 'vegeta', 9000.1), ('NaN', 'piccolo', '-Infinity');");

        ctx.fetch("CREATE TABLE id_and_name2(id NUMERIC(20, 10), name VARCHAR(200), power double precision);");
        ctx.fetch(
            "INSERT INTO id_and_name2 (id, name, power) VALUES (1,'goku', 'Infinity'),  (2, 'vegeta', 9000.1), ('NaN', 'piccolo', '-Infinity');");

        ctx.fetch(
            "CREATE TABLE names(first_name VARCHAR(200), last_name VARCHAR(200), power double precision, PRIMARY KEY (first_name, last_name));");
        ctx.fetch(
            "INSERT INTO names (first_name, last_name, power) VALUES ('san', 'goku', 'Infinity'),  ('prince', 'vegeta', 9000.1), ('piccolo', 'junior', '-Infinity');");
        return null;
      });
    }
  }

  private static DSLContext getDslContextWithSpecifiedUser(final JsonNode config, final String username, final String password) {
    return DSLContextFactory.create(
        username,
        password,
        DatabaseDriver.POSTGRESQL.getDriverClassName(),
        String.format(DatabaseDriver.POSTGRESQL.getUrlFormatString(),
            config.get("host").asText(),
            config.get("port").asInt(),
            config.get("database").asText()),
        SQLDialect.POSTGRES);
  }

  private static Database getDatabase(final DSLContext dslContext) {
    return new Database(dslContext);
  }

  private static DSLContext getDslContext(final JsonNode config) {
    return DSLContextFactory.create(
        config.get("username").asText(),
        config.get("password").asText(),
        DatabaseDriver.POSTGRESQL.getDriverClassName(),
        String.format(DatabaseDriver.POSTGRESQL.getUrlFormatString(),
            config.get("host").asText(),
            config.get("port").asInt(),
            config.get("database").asText()),
        SQLDialect.POSTGRES);
  }

  private JsonNode getConfig(final PostgreSQLContainer<?> psqlDb, final String dbName) {
    return Jsons.jsonNode(ImmutableMap.builder()
        .put("host", psqlDb.getHost())
        .put("port", psqlDb.getFirstMappedPort())
        .put("database", dbName)
        .put("schemas", List.of(SCHEMA_NAME))
        .put("username", psqlDb.getUsername())
        .put("password", psqlDb.getPassword())
        .put("ssl", false)
        .build());
  }

  private JsonNode getConfig(final PostgreSQLContainer<?> psqlDb, final String dbName, final String user, final String password) {
    return Jsons.jsonNode(ImmutableMap.builder()
        .put("host", psqlDb.getHost())
        .put("port", psqlDb.getFirstMappedPort())
        .put("database", dbName)
        .put("schemas", List.of(SCHEMA_NAME))
        .put("username", user)
        .put("password", password)
        .put("ssl", false)
        .build());
  }

  private JsonNode getConfig(final PostgreSQLContainer<?> psqlDb, final String user, final String password) {
    return getConfig(psqlDb, psqlDb.getDatabaseName(), user, password);
  }

  private JsonNode getConfig(final PostgreSQLContainer<?> psqlDb) {
    return getConfig(psqlDb, psqlDb.getDatabaseName());
  }

  @AfterAll
  static void cleanUp() {
    PSQL_DB.close();
  }

  @Test
  public void testCanReadUtf8() throws Exception {
    // force the db server to start with sql_ascii encoding to verify the source can read UTF8 even when
    // default settings are in another encoding
    try (final PostgreSQLContainer<?> db = new PostgreSQLContainer<>("postgres:13-alpine").withCommand("postgres -c client_encoding=sql_ascii")) {
      db.start();
      final JsonNode config = getConfig(db);
      try (final DSLContext dslContext = getDslContext(config)) {
        final Database database = getDatabase(dslContext);
        database.query(ctx -> {
          ctx.fetch("CREATE TABLE id_and_name(id INTEGER, name VARCHAR(200));");
          ctx.fetch("INSERT INTO id_and_name (id, name) VALUES (1,E'\\u2013 someutfstring'),  (2, E'\\u2215');");
          return null;
        });
      }

      final Set<AirbyteMessage> actualMessages = MoreIterators.toSet(new PostgresSource().read(config, CONFIGURED_CATALOG, null));
      setEmittedAtToNull(actualMessages);

      assertEquals(UTF8_MESSAGES, actualMessages);
      db.stop();
    }
  }

  @Test
  void testUserDoesntHasPrivilegesToSelectTable() throws Exception {
    try (final PostgreSQLContainer<?> db = new PostgreSQLContainer<>("postgres:13-alpine")) {
      db.start();
      final JsonNode config = getConfig(db);
      try (final DSLContext dslContext = getDslContext(config)) {
        final Database database = new Database(dslContext);
        database.query(ctx -> {
          ctx.fetch("CREATE TABLE id_and_name(id INTEGER, name VARCHAR(200));");
          ctx.fetch("INSERT INTO id_and_name (id, name) VALUES (1,'John'),  (2, 'Alfred'), (3, 'Alex');");
          ctx.fetch("CREATE USER test_user_3 password '132';");
          ctx.fetch("GRANT CONNECT ON DATABASE test TO test_user_3;");
          ctx.fetch("REVOKE ALL PRIVILEGES ON TABLE public.id_and_name FROM test_user_3");
          return null;
        });
      }
      try (final DSLContext dslContext = getDslContextWithSpecifiedUser(config, "test_user_3", "132")) {
        final Database database = new Database(dslContext);
        database.query(ctx -> {
          ctx.fetch("CREATE TABLE id_and_name_3(id INTEGER, name VARCHAR(200));");
          ctx.fetch("CREATE VIEW id_and_name_3_view(id, name) as\n"
              + "SELECT id_and_name_3.id,\n"
              + "       id_and_name_3.name\n"
              + "FROM id_and_name_3;\n"
              + "ALTER TABLE id_and_name_3_view\n"
              + "    owner TO test_user_3");
          ctx.fetch("INSERT INTO id_and_name_3 (id, name) VALUES (1,'Zed'),  (2, 'Jack'), (3, 'Antuan');");
          return null;
        });
      }
      final JsonNode anotherUserConfig = getConfig(db, "test_user_3", "132");
      final Set<AirbyteMessage> actualMessages = MoreIterators.toSet(new PostgresSource().read(anotherUserConfig, CONFIGURED_CATALOG, null));
      setEmittedAtToNull(actualMessages);
      assertEquals(6, actualMessages.size());
      assertEquals(PRIVILEGE_TEST_CASE_EXPECTED_MESSAGES, actualMessages);
      db.stop();
    }
  }

  @Test
  void testDiscoverWithPk() throws Exception {
    final AirbyteCatalog actual = new PostgresSource().discover(getConfig(PSQL_DB, dbName));
    actual.getStreams().forEach(actualStream -> {
      final Optional<AirbyteStream> expectedStream =
          CATALOG.getStreams().stream().filter(stream -> stream.getName().equals(actualStream.getName())).findAny();
      assertTrue(expectedStream.isPresent());
      assertEquals(expectedStream.get(), actualStream);
    });
  }

  @Test
  void testDiscoverRecursiveRolePermissions() throws Exception {
    try (final PostgreSQLContainer<?> db = new PostgreSQLContainer<>("postgres:13-alpine")) {
      db.start();
      final JsonNode config = getConfig(db);
      try (final DSLContext dslContext = getDslContext(config)) {
        final Database database = new Database(dslContext);
        database.query(ctx -> {
          ctx.fetch("CREATE TABLE id_and_name_7(id INTEGER, name VARCHAR(200));");
          ctx.fetch("CREATE TABLE id_and_name(id INTEGER, name VARCHAR(200));");

          ctx.fetch("CREATE USER test_user_4 password '132';");

          ctx.fetch("CREATE ROLE airbyte LOGIN password 'airbyte';");
          ctx.fetch("CREATE ROLE read_only LOGIN password 'read_only';");
          ctx.fetch("CREATE ROLE intermediate LOGIN password 'intermediate';");

          ctx.fetch("CREATE ROLE access_nothing LOGIN password 'access_nothing';");

          ctx.fetch("GRANT intermediate TO airbyte;");
          ctx.fetch("GRANT read_only TO intermediate;");

          ctx.fetch("GRANT SELECT ON id_and_name, id_and_name_7 TO read_only;");
          ctx.fetch("GRANT airbyte TO test_user_4;");

          ctx.fetch("CREATE TABLE unseen(id INTEGER, name VARCHAR(200));");
          ctx.fetch("GRANT CONNECT ON DATABASE test TO test_user_4;");
          return null;
        });
      }
      try (final DSLContext dslContext = getDslContextWithSpecifiedUser(config, "test_user_4", "132")) {
        final Database database = new Database(dslContext);
        database.query(ctx -> {
          ctx.fetch("CREATE TABLE id_and_name_3(id INTEGER, name VARCHAR(200));");
          return null;
        });
      }
      AirbyteCatalog actual = new PostgresSource().discover(getConfig(db, "test_user_4", "132"));
      Set<String> tableNames = actual.getStreams().stream().map(stream -> stream.getName()).collect(Collectors.toSet());
      assertEquals(Sets.newHashSet("id_and_name", "id_and_name_7", "id_and_name_3"), tableNames);

      actual = new PostgresSource().discover(getConfig(db, "access_nothing", "access_nothing"));
      tableNames = actual.getStreams().stream().map(stream -> stream.getName()).collect(Collectors.toSet());
      assertEquals(Sets.newHashSet(), tableNames);
      db.stop();
    }
  }

  @Test
  void testDiscoverDifferentGrantAvailability() throws Exception {
    try (final PostgreSQLContainer<?> db = new PostgreSQLContainer<>("postgres:13-alpine")) {
      db.start();
      final JsonNode config = getConfig(db);
      try (final DSLContext dslContext = getDslContext(config)) {
        final Database database = new Database(dslContext);
        database.query(ctx -> {
          ctx.fetch("create table not_granted_table_name_1(column_1 integer);");
          ctx.fetch("create table not_granted_table_name_2(column_1 integer);");
          ctx.fetch("create table not_granted_table_name_3(column_1 integer);");
          ctx.fetch("create table table_granted_by_role(column_1 integer);");
          ctx.fetch("create table test_table_granted_directly(column_1 integer);");
          ctx.fetch("create table table_granted_by_role_with_options(column_1 integer);");
          ctx.fetch("create table test_table_granted_directly_with_options(column_1 integer);");

          ctx.fetch("create materialized view not_granted_mv_name_1 as SELECT not_granted_table_name_1.column_1 FROM not_granted_table_name_1;");
          ctx.fetch("create materialized view not_granted_mv_name_2 as SELECT not_granted_table_name_2.column_1 FROM not_granted_table_name_2;");
          ctx.fetch("create materialized view not_granted_mv_name_3 as SELECT not_granted_table_name_3.column_1 FROM not_granted_table_name_3;");
          ctx.fetch("create materialized view mv_granted_by_role as SELECT table_granted_by_role.column_1 FROM table_granted_by_role;");
          ctx.fetch(
              "create materialized view test_mv_granted_directly as SELECT test_table_granted_directly.column_1 FROM test_table_granted_directly;");
          ctx.fetch(
              "create materialized view mv_granted_by_role_with_options as SELECT table_granted_by_role_with_options.column_1 FROM table_granted_by_role_with_options;");
          ctx.fetch(
              "create materialized view test_mv_granted_directly_with_options as SELECT test_table_granted_directly_with_options.column_1 FROM test_table_granted_directly_with_options;");

          ctx.fetch("create view not_granted_view_name_1(column_1) as SELECT not_granted_table_name_1.column_1 FROM not_granted_table_name_1;");
          ctx.fetch("create view not_granted_view_name_2(column_1) as SELECT not_granted_table_name_2.column_1 FROM not_granted_table_name_2;");
          ctx.fetch("create view not_granted_view_name_3(column_1) as SELECT not_granted_table_name_3.column_1 FROM not_granted_table_name_3;");
          ctx.fetch("create view view_granted_by_role(column_1) as SELECT table_granted_by_role.column_1 FROM table_granted_by_role;");
          ctx.fetch(
              "create view test_view_granted_directly(column_1) as SELECT test_table_granted_directly.column_1 FROM test_table_granted_directly;");
          ctx.fetch(
              "create view view_granted_by_role_with_options(column_1) as SELECT table_granted_by_role_with_options.column_1 FROM table_granted_by_role_with_options;");
          ctx.fetch(
              "create view test_view_granted_directly_with_options(column_1) as SELECT test_table_granted_directly_with_options.column_1 FROM test_table_granted_directly_with_options;");

          ctx.fetch("create role test_role;");

          ctx.fetch("grant delete on not_granted_table_name_2 to test_role;");
          ctx.fetch("grant delete on not_granted_mv_name_2 to test_role;");
          ctx.fetch("grant delete on not_granted_view_name_2 to test_role;");

          ctx.fetch("grant select on table_granted_by_role to test_role;");
          ctx.fetch("grant select on mv_granted_by_role to test_role;");
          ctx.fetch("grant select on view_granted_by_role to test_role;");

          ctx.fetch("grant select on table_granted_by_role_with_options to test_role with grant option;");
          ctx.fetch("grant select on mv_granted_by_role_with_options to test_role with grant option;");
          ctx.fetch("grant select on view_granted_by_role_with_options to test_role with grant option;");

          ctx.fetch("create user new_test_user;");
          ctx.fetch("ALTER USER new_test_user WITH PASSWORD 'new_pass';");
          ctx.fetch("GRANT CONNECT ON DATABASE test TO new_test_user;");

          ctx.fetch("grant test_role to new_test_user;");

          ctx.fetch("grant delete on not_granted_table_name_3 to new_test_user;");
          ctx.fetch("grant delete on not_granted_mv_name_3 to new_test_user;");
          ctx.fetch("grant delete on not_granted_view_name_3 to new_test_user;");

          ctx.fetch("grant select on test_table_granted_directly to new_test_user;");
          ctx.fetch("grant select on test_mv_granted_directly to new_test_user;");
          ctx.fetch("grant select on test_view_granted_directly to new_test_user;");

          ctx.fetch("grant select on test_table_granted_directly_with_options to test_role with grant option;");
          ctx.fetch("grant select on test_mv_granted_directly_with_options to test_role with grant option;");
          ctx.fetch("grant select on test_view_granted_directly_with_options to test_role with grant option;");
          return null;
        });
      }

      final AirbyteCatalog actual = new PostgresSource().discover(getConfig(db, "new_test_user", "new_pass"));
      final Set<String> tableNames = actual.getStreams().stream().map(stream -> stream.getName()).collect(Collectors.toSet());
      final Set<String> expectedVisibleNames = Sets.newHashSet(
          "table_granted_by_role",
          "table_granted_by_role_with_options",
          "test_table_granted_directly",
          "test_table_granted_directly_with_options",
          "mv_granted_by_role",
          "mv_granted_by_role_with_options",
          "test_mv_granted_directly",
          "test_mv_granted_directly_with_options",
          "test_view_granted_directly",
          "test_view_granted_directly_with_options",
          "view_granted_by_role",
          "view_granted_by_role_with_options");

      assertEquals(tableNames, expectedVisibleNames);

      db.stop();
    }
  }

  @Test
  void testReadSuccess() throws Exception {
    final ConfiguredAirbyteCatalog configuredCatalog =
        CONFIGURED_CATALOG.withStreams(CONFIGURED_CATALOG.getStreams().stream().filter(s -> s.getStream().getName().equals(STREAM_NAME)).collect(
            Collectors.toList()));
    final Set<AirbyteMessage> actualMessages = MoreIterators.toSet(new PostgresSource().read(getConfig(PSQL_DB, dbName), configuredCatalog, null));
    setEmittedAtToNull(actualMessages);

    assertEquals(ASCII_MESSAGES, actualMessages);
  }

  @Test
  void testGetUsername() {
    final String username = "airbyte-user";

    // normal host
    final JsonNode normalConfig = Jsons.jsonNode(Map.of(
        "username", username,
        "jdbc_url", "jdbc:postgresql://airbyte.database.com:5432:airbyte"));
    assertEquals(username, PostgresSource.getUsername(normalConfig));

    // azure host
    final JsonNode azureConfig = Jsons.jsonNode(Map.of(
        "username", username + "@airbyte",
        "jdbc_url", "jdbc:postgresql://airbyte.azure.com:5432:airbyte"));
    assertEquals(username, PostgresSource.getUsername(azureConfig));
  }

}
