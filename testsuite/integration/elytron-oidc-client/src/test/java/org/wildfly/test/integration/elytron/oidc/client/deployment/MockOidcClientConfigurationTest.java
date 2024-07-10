/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.test.integration.elytron.oidc.client.deployment;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SYSTEM_PROPERTY;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.VALUE;
import static org.jboss.as.test.integration.management.util.ModelUtil.createOpNode;
import static org.junit.Assert.assertEquals;
//import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.http.oidc.Oidc.AuthenticationRequestFormat.REQUEST;
import static org.wildfly.security.http.oidc.Oidc.AuthenticationRequestFormat.REQUEST_URI;
import static org.wildfly.security.http.oidc.Oidc.OIDC_SCOPE;
import static org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration.ALICE;
import static org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration.ALICE_PASSWORD;
import static org.wildfly.test.integration.elytron.oidc.client.OidcBaseTest.CLIENT_HOST_NAME;
import static org.wildfly.test.integration.elytron.oidc.client.OidcBaseTest.CLIENT_PORT;
import static org.wildfly.test.integration.elytron.oidc.client.OidcBaseTest.CLIENT_SECRET;
import static org.wildfly.test.integration.elytron.oidc.client.OidcBaseTest.KEYCLOAK_CONTAINER;
import static org.wildfly.test.integration.elytron.oidc.client.OidcBaseTest.OIDC_WITHOUT_SUBSYSTEM_CONFIG_WEB_XML;
import static org.wildfly.test.integration.elytron.oidc.client.OidcBaseTest.PLAINTEXT_REQUEST_MOCK_APP;
import static org.wildfly.test.integration.elytron.oidc.client.OidcBaseTest.PLAINTEXT_REQUEST_URI_MOCK_APP;
import static org.wildfly.test.integration.elytron.oidc.client.OidcBaseTest.TEST_REALM;

import io.restassured.RestAssured;
import mockit.Mock;
import mockit.MockUp;
import org.apache.http.HttpResponse;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.HttpClientUtils;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.jboss.arquillian.container.test.api.Deployer;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
//import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.controller.descriptions.ModelDescriptionConstants;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.as.test.http.util.TestHttpClientUtils;
import org.jboss.as.test.integration.management.ManagementOperations;
import org.jboss.as.test.integration.security.common.Utils;
import org.jboss.as.test.integration.security.common.servlets.SimpleServlet;
import org.jboss.as.test.shared.TestSuiteEnvironment;
import org.jboss.as.version.Stability;
import org.jboss.dmr.ModelNode;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;
//import mockit.integration.junit4.JMockit;
import org.wildfly.security.http.oidc.OidcClientConfiguration;
import org.wildfly.test.integration.elytron.oidc.client.ArquillianJMockitRunner;
import org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration;
import org.wildfly.test.integration.elytron.oidc.client.OidcBaseTest;
import org.wildfly.test.integration.elytron.oidc.client.OidcBaseTest.Form;
import org.wildfly.test.integration.elytron.oidc.client.subsystem.SimpleServletWithScope;
import org.wildfly.test.stabilitylevel.StabilityServerSetupSnapshotRestoreTasks;

import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * Tests for cases where the OpenID provider does not support
 * request parameters when sending the request object as a JWT.
 * The OidcClientConfiguration class is mocked to return values
 * indicating a lack of support for request parameters.
 *
 * @author <a href="mailto:prpaul@redhat.com">Prarthona Paul</a>
 */
@RunWith(ArquillianJMockitRunner.class)
@RunAsClient
@ServerSetup({MockOidcClientConfigurationTest.PreviewStabilitySetupTask.class, MockOidcClientConfigurationTest.KeycloakAndSystemPropertySetup.class })
public class MockOidcClientConfigurationTest {

    private final Stability desiredStability;
    private static final String OIDC_PROVIDER_URL = "oidc.provider.url";
    private static final String PLAIN_TEXT_REQUEST_MOCK_FILE = "OidcWithPlainTextMockRequest.json";
    private static final String PLAIN_TEXT_REQUEST_URI_MOCK_FILE = "OidcWIthPlainTextMockRequestUri.json";
    private static Map<String, KeycloakConfiguration.ClientAppType> APP_NAMES;

    static {
        APP_NAMES = new HashMap<>();
        APP_NAMES.put(PLAINTEXT_REQUEST_MOCK_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
        APP_NAMES.put(PLAINTEXT_REQUEST_URI_MOCK_APP, KeycloakConfiguration.ClientAppType.OIDC_CLIENT);
    }

    public MockOidcClientConfigurationTest() {
        desiredStability = Stability.PREVIEW;
    }

    @ArquillianResource
    protected static Deployer deployer;

    @Deployment(name = PLAINTEXT_REQUEST_MOCK_APP, managed = false, testable = false)
    public static WebArchive createOpenIDWithPlainTextRequest() {
        return ShrinkWrap.create(WebArchive.class, PLAINTEXT_REQUEST_MOCK_APP + ".war")
                .addClasses(SimpleServlet.class)
                .addClasses(SimpleServletWithScope.class)
                .addAsWebInfResource(OidcWithDeploymentConfigTest.class.getPackage(), OIDC_WITHOUT_SUBSYSTEM_CONFIG_WEB_XML, "web.xml")
                .addAsWebInfResource(OidcWithDeploymentConfigTest.class.getPackage(), PLAIN_TEXT_REQUEST_MOCK_FILE, "oidc.json");
    }


    @Deployment(name = PLAINTEXT_REQUEST_URI_MOCK_APP, managed = false, testable = false)
    public static WebArchive createOpenIDWithPlainTextRequestUri() {
        return ShrinkWrap.create(WebArchive.class, PLAINTEXT_REQUEST_URI_MOCK_APP + ".war")
                .addClasses(SimpleServlet.class)
                .addClasses(SimpleServletWithScope.class)
                .addAsWebInfResource(OidcWithDeploymentConfigTest.class.getPackage(), OIDC_WITHOUT_SUBSYSTEM_CONFIG_WEB_XML, "web.xml")
                .addAsWebInfResource(OidcWithDeploymentConfigTest.class.getPackage(), PLAIN_TEXT_REQUEST_URI_MOCK_FILE, "oidc.json");
    }


    @Test
    @OperateOnDeployment(PLAINTEXT_REQUEST_MOCK_APP)
    public void testOidcWithRequestParameterUnsupported() throws Exception {
        try {
            mockOidcClientConfig();
            deployer.deploy(PLAINTEXT_REQUEST_MOCK_APP);
            loginToApp(new URL("http", TestSuiteEnvironment.getHttpAddress(), TestSuiteEnvironment.getHttpPort(),
                            "/" + PLAINTEXT_REQUEST_MOCK_APP + SimpleServletWithScope.SERVLET_PATH).toURI(), OIDC_SCOPE + "+phone+profile+email", REQUEST.getValue());
        } finally {
            deployer.undeploy(PLAINTEXT_REQUEST_MOCK_APP);
        }
    }

    @Test
    @OperateOnDeployment(PLAINTEXT_REQUEST_URI_MOCK_APP)
    public void testOidcWithRequestUriParameterUnsupported() throws Exception {
        try {
            mockOidcClientConfig();
            deployer.deploy(PLAINTEXT_REQUEST_URI_MOCK_APP);
            loginToApp(new URL("http", TestSuiteEnvironment.getHttpAddress(), TestSuiteEnvironment.getHttpPort(),
                    "/" + PLAINTEXT_REQUEST_URI_MOCK_APP + SimpleServletWithScope.SERVLET_PATH).toURI(), OIDC_SCOPE + "+phone+profile+email", REQUEST_URI.getValue());
        } finally {
            deployer.undeploy(PLAINTEXT_REQUEST_URI_MOCK_APP);
        }
    }

    private void mockOidcClientConfig(){
        new MockUp<OidcClientConfiguration>(){
            // Used to indicate that the OpenID provider does not support request_uri parameter
            @Mock
            boolean getRequestUriParameterSupported(){
                return false;
            }

            // Used to indicate that the OpenID provider does not support request parameter
            @Mock
            boolean getRequestParameterSupported(){
                return false;
            }
        };
    }

    private static void loginToApp(URI requestUri, String expectedScope, String requestMethod) throws Exception {
        CookieStore store = new BasicCookieStore();
        HttpClient httpClient = TestHttpClientUtils.promiscuousCookieHttpClientBuilder()
                .setDefaultCookieStore(store)
                .setRedirectStrategy(new LaxRedirectStrategy())
                .build();
        HttpGet getMethod = new HttpGet(requestUri);
        HttpContext context = new BasicHttpContext();
        HttpResponse response = httpClient.execute(getMethod, context);
        try {
            int statusCode = response.getStatusLine().getStatusCode();
            assertTrue("Expected code == OK but got " + statusCode + " for request=" + requestUri, statusCode == HttpURLConnection.HTTP_OK);
            Form keycloakLoginForm = new Form(response);
            HttpResponse afterLoginClickResponse = OidcBaseTest.simulateClickingOnButton(httpClient, keycloakLoginForm, ALICE, ALICE_PASSWORD, "Sign In");
            afterLoginClickResponse.getEntity().getContent();
            assertEquals(HttpURLConnection.HTTP_OK, afterLoginClickResponse.getStatusLine().getStatusCode());

            String responseString = new BasicResponseHandler().handleResponse(afterLoginClickResponse);
            assertTrue("Unexpected result " + responseString, responseString.contains(SimpleServlet.RESPONSE_BODY));
//            assertTrue(context.toString().contains("scope=" + expectedScope));  //ALL scopes should be added to the URL directly
            assertTrue(responseString.contains("profile: " + KeycloakConfiguration.ALICE_FIRST_NAME + " " + KeycloakConfiguration.ALICE_LAST_NAME));
            assertTrue(responseString.contains("email: " + KeycloakConfiguration.ALICE_EMAIL_VERIFIED));
//            assertFalse(context.toString().contains(requestMethod + "="));
        } finally {
            HttpClientUtils.closeQuietly(response);
        }
    }

    static class KeycloakAndSystemPropertySetup extends OidcBaseTest.KeycloakSetup {

        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            super.setup(managementClient, containerId);
            OidcBaseTest.sendRealmCreationRequest(KeycloakConfiguration.getRealmRepresentation(TEST_REALM, CLIENT_SECRET, CLIENT_HOST_NAME, CLIENT_PORT, APP_NAMES));

            ModelControllerClient client = managementClient.getControllerClient();
            ModelNode operation = createOpNode("system-property=" + OIDC_PROVIDER_URL, ModelDescriptionConstants.ADD);
            operation.get("value").set(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + TEST_REALM);
            Utils.applyUpdate(operation, client);

        }

        @Override
        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
            RestAssured
                    .given()
                    .auth().oauth2(org.wildfly.test.integration.elytron.oidc.client.KeycloakConfiguration.getAdminAccessToken(KEYCLOAK_CONTAINER.getAuthServerUrl()))
                    .when()
                    .delete(KEYCLOAK_CONTAINER.getAuthServerUrl() + "/admin/realms/" + TEST_REALM).then().statusCode(204);

            super.tearDown(managementClient, containerId);
            ModelControllerClient client = managementClient.getControllerClient();
            ModelNode operation = createOpNode("system-property=" + OIDC_PROVIDER_URL, ModelDescriptionConstants.REMOVE);
            Utils.applyUpdate(operation, client);

        }
    }

    public static class PreviewStabilitySetupTask extends StabilityServerSetupSnapshotRestoreTasks.Preview {
        @Override
        protected void doSetup(ManagementClient managementClient) throws Exception {
            // Write a system property so the model gets stored with a lower stability level.
            // This is to make sure we can reload back to the higher level from the snapshot
            addSystemProperty(managementClient);
        }
    }

    protected static <T extends OidcBaseTest> void addSystemProperty(ManagementClient client) throws Exception {
        ModelNode add = Util.createAddOperation(PathAddress.pathAddress(SYSTEM_PROPERTY, MockOidcClientConfigurationTest.class.getName()));
        add.get(VALUE).set(MockOidcClientConfigurationTest.class.getName());
        ManagementOperations.executeOperation(client.getControllerClient(), add);
    }
}
