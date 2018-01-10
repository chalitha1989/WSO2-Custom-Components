/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.authorization;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.log4j.Logger;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.rest.AbstractHandler;

import org.apache.synapse.rest.RESTConstants;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.wso2.carbon.apimgt.gateway.APIMgtGatewayConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.*;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.dto.VerbInfoDTO;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.apache.axis2.Constants;

import java.io.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UserAuthorizationHandler extends AbstractHandler {
    static Logger log = Logger.getLogger(UserAuthorizationHandler.class.getName());

    public boolean handleRequest(MessageContext messageContext) {
        if (log.isDebugEnabled()) {
            log.debug("UserAuthorizationHandler engaged.");
        }
        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
                .getAxis2MessageContext();
        Object headers = axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        BufferedReader reader = null;
        InputStream input = null;
        try {
            if (headers != null && headers instanceof Map) {
                Map headersMap = (Map) headers;
                if (headersMap.get("Authorization") == null) {
                    headersMap.clear();
                    return unauthorizedResponse(axis2MessageContext, headersMap, messageContext, "401");
                } else {
                    String authHeader = ((String) headersMap.get("Authorization")).substring(6).trim();
                    //Should be read from a config
                    Properties prop = new Properties();
                    input = getClass().getClassLoader().getResourceAsStream(OktaConstants.CONFIG_FILE_NAME);
                    prop.load(input);
                    String introspectionEndpoint = prop.getProperty("introspectionEndpoint");
                    HttpPost httpPost = new HttpPost(introspectionEndpoint);

                    log.debug("Calling Introspection Endpoint: " + introspectionEndpoint);
                    List<NameValuePair> nvps = new ArrayList<>();
                    nvps.add(new BasicNameValuePair(OktaConstants.TOKEN, authHeader));
                    nvps.add(new BasicNameValuePair(OktaConstants.TOKEN_TYPE_HINT, "access_token"));
                    String clientId = prop.getProperty(OktaConstants.CLIENT_ID);
                    String clientSecret = prop.getProperty(OktaConstants.CLIENT_SECRET);
                    if (!"NA".equals(clientId)) {
                        nvps.add(new BasicNameValuePair(OktaConstants.CLIENT_ID, clientId));
                    } if (!"NA".equals(clientSecret)) {
                        nvps.add(new BasicNameValuePair(OktaConstants.CLIENT_SECRET, clientSecret));
                    }

                    httpPost.setEntity(new UrlEncodedFormEntity(nvps));
                    httpPost.setHeader("Content-Type", "application/x-www-form-urlencoded");

                    HttpResponse response = httpClient.execute(httpPost);
                    int responseCode = response.getStatusLine().getStatusCode();

                    log.debug("HTTP responseCode received: " + responseCode);
                    JSONObject resJSON = null;
                    if (HttpStatus.SC_OK == responseCode) {
                        HttpEntity entity = response.getEntity();
                        reader = new BufferedReader(new InputStreamReader(entity.getContent(), "UTF-8"));
                        JSONParser parser = new JSONParser();

                        if (reader != null) {
                            resJSON = (JSONObject) parser.parse(reader);
                            log.debug("Returned json value: " + resJSON.toJSONString());
                        }
                        if (resJSON != null) {
                            boolean isAuthenticated = (boolean) resJSON.get("active");
                            if (isAuthenticated) {
                                axis2MessageContext.setProperty("user", resJSON.get("username"));
                                //Set scope to the axis2 message context
                                //axis2MessageContext.setProperty("scope", resJSON.get("scope"));
                                authenticateInfo(messageContext);
                                setAPIParametersToMessageContext(messageContext);

                                return true;
                            } else {
                                return unauthorizedResponse(axis2MessageContext, headersMap, messageContext, "401");
                            }
                        }
                    } // for other HTTP error codes we just pass generic message.
                    else {
                        log.error("Error occurred while calling the Introspection Endpoint.");
                        return unauthorizedResponse(axis2MessageContext, headersMap, messageContext, "500");
                    }
                }
            }
            return false;
        } catch (Exception e) {
            log.error("Unable to execute the authorization process : ", e);
            return false;
        } finally {
            if (reader != null) {
                IOUtils.closeQuietly(reader);
            }
            if (input != null) {
                IOUtils.closeQuietly(input);
            }
            try {
                if (httpClient != null) {
                    httpClient.close();
                }
            } catch (IOException e) {
                log.error(e);
            }
        }
    }

    private void authenticateInfo(MessageContext messageContext) {
        String clientIP = null;

        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
                .getAxis2MessageContext();
        TreeMap<String, String> transportHeaderMap = (TreeMap<String, String>) axis2MessageContext
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        if (transportHeaderMap != null) {
            clientIP = transportHeaderMap.get(APIMgtGatewayConstants.X_FORWARDED_FOR);
        }

        //Setting IP of the client
        if (clientIP != null && !clientIP.isEmpty()) {
            if (clientIP.indexOf(",") > 0) {
                clientIP = clientIP.substring(0, clientIP.indexOf(","));
            }
        } else {
            clientIP = (String) axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.REMOTE_ADDR);
        }

        AuthenticationContext authContext = new AuthenticationContext();
        authContext.setAuthenticated(true);

        //Can modify to support scopes based throttle policy selection
        authContext.setTier(APIConstants.UNLIMITED_TIER);
        authContext.setStopOnQuotaReach(true);
        authContext.setApiKey(clientIP);
        authContext.setKeyType(APIConstants.API_KEY_TYPE_PRODUCTION);
        authContext.setUsername((String) axis2MessageContext.getProperty("user"));
        authContext.setCallerToken(null);
        authContext.setApplicationName(null);
        authContext.setApplicationId(clientIP);
        authContext.setConsumerKey(null);
        APISecurityUtils.setAuthenticationContext(messageContext, authContext, null);
    }

    private void setAPIParametersToMessageContext(MessageContext messageContext) {

        AuthenticationContext authContext = APISecurityUtils.getAuthenticationContext(messageContext);
        org.apache.axis2.context.MessageContext axis2MsgContext = ((Axis2MessageContext) messageContext)
                .getAxis2MessageContext();

        String consumerKey = "";
        String username = "";
        String applicationName = "";
        String applicationId = "";
        if (authContext != null) {
            consumerKey = authContext.getConsumerKey();
            username = authContext.getUsername();
            applicationName = authContext.getApplicationName();
            applicationId = authContext.getApplicationId();
        }

        String context = (String) messageContext.getProperty(RESTConstants.REST_API_CONTEXT);
        String apiVersion = (String) messageContext.getProperty(RESTConstants.SYNAPSE_REST_API);

        String apiPublisher = (String) messageContext.getProperty(APIMgtGatewayConstants.API_PUBLISHER);
        //if publisher is null,extract the publisher from the api_version
        if (apiPublisher == null) {
            int ind = apiVersion.indexOf("--");
            apiPublisher = apiVersion.substring(0, ind);
            if (apiPublisher.contains(APIConstants.EMAIL_DOMAIN_SEPARATOR_REPLACEMENT)) {
                apiPublisher = apiPublisher
                        .replace(APIConstants.EMAIL_DOMAIN_SEPARATOR_REPLACEMENT, APIConstants.EMAIL_DOMAIN_SEPARATOR);
            }
        }
        int index = apiVersion.indexOf("--");

        if (index != -1) {
            apiVersion = apiVersion.substring(index + 2);
        }

        String api = apiVersion.split(":")[0];
        String version = (String) messageContext.getProperty(RESTConstants.SYNAPSE_REST_API_VERSION);
        String resource = extractResource(messageContext);
        String method = (String) (axis2MsgContext.getProperty(Constants.Configuration.HTTP_METHOD));
        String hostName = APIUtil.getHostAddress();

        messageContext.setProperty(APIMgtGatewayConstants.CONSUMER_KEY, consumerKey);
        messageContext.setProperty(APIMgtGatewayConstants.USER_ID, username);
        messageContext.setProperty(APIMgtGatewayConstants.CONTEXT, context);
        messageContext.setProperty(APIMgtGatewayConstants.API_VERSION, apiVersion);
        messageContext.setProperty(APIMgtGatewayConstants.API, api);
        messageContext.setProperty(APIMgtGatewayConstants.VERSION, version);
        messageContext.setProperty(APIMgtGatewayConstants.RESOURCE, resource);
        messageContext.setProperty(APIMgtGatewayConstants.HTTP_METHOD, method);
        messageContext.setProperty(APIMgtGatewayConstants.HOST_NAME, hostName);
        messageContext.setProperty(APIMgtGatewayConstants.API_PUBLISHER, apiPublisher);
        messageContext.setProperty(APIMgtGatewayConstants.APPLICATION_NAME, applicationName);
        messageContext.setProperty(APIMgtGatewayConstants.APPLICATION_ID, applicationId);

        APIKeyValidator validator = new APIKeyValidator(null);
        try {
            VerbInfoDTO verb = validator.findMatchingVerb(messageContext);
            if (verb != null) {
                messageContext.setProperty(APIConstants.VERB_INFO_DTO, verb);
            }
        } catch (ResourceNotFoundException e) {
            log.error("Could not find matching resource for request", e);
        } catch (APISecurityException e) {
            log.error("APISecurityException for request:", e);
        }
    }

    private String extractResource(MessageContext mc) {
        String resource = "/";
        Pattern pattern = Pattern.compile("^/.+?/.+?([/?].+)$");
        Matcher matcher = pattern.matcher((String) mc.getProperty(RESTConstants.REST_FULL_REQUEST_PATH));
        if (matcher.find()) {
            resource = matcher.group(1);
        }
        return resource;
    }

    private boolean unauthorizedResponse(org.apache.axis2.context.MessageContext axis2MessageContext, Map headersMap,
            MessageContext messageContext, String status) {
        axis2MessageContext.setProperty("HTTP_SC", status);
        headersMap.put("WWW-Authenticate", "Basic realm=\"WSO2 AM\"");
        axis2MessageContext.setProperty("NO_ENTITY_BODY", new Boolean("true"));
        messageContext.setProperty("RESPONSE", "true");
        messageContext.setTo(null);
        Axis2Sender.sendBack(messageContext);
        return false;
    }

    public void addProperty(String s, Object o) {
    }

    public Map getProperties() {
        log.info("getProperties");
        return null;
    }

    public boolean handleResponse(MessageContext messageContext) {
        return true;
    }
}
