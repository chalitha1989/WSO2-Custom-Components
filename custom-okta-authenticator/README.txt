Steps
-------
1.Open the okta.properties file located at resources directory and provide values for introspectionEndpoint, client_id and client_secret for the APP developed in okta. you can provide 'NA' (client_secret=NA) if the values are not available for the app.
2.Use Maven to build the project,Copy the authorization-1.0.0-SNAPSHOT.jar￼ to <server-home>/repository/components/lib/ folder and restart the server.
3.Create and publish your API using API publisher UI(Eg: let's assume API name is BlogPost, API version is 1.0.0 and user who published the API is admin)
4.Then goto following directory
API_MANAGER_HOME/repository/deployment/server/synapse-configs/default/api/
5.Open the xml file with following format
{API Provider}–{API Name}_v{Version}.xml(Eg: admin--BlogPost_v1.0.0.xml)
6.Replace
<handler class="org.wso2.carbon.apimgt.gateway.handlers.security.APIAuthenticationHandler"/>
with 
<handler class="org.wso2.carbon.authorization.UserAuthorizationHandler"/>
7.Wait some time until API is get redeployed (Expects following message in <server-home>/repository/logs/wso2carbon.log file

[2017-02-08 11:51:54,988] INFO - API Initializing API: admin--BlogPost:v1.0.0
[2017-02-08 11:51:54,990] INFO - DependencyTracker API : admin--BlogPost:v1.0.0 was updated from the Synapse configuration successfully
[2017-02-08 11:51:54,990] INFO - APIDeployer API: admin-BlogPost:v1.0.0 has been updated from the file: /home/user/demo/setup/wso2am-2.1.0/repository/deployment/server/synapse-configs/default/api/admin--BlogPost_v1.0.0.xml
[2017-02-08 11:51:56,990] INFO - API Destroying API: admin--BlogPost:v1.0.0

8. Now the API is ready to be invoked with a token returned by OKTA.


Sample request

curl -X GET --header 'Accept: application/xml' --header 'Authorization: Bearer J6dqB5klNNFNHZZk9urPvBBpqS4gK_SRFbTPt7x4BMmz8OYYrDwhLLcw' 'https://10.200.7.41:8243/test/1/*' -k
