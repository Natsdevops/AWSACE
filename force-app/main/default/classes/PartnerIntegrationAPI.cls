@RestResource(urlMapping='/partnerIntegration/api/v1/inbound/*')
global with sharing class PartnerIntegrationAPI {
    
    @HttpPut
    global static void doPut() {
        if(RestContext.request.requestUri.endsWith('/aws')){
            system.debug('aws api call successful');
        }
        else{
            system.debug('api call unrecognized');     
        }  
    }
}