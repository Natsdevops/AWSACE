@RestResource(urlMapping='/partnerIntegration/api/v1/read')
global with sharing class PartnerIntegrationAPI {
    
    @HttpPut
    global static void doPut() {
        system.debug('api call successful');
    }
}