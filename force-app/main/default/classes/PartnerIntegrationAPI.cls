@RestResource(urlMapping='/partnerIntegration/api/v1/inbound/*')
global with sharing class PartnerIntegrationAPI {
    
    @HttpPut
    global static void doPut() {
        if(RestContext.request.requestUri.endsWith('/aws')){
            RestRequest req = RestContext.request;                                   
            JSONParser parser = JSON.createParser(req.requestBody.toString().trim());
            parser.nextToken();
            String jsonStr = parser.getText();
            System.debug('Ace Read API:' + jsonStr);
            List<OpportunityJSON> oppJSONs = AceHelperMethodsV2.convertJson(jsonStr);
            Map<String,Opportunity> apnIdtoOppMapping = AceHelperMethodsV2.createApnIdtoOppMapping(oppJSONs);
            Map<Database.UpsertResult,String> results = AceHelperMethodsV2.upsertOpps(apnIdtoOppMapping,oppJSONs);
            AceHelperMethodsV2.processUpsertResults(results);
        }
        else{
            system.debug('api call unrecognized');     
        }  
    }
}