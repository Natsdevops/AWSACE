@RestResource(urlMapping='/ace/api/v2/read')
global with sharing class AceReadAPIv2 { 

  @HttpPut
    global static void doPut() {    
        RestRequest req = RestContext.request;                                   
        JSONParser parser = JSON.createParser(req.requestBody.toString().trim());
        parser.nextToken();
        String jsonStr = parser.getText();
        System.debug('Ace Read API:' + jsonStr);
        AWS__c setting = AceHelperMethodsV2.CheckIntegrationType(jsonStr);
        List<OpportunityJSON> oppJSONs = AceHelperMethodsV2.ReadAWSUpdate(jsonStr);
        Map<String,Opportunity> APNIdtoOppMapping = AceHelperMethodsV2.CreateAPNIdtoOppMapping(oppJSONs);
        Map<Database.UpsertResult,String> results = AceHelperMethodsV2.UpsertOpps(APNIdtoOppMapping,oppJSONs,setting);
        AceHelperMethodsV2.ProcessUpsertResults(results,setting);
   }         
}