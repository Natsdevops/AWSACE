public class AceHelperMethodsV2{   

//---------------------------------CORE FUNCTIONS------------------------------------------    
   
//queries integration settings by partner name
    public static PartnerIntegration__mdt getIntegrationMetadata(){
        PartnerIntegration__mdt mdt = 
                                    [SELECT 
                                            AWS_Bucket__c, 
                                            AWS_Region__c, 
                                            Integration_Account__c, 
                                            Integration_User_Id__c,
                                            Partner_Name__c,
                                            Password__c,
                                            Username__c
                                    FROM PartnerIntegration__mdt
                                    WHERE Partner_Name__c = 'AWS'];
        return mdt;
    }
    
//transforms JSON string into a custom SFDC object with all the data populated 
    public static List<OpportunityJSON> convertJson(String jsonString){       
        List<OpportunityJSON> opps = new List<OpportunityJSON>();
        List<String> historicalAPNList = getHistoricalAPNList();
        JSONParser parser = JSON.createParser(jsonString);
        //parsing logic finds where opportunity list starts according to JSON structure 
        while (parser.nextToken() != null) {
            system.debug('Current token: ' + parser.getText());
            if (parser.getText() == 'opportunities') {  
                //loops through each opportunity          
                while (parser.nextToken() != null) {                                    
                    if (parser.getCurrentToken() == JSONToken.START_OBJECT) {  
                        //converts the json into custom SFDC object               
                        OpportunityJSON opp = (OpportunityJSON)parser.readValueAs(OpportunityJSON.class);
                        system.debug('Opportunity JSON: ' + opp);
                        system.debug('CRM Identifier:' + opp.partnerCrmUniqueIdentifier);
                        //checks if the opp is in the historical exclusion list
                        if(!isHistoricalAPN(historicalAPNList,opp)){
                            System.debug('ReadAWSUpdate:' + opp); 
                            opps.add(opp);
                        }
                        else{
                            system.debug(opp.partnerProjectTitle + ' has been excluded from syncing. APN ID: ' + opp.APNCRMUniqueIdentifier);
                        }                                        
                    } 
                }
            }
            parser.getText();      
        } 
        return opps;           
    } 
    
//creates a map the will return a SFDC opportunity using it's corresponding Apn Id
    public static Map<String,Opportunity> createApnIdtoOppMapping(List<OpportunityJSON> opps){        
        List<String> atosIdsFromJSON = new List<String>();
        List<String> apnIdsFromJSON = new List<String>();
        Map<String,Opportunity> oppMapping = new Map<String,Opportunity>();
        
        //sorts inbound JSON by whether partner CRM ID (Atos Opportunity Id) is blank
        for(OpportunityJSON oppJson : opps){
            if(oppJson.partnerCrmUniqueIdentifier != null){
                atosIdsFromJSON.add(oppJson.partnerCrmUniqueIdentifier);
            }
            else{
                apnIdsFromJSON.add(oppJson.APNCRMUniqueIdentifier); 
            }
        }
        
        System.debug(atosIdsFromJSON);
        System.debug(apnIdsFromJSON);
        
        //query opportunity by Atos Opportunity Id
        List<Opportunity> atosIdMatchedOpps = 
            [SELECT 
                id,
                Opportunity_ID__c, 
                APN_CRM_Unique_Identifier__c, 
                AWS_Update_Success__c, 
                AWS_Update_Errors__c, 
                IsClosed, 
                OwnerId, 
                StageName, 
                CloseDate, 
                First_Accepted_by_AWS__c,
                AWS_Acceptance_Status__c, 
                AWS_Launched_Date__c, 
                AWS_Sub_Use_Case__c, 
                AWS_Closed_Lost_Date__c 
            FROM 
                Opportunity 
            WHERE 
                Opportunity_ID__c IN :atosIdsFromJSON
            FOR UPDATE];        
        System.debug(atosIdMatchedOpps);

        //query opp by APN Id
        List<Opportunity> apnIdMatchedOpps = 
            [SELECT
                id, 
                Opportunity_ID__c,
                APN_CRM_Unique_Identifier__c, 
                AWS_Update_Success__c, 
                AWS_Update_Errors__c, 
                IsClosed, 
                OwnerId, 
                StageName, 
                CloseDate, 
                First_Accepted_by_AWS__c,
                AWS_Acceptance_Status__c, 
                AWS_Launched_Date__c, 
                AWS_Sub_Use_Case__c, 
                AWS_Closed_Lost_Date__c
            FROM    
                Opportunity
            WHERE
                APN_CRM_Unique_Identifier__c IN :apnIdsFromJSON
            FOR UPDATE
            ];

        System.debug(apnIdMatchedOpps);

        List<String> queriedAtosIds = new List<String>();
        List<String> queriedApnIds = new List<String>();

        //store list of Atos Ids that already exist on an opportunity 
        //**** if an json update has a crm partner id populated, the record should always exist because deletion is not allowed
        for(Opportunity o : atosIdMatchedOpps){
            queriedAtosIds.add(o.Opportunity_ID__c);
        }
        //store list of APN Ids that already exist on an opportunity
        for(Opportunity o : apnIdMatchedOpps){
            queriedApnIds.add(o.APN_CRM_Unique_Identifier__c);
        }
        
        //maps APN id to existing sfdc opportunity that matches the CRM Id from the AWS update
        for(OpportunityJSON oppJson : opps){
            if(oppJson.partnerCrmUniqueIdentifier != null && queriedAtosIds.contains(oppJson.partnerCrmUniqueIdentifier)){
                for(Opportunity o : atosIdMatchedOpps){
                    if(o.Opportunity_ID__c == oppJson.partnerCrmUniqueIdentifier){
                        oppMapping.put(oppJson.APNCRMUniqueIdentifier,o);
                    }
                }                   
            }
            //maps APN Id to an existing opportunity that matches APN Id
            else if(oppJson.partnerCrmUniqueIdentifier == null && queriedApnIds.contains(oppJson.APNCRMUniqueIdentifier)){
                for(Opportunity o : apnIdMatchedOpps){
                    if(o.APN_CRM_Unique_Identifier__c == oppJson.APNCRMUniqueIdentifier){
                        oppMapping.put(oppJson.APNCRMUniqueIdentifier,o);
                    }
                }  
            }
            //if no match exists (neither Atos Opportunity ID or APN Id), map APN Id to null
            else{
                if(!queriedApnIds.contains(oppJson.APNCRMUniqueIdentifier)){
                    oppMapping.put(oppJson.APNCRMUniqueIdentifier,null);   
                }
            }
        }
        System.debug('Create APN Id to Opp Mapping:' + oppMapping);
        return oppMapping;        
    }    
    
//inserts or updates opportunities in SFDC
    public static Map<Database.UpsertResult,String> upsertOpps(Map<String,Opportunity> ApntoOppMapping,List<OpportunityJSON> opps){
        List<Opportunity> upsertList = new List<Opportunity>();
        PartnerIntegration__mdt mdt = getIntegrationMetadata();
        for(OpportunityJSON json : opps){
            system.debug(json.APNCRMUniqueIdentifier);
            Opportunity o = APNtoOppMapping.get(json.APNCRMUniqueIdentifier);          
            System.debug(o);
            
            if(json.partnerCrmUniqueIdentifier == null && o == null){                            
                o = prepareNewInboundOpp(mdt,json);
                system.debug('New Inbound: ' + o);                                                        
            }
            else if(AceHelperMethodsV2.allowAWSUpdates(o) && o != null){ 
                o = prepareExistingInboundOpp(json,o);
                system.debug('Existing Inbound: ' + o);
            }
            upsertList.add(o);          
        }       
        Database.UpsertResult[] upsertResults = database.upsert(upsertList,false);
        Map<Database.UpsertResult,String> resultMap = new Map<Database.UpsertResult,String>();
        
        for(Integer i = 0;i < upsertResults.size();i++){
            resultMap.put(upsertResults[i],upsertList[i].APN_CRM_Unique_Identifier__c);
        }
        
        System.debug('Result Map:' + resultMap);
        return resultMap;       
    }
    
    public static void processUpsertResults(Map<Database.UpsertResult,String> resultMap){
        List<AWS_Integration_Log__c> logs = new List<AWS_Integration_Log__c>();        
        PartnerIntegration__mdt mdt  = getIntegrationMetadata();
        for(Database.UpsertResult result : resultMap.keySet()){
            String error = '';
            
            if(!result.isSuccess()){
                AWS_Integration_Log__c log = new AWS_Integration_Log__c();
                log.Account__c = mdt.Integration_Account__c;
                
                for(Database.Error err : result.getErrors()){
                    error += err.getMessage() + '; '; 
                }
                
                log.error__c = error;
                log.APN_Id__c = resultMap.get(result);
                
                if(!result.isCreated()){
                    log.Opportunity__c = result.getId();
                }
                
                logs.add(log);
            }
        }
        System.debug('Process Upsert Results:' + logs);
        Insert logs;    
    }
    
    public static Opportunity prepareNewInboundOpp(PartnerIntegration__mdt mdt,OpportunityJSON json){

        Opportunity o = new Opportunity();
                
        if(CheckFirstLaunched(o,json)){
            o.AWS_Launched_Date__c = Date.Today();
        }

        o.AccountId = mdt.Integration_Account__c;
        o.OwnerId = mdt.Integration_User_Id__c;
        o.Name = json.partnerProjectTitle;
        o.APN_CRM_Unique_Identifier__c = json.APNCRMUniqueIdentifier;
        o.AWS_Use_Case__c = json.useCase;
        o.CloseDate = date.valueOf(json.targetCloseDate);
        o.Target_Consumption_Date__c = date.valueOf(json.targetCloseDate);
        o.AWS_Stage__c = json.stage;
        o.stageName = 'Y0';
        o.status__c = 'E0001';
        o.Win_Probabilities__c = '10';
        o.Project_Description__c = json.projectDescription;                
        o.industry__c = IndustryMapping(json);
        o.Expected_Monthly_AWS_Revenue__c = Integer.valueOf(json.expectedMonthlyAwsRevenue);
        o.AWS_Acceptance_Status__c = json.status;
        o.Opportunity_ownership__c = json.opportunityOwnership;
        o.AWS_Sales_Rep__c = json.aWSSalesRepName;
        o.AWS_Sales_Rep_Email__c = json.aWSSalesRepEmail;
        o.AWS_Customer_Title__c = json.customerTitle;
        o.AWS_Customer_Name__c = json.customerFirstName + ' ' + json.customerLastName;
        o.AWS_Customer_Company_Name__c = json.customerCompanyName;
        o.AWS_Customer_Email__c = json.customerEmail;
        o.AWS_Customer_Phone__c = json.customerPhone;
        o.nextStep = json.nextStep;
        o.AWS_Sub_Use_Case__c = json.subUseCase; 
        o.Is_Opp_From_Marketing_Activity__c = json.IsOppFromMarketingActivity;
        o.Marketing_Activity_Channel__c = json.marketingActivityChannel;
        o.Marketing_Activity_Use_Case__c = json.marketingActivityUsecase;
        o.AWS_SF_Campaign_Name__c = json.awsSFCampaignName;
        o.RFX_Solicitation_Number__c = json.rfxSolicitationNumber;
        return o;
    }

    public static Opportunity prepareExistingInboundOpp(OpportunityJSON json, Opportunity o){
        
        if(CheckFirstLaunched(o,json)){
            o.AWS_Launched_Date__c = Date.Today();
        }
        
        if(checkFirstClosedLost(o,json)){
            o.AWS_Closed_Lost_Date__c = Date.Today();
        }
        
        if(CheckFirstApproved(o,json)){
            o.First_Accepted_by_AWS__c = Date.Today();
        } 

        o.APN_CRM_Unique_Identifier__c = json.APNCRMUniqueIdentifier;             
        o.AWS_Use_Case__c = json.useCase;
        o.Project_Description__c = json.projectDescription;
        o.AWS_Opportunity_Name__c = json.partnerProjectTitle;
        o.industry__c = IndustryMapping(json);
        o.Expected_Monthly_AWS_Revenue__c = Integer.valueOf(json.expectedMonthlyAwsRevenue);
        o.AWS_Acceptance_Status__c = json.status;
        o.Opportunity_ownership__c = json.opportunityOwnership;
        o.AWS_Sales_Rep__c = json.aWSSalesRepName;
        o.AWS_Sales_Rep_Email__c = json.aWSSalesRepEmail;
        o.AWS_Customer_Title__c = json.customerTitle;
        o.AWS_Customer_Name__c = json.customerFirstName + ' ' + json.customerLastName;
        o.AWS_Customer_Company_Name__c = json.customerCompanyName;
        o.AWS_Customer_Email__c = json.customerEmail;
        o.AWS_Customer_Phone__c = json.customerPhone;
        o.nextStep = json.nextStep;
        o.AWS_Sub_Use_Case__c = json.subUseCase; 
        o.Target_Consumption_Date__c = date.valueOf(json.targetCloseDate); 
        o.RFX_Solicitation_Number__c = json.rfxSolicitationNumber; 
        return o;             
    }

    public static OpportunityJSON prepareOutboundOpp(Opportunity o){
        OpportunityJSON oppJSON = new OpportunityJSON();
        oppJSON.name = o.Name;
        oppJSON.partnerProjectTitle = o.Name; 
        oppJSON.stage = o.AWS_Stage__c;            
        oppJSON.APNCRMUniqueIdentifier = o.APN_CRM_Unique_Identifier__c;                 
        oppJSON.useCase = o.AWS_Use_Case__c;
        oppJSON.targetCloseDate = String.valueOf(o.Target_Consumption_Date__c);
        oppJSON.projectDescription = o.Project_Description__c;
        oppJSON.primaryContactEmail = o.Owner.Email;
        oppJSON.postalCode = o.Account.BillingPostalCode;           
        oppJSON.partnerPrimaryNeedFromAws = o.Partner_Primary_Need__c;            
        oppJSON.partnerCrmUniqueIdentifier = o.id;
        oppJSON.industry = 'Aerospace';
        oppJSON.expectedMonthlyAwsRevenue = (Integer) o.Expected_Monthly_AWS_Revenue__c;
        oppJSON.deliveryModel = o.Delivery_Model__c;
        oppJSON.customerWebsite = o.Account.Website;
        oppJSON.customerCompanyName = o.Account.Name;
        oppJSON.country = o.Account.BillingCountry;
        oppJSON.contractVehicle = o.Contract_Vehicle__c;
        if(o.AWS_Stage__c == 'Closed Lost'){
            oppJSON.closedLostReason = 'Other';
        }
        oppJSON.state = o.Account.BillingState;
        oppJSON.primaryContactLastName = o.Owner.LastName;
        oppJSON.primaryContactFirstName = o.Owner.FirstName;
        oppJSON.primaryContactPhone = o.Owner.Phone;
        oppJSON.customerTitle = o.Main_Contact__r.Salutation;
        oppJSON.customerPhone = o.Main_Contact__r.Phone;
        oppJSON.customerLastName = o.Main_Contact__r.LastName;
        oppJSON.customerFirstName = o.Main_Contact__c;
        oppJSON.customerEmail = o.Main_Contact__r.Email;
        oppJSON.partnerAcceptanceStatus = o.Acceptance_status__c;
        oppJSON.nextStep = o.NextStep;
        oppJSON.awsAccountId = o.Customer_AWS_Account_Id__c;
        oppJSON.additionalComments = o.AWS_Campaign__c;
        oppJSON.subUseCase = o.AWS_Sub_Use_Case__c;
        oppJSON.campaignName = String.ValueOf(o.AWS_Campaign__c); 
        oppJSON.isMarketingDevelopmentFunded = String.ValueOf(o.Marketing_Development_Funded__c);
        oppJSON.isThisForMarketplace = String.ValueOf(o.Is_this_Marketplace__c);
        oppJSON.IsOppFromMarketingActivity = String.valueOf(o.Is_Opp_From_Marketing_Activity__c);
        oppJSON.marketingActivityChannel = String.valueOf(o.Marketing_Activity_Channel__c);
        oppJSON.marketingActivityUsecase = String.valueOf(o.Marketing_Activity_Use_Case__c);
        oppJSON.awsSFCampaignName = o.AWS_SF_Campaign_Name__c;
        oppJSON.rfxSolicitationNumber = o.RFX_Solicitation_Number__c;
        System.debug('Prepare JSON Request:' + oppJSON);    
        return oppJSON;
    }

    public static List<OpportunityResultJSON> readOutboundUpdateResults(string jsonResponse){
        String trimmedJson = jsonResponse.replace('\n','');
        List<OpportunityResultJSON> results = new List<OpportunityResultJSON>();
        JSONParser parser = JSON.createParser(trimmedJson);
        
        while (parser.nextToken() != null) {       
            if (parser.getText() == 'inboundApiResults') {           
                while (parser.nextToken() != null) {               
                    if (parser.getCurrentToken() == JSONToken.START_OBJECT) {                  
                        OpportunityResultJSON result = (OpportunityResultJSON)parser.readValueAs(OpportunityResultJSON.class);
                        results.add(result);                       
                    } 
                }
            }
        }        
        System.debug('Read CR Update Results:' + results);  
        return results;
    }
    
    public static void processOutboundUpdateResults(List<OpportunityResultJSON> results){
        Map<Id,List<String>> oppIdMapping = new Map<Id,List<String>>();
        
        for(OpportunityResultJSON result : results){
            List<String> oppResults = new List<String>{String.valueOf(result.isSuccess)};    
            
            system.debug('created list...');
            
            if(result.errors != null){
                system.debug('there are some errors...');
                oppResults.add(String.valueOf(result.errors.size()));
            }
            else{
                system.debug('there are no errors...');
                oppResults.add('0');
            }
                               
            if(!String.isBlank(result.apnCrmUniqueIdentifier)){
                system.debug('there is an Apn id...');
                oppResults.add(result.apnCrmUniqueIdentifier);
            }
            else{
                system.debug('there is no Apn id...');
                oppResults.add('');
            }
            
            if(Integer.valueOf(oppResults[1]) > 0 ){
                system.debug('there are some errors...');
                for(String s : result.errors){
                    system.debug('adding error...');                
                    oppResults.add(s);
                }
            }
            else{
            system.debug('there are no errors...');
                oppResults.add('');
            }    
            oppIdMapping.put(result.partnerCrmUniqueIdentifier,oppResults);
            system.debug('result mapping: ' + oppIdMapping);
        }
        
        List<Opportunity> oppsToUpdate = [SELECT id, AWS_Update_Success__c, AWS_Update_Errors__c, APN_CRM_Unique_Identifier__c FROM Opportunity WHERE id IN :oppIdMapping.keySet() FOR UPDATE];
        system.debug('Queried opps: ' + oppsToUpdate);
        
        List<String> result;
        integer errorCount = 0;
        
        for(Opportunity o : oppsToUpdate){
            system.debug('getting result from map...');
            result = oppIdMapping.get(o.id);
            system.debug('result: '+ result);
            o.AWS_Update_Success__c = result[0];
            
            if(o.APN_CRM_Unique_Identifier__c == null){
                system.debug('assigning apn Id');
                o.APN_CRM_Unique_Identifier__c = result[2];
            }
            
            system.debug('counting errors...');
            errorCount = Integer.valueOf(result[1]);
            o.AWS_Update_Errors__c = '';
            
            while(errorCount > 0){
                system.debug('assignig errors...');
                if(!String.isBlank(result[errorCount + 2])){                   
                    o.AWS_Update_Errors__c += result[errorCount + 2] +';';
                    system.debug('error assigned...');
                }
                errorCount -= 1;              
            }
        } 
        system.debug('Process CR Update Reults:' + oppsToUpdate);
        Update oppsToUpdate; 
    }
    
//---------------------------------SECONDARY FUNCTIONS------------------------------------------------------    

    public static Boolean allowAWSUpdates(Opportunity o){              
        Boolean allowUpdates = true;  
                 
        if(o.isClosed){
            allowUpdates = false;
        }
        
        System.debug('Allow AWS Updates:' + allowUpdates);
        return allowUpdates;
    }
    
    public static Boolean checkFirstShared(Opportunity o){
        Boolean firstShared = false;
        
        if(o.APN_CRM_Unique_Identifier__c == null && o.First_Shared_with_AWS__c == null){
            firstShared = true;
        }
        
        System.debug('Check First Shared:' + firstShared);
        return firstShared; 
    }
    
    public static Boolean checkFirstApproved(Opportunity o,OpportunityJSON json){
        Boolean firstApproved = false;
        
        if(o.First_Accepted_by_AWS__c == null && o.AWS_Acceptance_Status__c != 'Approved' && json.status == 'Approved'){
            firstApproved = true;
        }
        
        System.debug('Check First Approved:' + firstApproved);
        return firstApproved; 
    }
    
   public static Boolean checkFirstLaunched(Opportunity o,OpportunityJSON json){
        Boolean firstLaunched = false;
        
        if(o.AWS_Launched_Date__c == null && json.stage == 'Launched'){
            firstLaunched = true;
        }
        
        System.debug('Check First Launched:' + firstLaunched);
        return firstLaunched;
    }
    
    public static Boolean checkFirstClosedLost(Opportunity o, OpportunityJSON json){
        Boolean firstClosedLost = false;
        
        if(o.AWS_Closed_Lost_Date__c == null && json.stage == 'Closed Lost'){
            firstClosedLost = true;
        }
        
        System.debug('Check First Closed Lost:' + firstClosedLost);
        return firstClosedLost;
    }
    
    public static List<String> getHistoricalAPNList(){
        List<String> historicalApnIds = new List<String>();
        StaticResource sr = [SELECT Id, Body FROM StaticResource WHERE Name = 'AceHistoricalAPN' LIMIT 1];
        JSONParser parser = JSON.createParser(sr.Body.toString());
        while (parser.nextToken() != null) {
            if (parser.getCurrentToken() == JSONToken.START_ARRAY) {
                HistoricalAPNIds = (List<String>) parser.readValueAs(List<string>.Class);
            }
        }
        system.debug(historicalApnIds);
        return historicalApnIds;
    }

    public static Boolean isHistoricalApn(List<String> historicalList, OpportunityJSON opp){
        Boolean isHistoricalAtos = historicalList.contains(opp.APNCRMUniqueIdentifier);
        system.debug('isHistoricalAtos: ' + isHistoricalAtos);
        return isHistoricalAtos;
    }
    
    public static string IndustryMapping(Opportunity o){
        String convertedIndustry = '';
        
        switch on o.Market__c{
            when 'Aerospace'{
                convertedIndustry = 'Manufacturing';
            }

            when 'Agriculture'{
                convertedIndustry = 'Resources & Services';
            }
            when 'Automotive'{

                convertedIndustry = 'Manufacturing';
            }
            when 'Computers & Electronics'{
                convertedIndustry = 'Telecom, Media & Technology';
            }
           
            when 'Consumer Goods'{

                convertedIndustry = 'Manufacturing';
            }
            
            
            when 'Education'{
                convertedIndustry = 'Resources & Services';
            }
            when 'Financial Services'{

                convertedIndustry = 'Financial Services & Insurance';
            }
            when 'Gaming'{
                convertedIndustry = 'Telecom, Media & Technology';
            }
            when 'Government'{
                convertedIndustry = 'Public Sector & Defense';
            }
            when 'Healthcare' {

                convertedIndustry = 'Health & Life Sciences';
            }
            when 'Hospitality'{
                convertedIndustry = 'Resources & Services';
            }
            when 'Life Sciences'{
                convertedIndustry = 'Health & Life Sciences';
            }
            when 'Manufacturing' {

                convertedIndustry = 'Manufacturing';
            }
            when 'Marketing & Advertising'{
                convertedIndustry = 'Resources & Services';
            }
            when 'Media & Entertainment'{
                convertedIndustry = 'Telecom, Media & Technology';
            }
            when 'Mining'{
                convertedIndustry='Resources & Services';
            }
            when 'Non-Profit Organization'{
                convertedIndustry = 'Public Sector & Defense';
            }
            when 'Energy - Oil & Gas'{
                convertedIndustry = 'Resources & Services';
            }
            when 'Other'{
                convertedIndustry = 'Resources & Services';
            }
            when 'Energy - Power & Utilities'{
                convertedIndustry = 'Resources & Services';
            }
            when 'Professional Services'{
                convertedIndustry = 'Resources & Services';
            }
            when 'Real Estate & Construction'{
                convertedIndustry = 'Manufacturing';
            }
            when 'Retail'{
                convertedIndustry = 'Manufacturing';
            }
            when 'Software & Internet'{
                convertedIndustry = 'Telecom, Media & Technology';
            }
            when 'Telecommunications'{
                convertedIndustry = 'Telecom, Media & Technology';
            }
            
                
            
            when 'Wholesale & Distribution'{
                convertedIndustry = 'Resources & Services';
            }
            
        }
        System.debug('Convert Industry:' + convertedIndustry);
        return convertedIndustry;
    }

//---------------------------------API REQUESTS ----------------------------------------      
            
    public static String putUpdateCallout(List<OpportunityJSON> oppJSONScope){
        Map<String,Object> OppMap = new Map<String,Object>();
        OppMap.put('opportunities',oppJSONScope);
        OppMap.put('version','1');
        OppMap.put('spmsId','1450');
                    
        String finalJSON = JSON.serialize(OppMap);
        
        Http http = new Http();
        HttpRequest req = new HttpRequest(); 

        PartnerIntegration__mdt mdt = GetIntegrationMetadata();
        String user = mdt.Username__c;
        String pass = mdt.Password__c;
        String region = mdt.AWS_Region__c;
        String bucketName = mdt.AWS_Bucket__c;
        
        String endPointURL = 'https://s3.'+ region +'.amazonaws.com/' + bucketName + '/opportunity-inbound/';
        String filename = 'OpportunityBatch';
        filename += '-' + Datetime.now().month() + '-' + Datetime.now().day() + '-' + Datetime.now().year();
        filename += '-' + Datetime.now().hour() + 'h-' + Datetime.now().minute() + 'm-' + Datetime.now().second() + 's';
        String processedPath = filename;
        filename += '.json';
        PageReference pr = new PageReference(endPointURL + filename);
        Url endpoint = new Url(pr.getUrl());
                                               
        Map<String,String> headers1 = new Map<String,String>();
        headers1.put('x-amz-acl', 'bucket-owner-full-control');

        S3_Authentication s3Authentication = new S3_Authentication();
        req = s3Authentication.signedRequest('PUT',endpoint,headers1,Blob.valueOf(finalJSON),true,user,pass,region);        
        System.debug(req);        
                
        HTTPResponse res = http.send(req);
        System.debug(res);
        
        if (res.getStatusCode() == 200) {
            processedPath += '_result.json';
            }
        System.debug('CR Update Callout:' + processedPath);    
        return processedPath;
    }   
}
