public with sharing class AceUpdateBatchV2 implements Database.Batchable<SObject>, Database.Stateful, Database.AllowsCallouts, Schedulable {
    private final String QUERY = 'SELECT' 
                                    + 'id,' 
                                    + 'Opportunity_ID__c,'
                                    + 'APN_CRM_Unique_Identifier__c,'
                                    + 'AWS_Use_Case__c,'
                                    + 'Target_Consumption_Date__c,' 
                                    + 'Project_Description__c,'
                                    + 'Account.BillingPostalCode,'
                                    + 'Name,'
                                    + 'Owner.Email,'
                                    + 'Owner.FirstName,'
                                    + 'Owner.LastName,'
                                    + 'Owner.Phone,'
                                    + 'AWS_Stage__c,'
                                    + 'Market__c,'
                                    + 'Account.Website,'
                                    + 'Account.Name,'
                                    + 'Account.BillingCountry,'
                                    + 'Account.Country_Full_Name__c,'
                                    + 'Account.BillingState,'
                                    + 'Partner_Primary_Need__c,'
                                    + 'Contract_Vehicle__c,'
                                    + 'Reasons_for_losing__c,'
                                    + 'Expected_Monthly_AWS_Revenue__c,'
                                    + 'Delivery_Model__c,'
                                    + 'Main_Contact__r.Phone,'
                                    + 'Main_Contact__r.FirstName,'
                                    + 'Main_Contact__r.LastName,'
                                    + 'Main_Contact__r.Email,'
                                    + 'Main_Contact__r.Salutation,'
                                    + 'Acceptance_status__c,'
                                    + 'NextStep,'
                                    + 'Customer_AWS_Account_Id__c,'
                                    + 'AWS_Campaign__c,'
                                    + 'Send_to_AWS__c,'
                                    + 'First_Shared_with_AWS__c,'
                                    + 'AWS_Sub_Use_Case__c,'
                                    + 'AWS_Campaign_Name__c,'
                                    + 'Is_this_Marketplace__c,'
                                    + 'Marketing_Development_Funded__c,'
                                    + 'Marketing_Activity_Use_Case__c,'
                                    + 'Marketing_Activity_Channel__c,'
                                    + 'Is_Opp_From_Marketing_Activity__c,'
                                    + 'AWS_SF_Campaign_Name__c,'
                                    + 'RFX_Solicitation_Number__c' 
                                + 'FROM' 
                                    + 'Opportunity'
                                + 'WHERE' 
                                    + 'SystemModStamp >= LAST_N_DAYS:1' 
                                + 'AND' 
                                    +'LastModifiedById !=: integrationUser' 
                                + 'AND'
                                    + 'Send_to_AWS__c = true'
                                    + (Test.isRunningTest()? 'LIMIT 200':''); 
                                     
    PartnerIntegration__mdt mdt = AceHelperMethodsV2.getIntegrationMetadata();
    private List<Opportunity> firstShared = new List<Opportunity>();
    
    public AceUpdateBatchV2() {
         
    }
    
    public Database.QueryLocator start(Database.BatchableContext BC) { 
        system.debug(QUERY);
        return Database.getQueryLocator(QUERY);
    }
    
    public void execute(SchedulableContext SC) {
        database.executebatch(new AceUpdateBatchV2());
    }
    
    public void execute(Database.BatchableContext BC, List<Opportunity> scope) {
        List<OpportunityJSON> JSONScope = new List<OpportunityJSON>();

        for(Opportunity opp : scope){
            if(AceHelperMethodsV2.checkFirstShared(opp)){ 
                opp.First_Shared_with_AWS__c = Date.Today();
                firstShared.add(opp);              
            }            
            JSONScope.add(AceHelperMethodsV2.prepareOutboundOpp(opp));
        }
        
        String resultPath = AceHelperMethodsV2.putUpdateCallout(JSONScope);
        
        if(!Test.isRunningTest()){
            system.enqueueJob(new AceIntegrationFutureQueue(resultPath,mdt,1));
        }
    }
    
    public void finish(Database.BatchableContext BC) {
            Update firstShared;
    }
}