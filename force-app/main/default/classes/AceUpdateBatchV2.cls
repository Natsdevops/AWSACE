public with sharing class AceUpdateBatchV2 implements Database.Batchable<SObject>, Database.Stateful, Database.AllowsCallouts, Schedulable {
    private final String QUERY = 'SELECT id, APN_CRM_Unique_Identifier__c, AWS_Use_Case__c, CloseDate, Project_Description__c, Account.BillingPostalCode, name, Owner.Email, Owner.FirstName, Owner.LastName, Owner.Phone, stageName, Industry__c, Account.Website, Account.Name, Account.BillingCountry, Account.BillingState, Partner_Primary_Need__c, Contract_Vehicle__c, Reasons_for_loosing__c, Expected_Monthly_AWS_Revenue__c, Delivery_Model__c, Primary_Contact__r.Phone, Primary_Contact__r.FirstName, Primary_Contact__r.LastName, Primary_Contact__r.Email, Primary_Contact__r.Salutation, Acceptance_status__c, NextStep, Customer_AWS_Account_Id__c, AWS_Campaign__c, Send_to_AWS__c, AWS_Opportunity_Name__c, First_Shared_with_AWS__c, AWS_Sub_Use_Case__c, AWS_Campaign_Name__c, Is_this_Marketplace__c, Marketing_Development_Funded__c FROM Opportunity WHERE recordTypeId =: recordType AND SystemModStamp >= LAST_N_DAYS:1 AND LastModifiedById !=: integrationUser AND Send_to_AWS__c =: CMZBatch';  
    private Integer settingsIndex = 0;
    private AWS__c settings;
    private String recordType;
    private String integrationUser;
    private Boolean CMZBatch;
    private String spmsId;
    private List<Opportunity> firstShared = new List<Opportunity>();
    private List<ID> firstSharedIDs = new List<ID>();
    
    public AceUpdateBatchV2() {
        settings = AceHelperMethodsV2.CheckIntegrationType(settingsIndex);
        recordType = settings.AWS_Record_Type_ID__c;
        CMZBatch = settings.Is_CMZ__c;
        spmsId = settings.spmsID__c; 
    }
    
    public Database.QueryLocator start(Database.BatchableContext BC) { 
        return Database.getQueryLocator(QUERY);
    }
    
    public void execute(SchedulableContext SC) {
        database.executebatch(new AceUpdateBatchV2());
    }
    
    public void execute(Database.BatchableContext BC, List<Opportunity> scope) {
        List<OpportunityJSON> JSONScope = new List<OpportunityJSON>();
        
        for(Opportunity opp : scope){
            if(AceHelperMethodsV2.CheckFirstShared(opp)){ 
                opp.First_Shared_with_AWS__c = Date.Today();
                firstShared.add(opp);          
                //firstSharedIDs.add(opp.id);    
            }            
            JSONScope.add(AceHelperMethodsV2.PrepareJSONRequest(opp));
        }
        
        String resultPath = AceHelperMethodsV2.PutCRUpdateCallout(settings,JSONScope);
        
        if(!Test.isRunningTest()){
            system.enqueueJob(new AceIntegrationFutureQueue(resultPath,settings,0));
        }
    }
    
    public void finish(Database.BatchableContext BC) {
        settingsIndex++;
        if(settingsIndex <=1){
            settings = AceHelperMethodsV2.CheckIntegrationType(settingsIndex);
            recordType = settings.AWS_Record_Type_ID__c;
            CMZBatch = settings.Is_CMZ__c;
            spmsId = settings.spmsID__c;                        
            Database.executeBatch(this);
        }
        else{
            // = [SELECT id, First_Shared_with_AWS__c FROM Opportunity WHERE id IN: firstSharedIDs FOR UPDATE];
            //for(Opportunity o : firstshared){
            //    o.First_Shared_with_AWS__c = Date.Today();
            //}
            Update firstShared;
        }
    }
}