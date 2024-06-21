@isTest
public class AceUpdateBatchTest{
    
    @isTest(SeeAllData=true)
    public static void testBatch() {
    
        AWS__c settings = AWS__c.getValues('AWS Integration Settings');
        Date closeDate = System.today();
       
        Test.StartTest();
        Opportunity testOpp = new Opportunity(Name='Test',APN_CRM_Unique_Identifier__c='O7365934',AWS_Use_Case__c='Business Applications',OwnerId=settings.Integration_User_Id__c, RecordTypeId=settings.AWS_Record_Type_ID__c,AccountId=settings.AWS_Integration_Account_ID__c,closeDate=closeDate,stageName='Prospect',Project_Description__c='test',Industry__c='Financial Services',Delivery_Model__c='SaaS or PaaS',Partner_Primary_Need__c='Architectural validation',Expected_Monthly_AWS_Revenue__c=100);  
        Insert testOpp;       
        AceUpdateBatch ace = new AceUpdateBatch();
        database.executebatch(ace);
        Test.StopTest();
        
    }
    
}