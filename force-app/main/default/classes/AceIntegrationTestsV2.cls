@isTest
public class AceIntegrationTestsV2{
/*    
    @isTest(SeeAllData=True)
    public static void AceUpdateBatchV2Test(){
        String resultPath = 'testPath';
        AWS__c settings = AWS__c.getValues('AWS CMZ Integration Settings');
        Opportunity o1 = (Opportunity) Json.deserialize('{"name":"IntegrationTest1","stageName":"Propse","closeDate":"' + String.valueOf(Date.Today().addDays(1)) + '","recordTypeId":"0125I000000pGJLQA2","AWS_Use_Case__c":"Energy","Send_to_AWS__c":false,"SystemModStamp":"' + String.valueOf(Datetime.Now().Date()) + 'T' + String.valueOf(Datetime.Now().Time()) + '"}',Opportunity.Class);
        Opportunity o2 = (Opportunity) Json.deserialize('{"name":"IntegrationTest2","stageName":"Propse","closeDate":"' + String.valueOf(Date.Today().addDays(1)) + '","recordTypeId":"0125I000000pGJLQA2","AWS_Use_Case__c":"Big Data","Send_to_AWS__c":false,"SystemModStamp":"' + String.valueOf(Datetime.Now().Date()) + 'T' + String.valueOf(Datetime.Now().Time()) + '"}',Opportunity.Class);
        Opportunity o3 = (Opportunity) Json.deserialize('{"name":"IntegrationTest3","stageName":"Propse","closeDate":"' + String.valueOf(Date.Today().addDays(1)) + '","recordTypeId":"0120J000000VFZ0QAO","AWS_Use_Case__c":"Migration","Send_to_AWS__c":true,"SystemModStamp":"' + String.valueOf(Datetime.Now().Date()) + 'T' + String.valueOf(Datetime.Now().Time()) + '"}',Opportunity.Class);
        Opportunity o4 = (Opportunity) Json.deserialize('{"name":"IntegrationTest4","stageName":"Propse","closeDate":"' + String.valueOf(Date.Today().addDays(1)) + '","recordTypeId":"0120J000000VFZ0QAO","AWS_Use_Case__c":"Migration","Send_to_AWS__c":false,"SystemModStamp":"' + String.valueOf(Datetime.Now().Date()) + 'T' + String.valueOf(Datetime.Now().Time()) + '"}',Opportunity.Class);
        List<Opportunity> testOpps = new List<Opportunity>();
        testOpps.add(o1);
        testOpps.add(o2);
        testOpps.add(o3);
        testOpps.add(o4);
        Insert testOpps;
                
        StaticResourceCalloutMock mock = new StaticResourceCalloutMock();
        mock.setStaticResource('AceOutboundMockResponse');
        mock.setStatusCode(200);
        mock.setHeader('Content-Type', 'application/json');         
        Test.setMock(HttpCalloutMock.class, mock);
        
        Test.startTest();
        AceUpdateBatchV2 ace = new AceUpdateBatchV2();
        String jobId = database.executebatch(ace);              
        mock.setStaticResource('AceOutboundGetResults');       
        Test.setMock(HttpCalloutMock.class, mock);        
        system.enqueueJob(new AceIntegrationFutureQueue(resultPath,settings,0));        
        Test.stopTest();
    }
    
    @isTest(SeeAllData=True)
    public static void AceUpdateBatchV2Test2(){
        String resultPath = 'testPath';
        AWS__c settings = AWS__c.getValues('AWS CMZ Integration Settings');
        Opportunity o1 = (Opportunity) Json.deserialize('{"name":"IntegrationTest1","stageName":"Propse","closeDate":"' + String.valueOf(Date.Today().addDays(1)) + '","recordTypeId":"0125I000000pGJLQA2","AWS_Use_Case__c":"Energy","Send_to_AWS__c":false,"SystemModStamp":"' + String.valueOf(Datetime.Now().Date()) + 'T' + String.valueOf(Datetime.Now().Time()) + '"}',Opportunity.Class);
        Opportunity o2 = (Opportunity) Json.deserialize('{"name":"IntegrationTest2","stageName":"Propse","closeDate":"' + String.valueOf(Date.Today().addDays(1)) + '","recordTypeId":"0125I000000pGJLQA2","AWS_Use_Case__c":"Big Data","Send_to_AWS__c":false,"SystemModStamp":"' + String.valueOf(Datetime.Now().Date()) + 'T' + String.valueOf(Datetime.Now().Time()) + '"}',Opportunity.Class);
        Opportunity o3 = (Opportunity) Json.deserialize('{"name":"IntegrationTest3","stageName":"Propse","closeDate":"' + String.valueOf(Date.Today().addDays(1)) + '","recordTypeId":"0120J000000VFZ0QAO","AWS_Use_Case__c":"Migration","Send_to_AWS__c":true,"SystemModStamp":"' + String.valueOf(Datetime.Now().Date()) + 'T' + String.valueOf(Datetime.Now().Time()) + '"}',Opportunity.Class);
        Opportunity o4 = (Opportunity) Json.deserialize('{"name":"IntegrationTest4","stageName":"Propse","closeDate":"' + String.valueOf(Date.Today().addDays(1)) + '","recordTypeId":"0120J000000VFZ0QAO","AWS_Use_Case__c":"Migration","Send_to_AWS__c":false,"SystemModStamp":"' + String.valueOf(Datetime.Now().Date()) + 'T' + String.valueOf(Datetime.Now().Time()) + '"}',Opportunity.Class);
        List<Opportunity> testOpps = new List<Opportunity>();
        testOpps.add(o1);
        testOpps.add(o2);
        testOpps.add(o3);
        testOpps.add(o4);
        Insert testOpps;
        
        StaticResourceCalloutMock mock = new StaticResourceCalloutMock();
        mock.setStaticResource('AceOutboundMockResponse');
        mock.setStatusCode(200);
        mock.setHeader('Content-Type', 'application/json');         
        Test.setMock(HttpCalloutMock.class, mock);
        
        Test.startTest();
        AceUpdateBatchV2 ace = new AceUpdateBatchV2();
        String jobId = database.executebatch(ace);              
        mock.setStaticResource('AceOutboundGetResults');
        mock.setStatusCode(404);       
        Test.setMock(HttpCalloutMock.class, mock);        
        system.enqueueJob(new AceIntegrationFutureQueue(resultPath,settings,4));        
        Test.stopTest();
    }
    
    @isTest(SeeAllData=true)
    static void TestApiRequest(){
    
        RestRequest req = new RestRequest();
        RestResponse res = new RestResponse();
        
        req.requestURI = 'services/apexrest/ace/api/v2/read';
        req.httpMethod = 'PUT';
                                    
        String JSONString = '\"{\\"version\\":\\"1\\",\\"spmsId\\":\\"1450\\",\\"opportunities\\":[{\\"useCase\\":\\"AI/Machine Learning\\",\\"targetCloseDate\\":\\"2019-03-01\\",\\"streetAddress\\":\\"test\\",\\"status\\":\\"Approved\\",\\"state\\":\\"Washington\\",\\"stage\\":\\"Committed\\",\\"primaryContactPhone\\":\\"1234567890\\",\\"primaryContactLastName\\":\\"LastName\\",\\"primaryContactFirstName\\":\\"FirstName\\",\\"primaryContactEmail\\":\\"test@test.com\\",\\"postalCode\\":\\"12345\\",\\"partnerProjectTitle\\":\\"This opportunity name is too long to insert without hitting the validation\\",\\"partnerPrimaryNeedFromAws\\":\\"Competitive Information\\",\\"partnerDeveloperManagerPhone\\":\\"1234567890\\",\\"partnerCrmUniqueIdentifier\\":null,\\"opportunityOwnership\\":\\"Partner Referral\\",\\"opportunityOwnerName\\":\\"TestName\\",\\"opportunityOwnerEmail\\":\\"test@test.com\\",\\"nextStepHistory\\":\\"Test\\",\\"nextStep\\":\\"Test\\",\\"leadSource\\":\\"Event\\",\\"lastModifiedDate\\":\\"2020-01-17T20:03:10.000Z\\",\\"lastModifiedBy\\":\\"TestName\\",\\"industry\\":\\"Communications\\",\\"expectedMonthlyAwsRevenue\\":100.0,\\"deliveryModel\\":\\"SaaS or PaaS;BYOL or AMI;Managed Services;Resell\\",\\"customerFirstName\\":\\"FirstName\\",\\"customerEmail\\":\\"test@test.com\\",\\"customerCompanyName\\":\\"Test LLC\\",\\"createdDate\\":\\"2019-03-01T23:15:14.000Z\\",\\"createdBy\\":\\"TestName\\",\\"country\\":\\"United States\\",\\"contractVehicle\\":\\"Test\\",\\"competitiveTracking\\":\\"No Competition\\",\\"closedLostReason\\":null,\\"city\\":\\"test\\",\\"campaignName\\":\\"APN Marketing Central\\",\\"aWSStage\\":\\"Engaged\\",\\"aWSSalesRepName\\":\\"Test\\",\\"aWSSalesRepEmail\\":\\"test@test.com\\",\\"aWSPartnerSuccessManagerName\\":\\"Test\\",\\"aWSPartnerSuccessManagerEmail\\":\\"test@test.com\\",\\"aWSISVSuccessManagerName\\":\\"Test\\",\\"aWSISVSuccessManagerEmail\\":\\"test@test.com\\",\\"awsFieldEngagement\\":\\"No\\",\\"aWSCloseDate\\":\\"Test Date\\",\\"aWSAccountOwnerName\\":\\"Test\\",\\"aWSAccountOwnerEmail\\":\\"test@test.com\\",\\"awsAccountId\\":\\"111111111111\\",\\"apnCrmUniqueIdentifier\\":\\"O123456\\",\\"additionalComments\\":\\"TEST\\"}]}\"';
        req.requestBody = Blob.valueOf(JSONString);
        
        RestContext.request = req;
        RestContext.response = res;
        
        Test.startTest();
        List<Opportunity> testOppsNull = [SELECT id FROM Opportunity WHERE APN_CRM_Unique_Identifier__c = 'O123456'];
        System.Assert(testOppsNull.size() == 0); 
        AceReadAPIv2.doPut();
        List<Opportunity> testOpps = [SELECT id, createddate, lastmodifieddate FROM Opportunity WHERE APN_CRM_Unique_Identifier__c = 'O123456'];
        System.Assert(testOpps.size() >= 1);
        Test.stopTest(); 
    }
*/
}