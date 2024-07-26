@isTest
public class AceHelperMethodsV2Tests{
//-----------------------API REQUEST------------------------------------------------- 

@isTest(SeeAllData=true)
    public static void putUpdateCalloutTest(){
        OpportunityJSON json1 = (OpportunityJSON) Json.deserialize('{"partnerProjectTitle":"API Test","APNCRMUniqueIdentifier":"O713940","partnerCrmUniqueIdentifier":"0065I000008FdivQAC","targetCloseDate":"2022-01-01","stage":"Prospect"}',OpportunityJSON.Class);
        List<OpportunityJSON> oppJsonList = new List<OpportunityJSON>();
        oppjsonList.add(json1);
        StaticResourceCalloutMock mock = new StaticResourceCalloutMock();
        mock.setStaticResource('AceOutboundMockResponse');
        mock.setStatusCode(200);
        mock.setHeader('Content-Type', 'application/json'); 
        
        Test.setMock(HttpCalloutMock.class, mock);
        String processedPath = AceHelperMethodsV2.putUpdateCallout(oppJsonList);
        System.Assert(processedPath.startsWith('OpportunityBatch-' + Date.Today().month() + '-' + Date.Today().day() + '-' + Date.Today().year()));
        System.Assert(processedPath.endsWith('_result.json'));
    }  
//-----------------------CORE FUNCTIONS----------------------------------------------
    
    @isTest(SeeAllData=true)
    public static void UpsertOppsTest(){
        Map<Database.UpsertResult,String> upsertResults = new Map<Database.UpsertResult,String>();
        //List<Account> testAccount = Test.loadData(Account.sObjectType, 'AceTestAcc1');
        List<Opportunity> testOpps = Test.loadData(Opportunity.sObjectType, 'AceTestOpps1');
        

        Map<String,Opportunity> oppMapping = new Map<String,Opportunity>{
            'O999999' => testOpps[0],
            'O999998' => testOpps[1],
            'O999997' => testOpps[2]    
        };        
        List<OpportunityJSON> oppJsonList = new List<OpportunityJSON>();
        OpportunityJSON json1 = (OpportunityJSON) Json.deserialize('{"partnerProjectTitle":"FirstLaunched and Allow Updates","APNCRMUniqueIdentifier":"O999999","partnerCrmUniqueIdentifier":"' + testOpps[0].id + '","targetCloseDate":"2021-01-01","stage":"Launched"}',OpportunityJSON.Class);
        OpportunityJSON json2 = (OpportunityJSON) Json.deserialize('{"partnerProjectTitle":"First Approved","APNCRMUniqueIdentifier":"O999998","partnerCrmUniqueIdentifier":"' + testOpps[1].id + '","targetCloseDate":"2021-01-01","status":"Approved"}',OpportunityJSON.Class);
        OpportunityJSON json3 = (OpportunityJSON) Json.deserialize('{"partnerProjectTitle":"First Lost","APNCRMUniqueIdentifier":"O999997","partnerCrmUniqueIdentifier":"' + testOpps[2].id + '","targetCloseDate":"2021-01-01","stage":"Closed Lost"}',OpportunityJSON.Class);
        OpportunityJSON json4 = (OpportunityJSON) Json.deserialize('{"partnerProjectTitle":"New AWS Opp","APNCRMUniqueIdentifier":"O999996","targetCloseDate":"2021-01-01","stage":"Launched"}',OpportunityJSON.Class);
        oppJsonList.add(json1);
        oppJsonList.add(json2);
        oppJsonList.add(json3);
        oppJsonList.add(json4);
        
        upsertResults = AceHelperMethodsV2.UpsertOpps(oppMapping,oppJsonList);
    }

    @isTest(SeeAllData=true)
    public static void ProcessUpsertResultsTest(){        
        List<Opportunity> testOpps = Test.loadData(Opportunity.sObjectType, 'AceTestOpps1');
        testOpps[0].StageName = null;
        Opportunity upsertFailOpp = (Opportunity) Json.deserialize('{"name":"this name is way to long to be inserted correctly because it is longer than fifty characters","APN_CRM_Unique_Identifier__c":"O999996"}',Opportunity.Class);
        testOpps.add(upsertFailOpp);
                       
        Database.UpsertResult[] upsertResults = database.upsert(testOpps,false);
        system.debug(upsertResults);
        Map<Database.UpsertResult,String> upsertResultMap = new Map<Database.UpsertResult,String>();
        
        
        for(integer i = 0;i<upsertResults.size();i++){
            upsertResultMap.put(upsertResults[i],testOpps[i].APN_CRM_Unique_Identifier__c);    
        }
       
        system.debug(upsertResultMap);
        AceHelperMethodsV2.ProcessUpsertResults(upsertResultMap);
        
        List<AWS_Integration_Log__c> logs1 = [SELECT APN_Id__c, Error__c, Opportunity__c FROM AWS_Integration_Log__c WHERE APN_Id__c = 'O999996']; 
        System.Assert(logs1.size() > 0);
        
        List<AWS_Integration_Log__c> logs2 = [SELECT APN_Id__c, Error__c, Opportunity__c FROM AWS_Integration_Log__c WHERE APN_Id__c = 'O999999']; 
        System.Assert(logs2.size() > 0);
        
        List<AWS_Integration_Log__c> logs3 = [SELECT APN_Id__c, Error__c, Opportunity__c FROM AWS_Integration_Log__c WHERE APN_Id__c = 'O999998' OR APN_Id__c = 'O999997']; 
        System.Assert(logs3.size() == 0);          
    }

//-----------------------SECONDARY FUNCTIONS-----------------------------------------

    @isTest
    public static void CheckFirstSharedTest(){
        Opportunity o = new Opportunity();
        Boolean firstShared;    
        
        o = (Opportunity) Json.deserialize('{"name":"Test","APN_CRM_Unique_Identifier__c":null,"First_Shared_with_AWS__c":null}', Opportunity.class);
        firstShared = AceHelperMethodsV2.CheckFirstShared(o);
        System.AssertEquals(True,firstShared);
        
        o = (Opportunity) Json.deserialize('{"name":"Test","APN_CRM_Unique_Identifier__c":"O999999","First_Shared_with_AWS__c":null}', Opportunity.class);
        firstShared = AceHelperMethodsV2.CheckFirstShared(o);
        System.AssertEquals(False,firstShared);
        
        o = (Opportunity) Json.deserialize('{"name":"Test","APN_CRM_Unique_Identifier__c":null,"First_Shared_with_AWS__c":"2021-01-01"}', Opportunity.class);
        firstShared = AceHelperMethodsV2.CheckFirstShared(o);
        System.AssertEquals(False,firstShared);
        
        o = (Opportunity) Json.deserialize('{"name":"Test","APN_CRM_Unique_Identifier__c":"O999999","First_Shared_with_AWS__c":"2021-01-01"}', Opportunity.class);
        firstShared = AceHelperMethodsV2.CheckFirstShared(o);
        System.AssertEquals(False,firstShared);
    }
    
    @isTest
    public static void CheckFirstApprovedTest(){
        Opportunity o = new Opportunity();
        OpportunityJson OppJson = new OpportunityJson();
        Boolean firstApproved;
        
        o = (Opportunity) Json.deserialize('{"name":"Test","First_Accepted_by_AWS__c":null,"AWS_Acceptance_Status__c":null}', Opportunity.class);
        OppJson.status = 'Approved';
        firstApproved = AceHelperMethodsV2.CheckFirstApproved(o,OppJson);
        System.AssertEquals(True,firstApproved);
        
        o = (Opportunity) Json.deserialize('{"name":"Test","First_Accepted_by_AWS__c":"2021-01-01","AWS_Acceptance_Status__c":null}', Opportunity.class);
        OppJson.status = 'Approved';
        firstApproved = AceHelperMethodsV2.CheckFirstApproved(o,OppJson);
        System.AssertEquals(False,firstApproved);
        
        o = (Opportunity) Json.deserialize('{"name":"Test","First_Accepted_by_AWS__c":null,"AWS_Acceptance_Status__c":"Approved"}', Opportunity.class);
        OppJson.status = 'Approved';
        firstApproved = AceHelperMethodsV2.CheckFirstApproved(o,OppJson);
        System.AssertEquals(False,firstApproved);
        
        o = (Opportunity) Json.deserialize('{"name":"Test","First_Accepted_by_AWS__c":"2021-01-01","AWS_Acceptance_Status__c":"Approved"}', Opportunity.class);
        OppJson.status = 'Approved';
        firstApproved = AceHelperMethodsV2.CheckFirstApproved(o,OppJson);
        System.AssertEquals(False,firstApproved);
        
        o = (Opportunity) Json.deserialize('{"name":"Test","First_Accepted_by_AWS__c":null,"AWS_Acceptance_Status__c":null}', Opportunity.class);
        OppJson.status = 'Pending';
        firstApproved = AceHelperMethodsV2.CheckFirstApproved(o,OppJson);
        System.AssertEquals(False,firstApproved);
        
        o = (Opportunity) Json.deserialize('{"name":"Test","First_Accepted_by_AWS__c":"2021-01-01","AWS_Acceptance_Status__c":null}', Opportunity.class);
        OppJson.status = 'Pending';
        firstApproved = AceHelperMethodsV2.CheckFirstApproved(o,OppJson);
        System.AssertEquals(False,firstApproved);
        
        o = (Opportunity) Json.deserialize('{"name":"Test","First_Accepted_by_AWS__c":null,"AWS_Acceptance_Status__c":"Approved"}', Opportunity.class);
        OppJson.status = 'Pending';
        firstApproved = AceHelperMethodsV2.CheckFirstApproved(o,OppJson);
        System.AssertEquals(False,firstApproved);
        
        o = (Opportunity) Json.deserialize('{"name":"Test","First_Accepted_by_AWS__c":"2021-01-01","AWS_Acceptance_Status__c":"Approved"}', Opportunity.class);
        OppJson.status = 'Pending';
        firstApproved = AceHelperMethodsV2.CheckFirstApproved(o,OppJson);
        System.AssertEquals(False,firstApproved);
    }
    
    @isTest
    public static void CheckFirstLaunchedTest(){
        Opportunity o = new Opportunity();
        OpportunityJson oppJson = new OpportunityJson();
        Boolean firstLaunched;
        
        o = (Opportunity) Json.deserialize('{"name":"Test","AWS_Launched_Date__c":null}', Opportunity.class);
        oppJson.stage = 'Launched';
        firstLaunched = AceHelperMethodsV2.CheckFirstLaunched(o,oppJson);
        System.AssertEquals(True,firstLaunched);
        
        o = (Opportunity) Json.deserialize('{"name":"Test","AWS_Launched_Date__c":"2021-01-01"}', Opportunity.class);
        oppJson.stage = 'Launched';
        firstLaunched = AceHelperMethodsV2.CheckFirstLaunched(o,oppJson);
        System.AssertEquals(False,firstLaunched);
        
        o = (Opportunity) Json.deserialize('{"name":"Test","AWS_Launched_Date__c":null}', Opportunity.class);
        oppJson.stage = 'Technical Validation';
        firstLaunched = AceHelperMethodsV2.CheckFirstLaunched(o,oppJson);
        System.AssertEquals(False,firstLaunched);
        
        o = (Opportunity) Json.deserialize('{"name":"Test","AWS_Launched_Date__c":"2021-01-01"}', Opportunity.class);
        oppJson.stage = 'Technical Validation';
        firstLaunched = AceHelperMethodsV2.CheckFirstLaunched(o,oppJson);
        System.AssertEquals(False,firstLaunched);
    }
    
    
    @isTest
    public static void CheckFirstClosedLostTest(){
        Opportunity o = new Opportunity();
        OpportunityJson oppJson = new OpportunityJson();
        Boolean firstClosedLost;
        
        o = (Opportunity) Json.deserialize('{"name":"Test","AWS_Closed_Lost_Date__c":null}', Opportunity.class);
        oppJson.stage = 'Closed Lost';
        firstClosedLost = AceHelperMethodsV2.CheckFirstClosedLost(o,oppJson);
        System.AssertEquals(True,firstClosedLost);
        
        o = (Opportunity) Json.deserialize('{"name":"Test","AWS_Closed_Lost_Date__c":"2021-01-01"}', Opportunity.class);
        oppJson.stage = 'Closed Lost';
        firstClosedLost = AceHelperMethodsV2.CheckFirstClosedLost(o,oppJson);
        System.AssertEquals(False,firstClosedLost);
        
        o = (Opportunity) Json.deserialize('{"name":"Test","AWS_Closed_Lost_Date__c":null}', Opportunity.class);
        oppJson.stage = 'Closed Won';
        firstClosedLost = AceHelperMethodsV2.CheckFirstClosedLost(o,oppJson);
        System.AssertEquals(False,firstClosedLost);
        
        o = (Opportunity) Json.deserialize('{"name":"Test","AWS_Closed_Lost_Date__c":"2021-01-01"}', Opportunity.class);
        oppJson.stage = 'Closed Won';
        firstClosedLost = AceHelperMethodsV2.CheckFirstClosedLost(o,oppJson);
        System.AssertEquals(False,firstClosedLost);
    }

    
    @isTest
    public static void getHistoricalAPNListTest(){
        List<String> testList = AceHelperMethodsV2.getHistoricalAPNList();
        system.Assert(testList.size() > 0);
    }

    
    @isTest
    public static void isHistoricalAPNTest(){
        List<String> testList = new List<String>{'O999999','O999998','O999997'};
        OpportunityJSON testOpp1 = new OpportunityJSON();
        OpportunityJSON testOpp2 = new OpportunityJSON();
        testOpp1.APNCRMUniqueIdentifier = 'O999999';
        testOpp2.APNCRMUniqueIdentifier = 'O999996';
        Boolean test1 = AceHelperMethodsV2.isHistoricalAPN(testList,testOpp1);
        Boolean test2 = AceHelperMethodsV2.isHistoricalAPN(testList,testOpp2);
        system.Assert(test1);
        system.Assert(!test2);
    }

@isTest
public static void prepareNewInboundopptest(){
    PartnerIntegration__mdt mdt=AceHelperMethodsV2.getIntegrationMetadata();
    OpportunityJSON oppJson= new OpportunityJSON();
    oppJson.APNCRMUniqueIdentifier= 'O999999';
    oppJson.stage='Closed Won';
    oppJson.industry='Aerospace';
    oppJson.targetCloseDate='2024-09-01';
    Opportunity o= AceHelperMethodsV2.prepareNewInboundOpp(mdt, oppJson);
    system.assertEquals('O999999', o.APN_CRM_Unique_Identifier__c);
    
    
}

@isTest
public static void prepareExistingInboundOppTest(){
    //PartnerIntegration__mdt mdt=AceHelperMethodsV2.getIntegrationMetadata();
    OpportunityJSON oppJson= new OpportunityJSON();
    Opportunity o= New Opportunity();
    oppJson.APNCRMUniqueIdentifier= 'O999999';
    oppJson.stage='Closed Won';
    oppJson.industry='Aerospace';
    oppJson.targetCloseDate='2024-09-01';
    Opportunity Opp= AceHelperMethodsV2.prepareExistingInboundOpp(oppJson, o);
    system.assertEquals('O999999', Opp.APN_CRM_Unique_Identifier__c);
}

@isTest
public statiC void prepareOutboundOpp(){

    PartnerIntegration__mdt mdt=AceHelperMethodsV2.getIntegrationMetadata();
    Opportunity o= new Opportunity();
    o.Name='Test';
    o.APN_CRM_Unique_Identifier__c='O999999';
    OpportunityJSON oppJson=AceHelperMethodsV2.prepareOutboundOpp(o);

    system.assertEquals('O999999', oppJson.APNCRMUniqueIdentifier);
}
@isTest
    static void testConvertJsonWithValidData() {
        // Sample JSON string with valid data
        String jsonString = '{"opportunities":[{"partnerCrmUniqueIdentifier":"123","partnerProjectTitle":"Project A","APNCRMUniqueIdentifier":"APN123"},{"partnerCrmUniqueIdentifier":"124","partnerProjectTitle":"Project B","APNCRMUniqueIdentifier":"APN124"}]}';

        // Execute the test using the convertJson method
        Test.startTest();
        List<OpportunityJSON> result = AceHelperMethodsV2.convertJson(jsonString);
        Test.stopTest();

        // Verify the results
        System.assertEquals(2, result.size());
        System.assertEquals('123', result[0].partnerCrmUniqueIdentifier);
        System.assertEquals('124', result[1].partnerCrmUniqueIdentifier);
    }

    @isTest
    static void testConvertJsonWithHistoricalData() {
        // Sample JSON string with historical data
        String jsonString = '{"opportunities":[{"partnerCrmUniqueIdentifier":"123","partnerProjectTitle":"Project A","APNCRMUniqueIdentifier":"APN123"},{"partnerCrmUniqueIdentifier":"124","partnerProjectTitle":"Project B","APNCRMUniqueIdentifier":"APN124"}]}';

        // Update the static resource to include historical APNs
        // Note: You must ensure that the StaticResource 'AceHistoricalAPN' contains 'APN123' for this test to work as expected.

        // Execute the test using the convertJson method
        Test.startTest();
        List<OpportunityJSON> result = AceHelperMethodsV2.convertJson(jsonString);
        Test.stopTest();

        // Verify the results
        System.assertEquals(2, result.size());
        System.assertEquals('123', result[0].partnerCrmUniqueIdentifier);
    }

    @isTest
    static void testConvertJsonWithInvalidData() {
        // Sample JSON string with invalid data (missing required fields)
        String jsonString = '{"opportunities":[{"partnerCrmUniqueIdentifier":"123","partnerProjectTitle":"Project A"}]}';

        // Execute the test using the convertJson method
        Test.startTest();
        List<OpportunityJSON> result = AceHelperMethodsV2.convertJson(jsonString);
        Test.stopTest();

        // Verify the results
        System.assertEquals(1, result.size(), 'The result size should be zero due to invalid data');
    }
    
        @isTest
    static void testProcessOutboundUpdateResults() {
        
        Bkp_Utils.createByPassVR();

        //Custom Setting - ByPass ProcessBuilder
        ByPass_Procss_Builders__c process=new ByPass_Procss_Builders__c(Bypass_Process_Builders__c=true);
        insert process;
        
        //Custom Setting - ByPass Workflow
        WorkflowRuleBypassSettings__c work=new WorkflowRuleBypassSettings__c(
            ByPassAllWorkflow__c=true,
            ByPassWorkflowDataMig__c=true
        );
            
            // Create products. Trigger will create price book entries
            List<Product2> products = new List<Product2>();
        for(Integer i=0; i<10; i++){
            Product2 p = new Product2();
            p.Name='Generic Product'+i;
            p.ProductCode='Code'+i;
            p.IsActive = true;
            p.Software__c = 'AC100';
            p.Offering_Product_Type__c = 'Atos';
            products.add(p);
        }
        insert products; 
        
        set<id> acccids = new set<id>();
        Account IRISParentAccount = Utils.createParentIRISAccount();
        insert IRISParentAccount;

        //acccids.add(IRISParentAccount);
        List<Account> accList = new List<account>();
        Account CustomerAccount1 = Bkp_Utils.createChildCustomerAccount('Test Customer Account1', IRISParentAccount.Id);
        CustomerAccount1.Type = 'Z002';
        accList.add(CustomerAccount1);

        Account CustomerAccount2 = Bkp_Utils.createChildCustomerAccount('Test Customer Account2', IRISParentAccount.Id);
        CustomerAccount2.Type = 'Z002';
        accList.add(CustomerAccount2);

        Account CustomerAccount3 = Bkp_Utils.createChildCustomerAccount('Test Customer Account2', IRISParentAccount.Id);
        CustomerAccount3.Type = 'Z002';
        accList.add(CustomerAccount3);        

        insert accList;

        for(Account ac: accList){
            acccids.add(ac.id);
        }

        Contact con =new Contact();
        con.lastname='test';
        con.accountId=CustomerAccount1.Id;
        con.MailingCountry='India';
        con.FirstName = 'NDA';
        con.LastName = 'Contact';
        insert con;
        
        Profit_Center__c pf = Bkp_Utils.createProfitCenter();
        pf.shortname_GBU__c = 'FRA';
        pf.shortname_country__c = 'FR';
        pf.Leading_Profit_Center__c = true;
        pf.service_line__c = 'SYN';
        pf.active__c = 0;
        insert pf;

        List<Opportunity> oppList = new List<Opportunity>();

        Opportunity Oportunity1 = Bkp_Utils.createOpportunity(CustomerAccount1.Id, pf.Id);
        Oportunity1.Rainbow_Exemption_indicator__c ='RRP006';
        Oportunity1.Profit_Center__c =pf.Id;
        Oportunity1.Name = 'Test Opp 1';
        oppList.add(Oportunity1);
        
        Opportunity Oportunity2 = Bkp_Utils.createOpportunity(CustomerAccount2.Id, pf.Id);
        Oportunity2.Rainbow_Exemption_indicator__c ='RRP006';
        Oportunity2.Profit_Center__c =pf.Id;
        Oportunity2.Name = 'Test Opp 1';
        oppList.add(Oportunity2);

        Opportunity Oportunity3 = Bkp_Utils.createOpportunity(CustomerAccount3.Id, pf.Id);
        Oportunity3.Rainbow_Exemption_indicator__c ='RRP006';
        Oportunity3.Profit_Center__c =pf.Id;
        Oportunity3.Name = 'Test Opp 1';
        oppList.add(Oportunity3);
        
        insert oppList;

        // Create test results
        List<OpportunityResultJSON> results = new List<OpportunityResultJSON>();

        OpportunityResultJSON result1 = new OpportunityResultJSON();
        result1.partnerCrmUniqueIdentifier = oppList[0].Id;
        result1.isSuccess = true;
        result1.errors = new List<String>();
        result1.apnCrmUniqueIdentifier = 'APN001';
        results.add(result1);

        OpportunityResultJSON result2 = new OpportunityResultJSON();
        result2.partnerCrmUniqueIdentifier = oppList[1].Id;
        result2.isSuccess = false;
        result2.errors = new List<String>{'Error 1', 'Error 2'};
        result2.apnCrmUniqueIdentifier = null;
        results.add(result2);

        OpportunityResultJSON result3 = new OpportunityResultJSON();
        result3.partnerCrmUniqueIdentifier = oppList[2].Id;
        result3.isSuccess = true;
        result3.errors = null;
        result3.apnCrmUniqueIdentifier = 'APN002';
        results.add(result3);

        // Execute the method
        Test.startTest();
        AceHelperMethodsV2.processOutboundUpdateResults(results);
        Test.stopTest();

        // Verify the updates
        List<Opportunity> updatedOpportunities = [SELECT Id, AWS_Update_Success__c, AWS_Update_Errors__c, APN_CRM_Unique_Identifier__c FROM Opportunity WHERE Id IN :oppList];
        
        // Check the first opportunity
        Opportunity opp1 = updatedOpportunities[0];
        System.assertEquals('true', opp1.AWS_Update_Success__c);
        System.assertEquals(null, opp1.AWS_Update_Errors__c);
        System.assertEquals('APN001', opp1.APN_CRM_Unique_Identifier__c);

        // Check the second opportunity
        Opportunity opp2 = updatedOpportunities[1];
        System.assertEquals('false', opp2.AWS_Update_Success__c);
        System.assertEquals('Error 2;Error 1;', opp2.AWS_Update_Errors__c);
        System.assertEquals(null, opp2.APN_CRM_Unique_Identifier__c);

        // Check the third opportunity
        Opportunity opp3 = updatedOpportunities[2];
        System.assertEquals('true', opp3.AWS_Update_Success__c);
        System.assertEquals(null, opp3.AWS_Update_Errors__c);
        System.assertEquals('APN002', opp3.APN_CRM_Unique_Identifier__c);
    }

}