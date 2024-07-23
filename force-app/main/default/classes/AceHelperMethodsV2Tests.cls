@isTest
public class AceHelperMethodsV2Tests{
//-----------------------API REQUEST------------------------------------------------- 

@isTest(SeeAllData=true)
    public static void PutCRUpdateCalloutTest(){
        AWS__c CRsetting = AWS__c.getValues('AWS Integration Settings');
        OpportunityJSON json1 = (OpportunityJSON) Json.deserialize('{"partnerProjectTitle":"API Test","APNCRMUniqueIdentifier":"O713940","partnerCrmUniqueIdentifier":"0065I000008FdivQAC","targetCloseDate":"2022-01-01","stage":"Prospect"}',OpportunityJSON.Class);
        List<OpportunityJSON> oppJsonList = new List<OpportunityJSON>();
        oppjsonList.add(json1);
        StaticResourceCalloutMock mock = new StaticResourceCalloutMock();
        mock.setStaticResource('AceOutboundMockResponse');
        mock.setStatusCode(200);
        mock.setHeader('Content-Type', 'application/json'); 
        
        Test.setMock(HttpCalloutMock.class, mock);
        String processedPath = AceHelperMethodsV2.PutCRUpdateCallout(CRsetting,oppJsonList);
        System.Assert(processedPath.startsWith('OpportunityBatch-' + Date.Today().month() + '-' + Date.Today().day() + '-' + Date.Today().year()));
        System.Assert(processedPath.endsWith('_result.json'));
    }  
/*  
//-----------------------CORE FUNCTIONS----------------------------------------------
    @isTest
    public static void CheckIntegrationTypeJSONTest(){
        AWS__c setting;
        String jsonString = '';
        
        jsonString = '{"version":"1","spmsId":"1450","opportunities":[{"name":"Test"}]}';
        setting = AceHelperMethodsV2.CheckIntegrationType(jsonString);
        System.AssertEquals(AWS__c.getValues('AWS Integration Settings'),setting);
        
        jsonString = '{"version":"1","spmsId":"5896","opportunities":[{"name":"Test"}]}';
        setting = AceHelperMethodsV2.CheckIntegrationType(jsonString);
        System.AssertEquals(AWS__c.getValues('AWS CMZ Integration Settings'),setting);
    }
    
    @isTest
    public static void CheckIntegrationTypeIntegerTest(){
        AWS__c setting;
        Integer integrationType;
        
        integrationType = 0;
        setting = AceHelperMethodsV2.CheckIntegrationType(integrationType);
        System.AssertEquals(AWS__c.getValues('AWS Integration Settings'),setting);
        
        integrationType = 1;
        setting = AceHelperMethodsV2.CheckIntegrationType(integrationType);
        System.AssertEquals(AWS__c.getValues('AWS CMZ Integration Settings'),setting);
    }
    
    @isTest(SeeAllData=true)
    public static void ReadAWSUpdateTest(){
        List<OpportunityJSON> oppJsonList = new List<OpportunityJSON>();
        String jsonString = '';
        
        jsonString = '{"version":"1","spmsId":"1450","opportunities":[{"name":"Test1","partnerProjectTitle":"test1"},{"name":"Test2","partnerCrmUniqueIdentifier":"APN","partnerProjectTitle":"test2"},{"name":"Test3","partnerCrmUniqueIdentifier":"CR","partnerProjectTitle":"test3"},{"name":"Test4","APNCRMUniqueIdentifier":"O999999","partnerProjectTitle":"test4","partnerCrmUniqueIdentifier":"APN"},{"name":"Test5","partnerProjectTitle":"#Eviden","partnerCrmUniqueIdentifier":"APN"}]}';
        oppJsonList = AceHelperMethodsV2.ReadAWSUpdate(jsonString);
        System.AssertEquals(3,oppJsonList.size());
        System.AssertEquals('Test1',oppJsonList[0].name);
        System.AssertEquals('Test2',oppJsonList[1].name);  
        System.AssertEquals(oppJsonList.size(), 3);
    }
    
    @isTest
    public static void CreateAPNIdtoOppMappingTest(){
        Map<String,Opportunity> oppMapping = new Map<String,Opportunity>();       
        List<Opportunity> testOpps = Test.loadData(Opportunity.sObjectType, 'AceTestOpps1');        
        List<OpportunityJSON> oppJsonList = new List<OpportunityJSON>();
        OpportunityJSON json1 = (OpportunityJSON) Json.deserialize('{"name":"Test1","APNCRMUniqueIdentifier":"O999999","partnerCrmUniqueIdentifier":"' + testOpps[0].id + '"}',OpportunityJSON.Class);
        OpportunityJSON json2 = (OpportunityJSON) Json.deserialize('{"name":"Test2","APNCRMUniqueIdentifier":"O999998","partnerCrmUniqueIdentifier":"' + testOpps[1].id + '"}',OpportunityJSON.Class);
        OpportunityJSON json3 = (OpportunityJSON) Json.deserialize('{"name":"Test3","APNCRMUniqueIdentifier":"O999997","partnerCrmUniqueIdentifier":"' + testOpps[2].id + '"}',OpportunityJSON.Class);
        oppJsonList.add(json1);
        oppJsonList.add(json2);
        oppJsonList.add(json3);
         
        oppMapping = AceHelperMethodsV2.CreateAPNIdtoOppMapping(oppJsonList);
        System.AssertEquals(oppMapping.keySet().size(),3);
        System.AssertEquals(oppMapping.get(json1.APNCRMUniqueIdentifier).id,testOpps[0].id);
        System.AssertEquals(oppMapping.get(json2.APNCRMUniqueIdentifier).id,testOpps[1].id);
        System.AssertEquals(oppMapping.get(json3.APNCRMUniqueIdentifier).id,testOpps[2].id);
    }
       
    @isTest(SeeAllData=true)
    public static void UpsertOppsTest(){
        Map<Database.UpsertResult,String> upsertResults = new Map<Database.UpsertResult,String>();
        List<Opportunity> testOpps = Test.loadData(Opportunity.sObjectType, 'AceTestOpps1');
        AWS__c CRsetting = AWS__c.getValues('AWS Integration Settings');
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
        
        upsertResults = AceHelperMethodsV2.UpsertOpps(oppMapping,oppJsonList,CRsetting);
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
        AceHelperMethodsV2.ProcessUpsertResults(upsertResultMap,AWS__c.getValues('AWS CMZ Integration Settings'));
        
        List<AWS_Integration_Log__c> logs1 = [SELECT APN_Id__c, Error__c, Opportunity__c FROM AWS_Integration_Log__c WHERE APN_Id__c = 'O999996']; 
        System.Assert(logs1.size() > 0);
        
        List<AWS_Integration_Log__c> logs2 = [SELECT APN_Id__c, Error__c, Opportunity__c FROM AWS_Integration_Log__c WHERE APN_Id__c = 'O999999']; 
        System.Assert(logs2.size() > 0);
        
        List<AWS_Integration_Log__c> logs3 = [SELECT APN_Id__c, Error__c, Opportunity__c FROM AWS_Integration_Log__c WHERE APN_Id__c = 'O999998' OR APN_Id__c = 'O999997']; 
        System.Assert(logs3.size() == 0);          
    }
    
    @isTest
    public static void PrepareJSONRequestTest(){
        OpportunityJSON jsonResult = new OpportunityJSON();
        Opportunity opp = (Opportunity) Json.deserialize('{"name":"test1","APN_CRM_Unique_Identifier__c":"O999996"}',Opportunity.Class);
        Date endDate = date.parse('1/1/2020');
        jsonResult = AceHelperMethodsV2.PrepareJSONRequest(opp);
        
        System.AssertEquals(opp.name,jsonResult.name);
        System.AssertEquals(opp.APN_CRM_Unique_Identifier__c,jsonResult.APNCRMUniqueIdentifier);
    }
    
    @isTest
    public static void ReadCRUpdateResultsTest(){
        List<OpportunityResultJSON> jsonResults = new List<OpportunityResultJSON>();
        Map<String,String> idMap = new Map<String,String>{
            '0065I000008thZaQAI' => 'O874286',
            '0065I000008tZt5QAE' => 'O916682',
            '0065I000008spjlQAA' => null   
        };        
        String jsonString = '{"success":"Partial","spmsId":"1450","isApiError":false,"inboundApiResults":[{"warnings":null,"partnerCrmUniqueIdentifier":"0065I000008thZaQAI","isSuccess":true,"errors":null,"apnCrmUniqueIdentifier":"O874286"},{"warnings":null,"partnerCrmUniqueIdentifier":"0065I000008tZt5QAE","isSuccess":false,"errors":["Expected Monthly AWS Revenue cannot be blank or 0","Save failed due to one of the below reasons: \n1 Marking opportunity as Launched without AWS Account ID \n2 Removing/Deleting AWS Account ID from opportunity marked as Launched"],"apnCrmUniqueIdentifier":"O916682"},{"warnings":null,"partnerCrmUniqueIdentifier":"0065I000008spjlQAA","isSuccess":false,"errors":["Required: Postal Code","Estimated AWS Monthly Recurring Revenue cannot be blank or 0"],"apnCrmUniqueIdentifier":null}],"fileName":"opportunity-inbound/OpportunityBatch-12-20-2021-22h-0m-47s.json","fileApnProcessedDT":"2021-12-20T22:00:51.201Z","apiErrors":null}';
        
        jsonResults = AceHelperMethodsV2.ReadCRUpdateResults(jsonString);
        
        for(OpportunityResultJSON result : jsonResults){
            System.AssertEquals(idMap.get(result.partnerCrmUniqueIdentifier),result.apnCrmUniqueIdentifier);        
        }
        
    }
    
    @isTest
    public static void ProcessCRUpdateResultsTest(){
        List<Opportunity> testOpps = Test.loadData(Opportunity.sObjectType, 'AceTestOpps1');
        List<OpportunityResultJSON> results = new List<OpportunityResultJSON>();
        OpportunityResultJSON result1 = (OpportunityResultJSON) Json.deserialize('{"warnings":null,"partnerCrmUniqueIdentifier":"' + testOpps[0].id + '","isSuccess":true,"errors":null,"apnCrmUniqueIdentifier":"O999999"}',OpportunityResultJSON.class);
        OpportunityResultJSON result2 = (OpportunityResultJSON) Json.deserialize('{"warnings":null,"partnerCrmUniqueIdentifier":"' + testOpps[1].id + '","isSuccess":false,"errors":["The postal code is invalid for country United Kingdom, United Kingdom postal code must be in A(A)N(A/N)NAA OR A(A)N(A/N) NAA format.","Target Close Date cannot be in the past.","Target Close Date cannot be in the past."],"apnCrmUniqueIdentifier":"O999998"}',OpportunityResultJSON.class);
        OpportunityResultJSON result3 = (OpportunityResultJSON) Json.deserialize('{"warnings":null,"partnerCrmUniqueIdentifier":"' + testOpps[3].id + '","isSuccess":true,"errors":null,"apnCrmUniqueIdentifier":"O999996"}',OpportunityResultJSON.class);
        OpportunityResultJSON result4 = (OpportunityResultJSON) Json.deserialize('{"warnings":null,"partnerCrmUniqueIdentifier":"' + testOpps[2].id + '","isSuccess":false,"errors":["The postal code is invalid"],"apnCrmUniqueIdentifier":null}',OpportunityResultJSON.class);
        testOpps[2].APN_CRM_Unique_Identifier__c = null;
        results.add(result1);
        results.add(result2);
        results.add(result3);
        results.add(result4);
        
        System.AssertEquals(testOpps[0].AWS_Update_Success__c,null);
        System.AssertEquals(testOpps[1].AWS_Update_Success__c,null);
        System.AssertEquals(testOpps[2].AWS_Update_Success__c,null);
        System.Assert(testOpps[2].APN_CRM_Unique_Identifier__c == null);
        System.AssertEquals(testOpps[3].AWS_Update_Success__c,null);
        System.Assert(testOpps[3].APN_CRM_Unique_Identifier__c == null);
        
        AceHelperMethodsV2.ProcessCRUpdateResults(results);
        
        List<Opportunity> test1 = [SELECT id, AWS_Update_Success__c FROM Opportunity WHERE id = :testOpps[0].id];
        System.AssertEquals(test1[0].AWS_Update_Success__c,'true');
        
        List<Opportunity> test2 = [SELECT id, AWS_Update_Success__c FROM Opportunity WHERE id = :testOpps[1].id];
        System.AssertEquals(test2[0].AWS_Update_Success__c,'false');
        
        List<Opportunity> test3 = [SELECT id, AWS_Update_Success__c, APN_CRM_Unique_Identifier__c FROM Opportunity WHERE id = :testOpps[3].id];
        System.AssertEquals(test3[0].AWS_Update_Success__c,'true');
        System.AssertEquals(test3[0].APN_CRM_Unique_Identifier__c,'O999996');
        
        List<Opportunity> test4 = [SELECT id, AWS_Update_Success__c, APN_CRM_Unique_Identifier__c FROM Opportunity WHERE id = :testOpps[2].id];
        System.AssertEquals(test4[0].AWS_Update_Success__c,'false');
    }

//-----------------------SECONDARY FUNCTIONS-----------------------------------------
    @isTest
    public static void ConvertStageOpportunityTest(){   
        Opportunity o = new Opportunity();
        String convertedStage = '';
        Map<String,String> stageNames = new Map<String,String>{
            'Prospect' => 'Prospect',
            'Qualify' => 'Qualified',
            'Propose' => 'Technical Validation',
            'Negotiate' => 'Business Validation',
            'Procure' => 'Committed',           
            'Order Validated' => 'Committed',
            'Closed Lost' => 'Closed Lost'
        };
        
        for(String stageName : stageNames.keySet()){
            o.stageName = stageName;        
            convertedStage = AceHelperMethodsV2.ConvertStage(o);
            System.AssertEquals(stageNames.get(stagename),convertedStage);
        } 
        
        o.stageName = 'Closed Won';
        convertedStage = AceHelperMethodsV2.ConvertStage(o);
        System.AssertEquals('Committed',convertedStage);
        
        o.Customer_AWS_Account_Id__c = '123456789101';
        convertedStage = AceHelperMethodsV2.ConvertStage(o);
        System.AssertEquals('Launched',convertedStage);
              
    }
    
    @isTest
    public static void ConvertStageOpportunityJSONTest(){   
        OpportunityJSON json = new OpportunityJSON();
        String convertedStage = '';
        Map<String,String> stageNames = new Map<String,String>{
            'Prospect' => 'Prospect',
            'Qualified' => 'Qualify',
            'Technical Validation' => 'Propose',
            'Business Validation' => 'Negotiate',
            'Committed' => 'Procure',
            'Launched' => 'Closed Won',            
            'Closed Lost' => 'Closed Lost'
        };
        
        for(String stageName : stageNames.keySet()){
            json.stage = stageName;        
            convertedStage = AceHelperMethodsV2.ConvertStage(json);
            System.AssertEquals(stageNames.get(stagename),convertedStage);
        } 
    }
    
    @isTest
    public static void AllowAWSUpdatesTest(){
        Opportunity o = new Opportunity();
        Boolean allowAWSUpdate;
        
        o = (Opportunity) Json.deserialize('{"name":"Test", "isClosed": false}', Opportunity.class);
        allowAWSUpdate = AceHelperMethodsV2.AllowAWSUpdates(o);
        System.AssertEquals(True,allowAWSUpdate);
        
        o = (Opportunity) Json.deserialize('{"name":"Test", "isClosed": true}', Opportunity.class);                                                
        allowAWSUpdate = AceHelperMethodsV2.AllowAWSUpdates(o);
        System.AssertEquals(False,allowAWSUpdate);
    }
    
    @isTest(SeeAllData=true)
    public static void AllowStageAndCloseDateUpdatesTest(){
        Opportunity o = new Opportunity();
        Boolean AllowStageAndCloseDateUpdates;
        AWS__c setting = AWS__c.getValues('AWS Integration Settings');
        String integrationUserId = setting.Integration_User_Id__c;
        
        o = (Opportunity) Json.deserialize('{"name":"Test","APN_CRM_Unique_Identifier__c":null,"ownerId":"' + integrationUserId + '"}', Opportunity.class);
        AllowStageAndCloseDateUpdates = AceHelperMethodsV2.AllowStageAndCloseDateUpdates(o,setting);
        System.AssertEquals(True,AllowStageAndCloseDateUpdates);

        o = (Opportunity) Json.deserialize('{"name":"Test","APN_CRM_Unique_Identifier__c":"123456789101"}', Opportunity.class);
        AllowStageAndCloseDateUpdates = AceHelperMethodsV2.AllowStageAndCloseDateUpdates(o,setting);
        System.AssertEquals(False,AllowStageAndCloseDateUpdates);
    }
    
    @isTest
    public static void CheckNameLengthTest(){
        OpportunityJson json = new OpportunityJson();
        String name = '';
        
        json.partnerProjectTitle = 'This partner project title is longer than fifty characters and should be trimmed';
        name = AceHelperMethodsV2.CheckNameLength(json);
        System.AssertEquals(json.partnerProjectTitle.left(50),name);
        
        json.partnerProjectTitle = 'This partner project is less than 50 characters';
        name = AceHelperMethodsV2.CheckNameLength(json);
        System.AssertEquals(json.partnerProjectTitle,name);            
    }
    
    @isTest
    public static void CheckAWSNameTest(){
        Opportunity o = new Opportunity();
        String name = '';        
        
        o = (Opportunity) Json.deserialize('{"name":"Test"}', Opportunity.class);
        name = AceHelperMethodsV2.CheckAWSName(o);
        System.AssertEquals(o.name,name);
        
        o = (Opportunity) Json.deserialize('{"name":"Test","AWS_Opportunity_Name__c":"AWS Test"}', Opportunity.class);
        name = AceHelperMethodsV2.CheckAWSName(o);
        System.AssertEquals(o.AWS_Opportunity_Name__c,name);
    }
    */
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
    /*
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
    public static void getHistoricalAtosAPNListTest(){
        List<String> testList = AceHelperMethodsV2.getHistoricalAtosAPNList();
        system.Assert(testList.size() > 0);
    }

    @isTest
    public static void isHistoricalAtosAPNTest(){
        List<String> testList = new List<String>{'O999999','O999998','O999997'};
        OpportunityJSON testOpp1 = new OpportunityJSON();
        OpportunityJSON testOpp2 = new OpportunityJSON();
        testOpp1.APNCRMUniqueIdentifier = 'O999999';
        testOpp2.APNCRMUniqueIdentifier = 'O999996';
        Boolean test1 = AceHelperMethodsV2.isHistoricalAtosAPN(testList,testOpp1);
        Boolean test2 = AceHelperMethodsV2.isHistoricalAtosAPN(testList,testOpp2);
        system.Assert(test1);
        system.Assert(!test2);
    }

    @isTest
    public static void isAtosOppTest(){
        OpportunityJSON testOpp1 = new OpportunityJSON();
        OpportunityJSON testOpp2 = new OpportunityJSON();
        testOpp1.partnerProjectTitle = '#Eviden - Test Opportunity 1';
        testOpp2.partnerProjectTitle = 'Test Opportunity 2';
        Boolean test1 = AceHelperMethodsV2.isAtosOpp(testOpp1);
        Boolean test2 = AceHelperMethodsV2.isAtosOpp(testOpp2);
        system.Assert(test1);
        system.Assert(!test2);
    }

    @isTest(SeeAllData=true)
    public static void GetProjectEndDatesTest(){
        List<pse__Proj__c> projectList = [SELECT id, pse__End_Date__c, pse__Opportunity__c FROM pse__Proj__c WHERE pse__Opportunity__c != null  AND (NOT Name LIKE 'PS%') AND (NOT Name LIKE '%Funding%') LIMIT 3];
        List<ID> oppIds = new List<ID>();

        for(pse__Proj__c p : projectList){
            oppIds.add(p.pse__Opportunity__c);
        }

        system.debug(projectList);
        system.debug(oppIds);

        List<Opportunity> oList = [SELECT id FROM Opportunity WHERE id IN: oppIds];

        Map<id,date> endDateMap = AceHelperMethodsV2.GetProjectEndDates(oList);
        
        system.Assert(endDateMap.keySet().size() == 3);

        pse__Proj__c testProj1 = [SELECT id, pse__End_Date__c FROM pse__Proj__c WHERE pse__Opportunity__c = :oList[0].id AND (NOT Name LIKE 'PS%') AND (NOT Name LIKE '%Funding%')];
        pse__Proj__c testProj2 = [SELECT id, pse__End_Date__c FROM pse__Proj__c WHERE pse__Opportunity__c = :oList[1].id AND (NOT Name LIKE 'PS%') AND (NOT Name LIKE '%Funding%')];
        pse__Proj__c testProj3 = [SELECT id, pse__End_Date__c FROM pse__Proj__c WHERE pse__Opportunity__c = :oList[2].id AND (NOT Name LIKE 'PS%') AND (NOT Name LIKE '%Funding%')];
        
        system.Assert(endDateMap.get(oList[0].id) == testProj1.pse__End_Date__c);
        system.Assert(endDateMap.get(oList[1].id) == testProj2.pse__End_Date__c);
        system.Assert(endDateMap.get(oList[2].id) == testProj3.pse__End_Date__c);
    }
*/
}