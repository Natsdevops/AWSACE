public class AceIntegrationFutureQueue implements Queueable,Database.AllowsCallouts{    
    private final PartnerIntegration__mdt mdt; 
    private final string batchName;
    private integer retryCount;
    
    
    public AceIntegrationFutureQueue(string batchName,PartnerIntegration__mdt mdt,integer retryCount){       
        this.mdt = mdt;              
        this.batchName = batchName;
        
        if(retryCount >= 1 && retryCount <= 3){
            this.retryCount = retryCount;
        }
        else{
            this.retryCount = 3;
        }       
    }
    
    public void execute(QueueableContext qc){
               
        Http http = new Http();
        HttpRequest req = new HttpRequest();
        
        String user = mdt.Username__c;
        String pass = mdt.Password__c;
        String region = mdt.AWS_Region__c;
        String bucketName = mdt.AWS_Bucket__c;
        
        String filePath = 'https://s3.'+ region +'.amazonaws.com/' + bucketName + '/opportunity-inbound-processed-results/';
        filePath += batchName;
        PageReference pr = new PageReference(filePath);
        Url endpoint = new Url(pr.getUrl());
        
        S3_Authentication s3Authentication = new S3_Authentication();
        req = s3Authentication.signedRequest('GET',endpoint,null,null,true,user,pass,region);
        
        System.debug(req);

        Long startTime = DateTime.now().getTime();
        Long finalTime = DateTime.now().getTime();
        system.debug('Waiting 30 sec before retry ' + retryCount);
        Long millisecondsToWait = 30000; // vary this depending on your "sleep" needs
        
        while (finalTime - startTime < millisecondsToWait) {
            finalTime = DateTime.now().getTime();
        }

        system.debug('Making attempt '+ retryCount);
        HTTPResponse res = http.send(req);
        System.debug(res);
        
        if (res.getStatusCode() == 200) {
            String jsonResponse = res.getBody();
            System.debug('Response-' + jsonResponse);
            List<OpportunityResultJSON> results = AceHelperMethodsV2.readOutboundUpdateResults(jsonResponse);                                                   
            AceHelperMethodsV2.processOutboundUpdateResults(results);
        }
        else if(res.getStatusCode() == 404 && retryCount < 3){
            retryCount++;

            system.debug('Initiating retry attempt ' + retryCount);
            
            if(!Test.isRunningTest()){  
                system.enqueueJob(new AceIntegrationFutureQueue(this.batchName,this.mdt,this.retryCount));
            }
        }
    }
}