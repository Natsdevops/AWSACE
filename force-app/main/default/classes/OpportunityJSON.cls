public Class OpportunityJSON{
         
        //Update & Read fields
        public String partnerCrmUniqueIdentifier;
        public String name;
        public String useCase;
        public String targetCloseDate;
        public String status;
        public String stage;    
        public String primaryContactEmail;
        public String postalCode;
        public String partnerProjectTitle;
        public String partnerPrimaryNeedFromAws;                              
        public String deliveryModel;
        public String customerWebsite;
        public String customerCompanyName;
        public String country;      
        public String state;
        public String primaryContactPhone;
        public String primaryContactLastName;
        public String primaryContactFirstName;
        public String customerTitle;
        public String customerPhone;
        public String customerLastName;
        public String customerFirstName;
        public String customerEmail;
        public Date firstApproved;
        public Date launchedDate;
        public Date closedLostDate;
        public String IsOppFromMarketingActivity;
        public String  rfxSolicitationNumber;
        public List<String> solutionOffered;
        public String opportunityType;
        public String projectDescription;       
        public Decimal expectedMonthlyAwsRevenue;        
        public String industry;
        public string salesActivities;
        public String doesOppBelongToNatSec;
        
        //Read Only fields
        public String APNCRMUniqueIdentifier;
        public String closedLostReason;
        public String wWPSPDMEmail;
        public String wWPSPDM;
        public String subUseCase;
        public String streetAddress;        
        public String publicReferenceUrl;
        public String publicReferenceTitle;
        public String partnerPrimaryNeedFromAwsOther;
        public String partnerDeveloperManagerPhone;
        public String partnerDeveloperManagerEmail;
        public String partnerDeveloperManager;        
        public String partnerAcceptanceStatus;
        public String opportunityOwnership;
        public String opportunityOwnerName;
        public String opportunityOwnerEmail;
        public String nextStepHistory;
        public String nextStep;
        public String leadSource;
        public String lastModifiedDate;
        public String lastModifiedBy;
        public String isThisForMarketplace;
        public String isThisAPublicReference;
        public String isNetNewBusinessForCompany;
        public String isMarketingDevelopmentFunded;
        public String industryOther;
        public String createdDate;
        public String createdBy;
        public String contractVehicle;
        public String competitiveTrackingOther;
        public String competitiveTracking;
        public String city;
        public String campaignName;
        public String aWSStage;
        public String aWSSalesRepName;
        public String aWSSalesRepEmail;
        public String aWSPartnerSuccessManagerName;
        public String aWSPartnerSuccessManagerEmail;
        public String aWSISVSuccessManagerName;
        public String aWSISVSuccessManagerEmail;
        public String awsFieldEngagement;
        public String aWSCloseDate;
        public String aWSAccountOwnerName;
        public String aWSAccountOwnerEmail;
        public String awsAccountId;
        public String additionalComments;
        public String marketingActivityChannel;
        public String marketingActivityUsecase;
        public String awsSFCampaignName;
/*        
        public String status{
            get{ return status;}
            set{ 
                status = value;
                if(value == 'Approved'){
                    firstApproved = Date.Today();
                }                
            }
        }
                
        public String stage{
            get{ return stage;}
            set{
                stage = value;
                if( value == 'Launched'){
                    launchedDate = Date.Today();
                }
                if( value == 'Closed Lost'){
                    closedLostDate = Date.Today();
                }
            }
        }
*/        
}