# commonldap
Common Routines for Provisioning and Attestation Projects.  This package contains:
a) JCaData and JCaContainer classes re-implemented, originally from the CA Harvest SCM jar, jhsdk.jar.
b) Common methods for:
	* Reading user information from the CA Directory.
	* Reading and writing CSV files.
	* JSON Object and Array read routines.
	* Encryption and Decryption AES-256
	* HTML notifications 
	* Reading text resources (email templates)
	
Constructor:
		public CommonLdap(String aAppName, String aLogPath, String aBCC, JCaContainer cLDAP)
			Creates a common LDAP utility "frame" that:
			a) Opens and read CA Domain user information into a JCaContainer structure.
			b) Initialize a logger to a specific project
			c) Initialize BCC list for any email notifications that are sent.
			
		public void processStandardDL(String[][]     aAuthSchemas, 
									  String[][]     aDLLDAPGroupFormat, 
									  JCaContainer   cLDAP, 
									  JCaContainer[] cDLUsers, 
									  JCaContainer   cAddUsers, 
									  JCaContainer   cDelUsers,
									  int            iUserType,
									  String         sDumpFile,
									  boolean        bSynch)
			Basic processing for DL groups.
			