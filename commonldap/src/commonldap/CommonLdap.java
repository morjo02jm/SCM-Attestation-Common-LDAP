package commonldap;


import gvjava.org.json.*;

import java.util.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;

import java.util.*;

import java.io.*;
import java.net.URL;
import java.nio.charset.Charset;

import javax.naming.*;
import javax.naming.directory.*;


import javax.mail.*;
import javax.mail.internet.*;

import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CommonLdap {
	private static String sAppName = "commonldap";
	private static String sBCC= "Team-GIS-ToolsSolutions-Global@ca.com";
	private static PrintWriter Log = null;
	private static String sLogName = "";
	private static String sDumpFile = "";
	private static int iReturnCode = 0;
	private static int nEmployees = 0;
	private DirContext ctx;

	// Column names cLDAP 
	private static String tagSAMAccountName = "sAMAccountName";
	private static String tagMail           = "mail";
	private static String tagPhone          = "ipPhone";
	private static String tagDisplayName    = "displayName";
	private static String tagEmployeeType   = "employeeType";
	private static String tagDN             = "distinguishedName";
	
	private static String sAdminPassword = "";
	
    private static Key aesKey = new SecretKeySpec("Bar12345Bar12345".getBytes(), "AES");
    private static Cipher cipher;    	
	
	private String[] regions = { "ou=users,ou=north america",
            					 "ou=users,ou=itc hyderabad",
            					 "ou=users,ou=europe middle east africa",
            					 "ou=users,ou=asia pacific",
            					 "ou=users,ou=south america",
            					 "ou=joint venture consultants",
            					 "ou=role-based,ou=north america",
            					 "ou=role-based,ou=itc hyderabad",
            					 "ou=role-based,ou=europe middle east africa",
            					 "ou=role-based,ou=asia pacific",
            					 "ou=role-based,ou=south america",
            					 "cn=users"};
	
	public CommonLdap(String aAppName, String aLogPath, String aBCC, JCaContainer cLDAP) {
		if (!aBCC.isEmpty())
			sBCC = aBCC;
		
		DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd@HH_mm_ss");
		Date date = new Date();
		if (!aAppName.isEmpty()) {	
			sAppName = aAppName;
			sLogName = aLogPath+"\\"+aAppName+"_" +dateFormat.format(date) +".log";
		}

		try {	
			FileOutputStream osLogStream = new FileOutputStream(sLogName);
	        Log = new PrintWriter(osLogStream, true);
		} catch (FileNotFoundException e) {
			iReturnCode = 1001;
		    printErr(e.getLocalizedMessage());			
		    System.exit(iReturnCode);		    
		}
		
		try {
			cipher = Cipher.getInstance("AES");			
		} catch(Exception e) {
			iReturnCode = 1003;
		    printErr(e.getLocalizedMessage());			
		    System.exit(iReturnCode);		    
        } 


		Map<String, String> environ = System.getenv();
        for (String envName : environ.keySet()) {
        	if (envName.equalsIgnoreCase("FLOWDOCK_ADMIN_PASSWORD")) 
        		sAdminPassword = AESDecrypt(environ.get(envName));
        }
		
		Hashtable env = new Hashtable();
		env.put(Context.PROVIDER_URL, "ldap://usildc04.ca.com:389/dc=ca,dc=com");
		env.put(Context.SECURITY_PRINCIPAL, "toolsadmin");
		env.put(Context.SECURITY_CREDENTIALS, sAdminPassword);
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		
		try {
	        // Read user containers for CA.COM
			ctx = new InitialDirContext(env);
			
			for (int i=0; i<regions.length; i++)
			{
				processLDAPRegion(ctx, regions[i], cLDAP, i<5);
			}
		} catch (NamingException e) {
		    // attempt to re-acquire the authentication information
		    // Handle the error
			iReturnCode = 1002;
		    printErr(e.getLocalizedMessage());
		    System.exit(iReturnCode);			    
		}

		// Show cLDAP statistics
		printLog("Number of CA.COM user containers read: " + cLDAP.getKeyElementCount(tagMail)+
				" (Employees:"+nEmployees+")");
		
	}

	private static String readAll(Reader rd) throws IOException {
	    StringBuilder sb = new StringBuilder();
	    int cp;
	    while ((cp = rd.read()) != -1) {
	      sb.append((char) cp);
	    }
	    return sb.toString();
	}

	public JSONObject readJsonFromUrl(String url) throws IOException, JSONException {
	    InputStream is = new URL(url).openStream();
	    try {
	      BufferedReader rd = new BufferedReader(new InputStreamReader(is, Charset.forName("UTF-8")));
	      String jsonText = readAll(rd);
	      return new JSONObject(jsonText);
	    } finally {
	      is.close();
	    }
	}

	public JSONArray readJsonArrayFromUrl(String url) throws IOException, JSONException {
	    InputStream is = new URL(url).openStream();
	    try {
	      BufferedReader rd = new BufferedReader(new InputStreamReader(is, Charset.forName("UTF-8")));
	      String jsonText = readAll(rd);
	      return new JSONArray(jsonText);
	    } finally {
	      is.close();
	    }
	}	
	
	public void printLog(String str)
	{
		System.out.println(str);
		Log.println(str);
	}

	public static void printErr(String str)
	{
		System.err.println(str);
		Log.println("Error: "+str);
	}

	public void handleMessage(String sMessage)
	{
		printLog(sMessage);
	}
	
	public void sendEmailNotification(String email, String subjectText, String bodyText, boolean bHTML) {
        // sets SMTP server properties
		
	     // Recipient's email ID needs to be mentioned.
	      String to = email;
	      // Sender's email ID needs to be mentioned
	      String from = "Toolsadmin@ca.com";
	      String include = sBCC ;
	      // Assuming you are sending email from localhost
	      String host = "mail.ca.com";
	      // Get system properties
	      Properties properties = System.getProperties();
	      // Setup mail server
	      properties.setProperty("mail.smtp.host", host);
	      // Get the default Session object.
	      Session session = Session.getDefaultInstance(properties);	
	      
	      try{
	          // Create a default MimeMessage object.
	          MimeMessage message = new MimeMessage(session);

	          // Set From: header field of the header.
	          message.setFrom(new InternetAddress(from));

	          // Set To: header field of the header.
	          String recipient = to;
	          String[] recipientList = recipient.split(";");
	          InternetAddress[] recipientAddress = new InternetAddress[recipientList.length];
	          int counter = 0;
	          for (String recip : recipientList) {
	              recipientAddress[counter] = new InternetAddress(recip.trim());
	              counter++;
	          }
	          message.setRecipients(Message.RecipientType.TO, recipientAddress);

	          // Set To: header field of the header.
	          if (!include.isEmpty())
	        	  message.addRecipient(Message.RecipientType.BCC, new InternetAddress(include));
	          
	          // Set Subject: header field
	          message.setSubject(subjectText);
	          
	          MimeBodyPart mbp = new MimeBodyPart(); 
	          mbp.setContent(bodyText, "text/html"); 
	          MimeMultipart multipart = new MimeMultipart(); 
	          
	          if (bHTML) {
		          multipart.addBodyPart(mbp);
		          message.setContent(multipart);
	          }
	          else
	        	  message.setText(bodyText);

	          // Send message
	          Transport.send(message);
	          printLog("Sent message successfully to: "+email);
	       } catch (MessagingException mex) {
	          mex.printStackTrace();
	       }	      
	}
	
	public void writeCSVFileFromListGeneric( JCaContainer cList, String sOutputFileName, char sep)
	{
		File fout = new File(sOutputFileName);
		
		try {
			FileOutputStream fos = new FileOutputStream(fout);
			BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(fos));
			String[] keylist = cList.getKeyList();
			//int[] ord = new int[] {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21};
			
			String line = "";
			for (int i=0; i<keylist.length; i++) {
				if (!line.isEmpty()) 
					line += sep;
				//line += keylist[ord[i]];
				line += keylist[i];
			}
			bw.write(line);
			bw.newLine();
			
			for (int i=0; i < cList.getKeyElementCount(keylist[0]); i++) {
				if (!cList.getString("APP", i).isEmpty()) 
				{
					line = "";
					for (int j=0; j<keylist.length; j++) {
						if (!line.isEmpty())
							line += sep;
						//line += cList.getString(keylist[ord[j]], i);
						line += cList.getString(keylist[j], i);
					}
					bw.write(line);
					bw.newLine();
				}
			}
		 
			bw.close();
		} catch (FileNotFoundException e) {             
			iReturnCode = 201;
		    System.err.println(e);			
		    System.exit(iReturnCode);
		} catch (IOException e) {             
			iReturnCode = 202;
		    System.err.println(e);			
		    System.exit(iReturnCode);
		}
	}	


	public void readInputListGeneric( JCaContainer cUserList, String sInputFileName, char sep )
	{
		File file = new File(sInputFileName);         
		BufferedReader reader = null;  
		
		try {             
			reader = new BufferedReader(new FileReader(file));             
			// repeat until all lines is read   
			String text;
			List<String> headings = new ArrayList<String>();
			boolean bFirst = true;
			
			int index =0;
			while ((text = reader.readLine()) != null) {
				List<String> entries = new ArrayList<String>();
				int cIndex = -1;
				while ((cIndex=text.indexOf(sep))>=0) {
					entries.add(text.substring(0, cIndex));
					text = text.substring(cIndex+1);
				}
				entries.add(text);
				
				if (bFirst) {
					headings = entries;
				}
				else {
					for (int i=0; i<headings.size(); i++) {
						cUserList.setString(headings.get(i), entries.get(i), index);
					}
					index++;
				};
				bFirst = false;
			}    
		} catch (FileNotFoundException e) {             
			printErr(e.getStackTrace().toString());
		} catch (IOException e) {             
			e.printStackTrace();        
		} finally {             
			try {                 
				if (reader != null) 
				{                     
					reader.close();                 
				}             
			} catch (IOException e) {                 
				printErr(e.getStackTrace().toString());
			}         
		} 	
	}

	
	
	public String readTextResource(String sInputFileName, String sArg1, String sArg2, String sArg3, String sArg4) {
		File file = new File(sInputFileName); 
		//InputStream inputStream = githubrepldap.class.getResourceAsStream(InputFileName); //TBD
		
		BufferedReader reader = null;  
		String bodyText = "";
		
		try {             
			reader = new BufferedReader(new FileReader(file));
			//reader = new BufferedReader(new InputStreamReader(inputStream)); //TBD
			
			// repeat until all lines is read   
			String text;
			while ((text = reader.readLine()) != null) {
				int nIndex = 0;
				nIndex = text.indexOf("%1");
				if (nIndex >= 0) {
					text = text.substring(0, nIndex) + sArg1 + text.substring(nIndex+2);
				}
				nIndex = text.indexOf("%2");
				if (nIndex >= 0) {
					text = text.substring(0, nIndex) + sArg2 + text.substring(nIndex+2);
				}
				nIndex = text.indexOf("%3");
				if (nIndex >= 0) {
					text = text.substring(0, nIndex) + sArg3 + text.substring(nIndex+2);
				}
				nIndex = text.indexOf("%4");
				if (nIndex >= 0) {
					text = text.substring(0, nIndex) + sArg4 + text.substring(nIndex+2);
				}
				bodyText += text;
			}    
		} catch (FileNotFoundException e) {             
			printErr(e.getStackTrace().toString());
		} catch (IOException e) {             
			printErr(e.getStackTrace().toString());
		} finally {             
			try {                 
				if (reader != null) 
				{                     
					reader.close();                 
				}             
			} catch (IOException e) {                 
				printErr(e.getStackTrace().toString());
			}         
		} 		
		
		return bodyText;
	}

	// LDAP-related routines
	private static void processLDAPAttrs(Attributes attributes, 
			                             JCaContainer cLDAP,
			                             boolean isNormalUser) 
	{
		int cIndex = 0;		
		if (cLDAP.getKeyCount() > 0)
		{
			cIndex = cLDAP.getKeyElementCount(tagSAMAccountName);
		}

		if (attributes.size() >= 3)
		{
		    boolean bMail    = false;
		    boolean bPhone   = false;
		    boolean bGeneric = true;
		    try {
				for (NamingEnumeration ae = attributes.getAll(); ae.hasMore();) {
				    Attribute attr = (Attribute)ae.next();
				    for (NamingEnumeration e = attr.getAll(); e.hasMore(); )
				    {
				    	String sAttr = attr.getID();
				    	String sValue = (String)e.next();
				    	
				    	if (sAttr.equalsIgnoreCase(tagMail)) 
				    		bMail = true;
				    	else if (sAttr.equalsIgnoreCase(tagPhone)) 
				    		bPhone = true;
				    	
				    	if (sAttr.equalsIgnoreCase(tagEmployeeType)) 
				    		bGeneric=false;
				    	else
				    		cLDAP.setString(sAttr, sValue, cIndex);
				    	
				    }
				}

				/*
				String sID = cLDAP.getString(tagSAMAccountName, cIndex);
				bGeneric = !(isNormalUser &&
				             sID.length() == 7 &&
					         !sID.equalsIgnoreCase("clate98") &&
					         !sID.equalsIgnoreCase("clate99") &&
					         !sID.equalsIgnoreCase("urctest") &&
					         !sID.equalsIgnoreCase("BEStest"));
			    */
				
				if (!bMail) 
					cLDAP.setString(tagMail, "unknown", cIndex);
				if (!bPhone) 
					cLDAP.setString(tagPhone, "", cIndex);
									
				if (!bGeneric) 
					nEmployees++;
				cLDAP.setString("haspmfkey", 
						        (!bGeneric)? "Y" : "N", 
					            cIndex);
			 
			} catch (NamingException e) {
			    // Handle the error
				iReturnCode = 1005;
			    printErr(e.getLocalizedMessage());
			    System.exit(iReturnCode);
			}
		}
	} // end ProcessLDAPAttrs


	public static void processLDAPRegion(DirContext ctx, 
			                              String region, 
			                              JCaContainer cLDAP,
			                              boolean isNormalUser) 
	{
		try {
			// Search directory for containers
			// Create the default search controls
			SearchControls ctls = new SearchControls();
	
			// Specify the search filter to match
			String filter = "(&(!(objectclass=computer))(&(objectclass=person)(sAMAccountName=*)))";
			
			// Specify the ids of the attributes to return
			String[] attrIDs = {tagSAMAccountName, tagDisplayName, tagDN, tagPhone, tagMail, tagEmployeeType};
			ctls.setReturningAttributes(attrIDs);
	
			// Search for objects that have those matching attributes
			NamingEnumeration enumeration = ctx.search(region, filter, ctls);
			
			while (enumeration.hasMore()) {
			    SearchResult sr = (SearchResult)enumeration.next();
			    //System.out.println(">>>" + sr.getName());
			    processLDAPAttrs(sr.getAttributes(), cLDAP, isNormalUser);
			}			
		} catch (javax.naming.AuthenticationException e) {
			iReturnCode = 1004;
			System.err.println(e);
			System.exit(iReturnCode);			
		} catch (NamingException e) {
		    // attempt to reacquire the authentication information
		    // just skip region
			//iReturnCode = 2;
		    //System.err.println(e);
		    //System.exit(iReturnCode);
		}	
	} // end ProcessLDAPRegion
	
	
// Encrption/Decryption	
	public String AESEncrypt(String sDecrypted) {
		String sEncrypted = "";
		try {
	        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
	        byte[] encrypted = cipher.doFinal(sDecrypted.getBytes());
             
            for (byte b: encrypted) {
            	int iB = (int) b;
            	sEncrypted += ":"+ Integer.toHexString(iB & 0xFF);
            }
		} catch(Exception e) {
			iReturnCode = 1003;
		    printErr(e.getLocalizedMessage());			
		    System.exit(iReturnCode);		    
	    }
		return sEncrypted;
	}
	
	public String AESDecrypt(String myString) {
		String sDecrypted = "";
		try {
			int nLength = 0;
			byte[] bbi = new byte[myString.length()];
			while (!myString.isEmpty()) {
				myString = myString.substring(1);
				int nIndex = myString.indexOf(":");
				if (nIndex < 0) {
					bbi[nLength++] = (byte)Integer.parseInt(myString, 16);
					myString = "";
				}
				else {
					String myByte = myString.substring(0, nIndex);
					bbi[nLength++] = (byte)Integer.parseInt(myByte, 16);
					myString = myString.substring(nIndex);
				}
			}
				
			byte[] bb = new byte[nLength];
            for (int i=0; i<nLength; i++) {
                bb[i] = (byte) bbi[i];
            }
 
			cipher.init(Cipher.DECRYPT_MODE, aesKey);
		    byte[] decrypted = cipher.doFinal(bb);
	        sDecrypted = new String(decrypted);		
		} catch(Exception e) {
			iReturnCode = 1003;
		    printErr(e.getLocalizedMessage());			
		    System.exit(iReturnCode);		    
	    }
		return sDecrypted;
	}
	
	
	public void readUserListToContainer(JCaContainer cUserList,
            							String InputFileName )
	{
        File file = new File(InputFileName);         
        BufferedReader reader = null;  
        int iIndex = 0;
        
        try {             
        	reader = new BufferedReader(new FileReader(file));             
        	String text = null; 
        	String name = null;
        	// repeat until all lines is read             
        	while ((text = reader.readLine()) != null) 
        	{     
        		name = text;
        		int cIndex = text.indexOf('(');
        		if ( cIndex >= 0)
        		{
        			int eIndex = text.indexOf(')');
        			if (eIndex < 0) eIndex = text.length()-1;
        			if (cIndex > 0) name = text.substring(0, cIndex);
        			text = text.substring(cIndex+1, eIndex);
        		}
        		cUserList.setString("pmfkey", text, iIndex);
        		cUserList.setString("name", name, iIndex++);
        	}         
        } catch (FileNotFoundException e) {             
        	//e.printStackTrace();         
        } catch (IOException e) {             
        	//e.printStackTrace();        
        } finally {             
        	try {                 
        		if (reader != null) 
        		{                     
        			reader.close();                 
        		}             
        	} catch (IOException e) {                 
        		//e.printStackTrace();             
        	}         
        } 	
	}
	
// LDAP-related routines
	
	public boolean addUserToLDAPGroup(String sDLLDAPUserGroup, 
			                          String sUserDN)
	{		
		try {
			String sDN = sUserDN;
			
			//add to the required LDAP role   
			ModificationItem[] roleMods = new ModificationItem[]    
			{   
			    new ModificationItem( DirContext.ADD_ATTRIBUTE, new BasicAttribute( "member", sDN ) )   
			};  
			
			
			ctx.modifyAttributes(sDLLDAPUserGroup, roleMods );  

		} catch (javax.naming.AuthenticationException e) {
			iReturnCode = 1;
			printErr(e.getLocalizedMessage());
			System.exit(iReturnCode);
			
		// attempt to reacquire the authentication information
		} catch (NamingException e)	{
		    // Handle the error
			String sException = e.getMessage();
			if (sException.indexOf("ENTRY_EXISTS") < 0 ) 
			{
				iReturnCode = 2;
			    printErr(e.getLocalizedMessage());
			    System.exit(iReturnCode);
			}
			return false;
		}
		return true;
	}
	
	
	public boolean removeUserFromLDAPGroup(String sDLLDAPUserGroup, 
                                           String sUserDN)
	{		
		try {
			String sDN = sUserDN;
			
			//add to the required LDAP role   
			ModificationItem[] roleMods = new ModificationItem[]    
			{   
				new ModificationItem( DirContext.REMOVE_ATTRIBUTE, new BasicAttribute( "member", sDN ) )   
			};  
						
			ctx.modifyAttributes( sDLLDAPUserGroup, roleMods );  
		
		} catch (javax.naming.AuthenticationException e) {
			iReturnCode = 1;
			printErr(e.getLocalizedMessage());
			System.exit(iReturnCode);
		
		// attempt to reacquire the authentication information
		} catch (NamingException e)	{
			// Handle the error
			String sException = e.getMessage();
			if (sException.indexOf("ENTRY_NOT_FOUND") < 0 &&
				sException.indexOf("WILL_NOT_PERFORM") < 0) //forced deletion
			{
				iReturnCode = 1007;
				printErr(e.getLocalizedMessage());
				System.exit(iReturnCode);
			}
			return false;
		}
		return true;
	}
	
	
	
	public void readLDAPUserGroupToContainer(String sDLLDAPUserGroup, 
			                                 JCaContainer cDLUsers)
	{
		try {
			// Retrieve attributes for a specific container
			int cIndex = 0;		
			if (cDLUsers.getKeyCount() > 0)
			{
				cIndex = cDLUsers.getKeyElementCount("member");
			}
			
			Attributes attributes = ctx.getAttributes(sDLLDAPUserGroup);
			for (NamingEnumeration ae = attributes.getAll(); ae.hasMore();) {
			    Attribute attr = (Attribute)ae.next();
			    //printLog("attribute: " + attr.getID());
			    
			    if (attr.getID().indexOf("member")==0)
			    {
				    /* Process each member attribute */
				    for (NamingEnumeration e = attr.getAll(); 
				         e.hasMore();
					     //printLog("value: " + e.next()) ) ;
				         )
				    {
				    	String dn = (String)e.next();
				    	//printLog("DN:" + dn);
				    	int iStart = dn.indexOf("CN=");
				    	int iEnd   = dn.indexOf(',', iStart);
				    	String pmfkey = dn.substring(iStart+3, iEnd);
				    	int iDL[] = cDLUsers.find("member", pmfkey);
				    	if (iDL.length == 0) {
				    		cDLUsers.setString("dn",     dn,     cIndex);
				    		cDLUsers.setString("member", pmfkey, cIndex++);
				    	    //printLog("member: "+pmfkey); //temp
				    	}
				    }
				}
			}
		} catch (javax.naming.AuthenticationException e) {
			iReturnCode = 1006;
		    printErr(e.getLocalizedMessage());
		    System.exit(iReturnCode);		    
	    // attempt to reacquire the authentication information
		} catch (NamingException e)
		{
			//printErr(e.getLocalizedMessage());
		}	
	}
	
	private void processLDAPGroupUsers(JCaContainer cLDAP,
								       JCaContainer cDLUsers,
						               JCaContainer cAddUsers, 
						               JCaContainer cDelUsers,
						               String DLLDAPUserGroup,
						               String sAuthName) 
{

	printLog("Processing: " + sAuthName);
	
	try {
		boolean found=false;
		
		// 1. Active user accounts in CA.COM but with no DLUser privilege
		printLog("1. Remove "+sAppName+" Users ");
		if (!cDelUsers.isEmpty())
		{
			for (int i=0; i<cDelUsers.getKeyElementCount("pmfkey"); i++ )
			{
				String sID = cDelUsers.getString("pmfkey", i);
				
				int iLDAP[] = cLDAP.find("sAMAccountName", sID);
				if (iLDAP.length > 0)
				{
					String sUser  = cLDAP.getString("displayName", iLDAP[0]);
					String userDN = cLDAP.getString("distinguishedName", iLDAP[0]);									
					
					// Force removal if a valid user in directory
					if (removeUserFromLDAPGroup(DLLDAPUserGroup, userDN))
					{
						printLog(">>>User (deactivate): "+sUser+ "("+ sID+")");									
					}
				} // valid directory user
			
			}  //loop over user accounts						
		}	/* Delete List is not empty */
		
		// 2. LDAP users with no RTC user account
		printLog("2. Add "+sAppName+" Users");
		if (!cAddUsers.isEmpty())
		{
			for (int i=0; i<cAddUsers.getKeyElementCount("pmfkey"); i++ )
			{					
				String sID = cAddUsers.getString("pmfkey", i);
				
				int iLDAP[] = cLDAP.find("sAMAccountName", sID);
				if (iLDAP.length > 0)
				{
					String sUser  = cLDAP.getString("displayName", iLDAP[0]);
					String userDN = cLDAP.getString("distinguishedName", iLDAP[0]);									
					
					int iUser[] = cDLUsers.find("dn", userDN);
					
					if (iUser.length == 0) {
						if (addUserToLDAPGroup(DLLDAPUserGroup, userDN))
						{
							// Add user to LDAP DLUser group
							printLog(">>>User (activate): "+sUser+ "("+ sID+")");											
						}							
					} // user not found in DL 
				} //  user in directory 
			}  // loop over user accounts						
		} /* Add list is not empty */	
		
		// 3. Dump Request
		printLog("3. Dump "+sAppName+" User DL");
		if (!sDumpFile.isEmpty())
		{		
			File file = new File(sDumpFile);
			
			// if file doesnt exists, then create it
			if (!file.exists()) {
				file.createNewFile();
			}
			
			FileWriter fw = new FileWriter(file.getAbsoluteFile());
			BufferedWriter bw = new BufferedWriter(fw);
			
			int nSize = cDLUsers.getKeyElementCount("dn");
			if (nSize < 1500) {					
				for (int i=0; i<nSize; i++ )
				{
					String sDN = cDLUsers.getString("dn", i);
					int iLDAP[] = cLDAP.find("distinguishedName", sDN);
					if (iLDAP.length > 0)
					{
						String sUser = cLDAP.getString("displayName", iLDAP[0]);
						String sID   = cLDAP.getString("sAMAccountName", iLDAP[0]);									
						//printLog(sUser+ " ("+ sID+")");	
						bw.write(sUser+ " ("+ sID+")\n");
					} // user exists in domain
				}  // loop over DL members						
			} // DL size does not exceed 1499
			else {
				for (int i=0; i<cLDAP.getKeyElementCount("sAMAccountName"); i++) {
					String sID    = cLDAP.getString("sAMAccountName", i);	
					String sUser  = cLDAP.getString("displayName", i);
					String userDN = cLDAP.getString("distinguishedName", i);
					
					int iUser[]=cDLUsers.find("dn", userDN);
					if (iUser.length > 0)
					{
						bw.write(sUser + " ("+ sID + ")\n");
					}
					else {
						if (addUserToLDAPGroup(DLLDAPUserGroup, userDN)) {
						removeUserFromLDAPGroup(DLLDAPUserGroup, userDN);
					}
					else {
						bw.write(sUser + " ("+ sID + ")\n");								
					}
					} // loop over DL members
				}
			} // DL size exceeds 1499
			bw.close();
		} /* Dump Users */	
	} /* try block */
	catch (Throwable e) {
		printErr(e.getStackTrace().toString());
		System.exit(-1);
	}
	finally { }
} // processLDAPGroupUsers

	
	public void processStandardDL(String[][]     aAuthSchemas, 
			                      String[][]     aDLLDAPGroupFormat, 
			                      JCaContainer   cLDAP, 
			                      JCaContainer[] cDLUsers, 
			                      JCaContainer   cAddUsers, 
			                      JCaContainer   cDelUsers,
			                      int            iUserType,
			                      String         sHaveDumpFile,
			                      boolean        bS) 
	{
		sDumpFile = sHaveDumpFile;
		// Read DL LDAP group users
		for (int i=0; i<aAuthSchemas[iUserType].length; i++)
		{
			String[] aDLLDAPGroup = new String[aDLLDAPGroupFormat[iUserType].length];
			
			for (int j=0; j<aDLLDAPGroupFormat[iUserType].length; j++)
			{
				String sDLLDAPUserGroup = aDLLDAPGroupFormat[iUserType][j].replaceAll("%s", aAuthSchemas[iUserType][j]);
				//String sDLLDAPUserGroup = aDLLDAPGroup[j].format(aDLLDAPGroupFormat[iUserType][j],aAuthSchemas[iUserType][j]);
				
				readLDAPUserGroupToContainer(sDLLDAPUserGroup, cDLUsers[i]);
				processLDAPGroupUsers(cLDAP,
					                  cDLUsers[i],
                                      cAddUsers, 
                                      cDelUsers,
                                      sDLLDAPUserGroup,
                                      aAuthSchemas[iUserType][j]);
			}
		}
	}
} //end of class definition
