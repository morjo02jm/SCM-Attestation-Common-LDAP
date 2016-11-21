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
	private static String sBCC= "Team-GIS-ToolsSolutions-Global@ca.com";
	private static PrintWriter Log = null;
	private static String sLogName = "";
	private static int iReturnCode = 0;
	private static int nEmployees = 0;

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
			sLogName = aLogPath+"\\"+aAppName+"_" +dateFormat.format(date) +".log";
		}

		try {	
			FileOutputStream osLogStream = new FileOutputStream(sLogName);
	        Log = new PrintWriter(osLogStream, true);
		} catch (FileNotFoundException e) {
			iReturnCode = 1001;
		    System.err.println(e);			
		    System.exit(iReturnCode);		    
		}
		
		try {
			cipher = Cipher.getInstance("AES");			
		} catch(Exception e) {
			iReturnCode = 1003;
		    System.err.println(e);			
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
			DirContext ctx = new InitialDirContext(env);
			
			for (int i=0; i<regions.length; i++)
			{
				processLDAPRegion(ctx, regions[i], cLDAP, i<5);
			}
		} catch (NamingException e) {
		    // attempt to re-acquire the authentication information
		    // Handle the error
			iReturnCode = 1002;
		    System.err.println(e);
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
	          System.out.println("Sent message successfully to: "+email);
	       } catch (MessagingException mex) {
	          mex.printStackTrace();
	       }	      
	}
	


	public void processInputListGeneric( JCaContainer cUserList, String sInputFileName, char sep )
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
			e.printStackTrace();         
		} catch (IOException e) {             
			e.printStackTrace();        
		} finally {             
			try {                 
				if (reader != null) 
				{                     
					reader.close();                 
				}             
			} catch (IOException e) {                 
				e.printStackTrace();             
			}         
		} 	
	}
	
	public String readTextResource(String sInputFileName, String sArg1, String sArg2, String sArg3) {
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
				bodyText += text;
			}    
		} catch (FileNotFoundException e) {             
			e.printStackTrace();         
		} catch (IOException e) {             
			e.printStackTrace();        
		} finally {             
			try {                 
				if (reader != null) 
				{                     
					reader.close();                 
				}             
			} catch (IOException e) {                 
				e.printStackTrace();             
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
			    System.err.println(e);
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
			String[] attrIDs = {tagSAMAccountName, tagDisplayName, tagDN, tagPhone, tagMail,tagEmployeeType};
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
		    System.err.println(e);			
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
		    System.err.println(e);			
		    System.exit(iReturnCode);		    
	    }
		return sDecrypted;
	}
	
}
