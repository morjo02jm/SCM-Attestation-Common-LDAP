package commonldap;


import com.ca.harvest.jhsdk.*;
import com.ca.harvest.jhsdk.hutils.*;
import com.ca.harvest.jhsdk.logger.*;

import gvjava.org.json.*;

import java.sql.*;

import java.util.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;

import java.util.*;

import java.io.*;
import java.net.URL;
import java.nio.charset.Charset;

import javax.naming.*;
import javax.naming.directory.*;

import org.eclipse.core.runtime.*;

import junit.framework.*;

import java.util.*;
import javax.mail.*;
import javax.mail.internet.*;
import javax.activation.*;

public class CommonLdap {
	private static String sBCC= "Team-GIS-ToolsSolutions-Global@ca.com";
	private static PrintWriter Log = null;
	private static String sLogName = "";
	private static int iReturnCode = 0;

	// Column names cLDAP 
	private static String tagSAMAccountName = "sAMAccountName";
	private static String tagMail = "mail";
	private static String tagPhone = "ipPhone";
	private static String sAdminPassword = "";
	
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

		Map<String, String> environ = System.getenv();
        for (String envName : environ.keySet()) {
        	if (envName.equalsIgnoreCase("FLOWDOCK_ADMIN_PASSWORD")) sAdminPassword = environ.get(envName);
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
		printLog("Number of CA.COM user containers read: " + cLDAP.getKeyElementCount(tagMail));
		
	}

	private static String readAll(Reader rd) throws IOException {
	    StringBuilder sb = new StringBuilder();
	    int cp;
	    while ((cp = rd.read()) != -1) {
	      sb.append((char) cp);
	    }
	    return sb.toString();
	}

	public static JSONObject readJsonFromUrl(String url) throws IOException, JSONException {
	    InputStream is = new URL(url).openStream();
	    try {
	      BufferedReader rd = new BufferedReader(new InputStreamReader(is, Charset.forName("UTF-8")));
	      String jsonText = readAll(rd);
	      return new JSONObject(jsonText);
	    } finally {
	      is.close();
	    }
	}

	public static JSONArray readJsonArrayFromUrl(String url) throws IOException, JSONException {
	    InputStream is = new URL(url).openStream();
	    try {
	      BufferedReader rd = new BufferedReader(new InputStreamReader(is, Charset.forName("UTF-8")));
	      String jsonText = readAll(rd);
	      return new JSONArray(jsonText);
	    } finally {
	      is.close();
	    }
	}	
	
	public static void printLog(String str)
	{
		System.out.println(str);
		Log.println(str);
	}

	public void handleMessage(String sMessage)
	{
		printLog(sMessage);
	}
	
	public static void sendEmailNotification(String email, String subjectText, String bodyText, boolean bHTML) {
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
	


	private static void processInputListGeneric( JCaContainer cUserList, String sInputFileName, char sep )
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
	
	public static String readTextResource(String sInputFileName, String sArg1, String sArg2, String sArg3) {
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
		    boolean bMail = false;
		    boolean bPhone = false;
		    try {
				for (NamingEnumeration ae = attributes.getAll(); ae.hasMore();) {
				    Attribute attr = (Attribute)ae.next();
				    for (NamingEnumeration e = attr.getAll(); e.hasMore(); )
				    {
				    	String sAttr = attr.getID();
				    	if (sAttr.equalsIgnoreCase(tagMail)) bMail = true;
				    	if (sAttr.equalsIgnoreCase(tagPhone)) bPhone = true;
				    	cLDAP.setString(sAttr, (String)e.next(), cIndex);
				    	
				    }
				}

				String sID = cLDAP.getString(tagSAMAccountName, cIndex);
				
				if (!bMail) 
					cLDAP.setString(tagMail, "unknown", cIndex);
				if (!bPhone) 
					cLDAP.setString(tagPhone, "", cIndex);
									
				cLDAP.setString("haspmfkey", 
						        (isNormalUser &&
// TODO need a separate routine for validating the user id belongs to a user or not.						        		
					             sID.length() == 7 &&
					             !sID.equalsIgnoreCase("clate98") &&
					             !sID.equalsIgnoreCase("clate99") &&
					             !sID.equalsIgnoreCase("urctest") &&
					             !sID.equalsIgnoreCase("BEStest"))? "Y" : "N", 
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
			String[] attrIDs = {tagSAMAccountName, "displayName", "distinguishedName", tagPhone, tagMail};
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
		
}
