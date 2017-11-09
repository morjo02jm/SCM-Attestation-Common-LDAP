package commonldap;

//
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

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.activation.FileDataSource;

import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import java.lang.*;
import java.sql.*;
import java.util.*;


public class CommonLdap {
	private static String sAppName = "commonldap";
	private static String sBCC= "";
	private static PrintWriter Log = null;
	private static String sLogName = "";
	private static String sDumpFile = "";
	private static int iReturnCode = 0;
	private static int nEmployees = 0;
	private DirContext ctx;
	private static boolean bFileAppend = false;

	// Column names cLDAP 
	private static String tagSAMAccountName = "sAMAccountName";
	private static String tagMail           = "mail";
	private static String tagPhone          = "ipPhone";
	private static String tagDisplayName    = "displayName";
	private static String tagEmployeeType   = "employeeType";
	private static String tagDN             = "distinguishedName";
	private static String tagManager        = "manager";
	private static String tagDirectReports  = "directReports";
	
	private static String tagUserID         = "USERID";
	private static String tagManagerID      = "MANAGERID";
	
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
			iReturnCode = 101;
		    printErr(e.getLocalizedMessage());			
		    System.exit(iReturnCode);		    
		}
		
		try {
			cipher = Cipher.getInstance("AES");			
		} catch(Exception e) {
			iReturnCode = 102;
		    printErr(e.getLocalizedMessage());			
		    System.exit(iReturnCode);		    
        } 


		Map<String, String> environ = System.getenv();
        for (String envName : environ.keySet()) {
        	if (envName.equalsIgnoreCase("DL_ADMINISTRATOR_PASSWORD")) 
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
			iReturnCode = 103;
		    printErr(e.getLocalizedMessage());
		    System.exit(iReturnCode);			    
		}
		
		if (sBCC.isEmpty()) {
			sBCC = "faudo01@ca.com;morjo02@ca.com";
			sBCC += expandDistributionListforEmail("CN=Team - GIS - Tools Solutions - ITC,OU=Groups,OU=North America", cLDAP);
		}

		// Show cLDAP statistics
		printLog("Number of CA.COM user containers read: " + cLDAP.getKeyElementCount(tagMail)+
				" (Employees:"+nEmployees+")");
		
	}
	
	// *** JSON Routines ***
	
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
	
	// *** Logging Routines ****
	
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
	
	// ***GitHub routines ***
	
	public void readGitHubOrganizationTeams(String sOrg, JCaContainer cTeam, String sAccessToken, String sType) {
		String sAPI = "";
		switch (sType.toLowerCase()) {
		case "ghe":
			sAPI = "github-isl-01.ca.com/api/v3";
			break;
		case "ghe-dev":
			sAPI = "github-isl-dev-01.ca.com/api/v3";
			break;
		case "ghe-test":
			sAPI = "github-isl-test-01.ca.com/api/v3";
			break;
		case "github.com":
		default:
			sAPI = "api.github.com";
			break;
		}
		String sURL = "https://"+ sAPI + "/orgs/"+ sOrg + "/teams?access_token="+sAccessToken+"&&per_page=1000";
		
		int iIndex = cTeam.getKeyElementCount("Organization"); // was 0
		
		try {	
			JSONArray ja = readJsonArrayFromUrl(sURL);
			for (int j=0; j<ja.length(); j++) {
				String sNameJSON = ja.getJSONObject(j).getString("name");
				String sIdJSON = ja.getJSONObject(j).getString("id");
				
				cTeam.setString("Organization", sOrg, iIndex);
				cTeam.setString("Team", sNameJSON, iIndex);
				cTeam.setString("Team ID", sIdJSON, iIndex++);							
			}
		}
		catch (IOException e) {
			iReturnCode = 201;
		    printErr("Couldn't read JSON Object from: "+e.getLocalizedMessage());			
		    System.exit(iReturnCode);						
		}
		catch (JSONException e) {						
			iReturnCode = 202;
		    printErr("Couldn't read JSON Object from: "+e.getLocalizedMessage());			
		    System.exit(iReturnCode);						
		}									
	} //readGitHubOrganizationTeams
	
	public void readGitHubOrganizationRepositories(String sOrg, JCaContainer cRepo, String sAccessToken, String sType) {
		String sAPI = "";
		switch (sType.toLowerCase()) {
		case "ghe":
			sAPI = "github-isl-01.ca.com/api/v3";
			break;
		case "ghe-dev":
			sAPI = "github-isl-dev-01.ca.com/api/v3";
			break;
		case "ghe-test":
			sAPI = "github-isl-test-01.ca.com/api/v3";
			break;
		case "github.com":
		default:
			sAPI = "api.github.com";
			break;
		}
		
		int nPage = 1;
		int nRepos = 0;
		int iIndex = 0;
		
		do {
			nRepos = 0;
			// Run the API to get the organizations repositories.
			String sURL = "https://"+ sAPI + "/orgs/"+ sOrg + "/repos?access_token="+sAccessToken+"&&page="+nPage+"&&per_page=100";
			
			try {		
				JSONArray ja = readJsonArrayFromUrl(sURL);
				for (int j=0; j<ja.length(); j++) {
					String sNameJSON = ja.getJSONObject(j).getString("name");
					
					cRepo.setString("Organization", sOrg, iIndex);
					cRepo.setString("Repository", sNameJSON, iIndex++);
					nRepos++;
				}
			}
			catch (IOException e) {
				iReturnCode = 301;
			    printErr("Couldn't read JSON Object from: "+e.getLocalizedMessage());			
			    System.exit(iReturnCode);						
			}
			catch (JSONException e) {						
				iReturnCode = 302;
			    printErr("Couldn't read JSON Object from: "+e.getLocalizedMessage());			
			    System.exit(iReturnCode);						
			}	
			nPage++;
		} while (nRepos>=100);	
	}
	
	public void readGitHubInstanceUsers(JCaContainer cUsers, String sAccessToken, String sType) {
		String sAPI = "";
		switch (sType.toLowerCase()) {
		case "ghe":
			sAPI = "github-isl-01.ca.com/api/v3";
			break;
		case "ghe-dev":
			sAPI = "github-isl-dev-01.ca.com/api/v3";
			break;
		case "ghe-test":
			sAPI = "github-isl-test-01.ca.com/api/v3";
			break;
		case "github.com":
		default:
			sAPI = "api.github.com";
			break;
		}
		
		int iIndex = 0;
		int nLast = 1;
		int length = 0;
		
		do {
			// Run the API to get the organizations repositories.
			String sURL = "https://"+ sAPI + "/users?access_token="+sAccessToken+(nLast>1?"&&since="+nLast:"");
			
			try {		
				JSONArray ja = readJsonArrayFromUrl(sURL);
				length = ja.length();
				for (int j=0; j<ja.length(); j++) {
					try {
						String sNameJSON = ja.getJSONObject(j).getString("login");
						String sLdapJSON = ja.getJSONObject(j).getString("ldap_dn");
						
						int beginIndex = Integer.max(sLdapJSON.indexOf("cn=")+3,sLdapJSON.indexOf("CN=")+3);
						int endIndex=sLdapJSON.indexOf(',');
						String sID = sLdapJSON.substring(beginIndex, endIndex);
						
						cUsers.setString("login", sNameJSON, iIndex);
						cUsers.setString("pmfkey", sID, iIndex);
						cUsers.setString("ldap_dn", sLdapJSON, iIndex++);
					}
					catch (JSONException e) {
						// skipping entries with no ldap counterpart
					}
				}
			}
			catch (IOException e) {
				iReturnCode = 401;
			    printErr("Couldn't read JSON Object from: "+e.getLocalizedMessage());			
			    System.exit(iReturnCode);						
			}
			catch (JSONException e) {
				iReturnCode = 402;
			    printErr("Couldn't read JSON Object from: "+e.getLocalizedMessage());			
			    System.exit(iReturnCode);						
			}	
			nLast += length;
		} while (length>0);	
	}

	public void readGitHubSuspendedUsers(JCaContainer cUsers, String sAccessToken, String sType) {
		String sAPI = "";
		int connecting = 0;
		switch (sType.toLowerCase()) {
		case "ghe":
			sAPI = "github-isl-01.ca.com";
			break;
		case "ghe-dev":
			sAPI = "github-isl-dev-01.ca.com";
			break;
		case "ghe-test":
			sAPI = "github-isl-test-01.ca.com";
			break;
		case "github.com":
		default:
			sAPI = "api.github.com";
			break;
		}
		
		boolean bDone = false;
		int cIndex = 0;
		
		while (connecting<5 && !bDone) {	
			try {
		        String command = "curl -k -L -u toolsadmin:" + sAccessToken + " https://"+sAPI+"/stafftools/reports/suspended_users.csv";
		        Process p = Runtime.getRuntime().exec(command);
		        BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
		        boolean isHeader = true;
		        // reading the output from the command
		        String s;
		        while ((s = stdInput.readLine()) != null) {
		            if (!"".equals(s.trim())) {
		                // below are the headers
		                // created_at,id,login,email,role,suspended?,last_logged_ip,repos,ssh_keys,org_memberships,dormant?,last_active,raw_login,2fa_enabled?
		
		                // ignore the first line, as it is a header
		            	bDone = true;
		                if (!isHeader) {
	                        cUsers.setString("login", s.split(",")[2], cIndex);// login header
	                        String sID = s.split(",")[12];
	                        String sLDAP = "CN="+sID+",ou=users,ou=north america,dc=ca,dc=com";
	                        cUsers.setString("ldap_dn", sLDAP, cIndex);
	                        cUsers.setString("pmfkey", sID, cIndex++);// rawlogin header
		               }
		               isHeader = false;
		            }
		        }
			}
			catch (IOException e) {
				iReturnCode = 501;
			    printErr("Couldn't read user report: "+e.getLocalizedMessage());			
			    System.exit(iReturnCode);						
			}
	        connecting++;
		}
	}
	

	public void removeTerminatedUserFromOrganization(String sID, String sOrg, String sAccessToken, String sType) {
		String sAPI = "";
		switch (sType.toLowerCase()) {
		case "ghe":
			sAPI = "github-isl-01.ca.com/api/v3";
			break;
		case "ghe-dev":
			sAPI = "github-isl-dev-01.ca.com/api/v3";
			break;
		case "ghe-test":
			sAPI = "github-isl-test-01.ca.com/api/v3";
			break;
		case "github.com":
		default:
			sAPI = "api.github.com";
			break;
		}
		
		String sCommand = "curl -X \"DELETE\" -H \"Authorization: token "+sAccessToken+
				          "\"  https://"+sAPI+"/orgs/"+sOrg+"/memberships/"+sID;
		try {
			Process p = Runtime.getRuntime().exec(sCommand);
	        BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));	
	        //BufferedReader stdError = new BufferedReader(new InputStreamReader(p.getErrorStream()));
	        
	        // read the output from the command
	        printLog(">>>Removing user: "+ sID +" from organization: "+sOrg);
	        String s;
	        while ((s = stdInput.readLine()) != null) {
	        }	
		} catch (IOException e) {             
		}
	}
	
	// *** CSM Ticket Handling
	public void createServiceTicket(String sProblems, String ticketDescription, List<String> ticketProblems, String sGroup, String sRequestor) {
        String prblms = "";
        String tagUL="<ul> ";
        int nCount = 0;

        SDTicket sd = new SDTicket("production");
        try {
	        // Check for duplicate tickets
	        Set<String> existingTickets = sd.getActiveTickets(ticketDescription);
	        if (existingTickets != null) {
		        List<String> list = new ArrayList(ticketProblems);
		        for (String prbm : list) {
		            if (existingTickets.contains(prbm.replace("\n", ""))) {
		                ticketProblems.remove(prbm);
		            }
		        }	        	
	        }
        } catch (IOException e) {
        	iReturnCode = 601;
        	printErr(e.getStackTrace().toString());
        	System.exit(iReturnCode);
        }
        

        for(String prbm: ticketProblems){
            prblms += prbm + "\n\n";
            nCount++;
            if (nCount%10==0) {
	        	String ticket = "";
	            ticket = sd.serviceTicket(ticketDescription, prblms, sGroup, sRequestor, this);
	        	if (!ticket.isEmpty()) {	
	        		if (sProblems.isEmpty()) 
	        			sProblems += tagUL;
	        		sProblems += "<li>CSM ticket, <b>SRQ#"+ticket+"</b> created.</li>";
	        	}			            	
	            prblms="";
            }
        }
        
        if(!prblms.isEmpty()) {
        	String ticket = "";
            ticket = sd.serviceTicket(ticketDescription, prblms, sGroup, sRequestor, this);
        	if (!ticket.isEmpty()) {	
        		if (sProblems.isEmpty()) 
        			sProblems += tagUL;
        		sProblems += "<li>CSM ticket, <b>SRQ#"+ticket+"</b> created.</li>";
        	}	
        }
		
	}
	
	// *** Email Handling ****
	
	public void sendEmailNotification(String email, String subjectText, String bodyText, boolean bHTML) {
         // sets SMTP server properties
		
		 // Recipient's email ID needs to be mentioned.
		  String to = email;
		  // Sender's email ID needs to be mentioned
		  String from = "ToolsSolutionsCommunications@ca.com";
		  String include = sBCC ;
		  // Assuming you are sending email from localhost
		  String host = "mail.ca.com";
		  // Get system properties
		  Properties properties = System.getProperties();
		  // Setup mail server
		  properties.setProperty("mail.smtp.host", host);
		  // Get the default Session object.
		  Session session = Session.getDefaultInstance(properties);	
		  boolean haveAttachment = false;
		  
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
		      if (!include.isEmpty()) {
		    	  //message.addRecipient(Message.RecipientType.BCC, new InternetAddress(include));
		          String[] includeList = include.split(";");
		          InternetAddress[] includeAddress = new InternetAddress[includeList.length];
		          counter = 0;
		          for (String recip2 : includeList) {
		              includeAddress[counter] = new InternetAddress(recip2.trim());
		              counter++;
		          }
		          message.setRecipients(Message.RecipientType.BCC, includeAddress);
		      }
		      
		      // Set Subject: header field
		      message.setSubject(subjectText);
		      
		      MimeMultipart multipart = new MimeMultipart(); 
		      // Add attachments if any
		      if (bodyText.length() > 500000) {
		          MimeBodyPart mattach = new MimeBodyPart();
		          String filename = "/c/fileattachment.txt";
		          try {	            	  
		        	  File file = new File(filename);
		        	  FileWriter fileWriter = new FileWriter(file);
		        	  fileWriter.write(bodyText);
		        	  fileWriter.flush();
		        	  fileWriter.close();	  
		        	  file.deleteOnExit();
		          } catch (IOException e) {
		        	  iReturnCode = 602;
		        	  printErr(e.getMessage());
		        	  System.exit(iReturnCode);
		          }
				  DataSource source = new FileDataSource(filename);
		          mattach.setDataHandler(new DataHandler(source));
		          mattach.setFileName(filename);
		          multipart.addBodyPart(mattach);	 
		          haveAttachment = true;
		      }
		      
		      // Set body of message
		      MimeBodyPart mbp = new MimeBodyPart(); 
		      if (!haveAttachment)
		    	  mbp.setContent(bodyText, "text/html"); 
		      else 
		    	  mbp.setContent("<b>Please refer to the attached file.</b>", "text/html");
		      
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
	
	// *** Basic 2D Array File Processing ***
	
	public void setFileAppend(boolean bAppend) {
		bFileAppend = bAppend;
	}
	
	public void writeCSVFileFromListGeneric( JCaContainer cList, String sOutputFileName, char sep, JCaContainer cLDAP, boolean bGovernance)
	{
		File fout = new File(sOutputFileName);
		
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter(sOutputFileName, bFileAppend));
			String[] keylist = cList.getKeyList();
			String line = "";
			int uIndex = -1;
			
			for (int i=0; i<keylist.length; i++) {
				if (!line.isEmpty()) 
					line += sep;				
				line += keylist[i]; 
				if (keylist[i].equalsIgnoreCase(tagUserID)) {
					uIndex = i;
				}
			}
			if (!bFileAppend) {				
				if (cLDAP!=null && uIndex>=0) {
					line += sep + tagManagerID;
				}
				bw.write(line);
				bw.newLine();
			}
			
			for (int i=0; i < cList.getKeyElementCount(keylist[0]); i++) {
				if (!bGovernance || !cList.getString("APP", i).isEmpty()) 
				{
					line = "";
					for (int j=0; j<keylist.length; j++) {
						if (!line.isEmpty())
							line += sep;					
						line += cList.getString(keylist[j], i);  
					}
					if (cLDAP!=null && uIndex>=0) {
						String sManagerID = "";
						String sID = cList.getString(keylist[uIndex], i);
						
						int[] lUser=cLDAP.find(tagSAMAccountName, sID);
						if (lUser.length > 0) {
							sManagerID = cLDAP.getString(tagManager, lUser[0]);
						}
						line += sep + sManagerID;
					}
					bw.write(line);
					bw.newLine();
				}
			}
		 
			bw.close();
		} catch (FileNotFoundException e) {             
			iReturnCode = 701;
		    System.err.println(e);			
		    System.exit(iReturnCode);
		} catch (IOException e) {             
			iReturnCode = 702;
		    System.err.println(e);			
		    System.exit(iReturnCode);
		}
	}	

	public void writeCSVFileFromListGeneric(JCaContainer cList, String sOutputFileName, char sep)
	{
		writeCSVFileFromListGeneric(cList, sOutputFileName, sep, null, true);
	}
	
	public void writeCSVFileFromListGeneric( JCaContainer cList, String sOutputFileName, char sep, JCaContainer cLDAP)
	{
		writeCSVFileFromListGeneric(cList, sOutputFileName, sep, cLDAP, true);
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
	}

	public void readInputListGenericWithColumnList( JCaContainer cUserList, String sInputFileName, char sep, String[] aColumnList)
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
					for (int i=0; i<entries.size(); i++) {
						boolean bFound = false;
						for (int j=0; j<aColumnList.length && !bFound; j++) {
							headings.add(entries.get(i));
							bFound = true;
						}
					}
					headings = entries;
				}
				else {
					for (int i=0; i<headings.size(); i++) {
						boolean bFound = false;
						for (int j=0; j<aColumnList.length && !bFound; j++) {
							if (aColumnList[j].equals(headings.get(i))) {
								cUserList.setString(headings.get(i), entries.get(i), index);
								bFound = true;
							}
						}
					}
					index++;
				};
				bFirst = false;
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

	// *** LDAP-related routines ***
	
	public void readLDAPEntry(JCaContainer cUsers, JCaContainer cLDAP, String sID, boolean bGroup, boolean bRecurse, boolean bForceGeneric) {
		readLDAPEntry(cUsers, cLDAP, sID, bGroup, bRecurse, bForceGeneric, null);
	}
	
	public void readLDAPEntry(JCaContainer cUsers, JCaContainer cLDAP, String sID, boolean bGroup, boolean bRecurse, boolean bForceGeneric, JCaContainer cGHEUsers) {
		if (bGroup) {
			String sUsers = expandDistributionListforId(sID, cLDAP);
			
			while (!sUsers.isEmpty()) {
				int nIndex = sUsers.indexOf(';');
				String sReportID = sUsers;
				if (nIndex > 0) {
					sReportID = sUsers.substring(0, nIndex);
					sUsers = sUsers.substring(nIndex+1);
				}
				else
					sUsers = "";

				int[] iGHE = {};
				
				if (cGHEUsers!=null) {
					iGHE = cGHEUsers.find("pmfkey", sReportID);
				}

				if (iGHE.length==0) {
					int cIndex = cUsers.getKeyElementCount("id");
					cUsers.setString("pmfkey", sReportID, cIndex);										
				}
			}
		}
		else {
			int[] iLDAP = cLDAP.find("sAMAccountName", sID);
			int[] iGHE = {};
			
			if (cGHEUsers!=null) {
				iGHE = cGHEUsers.find("pmfkey", sID);
			}
			if (iLDAP.length > 0 && iGHE.length==0) {
				boolean bUser = cLDAP.getString("haspmfkey", iLDAP[0]).equalsIgnoreCase("y");
				if (bUser) {
					if (bRecurse) {
						String sDirectReports = cLDAP.getString("directReports", iLDAP[0]);
						while (!sDirectReports.isEmpty()) {
							int nIndex = sDirectReports.indexOf(';');
							String sReportID = sDirectReports;
							if (nIndex > 0) {
								sReportID = sDirectReports.substring(0, nIndex);
								sDirectReports = sDirectReports.substring(nIndex+1);
							}
							else
								sDirectReports = "";
							
							int[] iLDAP2 = cLDAP.find("sAMAccountName", sReportID);
							if (iLDAP2.length >0 && cLDAP.getString("haspmfkey", iLDAP2[0]).equalsIgnoreCase("y")) {
								readLDAPEntry(cUsers, cLDAP, sReportID, false, true, false);
							} // only interested in non-generic direct Reports
						}
					}
					int cIndex = cUsers.getKeyElementCount("pmfkey");
					cUsers.setString("pmfkey", sID, cIndex);					
				} // user account
				else { 
					String sManagerID = cLDAP.getString("manager", iLDAP[0]);
					if (sManagerID.isEmpty() && !bForceGeneric)
						bForceGeneric = true;
					
					if (!sManagerID.isEmpty() || bForceGeneric) {
					    int[] iLDAP2 = cLDAP.find("sAMAccountName", sManagerID);
						if (iLDAP2.length > 0 || bForceGeneric) {
							int cIndex = cUsers.getKeyElementCount("pmfkey");
							cUsers.setString("pmfkey", sID, cIndex);
						}
					}
				} // generic account
			}			
		}
	}
	
	
	
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
		    boolean bMail          = false;
		    boolean bPhone         = false;
		    boolean bGeneric       = true;
		    boolean bManager       = false;
		    boolean bDirectReports = false;
		    
		    String sDirectReports = "";
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
				    	else if (sAttr.equalsIgnoreCase(tagManager)) {
				    		int nIndex = sValue.indexOf(",");
				    		sValue=sValue.substring(3, nIndex);
				    		bManager = true;
				    	}
				    	else if (sAttr.equalsIgnoreCase(tagDirectReports)) {
				    		bDirectReports = true;
				    		int nIndex = sValue.indexOf(",");
				    		sValue=sValue.substring(3, nIndex);
				    		if (!sDirectReports.isEmpty())
				    			sValue = sDirectReports + ";" + sValue;
				    		sDirectReports = sValue;
				    	}
				    	
				    	if (sAttr.equalsIgnoreCase(tagEmployeeType)) 
				    		bGeneric=false;
				    	else
				    		cLDAP.setString(sAttr, sValue, cIndex);
				    	
				    }
				}
		
				if (!bMail) 
					cLDAP.setString(tagMail, "unknown", cIndex);
				if (!bPhone) 
					cLDAP.setString(tagPhone, "", cIndex);
				if (!bManager)
					cLDAP.setString(tagManager, "", cIndex);
				if (!bDirectReports)
					cLDAP.setString(tagDirectReports, "", cIndex);
									
				if (!bGeneric) 
					nEmployees++;
				cLDAP.setString("haspmfkey", 
						        (!bGeneric)? "Y" : "N", 
					            cIndex);
			 
			} catch (NamingException e) {
			    // Handle the error
				iReturnCode = 801;
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
			String[] attrIDs = {tagSAMAccountName, tagDisplayName, tagDN, tagPhone, tagMail, tagEmployeeType, tagManager, tagDirectReports};
			ctls.setReturningAttributes(attrIDs);
	
			// Search for objects that have those matching attributes
			NamingEnumeration enumeration = ctx.search(region, filter, ctls);
			
			while (enumeration.hasMore()) {
			    SearchResult sr = (SearchResult)enumeration.next();
			    //System.out.println(">>>" + sr.getName());
			    processLDAPAttrs(sr.getAttributes(), cLDAP, isNormalUser);
			}			
		} catch (javax.naming.AuthenticationException e) {
			iReturnCode = 901;
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
	
	
// Encryption/Decryption	
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
			iReturnCode = 1001;
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
			iReturnCode = 1101;
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
	
// *** LDAP-related routines ***
	public void clearLDAPGroup(String sDLLDAPUserGroup, JCaContainer cUsers) {
		for (int i=0; i<cUsers.getKeyElementCount("dn"); i++) {
			String sDN = cUsers.getString("dn", i);
			if (removeUserFromLDAPGroup(sDLLDAPUserGroup, sDN)) {
				printLog(">>>User (deactivate): "+sDN);															
			}
		}
	}
	
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
			iReturnCode = 1201;
			printErr(e.getLocalizedMessage());
			System.exit(iReturnCode);
			
		// attempt to reacquire the authentication information
		} catch (NamingException e)	{
		    // Handle the error
			String sException = e.getMessage();
			if (sException.indexOf("ENTRY_EXISTS") < 0 ) 
			{
				iReturnCode = 1202;
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
			iReturnCode = 1301;
			printErr(e.getLocalizedMessage());
			System.exit(iReturnCode);
		
		// attempt to reacquire the authentication information
		} catch (NamingException e)	{
			// Handle the error
			String sException = e.getMessage();
			if (sException.indexOf("ENTRY_NOT_FOUND") < 0 &&
				sException.indexOf("WILL_NOT_PERFORM") < 0) //forced deletion
			{
				iReturnCode = 1302;
				printErr(e.getLocalizedMessage());
				System.exit(iReturnCode);
			}
			return false;
		}
		return true;
	}
	
	public void readLDAPUserGroupToContainer(String sDLLDAPUserGroup, 
                                             JCaContainer cDLUsers) {
		readLDAPUserGroupToContainer(sDLLDAPUserGroup, cDLUsers, null);
	}	
	
	public void readLDAPUserGroupToContainer(String sDLLDAPUserGroup, 
			                                 JCaContainer cDLUsers,
			                                 JCaContainer cLDAP)
	{
		try {
			// Retrieve attributes for a specific container
			int cIndex = 0;		
			if (cDLUsers.getKeyCount() > 0)
			{
				cIndex = cDLUsers.getKeyElementCount("member");
			}
			
			boolean endString = true;
			int loopValue = 0;
			while (endString) {
			    int startValue = loopValue * 1000;
			    int endvalue = (loopValue + 1) * 1000;
			    SearchControls searchCtls = new SearchControls();
			    String[] returnedAttrs = new String[1];
			    String range = startValue + "-" + endvalue;
			    returnedAttrs[0] = "member;range=" + range;
			    searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
			    searchCtls.setReturningAttributes(returnedAttrs);
			    int iIndex = sDLLDAPUserGroup.indexOf("cn=");
			    int jIndex = sDLLDAPUserGroup.indexOf(',');
			    String sName = sDLLDAPUserGroup.substring(iIndex+3, jIndex);
			    String sRegion = sDLLDAPUserGroup.substring(jIndex+1);
			    String sFilter = "(&(objectClass=group)(sAMAccountName="+sName+"))";
			    
			    NamingEnumeration answer = ctx.search(sRegion, sFilter, searchCtls);
			    while (answer.hasMore()) {
			        SearchResult entry = (SearchResult) answer.next();
			        
			        Attributes attributes = entry.getAttributes();
			        for (NamingEnumeration ae = attributes.getAll(); ae.hasMore();) {
					    Attribute attr = (Attribute)ae.next();
					    
					    if (attr.getID().indexOf("member")==0)
					    {
						    // Process each member attribute 
						    for (NamingEnumeration e = attr.getAll(); 
						         e.hasMore();
						         )
						    {
						    	String dn = (String)e.next();
						    	int iDL[];
						    	String pmfkey = "<<<>>>";
						    	if (cLDAP == null) {
							    	int iStart = Math.max(dn.indexOf("CN="),dn.indexOf("cn="));
							    	int iEnd   = dn.indexOf(',', iStart);
							    	pmfkey = dn.substring(iStart+3, iEnd);
						    	}
						    	else {
						    		iDL = cLDAP.find(tagDN, dn);
						    		if (iDL.length > 0) 
						    			pmfkey = cLDAP.getString(tagSAMAccountName, iDL[0]);
						    	}
					    		iDL = cDLUsers.find("member", pmfkey);
						    	
						    	if (iDL.length == 0) {
						    		cDLUsers.setString("dn",     dn,     cIndex);
						    		cDLUsers.setString("member", pmfkey, cIndex++);
						    	}
						    }
						}
			        	
			        }
			        
			        if (entry.getAttributes().toString().contains("{member;range=" + startValue + "-*")) {
			            endString = false;
			        }
			    }
			    loopValue++;
			    if (cIndex == 0) // nothing in this DL
			    	endString = false;
			}
			
			//printLog("Number of Entries: "+cIndex);
			
		} catch (javax.naming.AuthenticationException e) {
			iReturnCode = 1401;
		    printErr(e.getLocalizedMessage());
		    System.exit(iReturnCode);		    
	    // attempt to reacquire the authentication information
		} catch (NamingException e)
		{
			//printErr(e.getLocalizedMessage());
		}	
	}
	
	public void processLDAPGroupUsers(JCaContainer cLDAP,
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
		if (!cDelUsers.isEmpty())
		{
			printLog("Remove "+sAppName+" Users ");
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
		if (!cAddUsers.isEmpty())
		{
			printLog("Add "+sAppName+" Users");
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
		if (!sDumpFile.isEmpty())
		{		
			printLog("Dump "+sAppName+" User DL");
			File file = new File(sDumpFile);
			
			// if file doesnt exists, then create it
			if (!file.exists()) {
				file.createNewFile();
			}
			
			BufferedWriter bw = new BufferedWriter(new FileWriter(file.getAbsoluteFile(), bFileAppend));
			
			int nSize = cDLUsers.getKeyElementCount("dn");
			for (int i=0; i<nSize; i++ )
			{
				String sDN = cDLUsers.getString("dn", i);
				int iLDAP[] = cLDAP.find("distinguishedName", sDN);
				if (iLDAP.length > 0)
				{
					String sUser = cLDAP.getString("displayName", iLDAP[0]);
					String sID   = cLDAP.getString("sAMAccountName", iLDAP[0]);	
					int iIndex = sUser.indexOf('(');
					if (iIndex > 0)
						sUser = sUser.substring(0, iIndex).trim();
					bw.write(sUser+ " ("+ sID+")\n");
				} // user exists in domain
			}  // loop over DL members		
				
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
			                      boolean        bSynch) 
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
				
				readLDAPUserGroupToContainer(sDLLDAPUserGroup, cDLUsers[i], cLDAP);
				processLDAPGroupUsers(cLDAP,
					                  cDLUsers[i],
                                      cAddUsers, 
                                      cDelUsers,
                                      sDLLDAPUserGroup,
                                      aAuthSchemas[iUserType][j]);
			}
		}
	}

	public String expandDistributionListforId(String sDLLDAPUserGroup, JCaContainer cLDAP) {
		String sResult = "";
		try {
			boolean endString = true;
			int loopValue = 0;
			while (endString) {
			    int startValue = loopValue * 1000;
			    int endvalue = (loopValue + 1) * 1000;
			    SearchControls searchCtls = new SearchControls();
			    String[] returnedAttrs = new String[1];
			    String range = startValue + "-" + endvalue;
			    returnedAttrs[0] = "member;range=" + range;
			    searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
			    searchCtls.setReturningAttributes(returnedAttrs);
			    int iIndex = Math.max(sDLLDAPUserGroup.indexOf("cn="),sDLLDAPUserGroup.indexOf("CN="));
			    int jIndex = sDLLDAPUserGroup.indexOf(',');
			    String sName = sDLLDAPUserGroup.substring(iIndex+3, jIndex);
			    String sRegion = sDLLDAPUserGroup.substring(jIndex+1);
			    String sFilter = "(&(objectClass=group)(sAMAccountName="+sName+"))";
			    
			    NamingEnumeration answer = ctx.search(sRegion, sFilter, searchCtls);
			    while (answer.hasMore()) {
			        SearchResult entry = (SearchResult) answer.next();
			        
			        Attributes attributes = entry.getAttributes();
			        for (NamingEnumeration ae = attributes.getAll(); ae.hasMore();) {
					    Attribute attr = (Attribute)ae.next();
					    
					    if (attr.getID().indexOf("member")==0)
					    {
						    // Process each member attribute 
						    for (NamingEnumeration e = attr.getAll(); 
						         e.hasMore();
						         )
						    {
						    	String dn = (String)e.next();
						    	int[] iLDAP = cLDAP.find(tagDN, dn);
						    	if (iLDAP.length > 0) {
						    		String pmfkey=cLDAP.getString(tagSAMAccountName, iLDAP[0]);
						    		String sID = cLDAP.getString(tagMail, iLDAP[0]);
						    	    sResult += sResult.isEmpty()?"":";" + sID;
						    	} // DN found in directory users
						    } // loop over member attributes
						} // attr contains "member"		        	
			        }
			        
			        if (entry.getAttributes().toString().contains("{member;range=" + startValue + "-*")) {
			            endString = false;
			        }
			    }
			    loopValue++;
			}
			
			//printLog("Number of Entries: "+cIndex);
			
		} catch (javax.naming.AuthenticationException e) {
			iReturnCode = 1501;
		    printErr(e.getLocalizedMessage());
		    System.exit(iReturnCode);		    
	    // attempt to reacquire the authentication information
		} catch (NamingException e)
		{
			//printErr(e.getLocalizedMessage());
		}	
		
		return sResult;
	}
	
	public String expandDistributionListforEmail(String sDLLDAPUserGroup, JCaContainer cLDAP) {
		String sResult = "";
		try {
			boolean endString = true;
			int loopValue = 0;
			while (endString) {
			    int startValue = loopValue * 1000;
			    int endvalue = (loopValue + 1) * 1000;
			    SearchControls searchCtls = new SearchControls();
			    String[] returnedAttrs = new String[1];
			    String range = startValue + "-" + endvalue;
			    returnedAttrs[0] = "member;range=" + range;
			    searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
			    searchCtls.setReturningAttributes(returnedAttrs);
			    int iIndex = Math.max(sDLLDAPUserGroup.indexOf("cn="),sDLLDAPUserGroup.indexOf("CN="));
			    int jIndex = sDLLDAPUserGroup.indexOf(',');
			    String sName = sDLLDAPUserGroup.substring(iIndex+3, jIndex);
			    String sRegion = sDLLDAPUserGroup.substring(jIndex+1);
			    String sFilter = "(&(objectClass=group)(sAMAccountName="+sName+"))";
			    
			    NamingEnumeration answer = ctx.search(sRegion, sFilter, searchCtls);
			    while (answer.hasMore()) {
			        SearchResult entry = (SearchResult) answer.next();
			        
			        Attributes attributes = entry.getAttributes();
			        for (NamingEnumeration ae = attributes.getAll(); ae.hasMore();) {
					    Attribute attr = (Attribute)ae.next();
					    
					    if (attr.getID().indexOf("member")==0)
					    {
						    // Process each member attribute 
						    for (NamingEnumeration e = attr.getAll(); 
						         e.hasMore();
						         )
						    {
						    	String dn = (String)e.next();
						    	int[] iLDAP = cLDAP.find(tagDN, dn);
						    	if (iLDAP.length > 0) {
						    		String eMail = cLDAP.getString(tagMail, iLDAP[0]);
						    		if (!eMail.equalsIgnoreCase("unknown")) {
						    			sResult += ";" + eMail;
						    		}
						    	} // DN found in LDAP users
						    } // loop over member attributes
						} // attribute contains "member"		        	
			        }
			        
			        if (entry.getAttributes().toString().contains("{member;range=" + startValue + "-*")) {
			            endString = false;
			        }
			    }
			    loopValue++;
			}
			
			//printLog("Number of Entries: "+cIndex);
			
		} catch (javax.naming.AuthenticationException e) {
			iReturnCode = 1601;
		    printErr(e.getLocalizedMessage());
		    System.exit(iReturnCode);		    
	    // attempt to reacquire the authentication information
		} catch (NamingException e)
		{
			//printErr(e.getLocalizedMessage());
		}	
		
		return sResult;
	}
	
		
	public void readSourceMinderContacts(JCaContainer cApplicationContacts, String sApplication, JCaContainer cLDAP) {
		int nIndex = 0;
		JCaContainer cContacts = new JCaContainer();
		
		readInputListGeneric(cContacts, "SourceMinder_Product_Contacts.tsv", '\t');
		
		for (int iIndex=0; iIndex<cContacts.getKeyElementCount("PROD_NAME"); iIndex++) {
			boolean bActive = true;
			boolean bExempt = false;
			if (cContacts.getString("SRC_MNGMT_TOOL", iIndex).contains(sApplication) ||
				sApplication.equalsIgnoreCase("mainframe")) {
				switch(cContacts.getString("PROD_STAT", iIndex).toLowerCase()) {
				case "end of life":
				case "retired":
				case "inactive":	
					bActive = false;
					// drop through
				case "exempt":
					bExempt = true;
					// drop through
				case "active":
				case "stabilized":
				case "internal":
					boolean bDoit = false;
					boolean bGitHub = false;
					String sProduct = "", sLocation = "";
					sLocation = cContacts.getString("SRC_PHYS_LOC", iIndex);
					
					switch (sApplication.toLowerCase()) {
					case "github":
						bDoit = sLocation.contains("github-isl-01.ca.com") ||
						        sLocation.contains("github.com");
						sProduct  = cContacts.getString("PROD_NAME", iIndex).replace("\"", "");
						sLocation = sLocation.replace("\"", "");
						bGitHub = true;
						break;
					case "harvest":
						bDoit = sLocation.toLowerCase().contains("cscr") &&
								cContacts.getString("SRC_RESOURCES", iIndex).isEmpty();
						sProduct  = cContacts.getString("PROD_NAME", iIndex).replace("\"", "");
						sLocation = sLocation.replace("\"", "");
						break;
					case "endevor":
						bDoit = !cContacts.getString("ENDEVOR_PRODUCT", iIndex).equalsIgnoreCase("null");
						sProduct  = cContacts.getString("PROD_NAME", iIndex).replace("\"", "");
						sLocation = cContacts.getString("ENDEVOR_PRODUCT", iIndex).trim();
						break;
					case "mainframe":
					default: // mainframe
						bDoit = cContacts.getString("ENDEVOR_PRODUCT", iIndex).equalsIgnoreCase("null") &&
						       !sLocation.isEmpty() &&
						       !cContacts.getString("SRC_RESOURCES", iIndex).isEmpty();
						sProduct  = cContacts.getString("PROD_NAME", iIndex).replace("\"", "");
						sLocation = sLocation.replace("\"", "");
						break;
					}
					if (bDoit) {
						String sRelease  = cContacts.getString("RELEASE", iIndex).replace("\"", "");
						
						String sApprovers = cContacts.getString("APPROVERS_PMFKEY", iIndex);
						sApprovers = sApprovers.replace("\"[", "[");
						sApprovers = sApprovers.replace("]\"", "]");
						sApprovers = sApprovers.replace("\"\"", "\"");
						String sTeamTypes = "";
						String sTeamNames = "";
						
						try {				
							JSONArray ja = new JSONArray(sApprovers);
							sApprovers = "";
							for (int j=0; j<ja.length(); j++) {
								String sApprover = ja.getJSONObject(j).getString("PMFKEY");
								int[] iLDAP = cLDAP.find("sAMAccountName", sApprover);
								if (iLDAP.length > 0) {
									if (!sApprovers.isEmpty()) {
										sApprovers += ";";
										if (bGitHub) {
											sTeamTypes += ";";
											sTeamNames += ";";
										}
									}
									sApprovers += sApprover;
									if (bGitHub) try {
										String sTeamType = ja.getJSONObject(j).getString("TYPE");
										String sTeamName = ja.getJSONObject(j).getString("NAME");
										sTeamTypes += sTeamType;
										sTeamNames += sTeamName;
									}
									catch (JSONException e) {
										sTeamTypes += "Organization";
										sTeamNames += "***this***";
									}
								}
							}
						}  catch (JSONException e) {
							iReturnCode = 1701;
						    printErr(e.getLocalizedMessage());
						    System.exit(iReturnCode);		    							
						}

						cApplicationContacts.setString("Product",  sProduct, nIndex);
						cApplicationContacts.setString("Release",  sRelease, nIndex);
						cApplicationContacts.setString("Location", sLocation, nIndex);
						cApplicationContacts.setString("Active", bActive?(bExempt? "E":"Y"):"N", nIndex);
						cApplicationContacts.setString("Approver", sApprovers, nIndex);
						switch (sApplication.toLowerCase()) {
						case "github":
							cApplicationContacts.setString("Type", sTeamTypes,  nIndex);
							cApplicationContacts.setString("Name", sTeamNames,  nIndex);
							break;
						case "mainframe":
							cApplicationContacts.setString("SourceResources", cContacts.getString("SRC_RESOURCES", iIndex),  nIndex);
							cApplicationContacts.setString("VMVSELocation",   cContacts.getString("VM_VSE_SRC_LOC", iIndex), nIndex);
							break;
						default:
							break;
						}
						nIndex++;
					}
					break;
					
				default:
					break;
				}
			} // Harvest Contact
		} // loop over SourceMinder contact list

	} // readSourceMinderContacts

	
	public String[] readAssignedApprovers(String sApprovers) {
		List<String> lObj = new ArrayList<String>();
		
		String sToken = sApprovers;
		
		while (!sToken.isEmpty()) {
			int nIndex = sToken.indexOf(';');
			String sApprover = sToken;
			if (nIndex >= 0) {
				sApprover = sToken.substring(0, nIndex);
				sToken = sToken.substring(nIndex+1);
			}
			else 
				sToken = "";
			
			lObj.add(sApprover);
		}
		
		String[] lStrings = new String[lObj.size()];
		ListIterator<String> lIter = lObj.listIterator();
		int i=0;
		
		while (lIter.hasNext()) {
			lStrings[i++] = (String)lIter.next();
		}
		return lStrings;
	} // readAssignedApprovers
	
	public String[] readAssignedBrokerProjects(String sLocation, String sBroker) {
		List<String> lObj = new ArrayList<String>();
		
		boolean bFound = false;		
		String sToken = sLocation;
		while (!bFound && !sToken.isEmpty()) {
			int nIndex = sToken.indexOf(";");
			String sNextBroker = sToken;
			if (nIndex >= 0) {
				sNextBroker = sToken.substring(0, nIndex);
				sToken = sToken.substring(nIndex+1);
			}
			else 
				sToken = "";
			
			if (sNextBroker.startsWith(sBroker) || sBroker.isEmpty()) {
				bFound = true;
				int mIndex = -1;
				boolean bAllProjects = false;
				if (sBroker.isEmpty()) { // Endevor
					mIndex = -1;
					bAllProjects = false;
				}
				else { // Harvest
					mIndex = sNextBroker.indexOf('/');
					bAllProjects = mIndex == -1;
				}
				if (bAllProjects) 
					lObj.add("");
				else {
					String sNextProject = sNextBroker.substring(mIndex+1);
					while (!sNextProject.isEmpty()) {
						int lIndex = sNextProject.indexOf(',');
						String sProject = sNextProject;
						if (lIndex>=0) {
							sProject = sNextProject.substring(0, lIndex);
							sNextProject = sNextProject.substring(lIndex+1);
						}
						else 
							sNextProject = "";
						
						lObj.add(sProject);
					}
				} // parse out leading project names					
			} // current broker found
			
		} // loop over broker specifications
		
		String[] lStrings = new String[lObj.size()];
		ListIterator<String> lIter = lObj.listIterator();
		int i=0;
		
		while (lIter.hasNext()) {
			lStrings[i++] = (String)lIter.next();
		}
		return lStrings;
	} // readAssignedBrokerProjects
	
	
	public boolean processProjectReleases(String sProject, String sReleases, boolean bActive) {
		boolean bIsActive = bActive;
		
		if (bIsActive && !sReleases.isEmpty()) {
			boolean bFound = false;		
			String sToken = sReleases;
			while (!bFound && !sToken.isEmpty()) {
				int nIndex = sToken.indexOf(';');
				String sNextRelease = sToken;
				if (nIndex >= 0) {
					sNextRelease = sToken.substring(0, nIndex);
					sToken = sToken.substring(nIndex+1);
				}
				else 
					sToken = "";
				
				sNextRelease = sNextRelease.toLowerCase();
				if (sNextRelease.startsWith("r")) {
					sNextRelease = sNextRelease.substring(1);
				}
				if (sNextRelease.endsWith("*")) {
					sNextRelease = sNextRelease.replace("*", "");
				}
				
				String[] aCheck = {
						sNextRelease,
						sNextRelease.replace(".", "_"),
						sNextRelease.replace(".", "")
				};
				
				for (int i=0; i<aCheck.length && !bFound; i++) {
					if (sProject.contains(aCheck[i]))
						bFound = true;
				}
				
			} // loop over broker specifications
			
			bIsActive = bFound;
		}
		
		return bIsActive;
	} // processProjectReleases
	
	
	// *******************  Harvest Processing Routines *****
	
	public boolean removeUserAccessFromHarvestProject(String sID, String sBroker, String sProject, String sPassword, boolean bProcessChanges) {
		boolean bSuccess = false;
		String sqlError = "DB2. Unable to execute query.";
		
		try {			
			PreparedStatement pstmt = null; 
			String sqlStmt;
			String sJDBC = "";
			String[] aJDBC = getHarvestJDBCConnections();
			
			for (int i=0; sJDBC.isEmpty() && i<aJDBC.length; i++) {
				if (aJDBC[i].contains(sBroker.toLowerCase())) 
					sJDBC = aJDBC[i];
			}

			int nIndex, lIndex;
			Class.forName("com.microsoft.sqlserver.jdbc.SQLServerDriver");
			String sURL = sJDBC + "password=" + sPassword+";";
			if (sID.endsWith("?"))
				sID=sID.substring(0, sID.lastIndexOf("?"));
			sID=sID.toLowerCase();
			sProject=sProject.toUpperCase();
			
			Connection conn = DriverManager.getConnection(sURL);
			
			List<String> aUserGroups = new ArrayList<String>();
			
			sqlError = "SQLServer.  Error retrieving list of user groups for user, "+sID+", on broker, "+sBroker+", for project, "+sProject+".";
			sqlStmt = 
					"select distinct usergroupname from harusergroup where usrgrpobjid in "+
			        "( "+
					"  select UG.usrgrpobjid from harusergroup UG "+							
					"  join harusersingroup UIG on UIG.usrgrpobjid = UG.usrgrpobjid "+
			        "  join haruser U on U.usrobjid = UIG.usrobjid "+
			        "  join haruserdata UD on (UD.usrobjid = U.usrobjid and UD.accountdisabled = \'N\') "+
			        "  left outer join harenvironment E on E.envobjid > \'0\' "+ 
			        "  where E.envisactive = \'Y\' "+ 
			        "    and UPPER(E.environmentname) in (\'"+sProject+"\') "+ 
			        "    and UG.usergroupname = \'Administrator\' "+
			        "    and LOWER(U.username) in (\'"+sID+"\') "+
			        "union all "+
					"  select UG.usrgrpobjid from harusergroup UG "+							
					"  join harusersingroup UIG on UIG.usrgrpobjid = UG.usrgrpobjid "+
			        "  join haruser U on U.usrobjid = UIG.usrobjid "+
			        "  join haruserdata UD on (UD.usrobjid = U.usrobjid and UD.accountdisabled = \'N\') "+
			        "  join harharvest HA on HA.usrgrpobjid = UIG.usrgrpobjid "+
			        "  left outer join harenvironment E on E.envobjid > \'0\' "+ 
			        "  where E.envisactive = \'Y\' "+ 
			        "    and UPPER(E.environmentname) in (\'"+sProject+"\') "+ 
			        "    and (HA.viewenvironment = \'Y\' or HA.adminuser = \'Y\' or  "+
			        "         HA.adminenvironment = \'Y\' or HA.adminuser = \'Y\' or "+
			        "         HA.secureharvest = \'Y\' ) "+ 
			        "    and LOWER(U.username) in (\'"+sID+"\') "+
			        "union all "+
					"  select UG.usrgrpobjid from harusergroup UG "+							
					"  join harusersingroup UIG on UIG.usrgrpobjid = UG.usrgrpobjid "+
			        "  join haruser U on U.usrobjid = UIG.usrobjid "+
			        "  join haruserdata UD on (UD.usrobjid = U.usrobjid and UD.accountdisabled = \'N\') "+
			        "  join harenvironmentaccess EA on EA.usrgrpobjid = UIG.usrgrpobjid "+
			        "  join harenvironment E on E.envobjid = EA.envobjid "+ 
			        "  where E.envisactive = \'Y\' "+ 
			        "    and UPPER(E.environmentname) in (\'"+sProject+"\') "+ 
			        "    and (EA.secureaccess = \'Y\' or EA.updateaccess = \'Y\' or "+
			        "         EA.viewaccess = \'Y\' or EA.executeaccess = \'Y\' or "+
			        "         EA.updateaccess = \'Y\' or EA.secureaccess = \'Y\' ) "+ 
			        "    and LOWER(U.username) in (\'"+sID+"\') "+
			        "union all "+
					"  select UG.usrgrpobjid from harusergroup UG "+							
					"  join harusersingroup UIG on UIG.usrgrpobjid = UG.usrgrpobjid "+
			        "  join haruser U on U.usrobjid = UIG.usrobjid "+
			        "  join haruserdata UD on (UD.usrobjid = U.usrobjid and UD.accountdisabled = \'N\') "+
			        "  join harstateaccess SA on SA.usrgrpobjid = UIG.usrgrpobjid "+
			        "  join harstate S on S.stateobjid = SA.stateobjid "+
			        "  join harenvironment E on E.envobjid = S.envobjid "+ 
			        "  where E.envisactive = \'Y\' "+ 
			        "    and UPPER(E.environmentname) in (\'"+sProject+"\') "+ 
			        "    and (SA.updateaccess = \'Y\' ) "+ 
			        "    and LOWER(U.username) in (\'"+sID+"\') "+
			        "union all "+
					"  select UG.usrgrpobjid from harusergroup UG "+							
					"  join harusersingroup UIG on UIG.usrgrpobjid = UG.usrgrpobjid "+
			        "  join haruser U on U.usrobjid = UIG.usrobjid "+
			        "  join haruserdata UD on (UD.usrobjid = U.usrobjid and UD.accountdisabled = \'N\') "+
			        "  join harstateprocessaccess SPA on SPA.usrgrpobjid = UIG.usrgrpobjid "+
			        "  join harstateprocess SP on SP.processobjid = SPA.processobjid"+
			        "  join harstate S on S.stateobjid = SP.stateobjid "+
			        "  join harenvironment E on E.envobjid = S.envobjid "+ 
			        "  where E.envisactive = \'Y\' "+ 
			        "    and UPPER(E.environmentname) in (\'"+sProject+"\') "+ 
			        "    and (SPA.executeaccess = \'Y\' ) "+ 
			        "    and LOWER(U.username) in (\'"+sID+"\') "+
			        "    and U.usrobjid in ( "+
			        "     select U2.usrobjid "+
			        "	  from harenvironmentaccess EA "+ 
			        "	  join harusersingroup UIG2 on UIG2.usrgrpobjid = EA.usrgrpobjid "+ 
			        "	  join harenvironment E2 on E2.envobjid = EA.envobjid "+
			        "     join haruser U2 on U2.usrobjid = UIG2.usrobjid "+
			        "     where EA.executeaccess = \'Y\' ) "+
			        " )";
			
			pstmt=conn.prepareStatement(sqlStmt);
			ResultSet rSet = pstmt.executeQuery();
			boolean hasPublic = false;
			
			while (rSet.next()) {		
				String sUserGroup = rSet.getString("USERGROUPNAME").trim();
				if (sUserGroup.equalsIgnoreCase("PUBLIC") )
					hasPublic = true;
				aUserGroups.add(sUserGroup);
			}
			
			if (/*!hasPublic &&*/ aUserGroups.size()>0) {
				String sGroups = ""; 
				String sGroups2 = "";
				for (int i=0; i<aUserGroups.size(); i++) {
					String sUserGroup = aUserGroups.get(i);
					if (sUserGroup.equalsIgnoreCase("PUBLIC")) continue;
					if (!sGroups.isEmpty()) {
						sGroups  += ",";
						sGroups2 += ",";
					}
					sGroups  += "\'"+sUserGroup+"\'";
					sGroups2 += sUserGroup;
				}
				
				if (!sGroups.isEmpty()) {					
					if (bProcessChanges && !sGroups.isEmpty()) {
						sqlError = "SQLServer. Error removing user, "+sID+", on broker, "+sBroker+", from user group set, {"+sGroups2+"}.";
						sqlStmt = "delete from harusersingroup "+
						          "where usrgrpobjid in "+
								  " (select usrgrpobjid from harusergroup where usergroupname in ("+sGroups+") ) "+
								  "  and usrobjid in "+
								  " (select usrobjid from haruser where LOWER(username) in (\'"+sID+"\') ) ";
	
						pstmt=conn.prepareStatement(sqlStmt);  
						int iResult = pstmt.executeUpdate();
						if (iResult > 0) 
							bSuccess = true;									
					}
					else 
						bSuccess = true;
				}
			}
			
			
			if (aUserGroups.isEmpty() || hasPublic) {	
				if (bProcessChanges) {					
					sqlError = "SQLServer. Error updating disabled status for user, "+sID+", on broker, "+ sBroker + ".";
					sqlStmt = "update haruserdata set ACCOUNTDISABLED=\'Y\' where ACCOUNTDISABLED=\'N\' and USROBJID in (select USROBJID from haruser where LOWER(USERNAME) in (\'"+sID+"\') )";
					
					pstmt=conn.prepareStatement(sqlStmt);  
					int iResult = pstmt.executeUpdate();
					if (iResult > 0) 
						bSuccess = true;
				}
				else
					bSuccess = true;
			}
			
			conn.close();
			
		} catch (ClassNotFoundException e) {
			iReturnCode = 1801;
			printErr(sqlError);
			printErr(e.getLocalizedMessage());			
			System.exit(iReturnCode);
		} catch (SQLException e) {     
			iReturnCode = 1802;
			printErr(sqlError);
			printErr(e.getLocalizedMessage());			
			System.exit(iReturnCode);
		}			
		return bSuccess;
	}
	
	public String[] getHarvestJDBCConnections() {
		String[] cscrBrokers = 
		{						
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr001;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr003;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr004;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr005;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr007;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr009;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr101;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr102;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr104;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr105;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr106;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr108;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr109;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr110;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr111;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr112;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr113;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr201;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr402;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr403;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			//"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr501;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			//"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr502;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr503;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr504;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr601;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr602;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr603;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr604;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB004P-1;databaseName=cscr605;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB004P-1;databaseName=cscr606_12.5;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			//"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr607;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr608;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr609;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr610;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr611;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB004P-1;databaseName=cscr612;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB004P-1;databaseName=cscr616;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr617;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr618;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr619;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr620;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr621;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr622;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr623;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr624;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr625;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr626;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr701;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB004P-1;databaseName=cscr702;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr703;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr704;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr706;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr707;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr708;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",			
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr709;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",			
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr801;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr802;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr803;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr804;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr805;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr806;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr807;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr808;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr809;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr810;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr811;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr901;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr902;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB004P-1;databaseName=cscr903;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr904;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr905;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB004P-1;databaseName=cscr906;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr907;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB004P-1;databaseName=cscr911;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB004P-1;databaseName=cscr911-a;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB004P-1;databaseName=cscr912;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr913;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr914;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB004P-1;databaseName=cscr917;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr919;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr920;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr921;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr922;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr924;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr925;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr927;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr929;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",			
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr1001;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr1002;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr1101;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr1102;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr1103;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr1201;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr1203;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr1301;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			//"jdbc:sqlserver://L1AGUSDB004P-1;databaseName=cscr1302;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr1303;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr1304;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr1305;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr1306;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr1307;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr1308;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB003P-1;databaseName=cscr1309;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;",
			"jdbc:sqlserver://L1AGUSDB002P-1;databaseName=cscr1400;integratedSecurity=false;selectMethod=cursor;multiSubnetFailover=true;user=harvest;"
		};
		
		return cscrBrokers;
	}
	
} //end of class definition
