package commonldap;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class SDTicket {

    private String username = "bsgautomation@ca.com";
    private String password = "S6mb2hT*gw";
    private String sCSMLandscape = "csmstaging";
    private String assignedToGroupName = "GIS-BSG-RnD-Tools-Support-L2";
    
	public SDTicket(String sLandscape) {
		switch (sLandscape.toLowerCase()) {
		case "test":
		default:
			username = "bsgautomation@ca.com";
			password = "S6mb2hT*gw";
			sCSMLandscape = "csmstaging";
			break;
			
		case "production":
			username = "bsgautomation@ca.com";
			password = "S6mb2hT*gw";
			sCSMLandscape = "csms3";
			break;
		}
	}


    public String serviceTicket(String ticketDescription, String descriptionLong, String requesterName, CommonLdap frame) {
        String resp = null;
        String payload = "";
        payload += "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:wrap=\"http://wrappers.webservice.appservices.core.inteqnet.com\" xmlns:xsd=\"http://beans.webservice.appservices.core.inteqnet.com/xsd\"> ";
        payload += "    <soapenv:Header/> ";
        payload += "    <soapenv:Body> ";
        payload += "        <wrap:logServiceRequest> ";
        payload += "            <wrap:credentials> ";
        payload += "                <xsd:userName>" + username + "</xsd:userName> ";
        payload += "                <xsd:userPassword>" + password + "</xsd:userPassword> ";
        payload += "            </wrap:credentials> ";
        payload += "            <wrap:extendedSettings> ";
        payload += "                <xsd:responseFormat>JSON</xsd:responseFormat> ";
        payload += "            </wrap:extendedSettings> ";
        payload += "            <wrap:srqBean> ";
        payload += "                <xsd:description_long>" + descriptionLong + "</xsd:description_long> ";
        payload += "                <xsd:assigned_to_group_name>" + assignedToGroupName + "</xsd:assigned_to_group_name> ";
        payload += "                <xsd:requester_name>" + requesterName + "</xsd:requester_name> ";
        payload += "                <xsd:ticket_description>" + ticketDescription + "</xsd:ticket_description>  ";
        payload += "            </wrap:srqBean> ";
        payload += "        </wrap:logServiceRequest> ";
        payload += "    </soapenv:Body> ";
        payload += "</soapenv:Envelope>";

        try {
            URL _url = new URL("https://"+sCSMLandscape+".serviceaide.com/NimsoftServiceDesk/servicedesk/webservices/ServiceRequest.ServiceRequestHttpSoap11Endpoint/");
            HttpURLConnection con = (HttpURLConnection) _url.openConnection();
            con.setRequestProperty("Content-Type", "application/xop+xml;charset=UTF-8;action=\"urn:logServiceRequest\"");
            con.setDoOutput(true);
            con.setDoInput(true);
            con.setRequestMethod("POST");

            DataOutputStream wr = new DataOutputStream(con.getOutputStream());
            wr.writeBytes(payload);
            wr.flush();
            wr.close();

            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer sb = null;
            while ((inputLine = in.readLine()) != null) {
                if (sb == null) {
                    sb = new StringBuffer();
                }
                sb.append(inputLine);
            }
            in.close();
            System.out.println(sb);
            
            String response = sb.toString().split("apache.org>")[1].split("--MIMEBoundary")[0];
            Document doc = Jsoup.parse(response);
            String text = doc.getElementsByTag("ax254:responseText").text();
            int cIndex = text.indexOf("}]");
            if (cIndex >= 0)
            	text=text.substring(0, cIndex+2);
            JsonParser jsonparser = new JsonParser();
            JsonElement jo = jsonparser.parse(text);
            JsonArray arr = jo.getAsJsonArray();
            JsonObject je = (JsonObject)arr.get(0);
            frame.printLog(je.get("ticket_identifier").getAsString());
            resp = je.get("ticket_identifier").getAsString();
        } catch (Exception e) {
            frame.printErr(e.getStackTrace().toString());
        }
        return resp;
    }
}
