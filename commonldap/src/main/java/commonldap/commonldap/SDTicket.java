package commonldap.commonldap;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

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
    private String requestorName = "desra04";
    private String sCSMservice = "/NimsoftServiceDesk/servicedesk/webservices/ServiceRequest?wsdl";

    public SDTicket(String sLandscape, String sGroup, String sRequestor) {
        switch (sLandscape.toLowerCase()) {
        case "test":
        default:
            username = "bsgautomation@ca.com";
            password = "S6mb2hT*gw";
            sCSMLandscape = "csmstaging";
            sCSMservice = "/servicedesk/webservices/ServiceRequest?wsdl";
            break;

        case "production":
            username = "bsgautomation@ca.com";
            password = "McB93RhD";
            sCSMLandscape = "csm3";
            sCSMservice = "/NimsoftServiceDesk/servicedesk/webservices/ServiceRequest?wsdl";
            break;
        }
        
        if (!sRequestor.isEmpty())
            requestorName = sRequestor.trim();
        if (!sGroup.isEmpty())
            assignedToGroupName = sGroup.trim();   
    }

    @SuppressWarnings("static-access")
    public String serviceTicket(String ticketDescription, String descriptionLong, String sGroup, String sRequestor, CommonLdap frame) {
        String resp = "";

        if (!sRequestor.isEmpty())
            requestorName = sRequestor.trim();
        if (!sGroup.isEmpty())
            assignedToGroupName = sGroup.trim();

        if (!password.isEmpty()) {
            try {
                String payload = generateServiceRequestPayload(descriptionLong, ticketDescription);
                String url = "https://" + sCSMLandscape + ".serviceaide.com"+sCSMservice;
                String sb = connectToServiceDesk(url, payload);

                Document doc = Jsoup.parse(sb.split("apache.org>")[1].split("--MIMEBoundary")[0]);
                String text = doc.getElementsByTag("ax254:responseText").text();
                int cIndex = text.indexOf("}]");
                if (cIndex >= 0)
                    text = text.substring(0, cIndex + 2);
                JsonParser jsonparser = new JsonParser();
                JsonElement jo = jsonparser.parse(text);
                JsonArray arr = jo.getAsJsonArray();
                JsonObject je = (JsonObject) arr.get(0);
                frame.printLog(je.get("ticket_identifier").getAsString());
                resp = je.get("ticket_identifier").getAsString();
            } catch (Exception e) {
                frame.printErr(e.getLocalizedMessage());
            }
        }

        return resp;
    }

    public Set<String> getActiveTickets(String sTicketDescription) throws IOException {
        Set<String> tickets = null;
        
        if (!password.isEmpty()) {
            String payload = activeTicketsPayload();
            String url = "https://" + sCSMLandscape + ".serviceaide.com"+sCSMservice;
            String sb = connectToServiceDesk(url, payload);
    
            Document doc = Jsoup.parse(sb.split("apache.org>")[1].split("--MIMEBoundary")[0]);
            String text = doc.getElementsByTag("ax286:responseText").text();
    
            int cIndex = text.indexOf("}]");
            if (cIndex >= 0)
                text = text.substring(0, cIndex + 2);
            JsonParser jsonparser = new JsonParser();
            JsonElement jo = jsonparser.parse(text);
            JsonArray arr = jo.getAsJsonArray();
            for (JsonElement ele : arr) {
                JsonObject json = ele.getAsJsonObject();
                //System.out.println(json.get("ticket_description").getAsString());
    
                if (json.get("ticket_description").getAsString().toUpperCase().contains(sTicketDescription.toUpperCase()) ) {
                    if (tickets == null) {
                        tickets = new HashSet<>();
                    }
                    String[] ticketDetails = json.get("ticket_details").getAsString().split("\n");
                    for (String t : ticketDetails) {
                        tickets.add(t);
                    }
                }
            }
        }

        return tickets;
    }

    private String generateServiceRequestPayload(String descriptionLong, String ticketDescription) {
        StringBuilder payload = new StringBuilder();
        payload.append("<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:wrap=\"http://wrappers.webservice.appservices.core.inteqnet.com\" xmlns:xsd=\"http://beans.webservice.appservices.core.inteqnet.com/xsd\"> ");
        payload.append("    <soapenv:Header/> ");
        payload.append("    <soapenv:Body> ");
        payload.append("        <wrap:logServiceRequest> ");
        payload.append("            <wrap:credentials> ");
        payload.append("                <xsd:userName>" + username + "</xsd:userName> ");
        payload.append("                <xsd:userPassword>" + password + "</xsd:userPassword> ");
        payload.append("            </wrap:credentials> ");
        payload.append("            <wrap:extendedSettings> ");
        payload.append("                <xsd:responseFormat>JSON</xsd:responseFormat> ");
        payload.append("            </wrap:extendedSettings> ");
        payload.append("            <wrap:srqBean> ");
        payload.append("                <xsd:description_long>" + descriptionLong + "</xsd:description_long> ");
        payload.append("                <xsd:assigned_to_group_name>" + assignedToGroupName + "</xsd:assigned_to_group_name> ");
        payload.append("                <xsd:requester_name>" + requestorName + "</xsd:requester_name> ");
        payload.append("                <xsd:ticket_description>" + ticketDescription + "</xsd:ticket_description>  ");
        payload.append("            </wrap:srqBean> ");
        payload.append("        </wrap:logServiceRequest> ");
        payload.append("    </soapenv:Body> ");
        payload.append("</soapenv:Envelope>");

        return payload.toString();
    }

    private String activeTicketsPayload() {
        StringBuilder payload = new StringBuilder();
        payload.append("<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:wrap=\"http://wrappers.webservice.appservices.core.inteqnet.com\" xmlns:xsd=\"http://beans.webservice.appservices.core.inteqnet.com/xsd\">");
        payload.append("    <soapenv:Header/>");
        payload.append("    <soapenv:Body>");
        payload.append("        <wrap:getSQLQueryResults>");
        payload.append("            <wrap:credentials>");
        payload.append("                <xsd:userName>" + username + "</xsd:userName>");
        payload.append("                <xsd:userPassword>" + password + "</xsd:userPassword>");
        payload.append("            </wrap:credentials>");
        payload.append("            <wrap:extendedSettings>");
        payload.append("                <xsd:responseFormat>JSON</xsd:responseFormat>");
        payload.append("            </wrap:extendedSettings>");
        payload.append("            <wrap:declareSection></wrap:declareSection>  ");
        payload.append("            <wrap:sqlSelect>SELECT slice, ticket_id, ticket_description, ticket_details, ticket_status, assigned_to_name, created_by_name, ccti_class FROM vapp_item (NOLOCK) where assigned_to_group_name = '" + assignedToGroupName + "' and ticket_status in ('Active','Queued')  </wrap:sqlSelect>");
        payload.append("            <wrap:orderByClause></wrap:orderByClause>");
        payload.append("        </wrap:getSQLQueryResults>");
        payload.append("    </soapenv:Body>");
        payload.append("</soapenv:Envelope>");

        return payload.toString();
    }

    private String connectToServiceDesk(String url, String payload) throws IOException {

        URL _url = new URL(url);
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

        return sb.toString();
    }

}