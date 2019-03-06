import continuesUpdate.*;
import java.io.FileInputStream;
import java.util.Properties;

public class MainParserSepses {
	
    public static void main(String[] args) throws Exception {
    	Properties prop =  new Properties();
    	FileInputStream ip= new FileInputStream("config.properties");
    	prop.load(ip);
    	    	
    	//parse as the order
    	//1. CAPEC
    		CAPECXMLContinuesParser.parseCAPEC(prop);
    	//2. CWE
    		CWEXMLContinuesParser.parseCWE(prop);
    	//3. CPE
    		CPEXMLContinuesParser.parseCPE(prop);
    	//4. CVE
    		CVEXMLContinuesParser.parseCVE(prop);
    		   		
    }
    
    
}
