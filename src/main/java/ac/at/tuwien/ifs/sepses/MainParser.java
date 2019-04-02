package ac.at.tuwien.ifs.sepses;

import ac.at.tuwien.ifs.sepses.update.parser.CAPECXMLContinuesParser;
import ac.at.tuwien.ifs.sepses.update.parser.CPEXMLContinuesParser;
import ac.at.tuwien.ifs.sepses.update.parser.CVEXMLContinuesParser;
import ac.at.tuwien.ifs.sepses.update.parser.CWEXMLContinuesParser;

import java.io.FileInputStream;
import java.util.Properties;

public class MainParser {

    public static void main(String[] args) throws Exception {
        Properties prop = new Properties();
        FileInputStream ip = new FileInputStream("config.properties");
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
