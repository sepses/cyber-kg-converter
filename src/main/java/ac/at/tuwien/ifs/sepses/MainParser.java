package ac.at.tuwien.ifs.sepses;

import ac.at.tuwien.ifs.sepses.processor.parser.CAPECParser;

import java.io.FileInputStream;
import java.util.Properties;

public class MainParser {

    public static void main(String[] args) throws Exception {
        Properties prop = new Properties();
        FileInputStream ip = new FileInputStream("config.properties");
        prop.load(ip);

        //parse as the order
        //1. CAPEC
        CAPECParser.parseCAPEC(prop);
        //        //2. CWE
        //        CWEParser.parseCWE(prop);
        //        //3. CPE
        //        CPEParser.parseCPE(prop);
        //        //4. CVE
        //        CVEParser.parseCVE(prop);

    }

}
