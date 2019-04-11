package ac.at.tuwien.ifs.sepses;

import ac.at.tuwien.ifs.sepses.parser.CAPECParser;
import ac.at.tuwien.ifs.sepses.parser.CPEParser;
import ac.at.tuwien.ifs.sepses.parser.CVEParser;
import ac.at.tuwien.ifs.sepses.parser.CWEParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.util.Properties;

public class MainParser {

    private static final Logger log = LoggerFactory.getLogger(MainParser.class);

    public static void main(String[] args) throws Exception {
        Properties prop = new Properties();
        FileInputStream ip = new FileInputStream("config.properties");
        prop.load(ip);

        long start = System.currentTimeMillis() / 1000;
        long end;

        // *** parse source files in the following order

        // 1. CAPEC
        log.info("start CAPEC process");
        CAPECParser.parseCAPEC(prop);

        // 2. CWE
        log.info("start CWE process");
        CWEParser.parseCWE(prop);

        // 3. CPE
        log.info("start CPE process");
        CPEParser.parseCPE(prop);

        // 4. CVE
        log.info("start CVE process");
        CVEParser.parseCVE(prop);

        end = System.currentTimeMillis() / 1000;
        log.info("Transformation process finished in " + (end - start) + " seconds");
    }

}
