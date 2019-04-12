package ac.at.tuwien.ifs.sepses;

import ac.at.tuwien.ifs.sepses.parser.Parser;
import ac.at.tuwien.ifs.sepses.parser.impl.CAPECParser;
import ac.at.tuwien.ifs.sepses.parser.impl.CPEParser;
import ac.at.tuwien.ifs.sepses.parser.impl.CVEParser;
import ac.at.tuwien.ifs.sepses.parser.impl.CWEParser;
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
        Parser capecParser = new CAPECParser(prop);
        Parser cweParser = new CWEParser(prop);
        Parser cpeParser = new CPEParser(prop);
        Parser cveParser = new CVEParser(prop);

        long start = System.currentTimeMillis() / 1000;
        long end;

        // *** parse source files in the following order

        // 1. CAPEC
        log.info("start CAPEC parser");
        capecParser.parse();
        log.info("************* CAPEC parser finished");

        // 2. CWE
        log.info("start CWE parser");
        cweParser.parse();
        log.info("************* CWE parser finished");

        // 3. CPE
        log.info("start CPE parser");
        cpeParser.parse();
        log.info("************* CPE parser finished");

        // 4. CVE
        log.info("start CVE parser");
        cveParser.parse();
        log.info("************* CVE parser finished");

        end = System.currentTimeMillis() / 1000;
        log.info("Transformation process finished in " + (end - start) + " seconds");
    }

}
