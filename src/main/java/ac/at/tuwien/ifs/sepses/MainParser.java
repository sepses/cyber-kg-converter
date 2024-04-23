package ac.at.tuwien.ifs.sepses;

import ac.at.tuwien.ifs.sepses.parser.Parser;
import ac.at.tuwien.ifs.sepses.parser.impl.CAPECParser;
import ac.at.tuwien.ifs.sepses.parser.impl.CATParser;
import ac.at.tuwien.ifs.sepses.parser.impl.CPEParser;
import ac.at.tuwien.ifs.sepses.parser.impl.CVEParserJson;
import ac.at.tuwien.ifs.sepses.parser.impl.CWEParser;
import ac.at.tuwien.ifs.sepses.parser.impl.ICSAParser;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.util.Properties;

public class MainParser {

    private static final Logger log = LoggerFactory.getLogger(MainParser.class);

    public static void main(String[] args) throws Exception {

        Options options = new Options();
        options.addOption("p", true, "Type of parser (cpe, cve, cwe, capec)");
        options.addOption("v", false, "Activation of the SHACL validation");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);
        String program = cmd.getOptionValue("p");
        Boolean isShaclActive = cmd.hasOption("v");

        Parser sourceParser;
        Properties prop = new Properties();
        FileInputStream ip = new FileInputStream("config.properties");
        prop.load(ip);
        ip.close();

        long start = System.currentTimeMillis();
        long end;
        if (program.equals("capec")) {
            log.info("start CAPEC parser");
            sourceParser = new CAPECParser(prop);
            sourceParser.parse(isShaclActive);
            log.info("************* CAPEC parser finished");
        } else if (program.equals("cpe")) {
            log.info("start CPE parser");
            sourceParser = new CPEParser(prop);
            sourceParser.parse(isShaclActive);
            log.info("************* CPE parser finished");
        } else if (program.equals("cwe")) {
            log.info("start CWE parser");
            sourceParser = new CWEParser(prop);
            sourceParser.parse(isShaclActive);
            log.info("************* CWE parser finished");
        } else if (program.equals("cve")) {
            log.info("start CVE parser");
            sourceParser = new CVEParserJson(prop);
            sourceParser.parse(isShaclActive);
            log.info("************* CVE parser finished");
        }else if (program.equals("cat")) {
            log.info("start CAT parser");
            sourceParser = new CATParser(prop);
            sourceParser.parse(isShaclActive);
            log.info("************* CAT parser finished");
        }else if (program.equals("icsa")) {
            log.info("start CAT parser");
            sourceParser = new ICSAParser(prop);
            sourceParser.parse(isShaclActive);
            log.info("************* ICSA parser finished");
        }

        end = System.currentTimeMillis();
        log.info("Transformation process finished in " + (end - start) + " milliseconds");
        System.gc();
        Thread.sleep(5000);
    }

}
