package ac.at.tuwien.ifs.sepses.processor.helper;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class Curl {

    public static void storeData(String file, String namegraph) throws IOException {
        System.out.println(file);
        String url = "http://localhost:8890/sparql-graph-crud-auth?graph-uri=" + namegraph;
        String user = "dba";
        String pass = "dba";
        String command = "curl --digest -u " + user + ":" + pass + " -v -X POST -T " + file + " " + url;
        Runtime.getRuntime().exec(command);

    }

    public static void storeInitData(String file, String namegraph) throws IOException {
        System.out.println(file);
        String url = "http://localhost:8890/sparql-graph-crud-auth?graph-uri=" + namegraph;
        String user = "dba";
        String pass = "dba";
        String command = "curl --digest -u " + user + ":" + pass + " -v -X PUT -T " + file + " " + url;
        Runtime.getRuntime().exec(command);

    }

    public static void produceOutputFile(org.apache.jena.rdf.model.Model model, String outputDir, String fileName)
            throws IOException {
        String CPEfileName = outputDir + "/" + fileName + "-output.ttl";
        File outputFile = new File(CPEfileName);
        outputFile.getParentFile().mkdirs();
        FileWriter out = new FileWriter(outputFile);
        try {
            model.write(out, "TURTLE");
        } finally {
            // model.close();
        }
    }

}
